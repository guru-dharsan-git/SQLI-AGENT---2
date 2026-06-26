import time
from copy import deepcopy
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import requests

from agent.config import LOCAL_HOSTS, MAX_RESPONSE_CHARS
from agent.redaction import redact_text


class TargetNotAllowed(ValueError):
    pass


def assert_allowed_target(url, allow_remote=False):
    host = (urlsplit(url).hostname or "").lower()

    if allow_remote or host in LOCAL_HOSTS:
        return

    raise TargetNotAllowed(
        f"Refusing non-local target {url}. Use --allow-remote-targets to override."
    )


def summarize_response(response, elapsed_ms):
    return {
        "status_code": response.status_code,
        "elapsed_ms": elapsed_ms,
        "content_type": response.headers.get("Content-Type", ""),
        "location": response.headers.get("Location", ""),
        "body_length": len(response.content),
        "body_sample": redact_text(
            response.text[:MAX_RESPONSE_CHARS],
            redact_paths=True,
        ),
    }


def path_with_replaced_segment(path, param, value):
    if "path_index" not in param:
        path = path.replace(f":{param['name']}", quote(value, safe=""))
        return path.replace(f"{{{param['name']}}}", quote(value, safe=""))

    segments = [segment for segment in path.split("/") if segment]
    index = int(param["path_index"])

    if index < 0 or index >= len(segments):
        return path

    segments[index] = quote(value, safe="")

    return "/" + "/".join(segments)


def request_with_value(target, param, value, timeout, allow_remote=False):
    url = target["url"]
    method = target["method"].upper()
    location = param["in"]
    name = param["name"]
    request_kwargs = {"timeout": timeout, "allow_redirects": False}
    parts = urlsplit(url)

    assert_allowed_target(url, allow_remote=allow_remote)

    if location == "query":
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        query[name] = value
        url = urlunsplit((
            parts.scheme,
            parts.netloc,
            parts.path,
            urlencode(query),
            "",
        ))

    elif location == "json":
        body = {
            item["name"]: "agent_baseline"
            for item in target.get("params", [])
            if item.get("in") == "json"
        }
        body[name] = value
        request_kwargs["json"] = body

    elif location == "form":
        body = {
            item["name"]: "agent_baseline"
            for item in target.get("params", [])
            if item.get("in") == "form"
        }
        body[name] = value
        request_kwargs["data"] = body

    elif location == "path":
        path = path_with_replaced_segment(parts.path, param, value)
        url = urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))

    started = time.perf_counter()
    response = requests.request(method, url, **request_kwargs)
    elapsed_ms = int((time.perf_counter() - started) * 1000)

    return summarize_response(response, elapsed_ms)


def baseline_value(param):
    if param.get("in") == "path" and param.get("original_value"):
        return str(param["original_value"])

    return "agent_baseline"


def probe_payload(target, param, payload, timeout, allow_remote=False):
    baseline_target = deepcopy(target)
    probe_target = deepcopy(target)

    baseline = request_with_value(
        baseline_target,
        param,
        baseline_value(param),
        timeout,
        allow_remote=allow_remote,
    )
    probe = request_with_value(
        probe_target,
        param,
        payload,
        timeout,
        allow_remote=allow_remote,
    )

    return baseline, probe
