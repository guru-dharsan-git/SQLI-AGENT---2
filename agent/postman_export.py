import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from agent.report import (
    capability_summary,
    has_login_bypass_signal,
    has_read_marker_signal,
    has_sql_error_signal,
    normalize_attempt_signals,
)


DEFAULT_AGENT_RESULTS_FILE = "agent_results.json"
DEFAULT_POSTMAN_TESTS_FILE = "postman_sqli_tests.md"
DEFAULT_POSTMAN_COLLECTION_FILE = "postman_sqli_collection.json"
DEFAULT_SUMMARY_FILE = "sqli_vulnerable_payloads.json"


def load_json(file_path):
    return json.loads(Path(file_path).read_text(encoding="utf-8"))


def signal_name(attempt):
    if has_read_marker_signal(attempt):
        return "constant_read_confirmation"

    if attempt.get("payload_phase") == "read_confirmation":
        return ""

    if has_login_bypass_signal(attempt):
        return "authentication_bypass"

    if has_sql_error_signal(attempt):
        return "sql_error"

    return ""


def evidence_text(attempt):
    signal = signal_name(attempt)
    probe = attempt.get("probe") or {}
    body = probe.get("body_sample", "")

    if signal == "authentication_bypass":
        return "Baseline returned 401, probe returned 200 with authentication data."

    if signal == "constant_read_confirmation":
        marker = (attempt.get("response_signal") or {}).get("read_marker", "")
        return f"Probe response reflected non-sensitive SQL marker `{marker}`."

    if "SQLITE_ERROR" in body:
        title_start = body.find("Error:")

        if title_start != -1:
            return body[title_start: title_start + 140].replace("\n", " ")

        return "Probe response exposed SQLITE_ERROR."

    return "Probe response changed in a SQLi-relevant way."


def confirmed_payloads(agent_results):
    items = []

    for target in agent_results.get("results", []):
        for param in target.get("params", []):
            for attempt in param.get("attempts", []):
                signal = signal_name(attempt)

                if not signal:
                    continue

                items.append({
                    "method": target.get("method", ""),
                    "url": target.get("url", ""),
                    "path": target.get("path", ""),
                    "endpoint_context": target.get("endpoint_context", {}),
                    "target_params": target.get("params", []),
                    "parameter": param.get("name", ""),
                    "parameter_location": param.get("in", ""),
                    "path_index": param.get("path_index"),
                    "original_value": param.get("original_value"),
                    "payload": attempt.get("payload", ""),
                    "payload_rationale": attempt.get("payload_rationale", ""),
                    "expected_signal": attempt.get("expected_signal", ""),
                    "observed_signal": signal,
                    "evidence": evidence_text(attempt),
                    "baseline_status": (attempt.get("baseline") or {}).get("status_code"),
                    "probe_status": (attempt.get("probe") or {}).get("status_code"),
                })

    return dedupe_payloads(items)


def dedupe_payloads(items):
    seen = set()
    deduped = []

    for item in items:
        key = (
            item["method"],
            item["path"],
            item["parameter"],
            item["parameter_location"],
            item["payload"],
        )

        if key in seen:
            continue

        seen.add(key)
        deduped.append(item)

    return deduped


def request_url(item):
    if item["parameter_location"] == "path":
        parts = urlsplit(item["url"])
        segments = [segment for segment in parts.path.split("/") if segment]
        index = item.get("path_index")

        if index is not None and 0 <= int(index) < len(segments):
            segments[int(index)] = quote(item["payload"], safe="")
            path = "/" + "/".join(segments)
            return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))

    if item["parameter_location"] != "query":
        return item["url"]

    parts = urlsplit(item["url"])
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[item["parameter"]] = item["payload"]

    return urlunsplit((
        parts.scheme,
        parts.netloc,
        parts.path,
        urlencode(query),
        "",
    ))


def request_body(item):
    if item["parameter_location"] != "json":
        return None

    body = {
        param.get("name"): "agent_baseline"
        for param in item.get("target_params", [])
        if param.get("in") == "json" and param.get("name")
    }
    body[item["parameter"]] = item["payload"]

    return body


def markdown_report(items):
    lines = [
        "# Postman SQLi Payload Tests",
        "",
        "These payloads came from confirmed local probe evidence in `agent_results.json`.",
        "Use them only against an authorized local target through the configured proxy.",
        "",
    ]

    if not items:
        lines.append("No confirmed SQLi payloads were found.")
        return "\n".join(lines) + "\n"

    for index, item in enumerate(items, 1):
        endpoint_context = item.get("endpoint_context") or {}
        lines.extend([
            f"## {index}. {item['method']} {item['path']}",
            "",
            f"- Endpoint type: `{endpoint_context.get('endpoint_type', 'unknown')}`",
            f"- Attack style: `{endpoint_context.get('recommended_attack_style', 'unknown')}`",
            f"- Vulnerable parameter: `{item['parameter']}` in `{item['parameter_location']}`",
            f"- Payload: `{item['payload']}`",
            f"- Observed signal: `{item['observed_signal']}`",
            f"- Evidence: {item['evidence']}",
            "",
            "Postman setup:",
            f"- Method: `{item['method']}`",
            f"- URL: `{request_url(item)}`",
        ])

        body = request_body(item)

        if body is not None:
            lines.extend([
                "- Header: `Content-Type: application/json`",
                "- Body:",
                "",
                "```json",
                json.dumps(body, indent=2),
                "```",
            ])

        lines.append("")

    return "\n".join(lines).strip() + "\n"


def postman_request(item):
    url = request_url(item)
    parts = urlsplit(url)
    raw_path = parts.path

    if parts.query:
        raw_path += "?" + parts.query

    request = {
        "method": item["method"],
        "header": [],
        "url": {
            "raw": url,
            "protocol": parts.scheme,
            "host": parts.hostname.split(".") if parts.hostname else [],
            "port": str(parts.port) if parts.port else "",
            "path": [part for part in parts.path.split("/") if part],
            "query": [
                {"key": key, "value": value}
                for key, value in parse_qsl(parts.query, keep_blank_values=True)
            ],
        },
        "description": item["evidence"],
    }
    body = request_body(item)

    if body is not None:
        request["header"].append({
            "key": "Content-Type",
            "value": "application/json",
        })
        request["body"] = {
            "mode": "raw",
            "raw": json.dumps(body, indent=2),
            "options": {"raw": {"language": "json"}},
        }

    request["url"]["raw"] = urlunsplit((
        parts.scheme,
        parts.netloc,
        raw_path,
        "",
        "",
    ))

    return request


def postman_collection(items):
    return {
        "info": {
            "name": "SQLi Confirmed Payloads",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            "description": (
                "Generated from confirmed local SQLi probe evidence. "
                "Run only against an authorized local target."
            ),
        },
        "item": [
            {
                "name": f"{item['method']} {item['path']} - {item['parameter']}",
                "request": postman_request(item),
            }
            for item in items
        ],
    }


def export_postman_tests(
        agent_results_file=DEFAULT_AGENT_RESULTS_FILE,
        markdown_file=DEFAULT_POSTMAN_TESTS_FILE,
        collection_file=DEFAULT_POSTMAN_COLLECTION_FILE,
        summary_file=DEFAULT_SUMMARY_FILE
):
    agent_results = normalize_attempt_signals(load_json(agent_results_file))
    items = confirmed_payloads(agent_results)
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "agent_results_file": agent_results_file,
        "confirmed_payload_count": len(items),
        "confirmed_payloads": items,
        "capability_summary": capability_summary(agent_results),
    }

    Path(summary_file).write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )
    Path(markdown_file).write_text(markdown_report(items), encoding="utf-8")
    Path(collection_file).write_text(
        json.dumps(postman_collection(items), indent=2),
        encoding="utf-8",
    )

    return {
        "summary": summary_file,
        "markdown": markdown_file,
        "collection": collection_file,
        "payload_count": len(items),
    }
