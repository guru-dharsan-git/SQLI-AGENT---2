import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import requests

from Scanner.scanner import scan


BASE_URL = "http://127.0.0.1:8080"
DEFAULT_DISCOVERY_URLS = (BASE_URL,)
LOCAL_HOSTS = {"localhost", "127.0.0.1"}
OBSERVED_ENDPOINTS = "observed_endpoints.txt"
OBSERVED_PARAMS = "observed_params.json"
OBSERVED_REQUESTS = "observed_requests.json"
SCAN_RESULTS = "scan_results.json"
SCAN_ENDPOINTS = "scan_endpoints.json"
SCAN_PARAMS = "scan_params.json"
SQLI_TARGETS = "sqli_targets.json"
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
PATH_PARAM_RE = re.compile(r":([A-Za-z_]\w*)|\{([A-Za-z_]\w*)\}")
DYNAMIC_PATH_SEGMENT_RE = re.compile(
    r"^\d+$|^[0-9a-fA-F]{8,}$|^[0-9a-fA-F-]{12,}$"
)


def describe_scan_source(url, timeout):
    try:
        response = requests.get(
            url,
            headers={"Accept-Encoding": "identity"},
            timeout=max(timeout, 10),
        )
    except Exception as error:
        return {"error": str(error)}

    details = {
        "http_status": response.status_code,
        "content_type": response.headers.get("Content-Type", ""),
    }

    try:
        body = response.json()
    except ValueError:
        body = None

    if isinstance(body, dict) and body.get("error"):
        details["error"] = body["error"]

    return details


def normalize_endpoint(endpoint, base_url=BASE_URL):
    base = urlsplit(base_url)
    parts = urlsplit(str(endpoint or "").strip())

    if not parts.scheme and not parts.netloc:
        parts = urlsplit("/" + str(endpoint).lstrip("/"))

    scheme = (parts.scheme or base.scheme or "http").lower()
    host = (parts.hostname or base.hostname or "127.0.0.1").lower()
    port = parts.port

    if host in LOCAL_HOSTS:
        host = (base.hostname or "127.0.0.1").lower()
        port = base.port

    path = re.sub(r"/+", "/", parts.path or "/")

    if path != "/":
        path = path.rstrip("/")

    query_params = sorted({
        name
        for name, _ in parse_qsl(parts.query, keep_blank_values=True)
    })
    netloc = f"{host}:{port}" if port else host

    return urlunsplit((scheme, netloc, path, "", "")), path, query_params


def is_usable_observed_endpoint(endpoint):
    value = str(endpoint or "")

    return "[REDACTED_PATH]" not in value


def clean_resource_name(value):
    resource = re.sub(r"[^A-Za-z0-9]+", "_", str(value or "").strip()).strip("_")

    if not resource:
        return "path"

    resource = resource.lower()

    if resource.endswith("ies") and len(resource) > 3:
        return resource[:-3] + "y"

    if resource.endswith("s") and len(resource) > 1:
        return resource[:-1]

    return resource


def inferred_path_params(path):
    segments = [segment for segment in path.split("/") if segment]
    params = []

    for index, segment in enumerate(segments):
        if not DYNAMIC_PATH_SEGMENT_RE.match(segment):
            continue

        resource = clean_resource_name(segments[index - 1] if index else "path")
        params.append({
            "name": f"{resource}_id",
            "path_index": index,
            "original_value": segment,
        })

    return params


def get_sqli_injection_targets(
        base_url=BASE_URL,
        discovery_urls=DEFAULT_DISCOVERY_URLS,
        include_observed=True,
        only_with_params=True,
        timeout=2
):
    inventory = {}
    warnings = []
    scan_sources = []

    def add_param(item, location, name, source, extra=None):
        if not name:
            return

        key = (location, name)
        item["params"].setdefault(key, {
            "name": name,
            "in": location,
            "sources": set(),
        })
        item["params"][key]["sources"].add(source)

        for extra_key, extra_value in (extra or {}).items():
            item["params"][key].setdefault(extra_key, extra_value)

    def add_endpoint(method, endpoint, source, params=None):
        if not is_usable_observed_endpoint(endpoint):
            warnings.append(f"Skipped unusable observed endpoint from {source}")
            return

        url, path, query_params = normalize_endpoint(endpoint, base_url)
        method = method.upper() if method and method.upper() in HTTP_METHODS else "GET"
        key = (method, path)
        item = inventory.setdefault(key, {
            "method": method,
            "path": path,
            "url": url,
            "params": {},
            "sources": set(),
        })
        item["sources"].add(source)

        for name in query_params:
            add_param(item, "query", name, source)

        for first, second in PATH_PARAM_RE.findall(path):
            add_param(item, "path", first or second, source)

        for path_param in inferred_path_params(path):
            add_param(
                item,
                "path",
                path_param["name"],
                source,
                {
                    "path_index": path_param["path_index"],
                    "original_value": path_param["original_value"],
                },
            )

        for location, names in (params or {}).items():
            for name in names:
                add_param(item, location, name, source)

    def read_json(file_name, default):
        path = Path(file_name)

        if not path.exists():
            return default

        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            warnings.append(f"Could not parse {file_name}")
            return default

    def run_live_scan():
        total_found = 0
        errors = []

        for discovery_url in discovery_urls:
            try:
                endpoints = scan(discovery_url, include_observed=False, timeout=timeout)
            except Exception as error:
                errors.append(f"{discovery_url}: {error}")
                continue

            for endpoint in endpoints:
                add_endpoint("GET", endpoint, "live_scan")

            scan_source = {
                "url": discovery_url,
                "endpoint_count": len(endpoints),
                "status": "ok" if endpoints else "no_endpoints",
            }

            if not endpoints:
                scan_source.update(describe_scan_source(discovery_url, timeout))

            scan_sources.append(scan_source)
            total_found += len(endpoints)

        if total_found == 0:
            warnings.append(f"Live scan found no endpoints. {'; '.join(errors)}")

    def load_observed_data():
        endpoint_file = Path(OBSERVED_ENDPOINTS)

        if endpoint_file.exists():
            for line in endpoint_file.read_text(encoding="utf-8").splitlines():
                parts = line.strip().split(" ", 1)

                if len(parts) == 2:
                    add_endpoint(parts[0], parts[1], "observed_endpoints")

        for item in read_json(OBSERVED_PARAMS, {}).values():
            if not is_usable_observed_endpoint(item.get("path", "")):
                warnings.append("Skipped unusable observed_params entry")
                continue

            add_endpoint(item.get("method", "GET"), item.get("path", "/"), "observed_params", {
                "query": item.get("query_params", []),
                "form": item.get("form_params", []),
                "json": item.get("json_body_fields", []),
            })

        for item in read_json(OBSERVED_REQUESTS, []):
            if not is_usable_observed_endpoint(item.get("path", "")):
                warnings.append("Skipped unusable observed_requests entry")
                continue

            add_endpoint(item.get("method", "GET"), item.get("path", "/"), "observed_requests", {
                "query": item.get("query_params", {}).keys(),
                "form": item.get("form_params", {}).keys(),
                "json": item.get("json_body_fields", []),
            })

    run_live_scan()

    if include_observed:
        load_observed_data()

    endpoints = []

    for item in inventory.values():
        params = []

        for param in item["params"].values():
            param_item = {
                "name": param["name"],
                "in": param["in"],
                "sources": sorted(param["sources"]),
            }

            for extra_key in ("path_index", "original_value"):
                if extra_key in param:
                    param_item[extra_key] = param[extra_key]

            params.append(param_item)

        params.sort(key=lambda param: (param["in"], param["name"]))

        endpoints.append({
            "method": item["method"],
            "path": item["path"],
            "url": item["url"],
            "params": params,
            "sources": sorted(item["sources"]),
        })

    endpoints.sort(key=lambda item: (item["path"], item["method"]))
    targets = [item for item in endpoints if item["params"] or not only_with_params]

    return {
        "base_url": normalize_endpoint(base_url, base_url)[0].rstrip("/"),
        "scan_sources": scan_sources,
        "live_endpoint_count": sum(
            source["endpoint_count"]
            for source in scan_sources
        ),
        "endpoint_count": len(endpoints),
        "target_count": len(targets),
        "endpoints": endpoints,
        "targets": targets,
        "warnings": warnings,
    }


def save_scan_artifacts(result, output_dir="."):
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    params = [
        {
            "method": endpoint["method"],
            "path": endpoint["path"],
            "url": endpoint["url"],
            "params": endpoint["params"],
            "sources": endpoint["sources"],
        }
        for endpoint in result["endpoints"]
        if endpoint["params"]
    ]

    files = {
        SCAN_RESULTS: result,
        SCAN_ENDPOINTS: result["endpoints"],
        SCAN_PARAMS: params,
        SQLI_TARGETS: result["targets"],
    }

    for file_name, data in files.items():
        (output_path / file_name).write_text(
            json.dumps(data, indent=2),
            encoding="utf-8"
        )

    return sorted(files)
