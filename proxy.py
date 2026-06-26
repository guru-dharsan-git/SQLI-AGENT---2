# proxy.py

from flask import Flask, request, Response, jsonify
import requests
import json
from datetime import datetime

from agent.redaction import redact_data, redact_text

app = Flask(__name__)

TARGET = "http://localhost:3000"

OBSERVED_ENDPOINTS_FILE = "observed_endpoints.txt"
OBSERVED_REQUESTS_FILE = "observed_requests.json"
OBSERVED_PARAMS_FILE = "observed_params.json"

EXCLUDED_RESPONSE_HEADERS = {
    "cache-control",
    "content-encoding",
    "content-length",
    "connection",
    "etag",
    "expires",
    "last-modified",
    "pragma",
    "transfer-encoding",
    "vary"
}

EXCLUDED_REQUEST_HEADERS = {
    "host",
    "content-length",
    "connection",
    "accept-encoding"
}

# Only these are considered REST/API traffic
REST_API_PREFIXES = (
    "/api",
    "/rest",
    "/b2b",
)

# These are proxy/system endpoints, not target app APIs
IGNORED_ENDPOINT_PREFIXES = (
    "/proxy-clear-cache",
    "/proxy-health",
    "/socket.io",
    "/observed-endpoints",
    "/observed-requests",
    "/observed-params",
    "/reset-observed",
)

observed_endpoints = set()
observed_requests = []
observed_params = {}

NO_CACHE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
}


def is_rest_api_path(path):
    base_path = path.split("?", 1)[0]

    return any(
        base_path == prefix or base_path.startswith(prefix + "/")
        for prefix in REST_API_PREFIXES
    )


def is_ignored_path(path):
    base_path = path.split("?", 1)[0]

    return any(
        base_path == prefix or base_path.startswith(prefix + "/")
        for prefix in IGNORED_ENDPOINT_PREFIXES
    )


def should_capture_endpoint(path):
    if is_ignored_path(path):
        return False

    if not is_rest_api_path(path):
        return False

    return True


def write_json_file(file_path, data):
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def save_all_observed_data():
    with open(OBSERVED_ENDPOINTS_FILE, "w", encoding="utf-8") as file:
        for method, path in sorted(observed_endpoints):
            file.write(f"{method} {path}\n")

    write_json_file(
        OBSERVED_REQUESTS_FILE,
        observed_requests
    )

    write_json_file(
        OBSERVED_PARAMS_FILE,
        observed_params
    )


def add_endpoint(method, path):
    if not should_capture_endpoint(path):
        return False

    observed_endpoints.add((method, path))
    save_all_observed_data()

    return True


def flatten_json_keys(data, prefix=""):
    keys = []

    if isinstance(data, dict):
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            keys.append(full_key)

            if isinstance(value, (dict, list)):
                keys.extend(
                    flatten_json_keys(value, full_key)
                )

    elif isinstance(data, list):
        for index, item in enumerate(data):
            full_key = f"{prefix}[{index}]"

            if isinstance(item, (dict, list)):
                keys.extend(
                    flatten_json_keys(item, full_key)
                )

    return keys


def extract_request_inputs():
    query_params = {}

    for key in request.args:
        query_params[key] = request.args.getlist(key)

    form_params = {}

    for key in request.form:
        form_params[key] = request.form.getlist(key)

    json_body = None
    json_body_fields = []

    if request.is_json:
        json_body = request.get_json(silent=True)

        if json_body is not None:
            json_body_fields = flatten_json_keys(json_body)

    raw_body = request.get_data(as_text=True)

    cookies = {}

    for key in request.cookies:
        cookies[key] = request.cookies.get(key)

    important_headers = {}

    for key, value in request.headers:
        lower_key = key.lower()

        if lower_key in [
            "authorization",
            "x-access-token",
            "x-auth-token",
            "cookie",
            "content-type"
        ]:
            important_headers[key] = value

    return {
        "query_params": redact_data(query_params),
        "form_params": redact_data(form_params),
        "json_body": redact_data(json_body),
        "json_body_fields": json_body_fields,
        "raw_body": redact_text(raw_body),
        "cookies": redact_data(cookies),
        "important_headers": redact_data(important_headers)
    }


def update_observed_params(method, endpoint_path, inputs):
    base_path = endpoint_path.split("?", 1)[0]
    key = f"{method} {base_path}"

    if key not in observed_params:
        observed_params[key] = {
            "method": method,
            "path": base_path,
            "query_params": [],
            "form_params": [],
            "json_body_fields": [],
            "cookie_params": [],
            "important_headers": [],
            "example_query_params": {},
            "example_form_params": {},
            "example_json_body": None,
            "seen_count": 0
        }

    item = observed_params[key]
    item["seen_count"] += 1

    for param, values in inputs["query_params"].items():
        if param not in item["query_params"]:
            item["query_params"].append(param)

        if param not in item["example_query_params"]:
            item["example_query_params"][param] = values

    for param, values in inputs["form_params"].items():
        if param not in item["form_params"]:
            item["form_params"].append(param)

        if param not in item["example_form_params"]:
            item["example_form_params"][param] = values

    for param in inputs["json_body_fields"]:
        if param not in item["json_body_fields"]:
            item["json_body_fields"].append(param)

    if item["example_json_body"] is None and inputs["json_body"] is not None:
        item["example_json_body"] = inputs["json_body"]

    for param in inputs["cookies"]:
        if param not in item["cookie_params"]:
            item["cookie_params"].append(param)

    for header in inputs["important_headers"]:
        if header not in item["important_headers"]:
            item["important_headers"].append(header)


def record_observed_request(method, endpoint_path, target_url, inputs, response):
    if not should_capture_endpoint(endpoint_path):
        return

    item = {
        "time": str(datetime.now()),
        "method": method,
        "path": endpoint_path,
        "base_path": endpoint_path.split("?", 1)[0],
        "target_url": redact_text(target_url),

        "query_params": inputs["query_params"],
        "form_params": inputs["form_params"],
        "json_body": inputs["json_body"],
        "json_body_fields": inputs["json_body_fields"],
        "raw_body": inputs["raw_body"],

        "cookies": inputs["cookies"],
        "important_headers": inputs["important_headers"],

        "response_status": response.status_code,
        "response_content_type": response.headers.get("Content-Type", ""),
        "response_sample": redact_text(response.text[:500], redact_paths=True)
    }

    observed_requests.append(item)

    update_observed_params(
        method,
        endpoint_path,
        inputs
    )

    save_all_observed_data()


def log_request(method, url, body):
    print("\n" + "=" * 80)
    print(f"[{datetime.now()}]")
    print(f"METHOD : {method}")
    print(f"URL    : {url}")
    print("BODY:")

    try:
        print(json.dumps(redact_data(body), indent=2))
    except Exception:
        print(redact_text(body))

    print("=" * 80)


def log_response(response):
    print(f"STATUS : {response.status_code}")
    print(f"TYPE   : {response.headers.get('Content-Type', 'Unknown')}")

    try:
        if "application/json" in response.headers.get("Content-Type", ""):
            print("RESPONSE:")
            print(redact_text(response.text[:500], redact_paths=True))
    except Exception:
        pass

    print("-" * 80)


@app.route("/observed-endpoints", methods=["GET"])
def show_observed_endpoints():
    return jsonify({
        "count": len(observed_endpoints),
        "endpoints": [
            {
                "method": method,
                "path": path
            }
            for method, path in sorted(observed_endpoints)
        ]
    })


@app.route("/observed-requests", methods=["GET"])
def show_observed_requests():
    return jsonify({
        "count": len(observed_requests),
        "requests": observed_requests
    })


@app.route("/observed-params", methods=["GET"])
def show_observed_params():
    return jsonify({
        "count": len(observed_params),
        "params": observed_params
    })


@app.route("/reset-observed", methods=["POST", "GET"])
def reset_observed():
    observed_endpoints.clear()
    observed_requests.clear()
    observed_params.clear()

    save_all_observed_data()

    return jsonify({
        "status": "reset_done"
    })


@app.route("/proxy-health", methods=["GET"])
def proxy_health():
    response = jsonify({
        "status": "ok",
        "target": TARGET,
        "proxy": "http://127.0.0.1:8080",
    })

    for key, value in NO_CACHE_HEADERS.items():
        response.headers[key] = value

    return response


@app.route("/proxy-clear-cache", methods=["GET"])
def proxy_clear_cache():
    html = """
<!doctype html>
<html>
  <body>
    <h1>Proxy cache clear</h1>
    <pre id="status">Clearing browser caches for this origin...</pre>
    <script>
      async function clearEverything() {
        const lines = [];

        if ("serviceWorker" in navigator) {
          const registrations = await navigator.serviceWorker.getRegistrations();
          for (const registration of registrations) {
            await registration.unregister();
          }
          lines.push(`Service workers removed: ${registrations.length}`);
        }

        if ("caches" in window) {
          const names = await caches.keys();
          for (const name of names) {
            await caches.delete(name);
          }
          lines.push(`Cache stores removed: ${names.length}`);
        }

        lines.push("Done. Open / again with a hard refresh.");
        document.getElementById("status").textContent = lines.join("\\n");
      }

      clearEverything().catch((error) => {
        document.getElementById("status").textContent = String(error);
      });
    </script>
  </body>
</html>
""".strip()

    return Response(
        html,
        status=200,
        headers=NO_CACHE_HEADERS,
        mimetype="text/html",
    )


@app.route("/", defaults={"path": ""}, methods=[
    "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
])
@app.route("/<path:path>", methods=[
    "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
])
def proxy(path):
    target_url = f"{TARGET}/{path}"

    try:
        endpoint_path = request.path

        if request.query_string:
            endpoint_path += "?" + request.query_string.decode()

        capture_this = should_capture_endpoint(endpoint_path)

        if request.is_json:
            body = request.get_json(silent=True)
        else:
            body = request.get_data(as_text=True)

        inputs = extract_request_inputs()

        if capture_this:
            log_request(
                request.method,
                target_url,
                body
            )

        headers = {}

        for key, value in request.headers:
            if key.lower() not in EXCLUDED_REQUEST_HEADERS:
                headers[key] = value

        headers["Accept-Encoding"] = "identity"

        response = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            params=request.args,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=20
        )

        if capture_this:
            add_endpoint(
                request.method,
                endpoint_path
            )

            record_observed_request(
                request.method,
                endpoint_path,
                target_url,
                inputs,
                response
            )

            print(
                f"[REST API CAPTURED] {request.method} {endpoint_path}"
            )

            log_response(response)

        response_headers = []

        for name, value in response.headers.items():
            if name.lower() not in EXCLUDED_RESPONSE_HEADERS:
                response_headers.append(
                    (name, value)
                )

        response_headers.extend(NO_CACHE_HEADERS.items())

        return Response(
            response.content,
            status=response.status_code,
            headers=response_headers
        )

    except Exception as e:
        print(f"[ERROR] {str(e)}")

        return Response(
            json.dumps({
                "error": str(e)
            }),
            status=500,
            mimetype="application/json"
        )


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("SQL Injection Detection Proxy")
    print(f"Target : {TARGET}")
    print("Proxy  : http://127.0.0.1:8080")
    print("Capturing only REST/API traffic:")
    print("  /api/*")
    print("  /rest/*")
    print("  /b2b/*")
    print("Observed files:")
    print(f"  {OBSERVED_ENDPOINTS_FILE}")
    print(f"  {OBSERVED_REQUESTS_FILE}")
    print(f"  {OBSERVED_PARAMS_FILE}")
    print("=" * 80 + "\n")

    app.run(
        host="0.0.0.0",
        port=8080,
        threaded=True,
        debug=False
    )
