import re
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


HEADERS = {"User-Agent": "SQLInjectionAgent/1.0"}
API_PREFIXES = ("/api", "/rest", "/b2b")
STATIC_EXTENSIONS = (
    ".css", ".gif", ".ico", ".jpeg", ".jpg", ".js", ".map",
    ".png", ".svg", ".ttf", ".woff", ".woff2",
)
COMMON_DOCS = (
    "/swagger.json",
    "/openapi.json",
    "/api-docs/swagger.json",
    "/api-docs/openapi.json",
)

ENDPOINT_RE = re.compile(
    r"""["'`](?P<url>(?:https?://[^"'`\s<>()]+|/)(?:api|rest|b2b)[^"'`\s<>()]*)["'`]""",
    re.IGNORECASE,
)


def is_same_origin(base_url, url):
    base = urlparse(base_url)
    target = urlparse(url)

    return (base.scheme, base.netloc) == (target.scheme, target.netloc)


def is_api_url(base_url, url):
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"

    if not is_same_origin(base_url, url):
        return False

    if path.lower().endswith(STATIC_EXTENSIONS):
        return False

    return any(path == prefix or path.startswith(prefix + "/") for prefix in API_PREFIXES)


def add_endpoint(endpoints, base_url, endpoint):
    if not endpoint:
        return

    endpoint = endpoint.strip().replace("\\/", "/")
    endpoint = re.sub(r"\$\{[^}]+\}", ":value", endpoint)
    full_url = endpoint if endpoint.startswith(("http://", "https://")) else urljoin(base_url, endpoint)

    if is_api_url(base_url, full_url):
        endpoints.add(full_url)


def extract_endpoints_from_text(endpoints, base_url, text):
    for match in ENDPOINT_RE.finditer(text):
        add_endpoint(endpoints, base_url, match.group("url"))


def fetch_text(session, url, timeout):
    response = session.get(url, headers=HEADERS, timeout=timeout)

    if response.status_code >= 400:
        return ""

    return response.text


def scan_html(endpoints, js_urls, base_url, html_text):
    soup = BeautifulSoup(html_text, "html.parser")

    for tag in soup.find_all(("a", "form"), href=True):
        add_endpoint(endpoints, base_url, tag["href"])

    for tag in soup.find_all("form", action=True):
        add_endpoint(endpoints, base_url, tag["action"])

    for tag in soup.find_all(("script", "a", "link"), src=True):
        url = urljoin(base_url, tag["src"])

        if is_same_origin(base_url, url) and urlparse(url).path.lower().endswith(".js"):
            js_urls.add(url)

    for tag in soup.find_all(("script", "a", "link"), href=True):
        url = urljoin(base_url, tag["href"])

        if is_same_origin(base_url, url) and urlparse(url).path.lower().endswith(".js"):
            js_urls.add(url)


def scan_openapi(endpoints, session, base_url, timeout):
    for path in COMMON_DOCS:
        try:
            document = session.get(
                urljoin(base_url, path.lstrip("/")),
                headers=HEADERS,
                timeout=timeout
            ).json()
        except Exception:
            continue

        for endpoint in document.get("paths", {}):
            endpoint = re.sub(r"\{([^}]+)\}", r":\1", endpoint)
            add_endpoint(endpoints, base_url, endpoint)


def detect_endpoints(base_url, timeout=2, verbose=False):
    base_url = base_url.rstrip("/") + "/"
    endpoints = set()
    js_urls = set()
    session = requests.Session()

    if verbose:
        print(f"\n[*] Scanning {base_url}\n")

    try:
        html_text = fetch_text(session, base_url, timeout)
    except Exception as error:
        if verbose:
            print(f"Error scanning {base_url}: {error}")
        return []

    extract_endpoints_from_text(endpoints, base_url, html_text)
    scan_html(endpoints, js_urls, base_url, html_text)

    for js_url in sorted(js_urls):
        try:
            extract_endpoints_from_text(
                endpoints,
                base_url,
                fetch_text(session, js_url, timeout)
            )
        except Exception:
            continue

    scan_openapi(endpoints, session, base_url, timeout)

    return sorted(endpoints)


if __name__ == "__main__":
    target = input("Enter Base URL: ").strip()
    results = detect_endpoints(target, verbose=True)

    print(f"\nDetected {len(results)} Endpoints:\n")

    for endpoint in results:
        print(endpoint)
