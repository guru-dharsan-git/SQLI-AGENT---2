from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
CANONICAL_BASE_URL = "http://127.0.0.1:8080"
LOCAL_HOST_ALIASES = {"localhost", "127.0.0.1"}




def filter_rest_apis(endpoints):
    """
    Filters and returns only REST API endpoints.
    """
    rest_apis = []

    for endpoint in endpoints:

        endpoint_lower = endpoint.lower()

        if (
            "/api/" in endpoint_lower
            or "/rest/" in endpoint_lower
            or "/b2b/" in endpoint_lower
        ):
            rest_apis.append(endpoint)

    return sorted(list(set(rest_apis)))


def filter_api_endpoints(observed_endpoints):

    api_endpoints = set()

    ignore_prefixes = [
        "/assets/",
        "/media/",
        "/socket.io/"
    ]

    ignore_suffixes = [
        ".js",
        ".css",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".woff",
        ".woff2"
    ]

    for method, path in observed_endpoints:

        path = path.split("?")[0]

        if any(path.startswith(x) for x in ignore_prefixes):
            continue

        if any(path.endswith(x) for x in ignore_suffixes):
            continue

        if (
            path.startswith("/api/")
            or path.startswith("/rest/")
            or path.startswith("/b2b/")
        ):
            api_endpoints.add(
                (method, path)
            )

    return sorted(api_endpoints)


def normalize_and_dedupe_endpoints(
        endpoints,
        canonical_base_url=CANONICAL_BASE_URL,
        strip_trailing_slash=True
):
    """
    Convert localhost/127.0.0.1 variants to one host and remove duplicates.
    Query strings are preserved because parameters can be valid scan targets.
    """
    canonical = urlsplit(canonical_base_url)
    canonical_scheme = canonical.scheme or "http"
    canonical_host = canonical.hostname or "127.0.0.1"
    canonical_port = canonical.port

    normalized = set()

    for endpoint in endpoints:
        endpoint = endpoint.strip()

        if not endpoint:
            continue

        parts = urlsplit(endpoint)

        if not parts.scheme and not parts.netloc:
            parts = urlsplit(
                urljoin(
                    canonical_base_url.rstrip("/") + "/",
                    endpoint.lstrip("/")
                )
            )

        scheme = (parts.scheme or canonical_scheme).lower()
        hostname = (parts.hostname or canonical_host).lower()
        port = parts.port

        if hostname in LOCAL_HOST_ALIASES:
            hostname = canonical_host
            port = canonical_port

        path = parts.path or "/"

        if strip_trailing_slash and path != "/":
            path = path.rstrip("/")

        query = urlencode(
            sorted(parse_qsl(parts.query, keep_blank_values=True))
        )

        netloc = f"{hostname}:{port}" if port else hostname

        normalized.add(
            urlunsplit((scheme, netloc, path, query, ""))
        )

    return sorted(normalized)

