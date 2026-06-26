from Scanner.detect_endpoints import detect_endpoints
from Scanner.filters import filter_rest_apis
from Scanner.loader import load_api_endpoints


def scan(url, include_observed=False, observed_file="observed_endpoints.txt", timeout=2, verbose=False):
    endpointsv1 = detect_endpoints(url, timeout=timeout, verbose=verbose)
    endpointsv2 = []

    if include_observed:
        endpointsv2 = load_api_endpoints(observed_file)

    endpoints = set(endpointsv1 + endpointsv2)
    return filter_rest_apis(endpoints)

# for endpoint in rest_endpoints:
#     print(endpoint)
