from agent.config import DEFAULT_MAX_PAYLOADS, DEFAULT_RESULTS_FILE, DEFAULT_TIMEOUT
from agent.postman_export import export_postman_tests
from agent.report import (
    DEFAULT_REPORT_JSON_FILE,
    DEFAULT_REPORT_MARKDOWN_FILE,
    DEFAULT_SCAN_RESULTS_FILE,
    generate_report,
)
from agent.runner import run_agent
from scan_helpers import get_sqli_injection_targets, save_scan_artifacts


PROXY_TARGET_URL = "http://127.0.0.1:8080"
DISCOVERY_URLS = (PROXY_TARGET_URL,)
INCLUDE_PROXY_OBSERVED_TRAFFIC = True
SCAN_TIMEOUT = 10
MAX_ATTEMPTS_PER_PARAM = DEFAULT_MAX_PAYLOADS
PROBE_TIMEOUT = DEFAULT_TIMEOUT
AGENT_TARGET_LIMIT = None


def main():
    result = get_sqli_injection_targets(
        base_url=PROXY_TARGET_URL,
        discovery_urls=DISCOVERY_URLS,
        include_observed=INCLUDE_PROXY_OBSERVED_TRAFFIC,
        timeout=SCAN_TIMEOUT,
    )

    print("Live scan complete")
    print(f"Proxy target URL: {PROXY_TARGET_URL}")
    print(f"Discovery URLs: {', '.join(DISCOVERY_URLS)}")
    print(f"Scanned sources: {len(result['scan_sources'])}")
    print(f"Live endpoints found: {result['live_endpoint_count']}")
    print(f"Endpoints found: {result['endpoint_count']}")
    print(f"SQLi-ready targets: {result['target_count']}")

    if result["warnings"]:
        print("Warnings:")

        for warning in result["warnings"]:
            print(f"  - {warning}")

    if result["live_endpoint_count"] == 0:
        print("Live scan is not ready, so artifacts and LLM probing were not updated.")

        for source in result["scan_sources"]:
            print(f"  - {source['url']}: {source['status']}")

            if source.get("http_status"):
                print(f"    HTTP status: {source['http_status']}")

            if source.get("error"):
                print(f"    Error: {source['error']}")

        print("Start the target application behind the proxy, then run app.py again.")
        return

    written_files = save_scan_artifacts(result)

    print("Wrote:")

    for file_name in written_files:
        print(f"  - {file_name}")

    try:
        agent_result = run_agent(
            output_file=DEFAULT_RESULTS_FILE,
            max_payloads=MAX_ATTEMPTS_PER_PARAM,
            timeout=PROBE_TIMEOUT,
            limit=AGENT_TARGET_LIMIT,
        )
        report_result = generate_report(
            scan_results_file=DEFAULT_SCAN_RESULTS_FILE,
            agent_results_file=DEFAULT_RESULTS_FILE,
            output_json_file=DEFAULT_REPORT_JSON_FILE,
            output_markdown_file=DEFAULT_REPORT_MARKDOWN_FILE,
        )
        postman_result = export_postman_tests(
            agent_results_file=DEFAULT_RESULTS_FILE,
        )

    except RuntimeError as error:
        print("LLM SQLi phase skipped")
        print(f"  {error}")
        print("  Set NVIDIA_API_KEY or GEMINI_API_KEY before running app.py to enable probing and reporting.")
        return

    print("LLM SQLi phase complete")
    print(f"Targets loaded: {agent_result['target_count']}")
    print(f"Probe results: {DEFAULT_RESULTS_FILE}")
    print("Report written:")
    print(f"  - {report_result['json']}")
    print(f"  - {report_result['markdown']}")
    print("Postman payload tests written:")
    print(f"  - {postman_result['summary']}")
    print(f"  - {postman_result['markdown']}")
    print(f"  - {postman_result['collection']}")


if __name__ == "__main__":
    main()
