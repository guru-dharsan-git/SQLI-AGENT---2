import re


SQL_ERROR_RE = re.compile(
    r"(SQLITE_ERROR|SQL syntax|syntax error|incomplete input|database error|SequelizeDatabaseError)",
    flags=re.IGNORECASE,
)
DBMS_HINTS = {
    "sqlite": re.compile(r"\b(SQLITE_ERROR|sqlite|sqlite_master)\b", flags=re.IGNORECASE),
    "mysql": re.compile(r"\b(MySQL|MariaDB|SQL syntax.*MySQL)\b", flags=re.IGNORECASE),
    "postgresql": re.compile(r"\b(PostgreSQL|pg_sleep|syntax error at or near)\b", flags=re.IGNORECASE),
    "mssql": re.compile(r"\b(SQL Server|ODBC|WAITFOR|Microsoft SQL)\b", flags=re.IGNORECASE),
    "oracle": re.compile(r"\b(ORA-\d+|Oracle)\b", flags=re.IGNORECASE),
}


def extract_error_excerpt(text, max_chars=240):
    text = str(text or "")
    match = SQL_ERROR_RE.search(text)

    if not match:
        return ""

    start = max(match.start() - 80, 0)
    end = min(match.end() + 160, len(text), start + max_chars)

    return text[start:end].strip()


def dbms_hint(text):
    text = str(text or "")

    for name, pattern in DBMS_HINTS.items():
        if pattern.search(text):
            return name

    return ""


def response_signal(baseline, probe):
    if not baseline or not probe:
        return {
            "available": False,
            "reason": "Probe did not return both baseline and injected responses.",
        }

    baseline_body = baseline.get("body_sample", "")
    probe_body = probe.get("body_sample", "")
    baseline_status = baseline.get("status_code")
    probe_status = probe.get("status_code")
    baseline_elapsed = baseline.get("elapsed_ms") or 0
    probe_elapsed = probe.get("elapsed_ms") or 0
    lower_probe_body = str(probe_body).lower()

    return {
        "available": True,
        "baseline_status": baseline_status,
        "probe_status": probe_status,
        "status_changed": baseline_status != probe_status,
        "content_type_changed": baseline.get("content_type") != probe.get("content_type"),
        "body_length_delta": (probe.get("body_length") or 0) - (baseline.get("body_length") or 0),
        "body_changed": baseline_body != probe_body,
        "elapsed_delta_ms": probe_elapsed - baseline_elapsed,
        "sql_error": bool(SQL_ERROR_RE.search(str(probe_body))),
        "sql_error_excerpt": extract_error_excerpt(probe_body),
        "dbms_hint": dbms_hint(probe_body),
        "auth_bypass_like": (
            baseline_status in {401, 403}
            and probe_status == 200
            and ("authentication" in lower_probe_body or "token" in lower_probe_body)
        ),
    }


def add_marker_signal(signal, probe, payload_info):
    marker = str(payload_info.get("expected_marker") or "").strip()

    if not marker:
        signal["read_marker"] = ""
        signal["read_marker_reflected"] = False
        return signal

    body = (probe or {}).get("body_sample", "")
    status = (probe or {}).get("status_code") or 0
    signal["read_marker"] = marker
    signal["read_marker_reflected"] = (
        200 <= status < 300
        and not signal.get("sql_error")
        and marker in body
    )

    return signal


def has_adaptive_signal(signal):
    if not signal.get("available"):
        return False

    return any([
        signal.get("sql_error"),
        signal.get("auth_bypass_like"),
        signal.get("status_changed"),
        signal.get("content_type_changed"),
        abs(signal.get("body_length_delta") or 0) > 32,
    ])


def normalize_attempt_signals(agent_results):
    for target in agent_results.get("results", []):
        for param in target.get("params", []):
            for attempt in param.get("attempts", []):
                signal = attempt.get("response_signal") or {}
                probe = attempt.get("probe") or {}

                if "read_marker_reflected" not in signal:
                    continue

                signal["read_marker_reflected"] = bool(
                    signal.get("read_marker_reflected")
                    and not signal.get("sql_error")
                    and 200 <= (probe.get("status_code") or 0) < 300
                )

    return agent_results


def has_sql_error_signal(attempt):
    probe = attempt.get("probe") or {}
    body = probe.get("body_sample", "")

    return bool(SQL_ERROR_RE.search(str(body)))


def has_login_bypass_signal(attempt):
    baseline = attempt.get("baseline") or {}
    probe = attempt.get("probe") or {}
    body = str(probe.get("body_sample", "")).lower()

    return (
        baseline.get("status_code") == 401
        and probe.get("status_code") == 200
        and ("authentication" in body or "token" in body)
    )


def has_read_marker_signal(attempt):
    signal = attempt.get("response_signal") or {}
    probe = attempt.get("probe") or {}

    return bool(
        signal.get("read_marker_reflected")
        and not signal.get("sql_error")
        and 200 <= (probe.get("status_code") or 0) < 300
    )


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


def technique_for_attempt(attempt):
    signal = signal_name(attempt)

    if signal == "sql_error":
        return "error_based_sqli"

    return signal


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

    if "SQL syntax" in body:
        return "Probe response exposed SQL syntax error."

    decision = attempt.get("llm_decision") or {}

    if decision.get("reason"):
        return decision["reason"]

    return "Probe response changed in a SQLi-relevant way."


def capability_summary(agent_results):
    confirmed = []
    dbms_hints = set()
    techniques = set()
    impacts = set()
    error_based_read_surfaces = set()
    confirmed_read_surfaces = set()

    for target in agent_results.get("results", []):
        endpoint_context = target.get("endpoint_context") or {}
        endpoint_type = endpoint_context.get("endpoint_type", "")

        for param in target.get("params", []):
            for attempt in param.get("attempts", []):
                technique = technique_for_attempt(attempt)

                if not technique:
                    continue

                signal = attempt.get("response_signal") or {}
                techniques.add(technique)

                if signal.get("dbms_hint"):
                    dbms_hints.add(signal["dbms_hint"])

                confirmed.append({
                    "method": target.get("method", ""),
                    "path": target.get("path", ""),
                    "parameter": param.get("name", ""),
                    "endpoint_type": endpoint_type,
                    "technique": technique,
                    "payload": attempt.get("payload", ""),
                })

                surface = (
                    target.get("method", ""),
                    target.get("path", ""),
                    param.get("name", ""),
                )

                if technique == "authentication_bypass":
                    impacts.add("authentication logic can be bypassed for the affected endpoint")

                if technique == "error_based_sqli":
                    impacts.add("database query structure is influenced by user input")

                    if endpoint_type in {"search", "list_filter", "product_collection"}:
                        error_based_read_surfaces.add(surface)

                if technique == "constant_read_confirmation":
                    impacts.add("non-sensitive data can be selected through the affected read endpoint")
                    confirmed_read_surfaces.add(surface)

    unverified = set()

    if error_based_read_surfaces - confirmed_read_surfaces:
        unverified.add("non-sensitive in-band read confirmation was not proven")

    return {
        "confirmed_surface_count": len({
            (
                item["method"],
                item["path"],
                item["parameter"],
                item["technique"],
            )
            for item in confirmed
        }),
        "confirmed_techniques": sorted(techniques),
        "dbms_hints": sorted(dbms_hints),
        "confirmed_surfaces": confirmed,
        "potential_impacts": sorted(impacts),
        "unverified_capabilities": sorted(unverified),
    }
