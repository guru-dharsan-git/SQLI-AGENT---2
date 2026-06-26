import json
from datetime import datetime, timezone
from pathlib import Path

from agent.config import DEFAULT_RESULTS_FILE, LLMConfig
from agent.llm_client import LLMClient
from agent.prompts import report_prompt


DEFAULT_SCAN_RESULTS_FILE = "scan_results.json"
DEFAULT_REPORT_JSON_FILE = "llm_report.json"
DEFAULT_REPORT_MARKDOWN_FILE = "llm_report.md"
REPORT_BODY_SAMPLE_CHARS = 320


def load_json(file_path):
    return json.loads(Path(file_path).read_text(encoding="utf-8"))


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


def trim_text(value, max_chars=REPORT_BODY_SAMPLE_CHARS):
    value = str(value or "")

    if len(value) <= max_chars:
        return value

    return value[:max_chars] + "...[truncated]"


def compact_response(response):
    if not response:
        return None

    return {
        "status_code": response.get("status_code"),
        "elapsed_ms": response.get("elapsed_ms"),
        "content_type": response.get("content_type", ""),
        "body_length": response.get("body_length"),
        "body_sample": trim_text(response.get("body_sample", "")),
    }


def compact_scan_results(scan_results):
    return {
        "base_url": scan_results.get("base_url"),
        "live_endpoint_count": scan_results.get("live_endpoint_count"),
        "endpoint_count": scan_results.get("endpoint_count"),
        "target_count": scan_results.get("target_count"),
        "scan_sources": scan_results.get("scan_sources", []),
        "warnings": scan_results.get("warnings", []),
        "targets": [
            {
                "method": target.get("method"),
                "path": target.get("path"),
                "params": target.get("params", []),
            }
            for target in scan_results.get("targets", [])
        ],
    }


def compact_agent_results(agent_results):
    compact = {
        "started_at": agent_results.get("started_at"),
        "finished_at": agent_results.get("finished_at"),
        "target_count": agent_results.get("target_count"),
        "results": [],
    }

    for target in agent_results.get("results", []):
        target_item = {
            "method": target.get("method"),
            "path": target.get("path"),
            "endpoint_context": target.get("endpoint_context", {}),
            "params": [],
        }

        for param in target.get("params", []):
            param_item = {
                "name": param.get("name"),
                "in": param.get("in"),
                "endpoint_context": param.get("endpoint_context", {}),
                "payload_count": param.get("payload_count"),
                "final_decision": param.get("final_decision"),
                "strongest_decision": param.get("strongest_decision"),
                "stop_reason": param.get("stop_reason", ""),
                "attempts": [],
            }

            for attempt in param.get("attempts", []):
                decision = attempt.get("llm_decision") or {}
                param_item["attempts"].append({
                    "payload": attempt.get("payload"),
                    "payload_rationale": attempt.get("payload_rationale", ""),
                    "expected_signal": attempt.get("expected_signal", ""),
                    "baseline": compact_response(attempt.get("baseline")),
                    "probe": compact_response(attempt.get("probe")),
                    "response_signal": attempt.get("response_signal", {}),
                    "llm_decision": {
                        "decision": decision.get("decision"),
                        "confidence": decision.get("confidence"),
                        "reason": decision.get("reason", ""),
                        "next_step": decision.get("next_step", ""),
                    },
                })

            target_item["params"].append(param_item)

        compact["results"].append(target_item)

    return compact


def markdown_from_report(report):
    lines = [
        "# SQL Injection Assessment Report",
        "",
        report.get("executive_summary", "No summary returned by the LLM."),
        "",
        "## Findings",
    ]

    findings = report.get("findings", [])

    if not findings:
        lines.append("No confirmed SQL injection findings were reported.")

    for finding in findings:
        lines.extend([
            "",
            f"### {finding.get('title', 'Finding')}",
            f"- Severity: {finding.get('severity', 'info')}",
            f"- Confidence: {finding.get('confidence', 'unknown')}",
            f"- Endpoint: {finding.get('method', '')} {finding.get('path', '')}",
            f"- Endpoint type: {finding.get('endpoint_type', 'unknown')}",
            f"- Attack style: {finding.get('attack_style', 'unknown')}",
            f"- Parameter: {finding.get('parameter', '')}",
            f"- Payload: `{finding.get('payload', '')}`",
            f"- Evidence: {finding.get('evidence', '')}",
            f"- Recommendation: {finding.get('recommendation', '')}",
        ])

    capability_summary = report.get("capability_summary", {})

    if capability_summary:
        lines.extend([
            "",
            "## Capability Coverage",
            "",
            f"- Confirmed surfaces: {capability_summary.get('confirmed_surface_count', 0)}",
            f"- Confirmed techniques: {', '.join(capability_summary.get('confirmed_techniques', [])) or 'none'}",
            f"- DBMS hints: {', '.join(capability_summary.get('dbms_hints', [])) or 'none'}",
        ])

        unverified = capability_summary.get("unverified_capabilities", [])

        if unverified:
            lines.append("- Unverified capabilities: " + "; ".join(unverified))

        impacts = capability_summary.get("potential_impacts", [])

        if impacts:
            lines.append("- Potential impact: " + "; ".join(impacts))

    return "\n".join(lines).strip() + "\n"


def finding_key(item):
    return (
        item.get("method", "").upper(),
        item.get("path", ""),
        item.get("parameter", ""),
    )


def has_sql_error_signal(attempt):
    probe = attempt.get("probe") or {}
    body = probe.get("body_sample", "")

    return "SQLITE_ERROR" in body or "SQL syntax" in body


def has_login_bypass_signal(attempt):
    baseline = attempt.get("baseline") or {}
    probe = attempt.get("probe") or {}
    body = probe.get("body_sample", "")

    return (
        baseline.get("status_code") == 401
        and probe.get("status_code") == 200
        and "authentication" in body
    )


def has_read_marker_signal(attempt):
    signal = attempt.get("response_signal") or {}
    probe = attempt.get("probe") or {}

    return bool(
        signal.get("read_marker_reflected")
        and not signal.get("sql_error")
        and 200 <= (probe.get("status_code") or 0) < 300
    )


def technique_for_attempt(attempt):
    if has_read_marker_signal(attempt):
        return "constant_read_confirmation"

    if attempt.get("payload_phase") == "read_confirmation":
        return ""

    if has_login_bypass_signal(attempt):
        return "authentication_bypass"

    if has_sql_error_signal(attempt):
        return "error_based_sqli"

    return ""


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

                if technique == "authentication_bypass":
                    impacts.add("authentication logic can be bypassed for the affected endpoint")

                if technique == "error_based_sqli":
                    impacts.add("database query structure is influenced by user input")

                    if endpoint_type in {"search", "list_filter", "product_collection"}:
                        error_based_read_surfaces.add(
                            (
                                target.get("method", ""),
                                target.get("path", ""),
                                param.get("name", ""),
                            )
                        )

                if technique == "constant_read_confirmation":
                    impacts.add("non-sensitive data can be selected through the affected read endpoint")
                    confirmed_read_surfaces.add(
                        (
                            target.get("method", ""),
                            target.get("path", ""),
                            param.get("name", ""),
                        )
                    )

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


def evidence_from_attempt(attempt):
    probe = attempt.get("probe") or {}
    body = probe.get("body_sample", "")

    if has_read_marker_signal(attempt):
        marker = (attempt.get("response_signal") or {}).get("read_marker", "")
        return f"Probe response reflected non-sensitive SQL marker `{marker}`."

    if "SQLITE_ERROR" in body:
        return "Probe response exposed SQLITE_ERROR."

    if "SQL syntax" in body:
        return "Probe response exposed SQL syntax error."

    if has_login_bypass_signal(attempt):
        return "Baseline login failed with 401, while probe returned 200 with authentication data."

    decision = attempt.get("llm_decision") or {}

    if decision.get("reason"):
        return decision["reason"]

    return "Probe evidence indicated SQL injection behavior."


def build_finding(target, param, attempt):
    path = target.get("path", "")
    name = param.get("name", "")
    signal = evidence_from_attempt(attempt)

    return {
        "title": f"SQL Injection in {path}",
        "severity": "critical",
        "confidence": 0.9 if has_sql_error_signal(attempt) or has_login_bypass_signal(attempt) else 0.75,
        "method": target.get("method", ""),
        "path": path,
        "endpoint_type": (target.get("endpoint_context") or {}).get("endpoint_type", ""),
        "attack_style": (target.get("endpoint_context") or {}).get("recommended_attack_style", ""),
        "parameter": name,
        "payload": attempt.get("payload", ""),
        "evidence": signal,
        "recommendation": "Use parameterized queries, avoid string-built SQL, and validate inputs server-side.",
    }


def best_evidence_attempt(attempts):
    for predicate in (
            has_read_marker_signal,
            has_login_bypass_signal,
            has_sql_error_signal,
    ):
        for attempt in attempts:
            if predicate(attempt):
                return attempt

    return None


def fallback_report(agent_results, error):
    findings = []
    not_decidable = []
    seen_findings = set()

    for target in agent_results.get("results", []):
        for param in target.get("params", []):
            key = (
                target.get("method", "").upper(),
                target.get("path", ""),
                param.get("name", ""),
            )
            matching_attempt = best_evidence_attempt(param.get("attempts", []))

            if matching_attempt and key not in seen_findings:
                findings.append(build_finding(target, param, matching_attempt))
                seen_findings.add(key)
                continue

            not_decidable.append({
                "method": target.get("method", ""),
                "path": target.get("path", ""),
                "parameter": param.get("name", ""),
                "reason": param.get("stop_reason") or "No clear SQL injection signal in probes.",
            })

    status = (
        "vulnerabilities_found"
        if findings
        else "not_decidable"
        if not_decidable
        else "no_vulnerabilities_confirmed"
    )
    report = {
        "overall_status": status,
        "executive_summary": (
            "SQL injection vulnerabilities were identified from probe evidence."
            if findings
            else "No confirmed SQL injection vulnerabilities were identified from probe evidence."
        ),
        "findings": findings,
        "not_decidable_targets": not_decidable,
        "report_generation": {
            "mode": "local_fallback",
            "reason": f"LLM report generation failed: {error}",
        },
    }
    report["markdown_report"] = markdown_from_report(report)

    return report


def evidence_findings(agent_results):
    findings = []
    seen = set()

    for target in agent_results.get("results", []):
        for param in target.get("params", []):
            key = (
                target.get("method", "").upper(),
                target.get("path", ""),
                param.get("name", ""),
            )
            matching_attempt = best_evidence_attempt(param.get("attempts", []))

            if matching_attempt and key not in seen:
                findings.append(build_finding(target, param, matching_attempt))
                seen.add(key)

    return findings


def keep_only_evidence_supported_findings(report, agent_results):
    evidence = evidence_findings(agent_results)
    evidence_by_key = {finding_key(finding): finding for finding in evidence}
    existing = report.get("findings", [])
    supported = []
    seen = set()

    for finding in existing:
        key = finding_key(finding)

        if key not in evidence_by_key or key in seen:
            continue

        supported.append({
            **finding,
            **evidence_by_key[key],
        })
        seen.add(key)

    for key, finding in evidence_by_key.items():
        if key not in seen:
            supported.append(finding)

    removed_count = len(existing) - len(supported)
    report["findings"] = supported

    if removed_count > 0:
        report.setdefault("report_generation", {})["evidence_filter"] = (
            f"Removed {removed_count} unsupported finding(s) that lacked local probe evidence."
        )

    if supported:
        report["overall_status"] = "vulnerabilities_found"
        report["executive_summary"] = (
            "SQL injection vulnerabilities were identified from local probe evidence."
        )
    elif report.get("not_decidable_targets"):
        report["overall_status"] = "not_decidable"
        report["executive_summary"] = (
            "No SQL injection vulnerabilities were confirmed; some targets remain not decidable."
        )
    else:
        report["overall_status"] = "no_vulnerabilities_confirmed"
        report["executive_summary"] = (
            "No SQL injection vulnerabilities were confirmed from local probe evidence."
        )

    report.pop("markdown_report", None)

    return report


def ensure_evidence_findings(report, agent_results):
    existing = {finding_key(finding) for finding in report.get("findings", [])}
    added = []

    for finding in evidence_findings(agent_results):
        key = finding_key(finding)

        if key not in existing:
            added.append(finding)
            existing.add(key)

    if not added:
        if report.get("findings"):
            report["overall_status"] = "vulnerabilities_found"

        return report

    report.setdefault("findings", []).extend(added)
    report["overall_status"] = "vulnerabilities_found"
    report["executive_summary"] = (
        "SQL injection vulnerabilities were identified from local probe evidence."
    )
    report.setdefault("report_generation", {})["post_processed"] = (
        "Added locally confirmed findings omitted by the LLM response."
    )
    report.pop("markdown_report", None)

    return report


def generate_report(
        scan_results_file=DEFAULT_SCAN_RESULTS_FILE,
        agent_results_file=DEFAULT_RESULTS_FILE,
        output_json_file=DEFAULT_REPORT_JSON_FILE,
        output_markdown_file=DEFAULT_REPORT_MARKDOWN_FILE
):
    llm = LLMClient(LLMConfig.from_env())
    scan_results = load_json(scan_results_file)
    agent_results = normalize_attempt_signals(load_json(agent_results_file))
    report_inputs = {
        "scan_results": compact_scan_results(scan_results),
        "agent_results": compact_agent_results(agent_results),
    }

    try:
        report = llm.ask_json(
            report_prompt(
                report_inputs["scan_results"],
                report_inputs["agent_results"],
            )
        )
        report["report_generation"] = {
            "mode": "llm",
            "provider": llm.config.provider,
            "model": llm.config.model,
            "input": "compacted_scan_and_probe_evidence",
        }
    except Exception as error:
        report = fallback_report(agent_results, error)

    report = ensure_evidence_findings(report, agent_results)
    report = keep_only_evidence_supported_findings(report, agent_results)
    report["capability_summary"] = capability_summary(agent_results)
    wrapped_report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_results_file": scan_results_file,
        "agent_results_file": agent_results_file,
        "report_input_summary": {
            "scan_target_count": report_inputs["scan_results"]["target_count"],
            "agent_target_count": report_inputs["agent_results"]["target_count"],
            "input_mode": "compacted_scan_and_probe_evidence",
        },
        "report": report,
    }

    Path(output_json_file).write_text(
        json.dumps(wrapped_report, indent=2),
        encoding="utf-8",
    )
    Path(output_markdown_file).write_text(
        markdown_from_report(report),
        encoding="utf-8",
    )

    return {
        "json": output_json_file,
        "markdown": output_markdown_file,
        "report": report,
    }
