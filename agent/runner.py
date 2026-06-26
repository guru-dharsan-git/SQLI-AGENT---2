import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from agent.config import (
    DEFAULT_MAX_PAYLOADS,
    DEFAULT_RESULTS_FILE,
    DEFAULT_TARGETS_FILE,
    DEFAULT_TIMEOUT,
    LLMConfig,
)
from agent.llm_client import LLMClient
from agent.probe import TargetNotAllowed, probe_payload
from agent.prompts import (
    decision_prompt,
    endpoint_classification_prompt,
    next_payload_prompt,
    read_confirmation_prompt,
    suitability_prompt,
)


VALID_DECISIONS = {"escalate", "not_decidable", "stop"}
DESTRUCTIVE_SQL_RE = re.compile(
    r"\b(drop|delete|update|insert|alter|truncate|create|replace|merge|grant|revoke|exec|execute)\b",
    flags=re.IGNORECASE,
)
UNSAFE_COMMAND_RE = re.compile(
    r"\b(xp_cmdshell|powershell|cmd(?:\.exe)?|bash|curl|wget|netcat)\b|\bnc\s+-",
    flags=re.IGNORECASE,
)
UNION_SQL_RE = re.compile(r"\bunion\b", flags=re.IGNORECASE)
FROM_SQL_RE = re.compile(r"\bfrom\b", flags=re.IGNORECASE)
TIME_DELAY_RE = re.compile(
    r"\b(sleep|pg_sleep|benchmark|waitfor\s+delay|dbms_lock\.sleep)\b",
    flags=re.IGNORECASE,
)
MALFORMED_COMPARISON_RE = re.compile(
    r"(=|<>|!=)\s*(--|#|/\*)|(['\"])\s*(=|<>|!=)\s*\3?\s*(--|#|/\*)",
    flags=re.IGNORECASE,
)
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
READ_CONFIRMATION_ENDPOINTS = {
    "search",
    "product_collection",
    "list_filter",
    "other_data_endpoint",
}
ENDPOINT_TYPES = {
    "auth_login",
    "auth_registration",
    "sensitive_write",
    "search",
    "product_detail",
    "product_collection",
    "lookup_by_id",
    "list_filter",
    "cart_or_order",
    "profile_or_user",
    "admin_or_management",
    "metadata_or_challenge",
    "static_or_noise",
    "other_data_endpoint",
}
ATTACK_STYLES = {
    "auth_boolean_bypass",
    "string_search_error_probe",
    "numeric_identifier_probe",
    "filter_boolean_probe",
    "generic_read_probe",
    "skip_low_value",
}
IDENTITY_PARAM_RE = re.compile(
    r"(^|[_-])(email|mail|username|user|login|userid|user_id|account|identifier)($|[_-])",
    flags=re.IGNORECASE,
)
PASSWORD_PARAM_RE = re.compile(r"(^|[_-])(password|pass|pwd)($|[_-])", flags=re.IGNORECASE)


def load_targets(file_path):
    return json.loads(Path(file_path).read_text(encoding="utf-8"))


def payload_allowed_for_endpoint(payload, endpoint_context, param=None):
    endpoint_type = (endpoint_context or {}).get("endpoint_type", "")
    attack_style = (endpoint_context or {}).get("recommended_attack_style", "")
    param_name = str((param or {}).get("name", "")).strip().lower()

    if param_name and payload.strip().lower().startswith(param_name + "="):
        return False, "Payload rejected because it includes a parameter assignment instead of only the parameter value."

    if endpoint_type == "auth_login" and UNION_SQL_RE.search(payload):
        return False, "UNION payload rejected for auth_login endpoint."

    if attack_style == "string_search_error_probe" and not any(
            marker in payload
            for marker in ("'", '"')
    ):
        return False, "String/search probe rejected because it lacks a string delimiter."

    if endpoint_type == "auth_login":
        has_delimiter = "'" in payload
        has_comment = any(marker in payload for marker in ("--", "#"))

        if not has_delimiter or not has_comment:
            return False, (
                "Auth probe rejected because it needs a single-quote delimiter "
                "and a line comment marker to neutralize trailing predicates."
            )

        if MALFORMED_COMPARISON_RE.search(payload):
            return False, (
                "Auth probe rejected because the boolean comparison appears incomplete."
            )

    return True, ""


def clean_next_payload(payload_response, attempted_payloads, endpoint_context=None, param=None):
    if payload_response.get("continue") is False:
        return None, payload_response.get("reason", "")

    item = payload_response.get("payload", payload_response)

    if isinstance(item, str):
        payload = item
        item = {}
    elif isinstance(item, dict):
        payload = item.get("payload")
    else:
        payload = None

    if not payload or not isinstance(payload, str):
        return None, "LLM did not provide a payload string."

    if payload in attempted_payloads:
        return None, "LLM repeated an already attempted payload."

    if DESTRUCTIVE_SQL_RE.search(payload):
        return None, "LLM returned a payload rejected by the safety filter."

    if UNSAFE_COMMAND_RE.search(payload):
        return None, "LLM returned a command-style payload rejected by the safety filter."

    if TIME_DELAY_RE.search(payload):
        return None, "LLM returned a time-delay payload rejected by the safety filter."

    allowed, reason = payload_allowed_for_endpoint(payload, endpoint_context, param)

    if not allowed:
        return None, reason

    return {
        "payload": payload,
        "rationale": item.get("rationale", payload_response.get("reason", "")),
        "expected_signal": item.get("expected_signal", ""),
        "expected_marker": item.get("expected_marker", ""),
    }, ""


def clean_read_confirmation_payload(payload_response, attempted_payloads, endpoint_context=None, param=None):
    payload_info, error = clean_next_payload(
        payload_response,
        attempted_payloads,
        endpoint_context,
        param,
    )

    if not payload_info:
        return None, error

    payload = payload_info["payload"]

    if FROM_SQL_RE.search(payload):
        return None, (
            "Read confirmation rejected because it references a FROM clause; "
            "constant-only confirmation must not reference tables."
        )

    if not payload_info.get("expected_marker"):
        return None, (
            "Read confirmation rejected because it needs an expected_marker."
        )

    if not UNION_SQL_RE.search(payload):
        return None, (
            "Read confirmation rejected because it needs a constant-only UNION/read-channel payload."
        )

    if UNION_SQL_RE.search(payload) and not payload_info.get("expected_marker"):
        return None, (
            "Read confirmation rejected because UNION confirmation needs an expected_marker."
        )

    return payload_info, ""


def clean_decision(decision_response):
    decision = decision_response.get("decision", "not_decidable")

    if decision not in VALID_DECISIONS:
        decision = "not_decidable"

    return {
        "decision": decision,
        "confidence": decision_response.get("confidence", 0),
        "reason": decision_response.get("reason", ""),
        "next_step": decision_response.get("next_step", ""),
    }


def clean_endpoint_context(context_response):
    endpoint_type = context_response.get("endpoint_type", "other_data_endpoint")
    attack_style = context_response.get("recommended_attack_style", "generic_read_probe")
    avoid_payload_styles = context_response.get("avoid_payload_styles", [])

    if endpoint_type not in ENDPOINT_TYPES:
        endpoint_type = "other_data_endpoint"

    if attack_style not in ATTACK_STYLES:
        attack_style = "generic_read_probe"

    if not isinstance(avoid_payload_styles, list):
        avoid_payload_styles = []

    avoid_payload_styles = [
        str(item).strip()
        for item in avoid_payload_styles
        if str(item).strip()
    ]

    if endpoint_type in {"search", "product_collection", "list_filter"}:
        avoid_payload_styles = [
            item
            for item in avoid_payload_styles
            if item.lower() not in {"union_enum", "union", "read_confirmation"}
        ]

    if endpoint_type == "sensitive_write":
        attack_style = "skip_low_value"
        context_response["probe_priority"] = "skip"

    return {
        "endpoint_type": endpoint_type,
        "resource": context_response.get("resource", ""),
        "likely_sql_context": context_response.get("likely_sql_context", "unknown"),
        "recommended_attack_style": attack_style,
        "avoid_payload_styles": avoid_payload_styles,
        "probe_priority": context_response.get("probe_priority", "medium"),
        "confidence": context_response.get("confidence", 0),
        "reason": context_response.get("reason", ""),
    }


def clean_suitability(suitability_response):
    return {
        "probe": bool(suitability_response.get("probe", False)),
        "confidence": suitability_response.get("confidence", 0),
        "reason": suitability_response.get("reason", ""),
        "starting_strategy": suitability_response.get("starting_strategy", ""),
    }


def is_identity_param(param):
    return bool(IDENTITY_PARAM_RE.search(str(param.get("name", ""))))


def is_password_param(param):
    return bool(PASSWORD_PARAM_RE.search(str(param.get("name", ""))))


def target_has_identity_param(target):
    return any(is_identity_param(param) for param in target.get("params", []))


def apply_suitability_policy(target, param, endpoint_context, suitability):
    if endpoint_context.get("endpoint_type") != "auth_login":
        return suitability

    adjusted = dict(suitability)

    if is_identity_param(param):
        adjusted.update({
            "probe": True,
            "confidence": max(float(adjusted.get("confidence") or 0), 0.9),
            "reason": (
                adjusted.get("reason")
                or "Identity field on authentication endpoint."
            ),
            "starting_strategy": "auth_boolean_bypass",
        })
        return adjusted

    if is_password_param(param) and target_has_identity_param(target):
        adjusted.update({
            "probe": False,
            "confidence": max(float(adjusted.get("confidence") or 0), 0.9),
            "reason": (
                "Skipped password field because an identity field is available "
                "for authentication-query testing."
            ),
            "starting_strategy": "skip_identity_field_preferred",
        })

    return adjusted


def should_stop_param(decision):
    return decision == "stop"


def strongest_decision(current, new_decision):
    rank = {"stop": 0, "not_decidable": 1, "escalate": 2}

    return current if rank[current] >= rank[new_decision] else new_decision


def extract_error_excerpt(text, max_chars=240):
    text = str(text or "")
    match = SQL_ERROR_RE.search(text)

    if not match:
        return ""

    start = max(match.start() - 80, 0)
    end = min(match.end() + 160, len(text))

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


def minimum_attempts_for_context(endpoint_context, suitability):
    priority = str((endpoint_context or {}).get("probe_priority", "")).lower()
    style = str((endpoint_context or {}).get("recommended_attack_style", "")).lower()
    confidence = suitability.get("confidence", 0) or 0

    if priority == "high" or confidence >= 0.85:
        return 2

    if style in {
            "string_search_error_probe",
            "numeric_identifier_probe",
            "filter_boolean_probe",
            "auth_boolean_bypass",
    } and confidence >= 0.65:
        return 2

    return 1


def normalize_decision_with_signal(decision, signal):
    if not signal.get("available"):
        return decision

    if (
            signal.get("sql_error")
            or signal.get("auth_bypass_like")
            or signal.get("read_marker_reflected")
    ):
        decision = dict(decision)
        decision["decision"] = "escalate"
        decision["confidence"] = max(float(decision.get("confidence") or 0), 0.9)

        if signal.get("read_marker_reflected"):
            decision["reason"] = "Probe response reflected a non-sensitive SQL read marker."
            decision["next_step"] = "Stop; constant-only in-band read confirmation is sufficient."
        elif signal.get("auth_bypass_like"):
            decision["reason"] = (
                "Baseline failed authorization/authentication, while probe succeeded."
            )
            decision["next_step"] = "Stop; authentication-bypass evidence is sufficient."
        else:
            decision["reason"] = "Probe response exposed a SQL parser/database error."
            decision["next_step"] = (
                "Use one non-destructive confirmation if useful; otherwise report."
            )

        return decision

    if not has_adaptive_signal(signal) and decision.get("decision") == "escalate":
        decision = dict(decision)
        decision["decision"] = "not_decidable"
        decision["confidence"] = min(float(decision.get("confidence") or 0), 0.5)
        decision["reason"] = (
            "Baseline and probe responses were effectively identical; "
            "there is no evidence to escalate yet."
        )
        decision["next_step"] = (
            "Try one endpoint-appropriate syntax variant if the probe budget allows; "
            "otherwise stop."
        )

    return decision


def attempts_for_prompt(attempts):
    compact = []

    for attempt in attempts:
        decision = attempt.get("llm_decision") or {}
        compact.append({
            "payload": attempt.get("payload"),
            "payload_phase": attempt.get("payload_phase", "primary_probe"),
            "response_signal": attempt.get("response_signal", {}),
            "llm_decision": {
                "decision": decision.get("decision"),
                "confidence": decision.get("confidence"),
                "reason": decision.get("reason", ""),
                "next_step": decision.get("next_step", ""),
            },
        })

    return compact


def rejected_payload_for_prompt(payload_response, reason):
    item = payload_response.get("payload", payload_response)

    if isinstance(item, dict):
        payload = item.get("payload", "")
    elif isinstance(item, str):
        payload = item
    else:
        payload = ""

    next_step = "Choose a different endpoint-appropriate payload value."

    if "lacks a string delimiter" in reason:
        next_step = (
            "Return only a parameter value that includes a quote or double-quote "
            "delimiter and a harmless boolean comparison."
        )
    elif "parameter assignment" in reason:
        next_step = (
            "Return only the injectable value, without name=, JSON, or form syntax."
        )
    elif "needs both a string delimiter and a comment marker" in reason:
        next_step = (
            "Return only a single-quote-delimited boolean value ending with a line comment marker."
        )
    elif "single-quote delimiter and a line comment marker" in reason:
        next_step = (
            "Return only a single-quote-delimited boolean value ending with a line comment marker."
        )
    elif "comparison appears incomplete" in reason:
        next_step = (
            "Return only a complete true boolean predicate with non-empty constants "
            "or numeric constants, followed by a SQL comment marker."
        )
    elif "needs an expected_marker" in reason:
        next_step = (
            "Return a constant-only read-channel payload and set expected_marker "
            "to the harmless marker literal expected in the response."
        )
    elif "constant-only UNION/read-channel" in reason:
        next_step = (
            "Use a UNION SELECT or equivalent read-channel expression containing "
            "only harmless constants and the expected marker."
        )
    elif "references a FROM clause" in reason:
        next_step = (
            "Remove table references and use only constants in the read-channel confirmation."
        )

    return {
        "payload": payload,
        "response_signal": {
            "available": False,
            "reason": f"Rejected before probe: {reason}",
        },
        "llm_decision": {
            "decision": "stop",
            "confidence": 1,
            "reason": reason,
            "next_step": next_step,
        },
    }


def should_try_read_confirmation(endpoint_context, param_result):
    endpoint_type = endpoint_context.get("endpoint_type", "")

    if endpoint_type not in READ_CONFIRMATION_ENDPOINTS:
        return False

    for attempt in param_result.get("attempts", []):
        signal = attempt.get("response_signal") or {}

        if signal.get("read_marker_reflected"):
            return False

    return any(
        (attempt.get("response_signal") or {}).get("sql_error")
        for attempt in param_result.get("attempts", [])
    )


def classify_endpoint(llm, target):
    try:
        return clean_endpoint_context(
            llm.ask_json(endpoint_classification_prompt(target))
        )
    except Exception as error:
        return {
            "endpoint_type": "other_data_endpoint",
            "resource": "",
            "likely_sql_context": "unknown",
            "recommended_attack_style": "generic_read_probe",
            "avoid_payload_styles": [],
            "probe_priority": "medium",
            "confidence": 0,
            "reason": f"Endpoint classification failed: {error}",
        }


def run_agent(
        targets_file=DEFAULT_TARGETS_FILE,
        output_file=DEFAULT_RESULTS_FILE,
        max_payloads=DEFAULT_MAX_PAYLOADS,
        timeout=DEFAULT_TIMEOUT,
        allow_remote_targets=False,
        limit=None
):
    llm = LLMClient(LLMConfig.from_env())
    targets = load_targets(targets_file)
    results = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "targets_file": targets_file,
        "target_count": len(targets),
        "results": [],
    }

    for target in targets[:limit]:
        endpoint_context = classify_endpoint(llm, target)
        target_with_context = dict(target)
        target_with_context["endpoint_context"] = endpoint_context
        target_result = {
            "method": target["method"],
            "path": target["path"],
            "url": target["url"],
            "endpoint_context": endpoint_context,
            "params": [],
        }

        for param in target.get("params", []):
            param_result = {
                "name": param["name"],
                "in": param["in"],
                "endpoint_context": endpoint_context,
                "suitability": {},
                "payload_count": 0,
                "attempts": [],
                "final_decision": "not_decidable",
                "strongest_decision": "stop",
                "stop_reason": "",
            }

            try:
                suitability = clean_suitability(
                    llm.ask_json(suitability_prompt(target_with_context, param))
                )
                suitability = apply_suitability_policy(
                    target_with_context,
                    param,
                    endpoint_context,
                    suitability,
                )
                param_result["suitability"] = suitability

            except Exception as error:
                param_result["final_decision"] = "not_decidable"
                param_result["strongest_decision"] = "not_decidable"
                param_result["stop_reason"] = (
                    f"Suitability check failed before probing: {error}"
                )
                target_result["params"].append(param_result)
                continue

            if not suitability["probe"]:
                param_result["final_decision"] = "stop"
                param_result["strongest_decision"] = "stop"
                param_result["stop_reason"] = (
                    "Skipped by suitability gate: "
                    + (suitability.get("reason") or "No SQLi-relevant signal expected.")
                )
                target_result["params"].append(param_result)
                continue

            attempted_payloads = set()
            payload_generation_rejections = []

            for _ in range(max_payloads):
                payload_info = None
                payload_error = ""
                payload_response = {}

                try:
                    for _ in range(3):
                        prompt_attempts = (
                            attempts_for_prompt(param_result["attempts"])
                            + payload_generation_rejections
                        )
                        payload_response = llm.ask_json(
                            next_payload_prompt(
                                target_with_context,
                                param,
                                prompt_attempts,
                                max_payloads,
                            )
                        )
                        payload_info, payload_error = clean_next_payload(
                            payload_response,
                            attempted_payloads,
                            endpoint_context,
                            param,
                        )

                        if payload_info:
                            break

                        payload_generation_rejections.append(
                            rejected_payload_for_prompt(
                                payload_response,
                                payload_error
                                or payload_response.get("reason")
                                or "Payload was not usable.",
                            )
                        )

                except Exception as error:
                    param_result["final_decision"] = "not_decidable"
                    param_result["strongest_decision"] = "not_decidable"
                    param_result["stop_reason"] = (
                        f"LLM payload generation failed: {error}"
                    )
                    break

                if not payload_info:
                    param_result["final_decision"] = "stop"
                    param_result["stop_reason"] = (
                        payload_error
                        or payload_response.get("reason")
                        or "LLM did not provide a new useful payload."
                    )
                    break

                attempted_payloads.add(payload_info["payload"])
                param_result["payload_count"] += 1

                try:
                    baseline, probe = probe_payload(
                        target_with_context,
                        param,
                        payload_info["payload"],
                        timeout,
                        allow_remote=allow_remote_targets,
                    )
                    signal = response_signal(baseline, probe)
                    decision_response = llm.ask_json(
                        decision_prompt(
                            target_with_context,
                            param,
                            baseline,
                            probe,
                            payload_info,
                            signal,
                        )
                    )
                    decision = clean_decision(decision_response)
                    decision = normalize_decision_with_signal(decision, signal)

                except TargetNotAllowed as error:
                    decision = {
                        "decision": "stop",
                        "confidence": 1,
                        "reason": str(error),
                        "next_step": "Use a local target or explicitly allow remote targets.",
                    }
                    baseline = None
                    probe = None
                    signal = response_signal(baseline, probe)

                except Exception as error:
                    decision = {
                        "decision": "not_decidable",
                        "confidence": 0,
                        "reason": f"Probe failed: {error}",
                        "next_step": "Retry after fixing connectivity or LLM configuration.",
                    }
                    baseline = None
                    probe = None
                    signal = response_signal(baseline, probe)

                param_result["attempts"].append({
                    "payload_phase": "primary_probe",
                    "payload": payload_info["payload"],
                    "payload_rationale": payload_info.get("rationale", ""),
                    "expected_signal": payload_info.get("expected_signal", ""),
                    "expected_marker": payload_info.get("expected_marker", ""),
                    "baseline": baseline,
                    "probe": probe,
                    "response_signal": signal,
                    "llm_decision": decision,
                })
                param_result["final_decision"] = decision["decision"]
                param_result["strongest_decision"] = strongest_decision(
                    param_result["strongest_decision"],
                    decision["decision"],
                )

                if signal.get("auth_bypass_like"):
                    param_result["stop_reason"] = (
                        "Stopped after sufficient authentication-bypass evidence."
                    )
                    break

                if (
                        signal.get("sql_error")
                        and should_try_read_confirmation(endpoint_context, param_result)
                        and param_result["payload_count"] < max_payloads
                ):
                    confirmation_info = None
                    confirmation_error = ""
                    confirmation_response = {}

                    try:
                        for _ in range(3):
                            confirmation_attempts = (
                                attempts_for_prompt(param_result["attempts"])
                                + param_result.get("confirmation_rejections", [])
                            )
                            confirmation_response = llm.ask_json(
                                read_confirmation_prompt(
                                    target_with_context,
                                    param,
                                    confirmation_attempts,
                                )
                            )
                            confirmation_info, confirmation_error = clean_read_confirmation_payload(
                                confirmation_response,
                                attempted_payloads,
                                endpoint_context,
                                param,
                            )

                            if confirmation_info:
                                break

                            param_result.setdefault("confirmation_rejections", []).append(
                                rejected_payload_for_prompt(
                                    confirmation_response,
                                    confirmation_error
                                    or confirmation_response.get("reason")
                                    or "Read confirmation payload was not usable.",
                                )
                            )

                    except Exception as error:
                        param_result.setdefault("confirmation_rejections", []).append({
                            "payload": "",
                            "response_signal": {
                                "available": False,
                                "reason": f"Read confirmation generation failed: {error}",
                            },
                            "llm_decision": {
                                "decision": "not_decidable",
                                "confidence": 0,
                                "reason": str(error),
                                "next_step": "Report confirmed error-based SQL injection.",
                            },
                        })
                        confirmation_info = None

                    if confirmation_info:
                        attempted_payloads.add(confirmation_info["payload"])
                        param_result["payload_count"] += 1

                        try:
                            confirmation_baseline, confirmation_probe = probe_payload(
                                target_with_context,
                                param,
                                confirmation_info["payload"],
                                timeout,
                                allow_remote=allow_remote_targets,
                            )
                            confirmation_signal = response_signal(
                                confirmation_baseline,
                                confirmation_probe,
                            )
                            confirmation_signal = add_marker_signal(
                                confirmation_signal,
                                confirmation_probe,
                                confirmation_info,
                            )
                            confirmation_decision_response = llm.ask_json(
                                decision_prompt(
                                    target_with_context,
                                    param,
                                    confirmation_baseline,
                                    confirmation_probe,
                                    confirmation_info,
                                    confirmation_signal,
                                )
                            )
                            confirmation_decision = clean_decision(
                                confirmation_decision_response
                            )
                            confirmation_decision = normalize_decision_with_signal(
                                confirmation_decision,
                                confirmation_signal,
                            )

                        except Exception as error:
                            confirmation_baseline = None
                            confirmation_probe = None
                            confirmation_signal = response_signal(None, None)
                            confirmation_decision = {
                                "decision": "not_decidable",
                                "confidence": 0,
                                "reason": f"Read confirmation probe failed: {error}",
                                "next_step": "Report confirmed error-based SQL injection.",
                            }

                        param_result["attempts"].append({
                            "payload_phase": "read_confirmation",
                            "payload": confirmation_info["payload"],
                            "payload_rationale": confirmation_info.get("rationale", ""),
                            "expected_signal": confirmation_info.get("expected_signal", ""),
                            "expected_marker": confirmation_info.get("expected_marker", ""),
                            "baseline": confirmation_baseline,
                            "probe": confirmation_probe,
                            "response_signal": confirmation_signal,
                            "llm_decision": confirmation_decision,
                        })
                        param_result["final_decision"] = confirmation_decision["decision"]
                        param_result["strongest_decision"] = strongest_decision(
                            param_result["strongest_decision"],
                            confirmation_decision["decision"],
                        )

                        if confirmation_signal.get("read_marker_reflected"):
                            param_result["stop_reason"] = (
                                "Stopped after non-sensitive in-band read confirmation."
                            )
                            break
                        else:
                            param_result.setdefault("confirmation_rejections", []).append({
                                "payload": confirmation_info["payload"],
                                "response_signal": confirmation_signal,
                                "llm_decision": confirmation_decision,
                            })

                if (
                        decision["decision"] == "not_decidable"
                        and not has_adaptive_signal(signal)
                        and len(param_result["attempts"]) >= minimum_attempts_for_context(
                            endpoint_context,
                            suitability,
                        )
                ):
                    param_result["stop_reason"] = (
                        "Stopped because the response matched baseline closely; "
                        "there was no useful error or behavior signal to adapt from."
                    )
                    break

                if should_stop_param(decision["decision"]):
                    param_result["stop_reason"] = decision.get("reason", "")
                    break

            if param_result["strongest_decision"] != "stop":
                param_result["final_decision"] = param_result["strongest_decision"]

            if param_result["attempts"] and not param_result["stop_reason"]:
                param_result["stop_reason"] = "Max attempts reached."

            target_result["params"].append(param_result)

        results["results"].append(target_result)
        Path(output_file).write_text(
            json.dumps(results, indent=2),
            encoding="utf-8",
        )

    results["finished_at"] = datetime.now(timezone.utc).isoformat()
    Path(output_file).write_text(
        json.dumps(results, indent=2),
        encoding="utf-8",
    )

    return results


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run the LLM-driven SQLi payload agent."
    )
    parser.add_argument("--targets", default=DEFAULT_TARGETS_FILE)
    parser.add_argument("--output", default=DEFAULT_RESULTS_FILE)
    parser.add_argument("--max-payloads", type=int, default=DEFAULT_MAX_PAYLOADS)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--allow-remote-targets", action="store_true")

    return parser.parse_args()


def main():
    args = parse_args()
    results = run_agent(
        targets_file=args.targets,
        output_file=args.output,
        max_payloads=args.max_payloads,
        timeout=args.timeout,
        allow_remote_targets=args.allow_remote_targets,
        limit=args.limit,
    )

    print("LLM agent run complete")
    print(f"Targets loaded: {results['target_count']}")
    print(f"Results written: {args.output}")


if __name__ == "__main__":
    main()
