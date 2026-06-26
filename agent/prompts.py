import json


SYSTEM_PROMPT = """
You are an authorized security testing agent working only on a local lab target.
Return strict JSON only. Do not explain outside JSON.
Avoid destructive actions, persistence, data extraction, or credential abuse.
""".strip()


def json_prompt(payload):
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": json.dumps(payload, indent=2),
        },
    ]


def payload_prompt(target, param, max_payloads):
    return next_payload_prompt(target, param, [], max_payloads)


def endpoint_classification_prompt(target):
    payload = {
        "task": "Classify this HTTP endpoint before SQL injection testing.",
        "rules": [
            "Infer the endpoint purpose from the method, path, URL, and parameter names.",
            "Classify the route generically; do not rely on hard-coded app-specific vulnerabilities.",
            "Choose the SQLi attack style that fits the endpoint purpose.",
            "For login or authentication endpoints, prefer boolean/comment authentication-bypass style probes and avoid UNION enumeration.",
            "For search endpoints, prefer string/search quote probes, SQL error confirmation, and only consider UNION-style confirmation if earlier response signals justify it.",
            "For product or item lookup endpoints, prefer numeric or identifier lookup probes when the injectable value is in the path or an id-like parameter.",
            "For password change, password reset, account update, delete, checkout, order placement, or other state-changing endpoints, classify them as sensitive_write and skip active SQLi probes unless the request is clearly read-only.",
            "For metadata, challenge lists, cache busters, static assets, and display-only controls, classify them as low value or skip.",
            "avoid_payload_styles must not contradict recommended_attack_style.",
            "Return strict JSON only.",
        ],
        "allowed_endpoint_types": [
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
        ],
        "allowed_attack_styles": [
            "auth_boolean_bypass",
            "string_search_error_probe",
            "numeric_identifier_probe",
            "filter_boolean_probe",
            "generic_read_probe",
            "skip_low_value",
        ],
        "output_schema": {
            "endpoint_type": "one allowed_endpoint_types value",
            "resource": "short noun phrase",
            "likely_sql_context": "auth_lookup | string_search | id_lookup | list_filter | write_operation | metadata | static_or_noise | unknown",
            "recommended_attack_style": "one allowed_attack_styles value",
            "avoid_payload_styles": ["short strings such as union_enum, auth_bypass, numeric_probe"],
            "probe_priority": "high | medium | low | skip",
            "confidence": "number between 0 and 1",
            "reason": "short string",
        },
        "target": target,
    }

    return json_prompt(payload)


def suitability_prompt(target, param):
    payload = {
        "task": "Decide whether this single parameter is worth a SQL injection probe.",
        "rules": [
            "Do not brute force every parameter.",
            "Use endpoint_context to decide whether the parameter fits the route purpose and recommended attack style.",
            "Probe only when the endpoint and parameter plausibly influence a database query, lookup, search, or authentication check.",
            "Skip parameters that look like cache busters, tracking values, display-only selectors, or static resource controls unless there is a clear SQLi reason.",
            "For auth_login endpoints, probe only credentials or auth selector fields; do not plan UNION enumeration.",
            "For sensitive_write endpoints, skip active probing to avoid changing application state.",
            "For search endpoints, probe search text or filter parameters before unrelated controls.",
            "For product_detail or lookup_by_id endpoints, prefer id-like values over cache or display parameters.",
            "Do not suggest credential brute force, password spraying, account enumeration, OS commands, or command injection.",
            "Return strict JSON only.",
        ],
        "output_schema": {
            "probe": "boolean",
            "confidence": "number between 0 and 1",
            "reason": "short string",
            "starting_strategy": "short string",
        },
        "target": target,
        "endpoint_context": target.get("endpoint_context", {}),
        "parameter": param,
    }

    return json_prompt(payload)


def next_payload_prompt(target, param, prior_attempts, max_attempts):
    payload = {
        "task": "Choose the next SQL injection probe payload for this one parameter.",
        "rules": [
            "The payload string must come from your reasoning, not from code constants.",
            "The payload is the value for this one parameter only; never return name=value, JSON, form data, or the parameter name prefix.",
            "Use only non-destructive probes suitable for a local training app.",
            "Choose the payload style from endpoint_context.recommended_attack_style and avoid endpoint_context.avoid_payload_styles.",
            "For auth_login endpoints, do not use UNION-style enumeration; use compact single-quote-delimited boolean probes ending with a line comment marker to account for trailing password predicates.",
            "For auth_login boolean probes, avoid empty-string comparisons; use a complete true comparison with numeric constants or matching non-empty quoted constants.",
            "For search endpoints, start with a delimiter-aware string/search probe; raw OR conditions without a quote or comment are usually just literal search text.",
            "For search endpoints, adapt from SQL parser errors by balancing quotes, parentheses, and comments before considering broader read-style confirmation.",
            "If using read-style confirmation after a SQL parser error, use harmless constants or markers, not table names, credential fields, schema dumping, or real data extraction.",
            "A non-sensitive read confirmation must use constants only and should not reference application table names, system schema tables, usernames, credentials, files, or secrets.",
            "If the previous SQL error suggests unmatched parentheses or LIKE-wrapped search text, repair the delimiter/parenthesis/comment shape before trying a different technique.",
            "For product_detail, lookup_by_id, or numeric identifier endpoints, avoid login-bypass payloads and use identifier-shaped probes only if the tested value is actually injectable.",
            "For sensitive_write endpoints, set continue to false.",
            "Use the latest response_signal, status change, SQL error text, auth behavior, and body difference to choose the next payload.",
            "Do not use a generic payload list or brute force commands across unrelated parameters.",
            "Do not use time-delay functions unless a future explicit blind-time mode is added.",
            "Do not use credential brute force, password spraying, account enumeration, OS commands, command injection, persistence, or destructive SQL.",
            "Do not repeat an already attempted payload.",
            "Rejected prior_attempts are feedback, not successful probes; correct the exact rejection reason before trying anything else.",
            "If a prior rejected attempt says a string delimiter is missing, the next payload must contain a quote or double-quote character.",
            "If a prior rejected attempt says name=value was used, remove the parameter name and return only the value.",
            "If a prior rejected auth attempt says a comment marker is missing, the next payload must include both a single quote and a line comment marker.",
            "If the last response gave no useful SQLi signal, set continue to false instead of trying random payloads.",
            "If the last response showed a SQL parser error, adapt the next payload to that specific error class instead of returning another equivalent syntax error.",
            "If the last response already confirms SQLi clearly, set continue to false unless one more non-destructive confirmation is justified.",
        ],
        "output_schema": {
            "continue": "boolean",
            "payload": {
                "payload": "string",
                "rationale": "short string",
                "expected_signal": "short string",
            },
            "reason": "short string",
        },
        "attempt_index": len(prior_attempts) + 1,
        "max_attempts": max_attempts,
        "target": target,
        "endpoint_context": target.get("endpoint_context", {}),
        "parameter": param,
        "prior_attempts": prior_attempts,
        "agent_guidance": next_payload_guidance(target, prior_attempts),
    }

    return json_prompt(payload)


def next_payload_guidance(target, prior_attempts):
    endpoint_context = target.get("endpoint_context", {})
    endpoint_type = endpoint_context.get("endpoint_type", "")

    if not prior_attempts:
        return {
            "phase": "initial_probe",
            "instruction": "Choose the first endpoint-appropriate syntax probe.",
        }

    last = prior_attempts[-1]
    signal = last.get("response_signal") or {}

    if not signal.get("available") and "Rejected before probe" in signal.get("reason", ""):
        return {
            "phase": "repair_rejected_payload",
            "instruction": (
                "The previous payload was rejected locally. Correct that exact "
                "shape problem before choosing any new technique."
            ),
        }

    if signal.get("sql_error") and endpoint_type in {
            "search",
            "list_filter",
            "product_collection",
            "other_data_endpoint",
    }:
        return {
            "phase": "post_error_confirmation",
            "instruction": (
                "The previous probe already produced a SQL parser error. Do not "
                "send another equivalent boolean syntax error. Either repair the "
                "delimiter/parenthesis/comment shape, or use a non-sensitive "
                "constant-only read confirmation. Do not reference table names, "
                "system schema tables, credentials, users, secrets, files, or real data."
            ),
        }

    if signal.get("auth_bypass_like"):
        return {
            "phase": "sufficient_auth_evidence",
            "instruction": "Authentication-bypass evidence is sufficient; stop.",
        }

    if signal.get("body_changed") or signal.get("status_changed"):
        return {
            "phase": "behavior_confirmation",
            "instruction": (
                "Use one small endpoint-appropriate confirmation payload only if it "
                "can clarify the observed behavior without extracting data."
            ),
        }

    return {
        "phase": "no_signal",
        "instruction": "If there is no useful signal after suitable attempts, stop.",
    }


def read_confirmation_prompt(target, param, prior_attempts):
    payload = {
        "task": "Choose one optional non-sensitive in-band SQLi read-confirmation payload.",
        "rules": [
            "Use this only after prior attempts already produced a SQL parser/database error on a read/search/filter endpoint.",
            "The payload string must come from your reasoning, not from code constants.",
            "The payload is the value for this one parameter only; never return name=value, JSON, form data, or the parameter name prefix.",
            "If continue is true, the payload must attempt a non-sensitive marker-based read confirmation.",
            "For marker-based read confirmation, include a UNION SELECT or equivalent read-channel expression using only constants.",
            "Set expected_marker to the exact harmless marker string you expect in the HTTP response.",
            "Do not reference application table names, system schema tables, credential fields, usernames, emails, files, secrets, or real data.",
            "Use only harmless constants and a short marker string if attempting a UNION/read-channel confirmation.",
            "If the SQL shape cannot be inferred enough for a safe constant-only confirmation, set continue to false.",
            "If using UNION, use only constant literals or numbers and keep it read-only.",
            "If using ORDER BY or column-count probing, keep it numeric and non-destructive.",
            "Repair quote, parenthesis, and comment shape from the prior SQL error before adding a new technique.",
            "Do not use time delays, stacked queries, comments that hide destructive clauses, OS commands, credential extraction, or schema extraction.",
            "Return strict JSON only.",
        ],
        "output_schema": {
            "continue": "boolean",
            "payload": {
                "payload": "string",
                "rationale": "short string",
                "expected_signal": "short string",
                "expected_marker": "short string or empty",
            },
            "reason": "short string",
        },
        "target": target,
        "endpoint_context": target.get("endpoint_context", {}),
        "parameter": param,
        "prior_attempts": prior_attempts,
    }

    return json_prompt(payload)


def decision_prompt(target, param, baseline, probe, payload_info, signal=None):
    payload = {
        "task": "Decide what the SQLi agent should do after this probe.",
        "rules": [
            "Escalate only when response evidence supports SQL injection behavior.",
            "If baseline and probe are effectively identical and there is no SQL error, auth bypass, timing, content-type, or meaningful body change, return not_decidable or stop, not escalate.",
            "Do not recommend a payload style that endpoint_context says to avoid.",
            "Do not recommend UNION enumeration for login/authentication endpoints.",
            "For sensitive_write endpoints, stop.",
        ],
        "allowed_decisions": [
            "escalate",
            "not_decidable",
            "stop",
        ],
        "decision_meaning": {
            "escalate": "Evidence suggests injection behavior; continue with stronger confirmation if attempts remain.",
            "not_decidable": "Evidence is ambiguous; try another payload or gather more context.",
            "stop": "Enough evidence was gathered, no useful signal remains, or endpoint is not suitable.",
        },
        "output_schema": {
            "decision": "escalate | not_decidable | stop",
            "confidence": "number between 0 and 1",
            "reason": "short string",
            "next_step": "short string",
        },
        "target": target,
        "endpoint_context": target.get("endpoint_context", {}),
        "parameter": param,
        "payload": payload_info,
        "response_signal": signal or {},
        "baseline_result": baseline,
        "probe_result": probe,
    }

    return json_prompt(payload)


def report_prompt(scan_results, agent_results):
    payload = {
        "task": "Generate the final SQL injection assessment report.",
        "rules": [
            "Use only the supplied scan inventory and probe results.",
            "Do not invent endpoints, parameters, payloads, status codes, or errors.",
            "Treat strongest_decision=escalate as stronger than a later final_decision=not_decidable.",
            "Report confirmed or likely SQL injection only when probe evidence supports it.",
            "Mention business impact separately from directly observed evidence.",
            "Put ambiguous evidence in not_decidable_targets instead of calling it vulnerable.",
            "Keep recommendations focused on SQL injection prevention and safe verification.",
        ],
        "output_schema": {
            "overall_status": "vulnerabilities_found | not_decidable | no_vulnerabilities_confirmed",
            "executive_summary": "short string",
            "findings": [
                {
                    "title": "short string",
                    "severity": "critical | high | medium | low | info",
                    "confidence": "number between 0 and 1",
                    "method": "HTTP method",
                    "path": "endpoint path",
                    "endpoint_type": "classified endpoint type if available",
                    "attack_style": "classified attack style if available",
                    "parameter": "parameter name",
                    "payload": "payload that produced evidence, if available",
                    "evidence": "short string",
                    "recommendation": "short string",
                }
            ],
            "not_decidable_targets": [
                {
                    "method": "HTTP method",
                    "path": "endpoint path",
                    "parameter": "parameter name",
                    "reason": "short string",
                }
            ],
            "markdown_report": "complete concise Markdown report string",
        },
        "scan_results": scan_results,
        "agent_results": agent_results,
    }

    return json_prompt(payload)
