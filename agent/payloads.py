import re


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
# TIME_DELAY_RE = re.compile(
#     r"\b(sleep|pg_sleep|benchmark|waitfor\s+delay|dbms_lock\.sleep)\b",
#     flags=re.IGNORECASE,
# )
MALFORMED_COMPARISON_RE = re.compile(
    r"(=|<>|!=)\s*(--|#|/\*)|(['\"])\s*(=|<>|!=)\s*\3?\s*(--|#|/\*)",
    flags=re.IGNORECASE,
)
QUOTED_COMPARISON_RE = re.compile(
    r"(['\"])(.*?)\1\s*=\s*(['\"])(.*?)\3",
    flags=re.IGNORECASE,
)
AUTH_BOOLEAN_COMPARISON_RE = re.compile(
    r"\b(or|and)\b\s+(?:\d+\s*=\s*\d+|(['\"])[^'\"]+\2\s*=\s*(['\"])[^'\"]+\3)",
    flags=re.IGNORECASE,
)


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
        has_boolean_operator = re.search(r"\b(or|and)\b", payload, flags=re.IGNORECASE)

        if not has_delimiter or not has_comment:
            return False, (
                "Auth probe rejected because it needs a single-quote delimiter "
                "and a line comment marker to neutralize trailing predicates."
            )

        if not has_boolean_operator:
            return False, (
                "Auth probe rejected because it needs a boolean operator before "
                "the comparison."
            )

        if MALFORMED_COMPARISON_RE.search(payload):
            return False, (
                "Auth probe rejected because the boolean comparison appears incomplete."
            )

        for left_quote, left, right_quote, right in QUOTED_COMPARISON_RE.findall(payload):
            if left_quote != right_quote or not left.strip() or not right.strip():
                return False, (
                    "Auth probe rejected because the boolean comparison must use "
                    "non-empty constants on both sides."
                )

        if not AUTH_BOOLEAN_COMPARISON_RE.search(payload):
            return False, (
                "Auth probe rejected because it needs a complete boolean comparison "
                "with numeric constants or non-empty quoted constants."
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

    return payload_info, ""


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
    elif "boolean comparison" in reason or "boolean operator" in reason:
        next_step = (
            "Return only a single-quote-delimited auth value with OR/AND, a complete "
            "true comparison using numeric constants or matching non-empty quoted "
            "constants, and a SQL line comment marker."
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
