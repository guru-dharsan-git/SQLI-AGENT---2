import re


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
