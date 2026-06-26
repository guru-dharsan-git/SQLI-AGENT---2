import re


JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
JWT_PREFIX_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]*){0,2}")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", flags=re.IGNORECASE)
HEX_SECRET_RE = re.compile(r"\b[a-fA-F0-9]{32,}\b")
JSON_SECRET_FIELD_RE = re.compile(
    r'("(?:token|access_token|refresh_token|password|pass|secret|api[_-]?key|authorization)"\s*:\s*")[^"]*(")',
    flags=re.IGNORECASE,
)
TRUNCATED_JSON_SECRET_FIELD_RE = re.compile(
    r'("(?:token|access_token|refresh_token|password|pass|secret|api[_-]?key|authorization)"\s*:\s*")[^"]*$',
    flags=re.IGNORECASE,
)
BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", flags=re.IGNORECASE)
HTML_HEADING_RE = re.compile(r"<h1\b[^>]*>.*?</h1>", flags=re.IGNORECASE | re.DOTALL)
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", flags=re.DOTALL)
HTML_TITLE_RE = re.compile(r"<title\b[^>]*>.*?</title>", flags=re.IGNORECASE | re.DOTALL)
HTML_META_DESCRIPTION_RE = re.compile(
    r"<meta\b[^>]*name=[\"']description[\"'][^>]*>",
    flags=re.IGNORECASE | re.DOTALL,
)
UNIX_ABSOLUTE_PATH_RE = re.compile(r"(?<![:\w])/(?:[A-Za-z0-9_.-]+/){1,}[A-Za-z0-9_.-]+")


def redact_text(value, redact_paths=False):
    text = str(value or "")
    text = JWT_RE.sub("[REDACTED_JWT]", text)
    text = JWT_PREFIX_RE.sub("[REDACTED_JWT]", text)
    text = BEARER_RE.sub("Bearer [REDACTED]", text)
    text = JSON_SECRET_FIELD_RE.sub(r"\1[REDACTED]\2", text)
    text = TRUNCATED_JSON_SECRET_FIELD_RE.sub(r"\1[REDACTED_TRUNCATED]", text)
    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = HEX_SECRET_RE.sub("[REDACTED_HEX]", text)

    if redact_paths:
        text = HTML_COMMENT_RE.sub("[REDACTED_HTML_COMMENT]", text)
        text = HTML_TITLE_RE.sub("<title>[REDACTED_TITLE]</title>", text)
        text = HTML_META_DESCRIPTION_RE.sub("<meta name=\"description\" content=\"[REDACTED_DESCRIPTION]\">", text)
        text = HTML_HEADING_RE.sub("<h1>[REDACTED_SERVER_BANNER]</h1>", text)
        text = UNIX_ABSOLUTE_PATH_RE.sub("[REDACTED_PATH]", text)

    return text


def redact_data(value, key_name=""):
    if isinstance(value, dict):
        return {
            key: "[REDACTED]"
            if str(key).lower() in {
                "token",
                "access_token",
                "refresh_token",
                "password",
                "pass",
                "secret",
                "api_key",
                "apikey",
                "authorization",
            }
            else redact_data(item, key)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [redact_data(item, key_name) for item in value]

    if isinstance(value, str):
        return redact_text(
            value,
            redact_paths=str(key_name).lower() in {"body_sample", "response_sample"},
        )

    return value
