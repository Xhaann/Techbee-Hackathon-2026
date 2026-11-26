import re

REDACTED = "[redacted]"
SECRET_PATTERN = re.compile(
    r"(sk-[A-Za-z0-9_-]{12,}"
    r"|\b(?:api[_-]?key|password|passwd|secret|token|community)\b\s*[:=]\s*\S+"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|\bbearer\s+[A-Za-z0-9._-]{12,}"
    r"|\bAKIA[0-9A-Z]{16}\b)",
    re.IGNORECASE,
)


def contains_secret(text: str) -> bool:
    return bool(SECRET_PATTERN.search(text))


def redact_values(value: object) -> object:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {key: redact_values(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_values(item) for item in value]
    return value


def redact(text: str, known: tuple[str, ...] = ()) -> str:
    for value in known:
        if value:
            text = text.replace(value, REDACTED)
    return SECRET_PATTERN.sub(REDACTED, text)
