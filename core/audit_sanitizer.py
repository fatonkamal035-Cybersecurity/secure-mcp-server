from typing import Any


REDACTED = "[REDACTED]"

SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "client_secret",
    "password",
    "refresh_token",
    "secret",
    "token",
}


def sanitize_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """Redact sensitive argument values without mutating the input."""
    if not isinstance(arguments, dict):
        raise TypeError("arguments harus berupa dictionary")

    return _sanitize_mapping(arguments)


def _sanitize_mapping(mapping: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}

    for key, value in mapping.items():
        if isinstance(key, str) and key.lower() in SENSITIVE_KEYS:
            result[key] = REDACTED
        else:
            result[key] = _sanitize_value(value)

    return result


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, dict):
        return _sanitize_mapping(value)

    if isinstance(value, list):
        return [_sanitize_value(item) for item in value]

    if isinstance(value, tuple):
        return tuple(_sanitize_value(item) for item in value)

    return value
