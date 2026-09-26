import pytest

from core.audit_sanitizer import sanitize_arguments


def test_non_sensitive_arguments_are_preserved():
    arguments = {"filename": "README.md"}

    result = sanitize_arguments(arguments)

    assert result == {"filename": "README.md"}
    assert arguments == {"filename": "README.md"}


def test_sensitive_argument_is_redacted():
    arguments = {"password": "super-secret"}

    result = sanitize_arguments(arguments)

    assert result == {"password": "[REDACTED]"}
    assert arguments == {"password": "super-secret"}


def test_sensitive_keys_are_case_insensitive():
    arguments = {
        "API_KEY": "secret",
        "Authorization": "Bearer secret",
        "token": "secret",
    }

    result = sanitize_arguments(arguments)

    assert result == {
        "API_KEY": "[REDACTED]",
        "Authorization": "[REDACTED]",
        "token": "[REDACTED]",
    }


def test_nested_structures_are_sanitized():
    arguments = {
        "config": {
            "username": "tester",
            "api_key": "secret-value",
        },
        "items": [
            {"password": "secret-password"},
            "normal-value",
        ],
    }

    result = sanitize_arguments(arguments)

    assert result == {
        "config": {
            "username": "tester",
            "api_key": "[REDACTED]",
        },
        "items": [
            {"password": "[REDACTED]"},
            "normal-value",
        ],
    }


def test_none_is_preserved():
    assert sanitize_arguments({"value": None}) == {"value": None}


def test_non_mapping_input_is_rejected():
    with pytest.raises(TypeError, match="arguments harus berupa dictionary"):
        sanitize_arguments(["not", "a", "dict"])
