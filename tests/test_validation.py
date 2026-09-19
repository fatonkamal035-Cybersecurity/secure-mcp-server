from core.validation import validate_filename


def test_valid_filename():
    assert validate_filename("test.txt") == "test.txt"


def test_valid_nested_path():
    assert validate_filename("logs/test.txt") == "logs/test.txt"


def test_reject_path_traversal():
    try:
        validate_filename("../secret.txt")
        assert False
    except ValueError:
        pass


def test_reject_absolute_path():
    try:
        validate_filename("/etc/passwd")
        assert False
    except ValueError:
        pass


def test_reject_empty_filename():
    try:
        validate_filename("")
        assert False
    except ValueError:
        pass
