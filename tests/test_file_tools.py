import pytest

from tools import read_text_file


def test_read_existing_file():
    result = read_text_file("server.py")
    assert "MCPServer" in result


def test_reject_path_traversal():
    with pytest.raises(ValueError):
        read_text_file("../server.py")


def test_reject_absolute_path():
    with pytest.raises(ValueError):
        read_text_file("/etc/passwd")


def test_missing_file():
    with pytest.raises(FileNotFoundError):
        read_text_file("tests/file-that-does-not-exist.txt")


def test_reject_large_file(tmp_path, monkeypatch):
    from tools import file_tools

    large_file = tmp_path / "large.txt"
    large_file.write_bytes(b"x" * (file_tools.MAX_FILE_SIZE + 1))

    monkeypatch.setattr(file_tools, "BASE_DIR", tmp_path)

    with pytest.raises(ValueError, match="ukuran file melebihi batas 1 MiB"):
        file_tools.read_text_file("large.txt")
