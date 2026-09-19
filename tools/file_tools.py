from pathlib import Path

from core.validation import validate_filename


BASE_DIR = Path.home() / "mcp-kali"
MAX_FILE_SIZE = 1024 * 1024


def read_text_file(filename: str) -> str:
    """Membaca file teks yang berada di dalam direktori project MCP."""
    filename = validate_filename(filename)

    file_path = (BASE_DIR / filename).resolve()

    if BASE_DIR.resolve() not in file_path.parents:
        raise ValueError("akses file di luar project tidak diizinkan")

    if not file_path.is_file():
        raise FileNotFoundError(f"file tidak ditemukan: {filename}")

    if file_path.stat().st_size > MAX_FILE_SIZE:
        raise ValueError("ukuran file melebihi batas 1 MiB")

    return file_path.read_text(encoding="utf-8")
