from pathlib import Path


def validate_filename(filename: str) -> str:
    """Validasi nama file agar tidak mengandung path traversal."""
    if not isinstance(filename, str):
        raise TypeError("filename harus berupa string")

    if not filename.strip():
        raise ValueError("filename tidak boleh kosong")

    path = Path(filename)

    if path.is_absolute():
        raise ValueError("absolute path tidak diizinkan")

    if ".." in path.parts:
        raise ValueError("path traversal tidak diizinkan")

    return filename
