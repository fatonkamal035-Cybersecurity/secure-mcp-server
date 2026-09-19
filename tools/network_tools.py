import subprocess


def network_interfaces() -> str:
    """Menampilkan interface jaringan dan alamat IPv4-nya."""
    result = subprocess.run(
        ["ip", "-4", "-o", "addr", "show"],
        capture_output=True,
        text=True,
        check=True,
        timeout=5,
    )

    lines = []

    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            interface = parts[1]
            address = parts[3]
            lines.append(f"{interface}: {address}")

    return "\n".join(lines) if lines else "Tidak ada interface IPv4."
