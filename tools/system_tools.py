def system_status() -> str:
    """Menampilkan status dasar sistem Kali."""
    import platform

    return (
        f"OS: {platform.system()} {platform.release()}\n"
        f"Hostname: {platform.node()}\n"
        f"Python: {platform.python_version()}"
    )


def disk_status() -> str:
    """Menampilkan penggunaan disk root Kali."""
    import shutil

    total, used, free = shutil.disk_usage("/")
    gb = 1024**3

    return (
        f"Disk total: {total / gb:.1f} GB\n"
        f"Disk terpakai: {used / gb:.1f} GB\n"
        f"Disk bebas: {free / gb:.1f} GB"
    )


def memory_status() -> str:
    """Menampilkan penggunaan RAM Kali."""
    meminfo = {}

    with open("/proc/meminfo", "r") as f:
        for line in f:
            key, value = line.split(":", 1)
            meminfo[key] = int(value.strip().split()[0])

    total = meminfo["MemTotal"]
    available = meminfo["MemAvailable"]
    used = total - available

    gb = 1024 * 1024

    return (
        f"RAM total: {total / gb:.1f} GB\n"
        f"RAM terpakai: {used / gb:.1f} GB\n"
        f"RAM tersedia: {available / gb:.1f} GB"
    )


def network_status() -> str:
    """Menampilkan informasi jaringan dasar Kali."""
    import socket

    hostname = socket.gethostname()

    try:
        local_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        local_ip = "Tidak tersedia"

    return f"Hostname: {hostname}\nIP lokal: {local_ip}"
