from tools import (
    kali_info,
    system_status,
    disk_status,
    memory_status,
    network_status,
    network_interfaces,
)


def test_kali_info():
    result = kali_info()
    assert "Kali MCP Server aktif." in result


def test_system_status():
    result = system_status()
    assert "OS:" in result
    assert "Hostname:" in result
    assert "Python:" in result


def test_disk_status():
    result = disk_status()
    assert "Disk total:" in result
    assert "Disk terpakai:" in result
    assert "Disk bebas:" in result


def test_memory_status():
    result = memory_status()
    assert "RAM total:" in result
    assert "RAM terpakai:" in result
    assert "RAM tersedia:" in result


def test_network_status():
    result = network_status()
    assert "Hostname:" in result
    assert "IP lokal:" in result


def test_network_interfaces():
    result = network_interfaces()
    assert "wlan0:" in result
    assert "192.168.1.7/24" in result
