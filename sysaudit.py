import json
import os
import platform
import socket
import psutil
from datetime import datetime

report = {}

# ----------------------------
# System Information
# ----------------------------
report["system"] = {
    "hostname": socket.gethostname(),
    "os": platform.system(),
    "release": platform.release(),
    "version": platform.version(),
    "architecture": platform.machine(),
    "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
}

# ----------------------------
# CPU
# ----------------------------
report["cpu"] = {
    "physical_cores": psutil.cpu_count(logical=False),
    "logical_cores": psutil.cpu_count(logical=True),
    "usage_percent": psutil.cpu_percent(interval=1),
}

# ----------------------------
# Memory
# ----------------------------
mem = psutil.virtual_memory()
report["memory"] = {
    "total_gb": round(mem.total / (1024**3), 2),
    "used_gb": round(mem.used / (1024**3), 2),
    "available_gb": round(mem.available / (1024**3), 2),
    "usage_percent": mem.percent,
}

# ----------------------------
# Disk
# ----------------------------
report["disks"] = []

for p in psutil.disk_partitions():
    try:
        usage = psutil.disk_usage(p.mountpoint)
        report["disks"].append({
            "device": p.device,
            "mount": p.mountpoint,
            "filesystem": p.fstype,
            "total_gb": round(usage.total / (1024**3), 2),
            "used_gb": round(usage.used / (1024**3), 2),
            "free_gb": round(usage.free / (1024**3), 2),
            "usage_percent": usage.percent,
        })
    except PermissionError:
        pass

# ----------------------------
# Processes
# ----------------------------
report["processes"] = []

for proc in psutil.process_iter([
    "pid",
    "name",
    "username",
    "cpu_percent",
    "memory_percent",
    "exe",
    "cmdline"
]):
    try:
        report["processes"].append(proc.info)
    except Exception:
        pass

# ----------------------------
# Services (Windows only)
# ----------------------------
report["services"] = []

if os.name == "nt":
    try:
        for s in psutil.win_service_iter():
            try:
                report["services"].append(s.as_dict())
            except Exception:
                pass
    except Exception:
        pass

# ----------------------------
# Network Connections
# ----------------------------
report["connections"] = []

for conn in psutil.net_connections(kind="inet"):
    report["connections"].append({
        "pid": conn.pid,
        "status": conn.status,
        "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
        "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
    })

# ----------------------------
# Startup Programs (Windows)
# ----------------------------
report["startup"] = []

if os.name == "nt":
    import winreg

    KEYS = [
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ]

    for hive, key in KEYS:
        try:
            reg = winreg.OpenKey(hive, key)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(reg, i)
                    report["startup"].append({
                        "name": name,
                        "command": value
                    })
                    i += 1
                except OSError:
                    break
        except Exception:
            pass

# ----------------------------
# Save Report
# ----------------------------
with open("sysaudit_report.json", "w", encoding="utf-8") as f:
    json.dump(report, f, indent=4)

print("Report saved as sysaudit_report.json")