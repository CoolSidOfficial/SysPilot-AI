"""
collectors/disk.py

Collect disk and partition information.
"""

import psutil


GB = 1024 ** 3


def collect():
    report = {
        "partitions": [],
        "io": {}
    }

    # ----------------------------------------
    # Partitions
    # ----------------------------------------

    for partition in psutil.disk_partitions(all=False):

        try:
            usage = psutil.disk_usage(partition.mountpoint)
        except PermissionError:
            continue

        report["partitions"].append({
            "device": partition.device,
            "mountpoint": partition.mountpoint,
            "filesystem": partition.fstype,
            "options": partition.opts,

            "size": {
                "total_gb": round(usage.total / GB, 2),
                "used_gb": round(usage.used / GB, 2),
                "free_gb": round(usage.free / GB, 2),
                "percent": usage.percent
            }
        })

    # ----------------------------------------
    # Disk I/O
    # ----------------------------------------

    io = psutil.disk_io_counters()

    if io:
        report["io"] = {
            "read_count": io.read_count,
            "write_count": io.write_count,

            "read_bytes_gb": round(io.read_bytes / GB, 2),
            "write_bytes_gb": round(io.write_bytes / GB, 2),

            "read_time_ms": io.read_time,
            "write_time_ms": io.write_time,
        }

    return report