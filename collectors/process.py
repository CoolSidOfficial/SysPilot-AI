"""
collectors/process.py

Collect process information.
"""

import datetime
import psutil


def collect():

    processes = []

    for proc in psutil.process_iter():

        try:

            with proc.oneshot():

                mem = proc.memory_info()

                processes.append({
                    "pid": proc.pid,
                    "parent_pid": proc.ppid(),

                    "name": proc.name(),

                    "exe": proc.exe(),

                    "cmdline": proc.cmdline(),

                    "username": proc.username(),

                    "status": proc.status(),

                    "created": datetime.datetime.fromtimestamp(
                        proc.create_time()
                    ).isoformat(),

                    "threads": proc.num_threads(),

                    "cpu_percent": proc.cpu_percent(),

                    "memory": {
                        "rss_mb": round(mem.rss / 1024 / 1024, 2),
                        "vms_mb": round(mem.vms / 1024 / 1024, 2),
                    }

                })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            continue

        except Exception:
            continue

    processes.sort(
        key=lambda p: p["memory"]["rss_mb"],
        reverse=True,
    )

    return processes