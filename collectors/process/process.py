"""
process/process.py

Main Process Collector
"""

import psutil

from . import basic
from . import cpu
from . import memory
from . import executable
from . import threads
from . import network
from . import io


def collect():

    processes = []

    for proc in psutil.process_iter():

        try:

            process = {

                "basic": basic.collect(proc),

                "cpu": cpu.collect(proc),

                "memory": memory.collect(proc),

                "executable": executable.collect(proc),

                "threads": threads.collect(proc),

                "network": network.collect(proc),

                "io": io.collect(proc),

            }

            processes.append(process)

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            continue

        except Exception:
            continue

    processes.sort(
        key=lambda p: p["memory"].get("rss_mb", 0),
        reverse=True,
    )

    return processes