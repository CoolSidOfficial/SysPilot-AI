"""
collectors/process/basic.py

Basic process identity information.
"""

import datetime
import psutil


def collect(proc: psutil.Process):

    with proc.oneshot():

        return {

            # -------------------------
            # Identity
            # -------------------------

            "pid": proc.pid,
            "parent_pid": proc.ppid(),
            "name": proc.name(),

            # -------------------------
            # Executable
            # -------------------------

            "exe": safe(proc.exe),
            "cwd": safe(proc.cwd),
            "cmdline": safe(proc.cmdline),

            # -------------------------
            # User
            # -------------------------

            "username": safe(proc.username),

            # -------------------------
            # State
            # -------------------------

            "status": safe(proc.status),

            "is_running": proc.is_running(),

            # -------------------------
            # Lifetime
            # -------------------------

            "created": iso(proc.create_time()),

            "uptime_seconds": uptime(proc),

            # -------------------------
            # Relationships
            # -------------------------

            "children": children(proc),

            "parent_name": parent_name(proc),

            # -------------------------
            # Misc
            # -------------------------

            "terminal": safe(proc.terminal),

            "num_threads": safe(proc.num_threads),

            "num_handles": safe(proc.num_handles),

            "num_fds": safe(proc.num_fds),
        }


def safe(func):
    try:
        return func()
    except Exception:
        return None


def iso(timestamp):

    try:
        return datetime.datetime.fromtimestamp(
            timestamp
        ).isoformat()
    except Exception:
        return None


def uptime(proc):

    try:
        return int(
            datetime.datetime.now().timestamp()
            - proc.create_time()
        )
    except Exception:
        return None


def parent_name(proc):

    try:
        return proc.parent().name()
    except Exception:
        return None


def children(proc):

    try:

        return [
            {
                "pid": child.pid,
                "name": child.name()
            }
            for child in proc.children()
        ]

    except Exception:
        return []