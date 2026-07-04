"""
collectors/system.py

Collect basic system information.
"""

import platform
import socket
import getpass
import psutil
from datetime import datetime


def collect():
    """Collect system information."""

    uname = platform.uname()
    boot_time = datetime.fromtimestamp(psutil.boot_time())

    return {
        "hostname": socket.gethostname(),
        "username": getpass.getuser(),

        "os": {
            "system": uname.system,
            "release": uname.release,
            "version": uname.version,
            "platform": platform.platform(),
            "architecture": platform.machine(),
        },

        "boot": {
            "boot_time": boot_time.isoformat(),
            "uptime_seconds": int(psutil.boot_time()),
        },

        "python": {
            "version": platform.python_version(),
        },
    }