"""
collectors/cpu.py

Collect CPU information.
"""

import platform
import psutil


def collect():
    """Collect CPU information."""

    freq = psutil.cpu_freq()

    return {
        "model": platform.processor() or "Unknown",

        "physical_cores": psutil.cpu_count(logical=False),

        "logical_cores": psutil.cpu_count(logical=True),

        "usage": {
            "overall_percent": psutil.cpu_percent(interval=1),
            "per_core_percent": psutil.cpu_percent(interval=1, percpu=True),
        },

        "frequency": {
            "current_mhz": round(freq.current, 2) if freq else None,
            "min_mhz": round(freq.min, 2) if freq else None,
            "max_mhz": round(freq.max, 2) if freq else None,
        },

        "stats": {
            "ctx_switches": psutil.cpu_stats().ctx_switches,
            "interrupts": psutil.cpu_stats().interrupts,
            "soft_interrupts": psutil.cpu_stats().soft_interrupts,
            "syscalls": psutil.cpu_stats().syscalls,
        },

        "load_average": (
            psutil.getloadavg() if hasattr(psutil, "getloadavg") else None
        ),
    }