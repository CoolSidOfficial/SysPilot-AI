"""
collectors/memory.py

Collect memory information.
"""

import psutil


def collect():

    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()

    gb = 1024 ** 3

    return {

        "physical": {
            "total_gb": round(vm.total / gb, 2),
            "available_gb": round(vm.available / gb, 2),
            "used_gb": round(vm.used / gb, 2),
            "free_gb": round(vm.free / gb, 2),
            "percent": vm.percent,
            "cached_gb": round(getattr(vm, "cached", 0) / gb, 2),
        },

        "swap": {
            "total_gb": round(swap.total / gb, 2),
            "used_gb": round(swap.used / gb, 2),
            "free_gb": round(swap.free / gb, 2),
            "percent": swap.percent,
        }

    }