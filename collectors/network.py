"""
collectors/network.py

Collect network information.
"""

import psutil
import socket


def collect():
    report = {
        "interfaces": [],
        "connections": [],
        "io": {}
    }

    # ----------------------------
    # Network Interfaces
    # ----------------------------

    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for interface, addrs in addresses.items():

        iface = {
            "name": interface,
            "is_up": stats.get(interface).isup if interface in stats else False,
            "speed_mbps": stats.get(interface).speed if interface in stats else None,
            "mtu": stats.get(interface).mtu if interface in stats else None,
            "mac": None,
            "ipv4": [],
            "ipv6": []
        }

        for addr in addrs:

            # MAC Address
            if getattr(psutil, "AF_LINK", object()) == addr.family:
                iface["mac"] = addr.address

            # IPv4
            elif addr.family == socket.AF_INET:
                iface["ipv4"].append({
                    "address": addr.address,
                    "netmask": addr.netmask,
                    "broadcast": addr.broadcast
                })

            # IPv6
            elif addr.family == socket.AF_INET6:
                iface["ipv6"].append({
                    "address": addr.address,
                    "netmask": addr.netmask
                })

        report["interfaces"].append(iface)

    # ----------------------------
    # Active Connections
    # ----------------------------

    try:
        connections = psutil.net_connections(kind="inet")
    except Exception:
        connections = []

    for conn in connections:

        process_name = None

        if conn.pid:
            try:
                process_name = psutil.Process(conn.pid).name()
            except Exception:
                process_name = None

        report["connections"].append({
            "pid": conn.pid,
            "process": process_name,
            "family": str(conn.family),
            "type": str(conn.type),

            "local": {
                "ip": conn.laddr.ip if conn.laddr else None,
                "port": conn.laddr.port if conn.laddr else None
            },

            "remote": {
                "ip": conn.raddr.ip if conn.raddr else None,
                "port": conn.raddr.port if conn.raddr else None
            },

            "status": conn.status
        })

    # ----------------------------
    # Network I/O
    # ----------------------------

    io = psutil.net_io_counters()

    report["io"] = {
        "bytes_sent": io.bytes_sent,
        "bytes_received": io.bytes_recv,
        "packets_sent": io.packets_sent,
        "packets_received": io.packets_recv,
        "errors_in": io.errin,
        "errors_out": io.errout,
        "drops_in": io.dropin,
        "drops_out": io.dropout
    }

    return report