"""
collectors/startup.py

Collect Windows startup programs.
"""

import os
import winreg
from pathlib import Path


def _read_registry(root, path, location):
    entries = []

    try:
        key = winreg.OpenKey(root, path)

        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)

                entries.append({
                    "name": name,
                    "command": value,
                    "location": location,
                    "source": "Registry"
                })

                i += 1

            except OSError:
                break

        winreg.CloseKey(key)

    except FileNotFoundError:
        pass

    return entries


def _read_startup_folder(folder, location):
    entries = []

    if not folder.exists():
        return entries

    for item in folder.iterdir():

        entries.append({
            "name": item.name,
            "command": str(item),
            "location": location,
            "source": "Startup Folder"
        })

    return entries


def collect():

    startup = []

    # ----------------------------------
    # Registry
    # ----------------------------------

    startup.extend(_read_registry(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU\\Run"
    ))

    startup.extend(_read_registry(
        winreg.HKEY_LOCAL_MACHINE,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM\\Run"
    ))

    startup.extend(_read_registry(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU\\RunOnce"
    ))

    startup.extend(_read_registry(
        winreg.HKEY_LOCAL_MACHINE,
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM\\RunOnce"
    ))

    # ----------------------------------
    # Startup Folders
    # ----------------------------------

    user_startup = (
        Path(os.getenv("APPDATA"))
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
    )

    common_startup = (
        Path(os.getenv("PROGRAMDATA"))
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
    )

    startup.extend(
        _read_startup_folder(user_startup, "Current User Startup Folder")
    )

    startup.extend(
        _read_startup_folder(common_startup, "All Users Startup Folder")
    )

    return startup