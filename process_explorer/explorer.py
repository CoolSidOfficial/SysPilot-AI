
from .winapi import *
from .process import Process

def enumerate_processes():

    processes = []

    snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS,
        0,
    )

    if snapshot == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())

    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

    success = Process32FirstW(snapshot, ctypes.byref(entry))

    while success:

        processes.append(
            Process(
                pid=entry.th32ProcessID,
                parent_pid=entry.th32ParentProcessID,
                name=entry.szExeFile,
                path=get_process_path(entry.th32ProcessID),
            )
        )

        success = Process32NextW(
            snapshot,
            ctypes.byref(entry),
        )

    CloseHandle(snapshot)

    return processes