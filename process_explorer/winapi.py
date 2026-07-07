import ctypes
from ctypes import wintypes

# ============================================================
# DLL
# ============================================================

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# ============================================================
# CONSTANTS
# ============================================================

TH32CS_SNAPPROCESS = 0x00000002

MAX_PATH = 260

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# ============================================================
# STRUCTURES
# ============================================================


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH),
    ]


# ============================================================
# CreateToolhelp32Snapshot
# ============================================================

CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot

CreateToolhelp32Snapshot.argtypes = [
    wintypes.DWORD,
    wintypes.DWORD,
]

CreateToolhelp32Snapshot.restype = wintypes.HANDLE


# ============================================================
# Process32FirstW
# ============================================================

Process32FirstW = kernel32.Process32FirstW

Process32FirstW.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(PROCESSENTRY32W),
]

Process32FirstW.restype = wintypes.BOOL


# ============================================================
# Process32NextW
# ============================================================

Process32NextW = kernel32.Process32NextW

Process32NextW.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(PROCESSENTRY32W),
]

Process32NextW.restype = wintypes.BOOL


# ============================================================
# OpenProcess
# ============================================================

OpenProcess = kernel32.OpenProcess

OpenProcess.argtypes = [
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD,
]

OpenProcess.restype = wintypes.HANDLE


# ============================================================
# QueryFullProcessImageNameW
# ============================================================

QueryFullProcessImageNameW = kernel32.QueryFullProcessImageNameW

QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
]

QueryFullProcessImageNameW.restype = wintypes.BOOL


# ============================================================
# CloseHandle
# ============================================================

CloseHandle = kernel32.CloseHandle

CloseHandle.argtypes = [
    wintypes.HANDLE,
]

CloseHandle.restype = wintypes.BOOL


# ============================================================
# HELPERS
# ============================================================

def get_process_path(pid: int) -> str | None:
    """
    Returns the full executable path for a process.

    Returns None if the process cannot be opened.
    """

    handle = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        pid,
    )

    if not handle:
        return None

    try:

        size = wintypes.DWORD(32768)

        buffer = ctypes.create_unicode_buffer(size.value)

        success = QueryFullProcessImageNameW(
            handle,
            0,
            buffer,
            ctypes.byref(size),
        )

        if not success:
            return None

        return buffer.value

    finally:
        CloseHandle(handle)