# winapi.py
"""
Native Windows API wrappers using ctypes
Complete implementation for SysPilot-Ai
"""

import ctypes
from ctypes import wintypes
import struct
import time
from typing import Optional, Dict, Any

# ============================================================
# DLL
# ============================================================

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
version = ctypes.WinDLL("version", use_last_error=True)  # <-- ADD THIS

# ============================================================
# CONSTANTS
# ============================================================

# Process snapshot
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPMODULE32 = 0x00000010
TH32CS_SNAPFULL = 0x0000000F
TH32CS_SNAPALL = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)

MAX_PATH = 260
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# Process access rights
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_TERMINATE = 0x0001
PROCESS_CREATE_THREAD = 0x0002
PROCESS_SET_SESSIONID = 0x0004
PROCESS_SET_QUOTA = 0x0100
PROCESS_SET_INFORMATION = 0x0200
PROCESS_DUP_HANDLE = 0x0040
PROCESS_CREATE_PROCESS = 0x0080
PROCESS_SET_PORT = 0x0400
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFFF)

# Token access rights
TOKEN_QUERY = 0x0008
TOKEN_READ = 0x00020000
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATE = 0x0004

# Token information class
TokenUser = 1
TokenGroups = 2
TokenPrivileges = 3
TokenOwner = 4
TokenPrimaryGroup = 5
TokenDefaultDacl = 6
TokenSource = 7
TokenType = 8
TokenImpersonationLevel = 9
TokenStatistics = 10
TokenRestrictedSids = 11
TokenSessionId = 12
TokenGroupsAndPrivileges = 13
TokenSessionReference = 14
TokenSandBoxInert = 15
TokenAuditPolicy = 16
TokenOrigin = 17
TokenElevationType = 18
TokenLinkedToken = 19
TokenElevation = 20
TokenHasRestrictions = 21
TokenAccessInformation = 22
TokenVirtualizationAllowed = 23
TokenVirtualizationEnabled = 24
TokenIntegrityLevel = 25
TokenUIAccess = 26
TokenMandatoryPolicy = 27
TokenLogonSid = 28

# WinTrust constants
WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}"
WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2

# Version info flags
VS_FF_DEBUG = 0x1
VS_FF_PRERELEASE = 0x2
VS_FF_PATCHED = 0x4
VS_FF_PRIVATEBUILD = 0x8
VS_FF_INFOINFERRED = 0x10
VS_FF_SPECIALBUILD = 0x20

VFT_UNKNOWN = 0x0000
VFT_APP = 0x0001
VFT_DLL = 0x0002
VFT_DRV = 0x0003
VFT_FONT = 0x0004
VFT_VXD = 0x0005
VFT_STATIC_LIB = 0x0007

# Process information class
PROCESSINFOCLASS_PROCESS_BASIC_INFORMATION = 0
PROCESSINFOCLASS_PROCESS_COMMAND_LINE = 60

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

class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]

class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]

class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ExitStatus", wintypes.LONG),
        ("PebBaseAddress", ctypes.c_void_p),
        ("AffinityMask", ctypes.c_size_t),
        ("BasePriority", wintypes.LONG),
        ("UniqueProcessId", ctypes.c_void_p),
        ("InheritedFromUniqueProcessId", ctypes.c_void_p),
    ]

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]

class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Sid", ctypes.c_void_p),
        ("Attributes", wintypes.DWORD),
    ]

class TOKEN_USER(ctypes.Structure):
    _fields_ = [
        ("User", SID_AND_ATTRIBUTES),
    ]

class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.c_void_p),
    ]

class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
    ]

class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", wintypes.WORD),
        ("wReserved", wintypes.WORD),
        ("dwPageSize", wintypes.DWORD),
        ("lpMinimumApplicationAddress", ctypes.c_void_p),
        ("lpMaximumApplicationAddress", ctypes.c_void_p),
        ("dwActiveProcessorMask", ctypes.c_size_t),
        ("dwNumberOfProcessors", wintypes.DWORD),
        ("dwProcessorType", wintypes.DWORD),
        ("dwAllocationGranularity", wintypes.DWORD),
        ("wProcessorLevel", wintypes.WORD),
        ("wProcessorRevision", wintypes.WORD),
    ]

# ============================================================
# API FUNCTIONS
# ============================================================

# Kernel32
CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
CreateToolhelp32Snapshot.restype = wintypes.HANDLE

Process32FirstW = kernel32.Process32FirstW
Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
Process32FirstW.restype = wintypes.BOOL

Process32NextW = kernel32.Process32NextW
Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
Process32NextW.restype = wintypes.BOOL

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

QueryFullProcessImageNameW = kernel32.QueryFullProcessImageNameW
QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
QueryFullProcessImageNameW.restype = wintypes.BOOL

GetProcessTimes = kernel32.GetProcessTimes
GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME)]
GetProcessTimes.restype = wintypes.BOOL

GetProcessHandleCount = kernel32.GetProcessHandleCount
GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
GetProcessHandleCount.restype = wintypes.BOOL

GetSystemInfo = kernel32.GetSystemInfo
GetSystemInfo.argtypes = [ctypes.POINTER(SYSTEM_INFO)]
GetSystemInfo.restype = None

GetSystemTimes = kernel32.GetSystemTimes
GetSystemTimes.argtypes = [ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME)]
GetSystemTimes.restype = wintypes.BOOL

GetCurrentProcess = kernel32.GetCurrentProcess
GetCurrentProcess.argtypes = []
GetCurrentProcess.restype = wintypes.HANDLE

GetCurrentProcessId = kernel32.GetCurrentProcessId
GetCurrentProcessId.argtypes = []
GetCurrentProcessId.restype = wintypes.DWORD

# Version API (from version.dll)
GetFileVersionInfoSizeW = version.GetFileVersionInfoSizeW
GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
GetFileVersionInfoSizeW.restype = wintypes.DWORD

GetFileVersionInfoW = version.GetFileVersionInfoW
GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID]
GetFileVersionInfoW.restype = wintypes.BOOL

VerQueryValueW = version.VerQueryValueW
VerQueryValueW.argtypes = [wintypes.LPCVOID, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT)]
VerQueryValueW.restype = wintypes.BOOL

# PSAPI
GetProcessMemoryInfo = psapi.GetProcessMemoryInfo
GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX), wintypes.DWORD]
GetProcessMemoryInfo.restype = wintypes.BOOL

# Advapi32
OpenProcessToken = advapi32.OpenProcessToken
OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
OpenProcessToken.restype = wintypes.BOOL

GetTokenInformation = advapi32.GetTokenInformation
GetTokenInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
GetTokenInformation.restype = wintypes.BOOL

LookupAccountSidW = advapi32.LookupAccountSidW
LookupAccountSidW.argtypes = [
    wintypes.LPCWSTR,
    ctypes.c_void_p,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
]
LookupAccountSidW.restype = wintypes.BOOL

# NTDLL
NtQueryInformationProcess = ntdll.NtQueryInformationProcess
NtQueryInformationProcess.argtypes = [
    wintypes.HANDLE,
    wintypes.ULONG,
    ctypes.c_void_p,
    wintypes.ULONG,
    ctypes.POINTER(wintypes.ULONG)
]
NtQueryInformationProcess.restype = wintypes.LONG

# WinTrust
WinVerifyTrust = wintrust.WinVerifyTrust
WinVerifyTrust.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(WINTRUST_DATA)]
WinVerifyTrust.restype = wintypes.LONG

# ============================================================
# CPU USAGE TRACKING
# ============================================================

class CPUSample:
    """Stores CPU timing data for a process"""
    def __init__(self):
        self.kernel_time = 0
        self.user_time = 0
        self.total_time = 0
        self.timestamp = 0.0

_cpu_samples = {}
_last_system_cpu = None

def get_cpu_usage(pid: int, current_times: dict) -> float:
    """
    Calculate CPU usage percentage using two samples
    Returns CPU usage as percentage (0-100)
    """
    global _cpu_samples
    
    current_time = current_times['total_time']
    current_timestamp = time.perf_counter()
    
    # Get system times for accurate CPU calculation
    system_idle = FILETIME()
    system_kernel = FILETIME()
    system_user = FILETIME()
    
    if not GetSystemTimes(ctypes.byref(system_idle), ctypes.byref(system_kernel), ctypes.byref(system_user)):
        return 0.0
    
    system_total = ((system_kernel.dwHighDateTime << 32) | system_kernel.dwLowDateTime) + \
                   ((system_user.dwHighDateTime << 32) | system_user.dwLowDateTime)
    
    # Check if we have previous sample
    if pid not in _cpu_samples:
        sample = CPUSample()
        sample.kernel_time = current_times['kernel_time']
        sample.user_time = current_times['user_time']
        sample.total_time = current_time
        sample.timestamp = current_timestamp
        _cpu_samples[pid] = sample
        return 0.0
    
    prev = _cpu_samples[pid]
    
    # Calculate deltas
    delta_kernel = current_times['kernel_time'] - prev.kernel_time
    delta_user = current_times['user_time'] - prev.user_time
    delta_total = (delta_kernel + delta_user)
    
    # Time elapsed in seconds
    time_elapsed = current_timestamp - prev.timestamp
    if time_elapsed <= 0 or delta_total <= 0:
        return 0.0
    
    # CPU usage = (process_time_delta / time_elapsed) * 100
    # Convert from 100-nanosecond units to seconds
    cpu_seconds = delta_total / 10000000.0
    cpu_percent = (cpu_seconds / time_elapsed) * 100.0
    
    # Update sample
    prev.kernel_time = current_times['kernel_time']
    prev.user_time = current_times['user_time']
    prev.total_time = current_time
    prev.timestamp = current_timestamp
    
    return round(min(cpu_percent, 100.0), 1)

def reset_cpu_samples():
    """Reset all CPU samples (call between collections)"""
    global _cpu_samples
    _cpu_samples.clear()

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_process_path(pid: int) -> Optional[str]:
    """Get full executable path for a process"""
    handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        success = QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size))
        if success:
            return buffer.value
        return None
    finally:
        CloseHandle(handle)

def get_process_memory(handle: int) -> Optional[Dict[str, float]]:
    """Get memory information for a process"""
    try:
        counters = PROCESS_MEMORY_COUNTERS_EX()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
        
        if GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return {
                'working_set_mb': counters.WorkingSetSize / (1024 * 1024),
                'private_mb': counters.PrivateUsage / (1024 * 1024),
                'pagefile_mb': counters.PagefileUsage / (1024 * 1024),
                'peak_working_set_mb': counters.PeakWorkingSetSize / (1024 * 1024),
                'peak_pagefile_mb': counters.PeakPagefileUsage / (1024 * 1024),
            }
        return None
    except Exception:
        return None

def get_process_handle_count(handle: int) -> Optional[int]:
    """Get handle count for a process"""
    try:
        count = wintypes.DWORD()
        if GetProcessHandleCount(handle, ctypes.byref(count)):
            return count.value
        return None
    except Exception:
        return None

def get_process_cpu_times(handle: int) -> Optional[Dict[str, int]]:
    """
    Get CPU times for a process using GetProcessTimes
    Returns times in 100-nanosecond units
    """
    try:
        creation = FILETIME()
        exit_time = FILETIME()
        kernel = FILETIME()
        user = FILETIME()
        
        if GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_time),
                          ctypes.byref(kernel), ctypes.byref(user)):
            
            kernel_time = (kernel.dwHighDateTime << 32) | kernel.dwLowDateTime
            user_time = (user.dwHighDateTime << 32) | user.dwLowDateTime
            
            return {
                'kernel_time': kernel_time,
                'user_time': user_time,
                'total_time': kernel_time + user_time,
                'creation_time': (creation.dwHighDateTime << 32) | creation.dwLowDateTime,
            }
        return None
    except Exception:
        return None

def get_process_username(pid: int) -> Optional[str]:
    """
    Get the username that owns a process
    """
    handle = OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return None
    
    try:
        # Open process token
        token = wintypes.HANDLE()
        if not OpenProcessToken(handle, TOKEN_QUERY, ctypes.byref(token)):
            return None
        
        try:
            # Get required buffer size
            return_length = wintypes.DWORD()
            GetTokenInformation(token, TokenUser, None, 0, ctypes.byref(return_length))
            
            if return_length.value == 0:
                return None
            
            # Allocate buffer
            buffer = ctypes.create_string_buffer(return_length.value)
            
            if not GetTokenInformation(token, TokenUser, buffer, return_length, ctypes.byref(return_length)):
                return None
            
            # Parse token user
            token_user = ctypes.cast(buffer, ctypes.POINTER(TOKEN_USER)).contents
            sid = token_user.User.Sid
            
            if not sid:
                return None
            
            # Lookup account name from SID
            name_length = wintypes.DWORD(0)
            domain_length = wintypes.DWORD(0)
            sid_use = wintypes.DWORD()
            
            # Get required buffer sizes
            LookupAccountSidW(None, sid, None, ctypes.byref(name_length),
                            None, ctypes.byref(domain_length), ctypes.byref(sid_use))
            
            if name_length.value == 0:
                return None
            
            # Allocate buffers
            name_buffer = ctypes.create_unicode_buffer(name_length.value)
            domain_buffer = ctypes.create_unicode_buffer(domain_length.value)
            
            if LookupAccountSidW(None, sid, name_buffer, ctypes.byref(name_length),
                                domain_buffer, ctypes.byref(domain_length), ctypes.byref(sid_use)):
                if domain_buffer.value:
                    return f"{domain_buffer.value}\\{name_buffer.value}"
                return name_buffer.value
            
            return None
            
        finally:
            CloseHandle(token)
            
    except Exception:
        return None
    finally:
        CloseHandle(handle)

def get_file_version_info(file_path: str) -> Optional[Dict[str, str]]:
    """
    Get version information from a file using Windows APIs
    Returns dict with company, version, description, etc.
    """
    if not file_path:
        return None
    
    try:
        # Get size of version info
        size = GetFileVersionInfoSizeW(file_path, None)
        if size == 0:
            return None
        
        # Allocate buffer
        buffer = ctypes.create_string_buffer(size)
        
        # Get version info
        if not GetFileVersionInfoW(file_path, 0, size, buffer):
            return None
        
        result = {}
        
        # Query specific fields
        fields = {
            'CompanyName': 'company',
            'FileVersion': 'file_version',
            'FileDescription': 'file_description',
            'ProductName': 'product_name',
            'OriginalFilename': 'original_filename',
            'InternalName': 'internal_name',
            'LegalCopyright': 'copyright',
            'LegalTrademarks': 'trademarks',
            'ProductVersion': 'product_version',
        }
        
        for field, key in fields.items():
            value = _get_version_string(buffer, field)
            if value:
                result[key] = value
        
        return result
        
    except Exception:
        return None

def _get_version_string(buffer, field: str) -> Optional[str]:
    """Query a specific field from version info"""
    try:
        # Try common language codes
        language_codes = [
            "040904B0",  # English US, Unicode
            "040904E4",  # English US, ANSI
            "04090904",  # English US, UTF-16
            "041904B0",  # English UK, Unicode
        ]
        
        for lang in language_codes:
            sub_block = f"\\StringFileInfo\\{lang}\\{field}"
            value_ptr = ctypes.c_void_p()
            value_size = wintypes.UINT()
            
            if VerQueryValueW(buffer, sub_block, ctypes.byref(value_ptr), ctypes.byref(value_size)):
                if value_ptr.value and value_size.value > 0:
                    try:
                        return ctypes.wstring_at(value_ptr, value_size.value - 1)
                    except:
                        continue
        
        return None
        
    except Exception:
        return None

def check_digital_signature(file_path: str) -> bool:
    """
    Check if a file has a valid digital signature using WinTrust API
    """
    if not file_path:
        return False
    
    try:
        # Create file info structure
        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = file_path
        file_info.hFile = None
        file_info.pgKnownSubject = None
        
        # Create WinTrust data structure
        wintrust_data = WINTRUST_DATA()
        wintrust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        wintrust_data.dwUIChoice = WTD_UI_NONE
        wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE
        wintrust_data.dwUnionChoice = WTD_CHOICE_FILE
        wintrust_data.pFile = ctypes.pointer(file_info)
        wintrust_data.dwStateAction = WTD_STATEACTION_VERIFY
        
        # Verify signature
        guid = ctypes.create_unicode_buffer(WINTRUST_ACTION_GENERIC_VERIFY_V2)
        result = WinVerifyTrust(0, ctypes.byref(guid), ctypes.byref(wintrust_data))
        
        # Close state action
        wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE
        WinVerifyTrust(0, ctypes.byref(guid), ctypes.byref(wintrust_data))
        
        return result == 0  # 0 = trusted
        
    except Exception:
        return False

def get_signer_info(file_path: str) -> Optional[str]:
    """
    Get signer name from digital signature
    This is a simplified implementation
    For full implementation, use CryptQueryObject
    """
    # Simplified - check if signed and return placeholder
    if check_digital_signature(file_path):
        # Try to extract signer from file properties
        try:
            # Use version info to check if it's Microsoft
            version_info = get_file_version_info(file_path)
            if version_info and version_info.get('company'):
                company = version_info['company']
                if 'Microsoft' in company:
                    return 'Microsoft Corporation'
                return company
        except:
            pass
        return 'Verified (Unknown Signer)'
    return None

def get_process_command_line(pid: int) -> Optional[str]:
    """
    Get command line for a process using NtQueryInformationProcess
    This is a more complex operation requiring PEB reading
    """
    try:
        # Using WMI is more reliable for command line
        return _get_process_command_line_wmi(pid)
    except:
        return None

def _get_process_command_line_wmi(pid: int) -> Optional[str]:
    """
    Get command line using WMI (requires pywin32)
    """
    try:
        import win32com.client
        import pythoncom
        
        pythoncom.CoInitialize()
        wmi = win32com.client.GetObject("winmgmts:")
        query = f"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}"
        processes = wmi.ExecQuery(query)
        for proc in processes:
            return proc.CommandLine
        return None
    except ImportError:
        return None
    except Exception:
        return None
    finally:
        try:
            pythoncom.CoUninitialize()
        except:
            pass

def get_process_creation_time(handle: int) -> Optional[str]:
    """
    Get process creation time as ISO format string
    """
    try:
        creation = FILETIME()
        exit_time = FILETIME()
        kernel = FILETIME()
        user = FILETIME()
        
        if GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_time),
                          ctypes.byref(kernel), ctypes.byref(user)):
            
            # Convert FILETIME to datetime
            # FILETIME is 100-nanosecond intervals since 1601-01-01
            timestamp = ((creation.dwHighDateTime << 32) | creation.dwLowDateTime)
            
            # Convert to seconds since 1601
            seconds = timestamp / 10000000.0
            
            # Offset to Unix epoch (1601 to 1970 is 11644473600 seconds)
            unix_timestamp = seconds - 11644473600.0
            
            from datetime import datetime
            dt = datetime.fromtimestamp(unix_timestamp)
            return dt.isoformat()
            
        return None
    except Exception:
        return None

def get_system_info() -> Dict[str, Any]:
    """Get system information"""
    try:
        si = SYSTEM_INFO()
        GetSystemInfo(ctypes.byref(si))
        
        # Get memory info
        memory = ctypes.c_ulonglong()
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory))
        
        return {
            'processor_count': si.dwNumberOfProcessors,
            'processor_architecture': si.wProcessorArchitecture,
            'page_size': si.dwPageSize,
            'processor_level': si.wProcessorLevel,
        }
    except Exception:
        return {}

# ============================================================
# TEST FUNCTIONS
# ============================================================

def test_winapi():
    """Test all API functions"""
    print("Testing Windows API wrappers...")
    
    # Test process enumeration
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot and snapshot != INVALID_HANDLE_VALUE:
        print("✓ CreateToolhelp32Snapshot works")
        
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        
        if Process32FirstW(snapshot, ctypes.byref(entry)):
            print("✓ Process32FirstW works")
            
            count = 0
            while count < 5:
                pid = entry.th32ProcessID
                name = entry.szExeFile
                print(f"  PID: {pid}, Name: {name}")
                
                # Test get_process_path
                path = get_process_path(pid)
                if path:
                    print(f"    Path: {path}")
                
                # Test get_process_username
                username = get_process_username(pid)
                if username:
                    print(f"    User: {username}")
                
                # Test get_file_version_info (if path exists)
                if path:
                    version = get_file_version_info(path)
                    if version:
                        print(f"    Version: {version.get('file_version', 'N/A')}")
                        print(f"    Company: {version.get('company', 'N/A')}")
                    
                    # Test signature check
                    signed = check_digital_signature(path)
                    print(f"    Signed: {signed}")
                
                count += 1
                if not Process32NextW(snapshot, ctypes.byref(entry)):
                    break
        
        CloseHandle(snapshot)
    else:
        print("✗ Failed to create snapshot")
    
    print("\nTest complete!")

if __name__ == "__main__":
    test_winapi()