# main.py
"""
SysPilot-Ai - Main Entry Point
"""

import sys
import os

# Add the process_explorer folder to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'process_explorer'))

import ctypes
from process import Process
from winapi import *
from explorer import generate_text_report_file, generate_json_report


def collect_processes() -> list[Process]:
    """
    Collect all running processes with complete data
    """
    processes = []
    
    print("\n" + "="*70)
    print("  SysPilot-Ai - Process Data Collection")
    print("="*70)
    
    print("\n[1/3] Taking process snapshot...")
    
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        
        success = Process32FirstW(snapshot, ctypes.byref(entry))
        count = 0
        
        while success:
            pid = entry.th32ProcessID
            
            # Create process with basic info
            proc = Process(
                pid=pid,
                name=entry.szExeFile,
                parent_pid=entry.th32ParentProcessID,
                path=get_process_path(pid),
                threads=entry.cntThreads,
            )
            
            # Enrich with memory info
            handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if handle:
                try:
                    # Memory
                    memory = get_process_memory(handle)
                    if memory:
                        proc.memory_private_mb = round(memory['private_mb'], 1)
                        proc.memory_working_set_mb = round(memory['working_set_mb'], 1)
                    
                    # Handles
                    handles = get_process_handle_count(handle)
                    if handles is not None:
                        proc.handles = handles
                        
                finally:
                    CloseHandle(handle)
            
            # Basic risk analysis
            if proc.memory_private_mb > 1000:
                proc.risk_indicators.append('high_memory')
            if proc.threads > 100:
                proc.risk_indicators.append('many_threads')
            if proc.handles and proc.handles > 500:
                proc.risk_indicators.append('many_handles')
            
            processes.append(proc)
            count += 1
            
            if count % 50 == 0:
                print(f"  Processed {count} processes...")
            
            success = Process32NextW(snapshot, ctypes.byref(entry))
            
        print(f"\n  ✓ Collected {count} processes")
        
    finally:
        CloseHandle(snapshot)
    
    return processes


def main():
    """Main entry point"""
    # Collect processes
    processes = collect_processes()
    
    print("\n[2/3] Generating reports...")
    
    # Generate reports
    txt_file = generate_text_report_file(processes)
    json_file = generate_json_report(processes)
    
    print("\n[3/3] ✅ Reports generated:")
    print(f"  📄 Text Report:  {txt_file}")
    print(f"  📊 JSON Report:  {json_file}")
    
    # Statistics
    risky = [p for p in processes if p.risk_indicators]
    unsigned = [p for p in processes if p.path and not p.signed]
    
    print(f"\n  📊 Process Statistics:")
    print(f"     Total processes:   {len(processes)}")
    print(f"     ⚠️  Risky:           {len(risky)}")
    print(f"     📄 Unsigned:        {len(unsigned)}")
    print(f"     💾 High memory:     {len([p for p in processes if p.memory_private_mb > 1000])}")
    
    print("\n" + "="*70)
    print("  ✅ Data collection complete!")
    print("  📖 Reports saved to 'reports/' directory")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()