# main.py
"""
SysPilot-Ai - Main Entry Point
AI-powered Windows system inspection tool
"""

import sys
import os
import time
import json
from pathlib import Path
from typing import List, Optional

# Add the process_explorer folder to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'process_explorer'))

import ctypes
from process import Process
from winapi import *
from explorer import generate_text_report_file, generate_json_report


# ============================================================
# COLLECTION FUNCTIONS
# ============================================================

def collect_processes() -> List[Process]:
    """
    Collect all running processes with complete data
    
    Returns:
        List of Process objects with full information
    """
    processes = []
    
    print("\n" + "="*70)
    print("  SysPilot-Ai - Process Data Collection")
    print("="*70)
    
    print("\n[1/5] Taking process snapshot...")
    
    # Take snapshot of all processes
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        
        success = Process32FirstW(snapshot, ctypes.byref(entry))
        count = 0
        
        print("[2/5] Enumerating processes...")
        
        while success:
            pid = entry.th32ProcessID
            name = entry.szExeFile
            
            # Skip the idle process (PID 0) - it causes issues
            if pid == 0:
                success = Process32NextW(snapshot, ctypes.byref(entry))
                continue
            
            # Get executable path
            path = get_process_path(pid)
            
            # Create process with basic info
            proc = Process(
                pid=pid,
                name=name,
                parent_pid=entry.th32ParentProcessID,
                path=path,
                threads=entry.cntThreads,
            )
            
            # Enrich with detailed info if we can open the process
            if path:
                handle = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 
                    False, 
                    pid
                )
                if handle:
                    try:
                        # Memory information
                        memory = get_process_memory(handle)
                        if memory:
                            proc.memory_private_mb = round(memory['private_mb'], 1)
                            proc.memory_working_set_mb = round(memory['working_set_mb'], 1)
                            proc.memory_pagefile_mb = round(memory['pagefile_mb'], 1)
                            proc.memory_peak_working_set_mb = round(memory.get('peak_working_set_mb', 0), 1)
                            proc.memory_peak_pagefile_mb = round(memory.get('peak_pagefile_mb', 0), 1)
                        
                        # Handle count
                        handles = get_process_handle_count(handle)
                        if handles is not None:
                            proc.handles = handles
                        
                        # CPU times (first sample for CPU calculation)
                        cpu_times = get_process_cpu_times(handle)
                        if cpu_times:
                            proc.cpu_kernel_time = cpu_times['kernel_time']
                            proc.cpu_user_time = cpu_times['user_time']
                            proc.cpu_total_time = cpu_times['total_time']
                            
                            # Create time
                            create_time = get_process_creation_time(handle)
                            if create_time:
                                proc.create_time = create_time
                        
                        # Username
                        username = get_process_username(pid)
                        if username:
                            proc.username = username
                        
                    except Exception as e:
                        # Silently continue if a specific process can't be read
                        pass
                    finally:
                        CloseHandle(handle)
                
                # File version info (doesn't need process handle)
                version_info = get_file_version_info(path)
                if version_info:
                    proc.company = version_info.get('company')
                    proc.file_version = version_info.get('file_version')
                    proc.file_description = version_info.get('file_description')
                    proc.product_name = version_info.get('product_name')
                    proc.product_version = version_info.get('product_version')
                    proc.original_filename = version_info.get('original_filename')
                    proc.internal_name = version_info.get('internal_name')
                    proc.copyright = version_info.get('copyright')
                    proc.trademarks = version_info.get('trademarks')
                
                # Digital signature
                try:
                    proc.signed = check_digital_signature(path)
                    if proc.signed:
                        proc.signer = get_signer_info(path)
                except Exception:
                    proc.signed = False
            
            # Risk analysis
            proc.risk_indicators = analyze_risks(proc)
            
            processes.append(proc)
            count += 1
            
            if count % 50 == 0:
                print(f"  Processed {count} processes...")
            
            success = Process32NextW(snapshot, ctypes.byref(entry))
        
        print(f"\n  ✓ Collected {count} processes")
        
    finally:
        CloseHandle(snapshot)
    
    return processes


def analyze_risks(proc: Process) -> List[str]:
    """
    Analyze process for risk indicators
    
    Args:
        proc: Process to analyze
        
    Returns:
        List of risk indicator strings
    """
    risks = []
    
    # ============================================================
    # Memory Risks
    # ============================================================
    if proc.memory_private_mb > 1000:
        risks.append('high_memory')
    if proc.memory_private_mb > 5000:
        risks.append('extremely_high_memory')
    
    # ============================================================
    # CPU Risks
    # ============================================================
    if proc.cpu_percent > 50:
        risks.append('high_cpu')
    if proc.cpu_percent > 80:
        risks.append('critical_cpu')
    
    # ============================================================
    # Thread Risks
    # ============================================================
    if proc.threads > 100:
        risks.append('many_threads')
    if proc.threads > 200:
        risks.append('excessive_threads')
    
    # ============================================================
    # Handle Risks
    # ============================================================
    if proc.handles and proc.handles > 1000:
        risks.append('many_handles')
    if proc.handles and proc.handles > 2000:
        risks.append('excessive_handles')
    
    # ============================================================
    # Signature Risks
    # ============================================================
    if proc.path and not proc.signed:
        risks.append('unsigned')
        
        # Unsigned non-system files are more suspicious
        if proc.path:
            path_lower = proc.path.lower()
            if '\\system32\\' not in path_lower and '\\windows\\' not in path_lower:
                risks.append('unsigned_non_system')
    
    # ============================================================
    # Location Risks
    # ============================================================
    if proc.path:
        path_lower = proc.path.lower()
        
        # Running from temp directories
        if '\\temp\\' in path_lower or '\\tmp\\' in path_lower:
            risks.append('running_from_temp')
        if '\\appdata\\local\\temp\\' in path_lower:
            risks.append('running_from_appdata_temp')
        if '\\windows\\temp\\' in path_lower:
            risks.append('running_from_windows_temp')
        
        # Running from ProgramData
        if '\\programdata\\' in path_lower:
            risks.append('running_from_programdata')
        
        # Running from Downloads
        if '\\downloads\\' in path_lower:
            risks.append('running_from_downloads')
    
    # ============================================================
    # Process Name Risks
    # ============================================================
    name_lower = proc.name.lower()
    
    # svchost.exe not in System32
    if name_lower == 'svchost.exe' and proc.path:
        if '\\system32\\' not in proc.path.lower():
            risks.append('svchost_not_in_system32')
    
    # Suspicious names (common malware patterns)
    suspicious_names = [
        'svchost.exe', 'explorer.exe', 'services.exe', 'lsass.exe',
        'winlogon.exe', 'csrss.exe', 'smss.exe', 'wininit.exe'
    ]
    if name_lower in suspicious_names and proc.path:
        if '\\system32\\' not in proc.path.lower():
            risks.append('suspicious_process_name')
    
    # ============================================================
    # User Account Risks
    # ============================================================
    if proc.username:
        if proc.username in ['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE']:
            # System processes should generally be signed
            if proc.path and not proc.signed:
                risks.append('system_process_unsigned')
        elif proc.username.endswith('\\Administrator') or proc.username == 'Administrator':
            risks.append('running_as_admin')
        elif 'admin' in proc.username.lower():
            risks.append('running_as_admin')
    
    # ============================================================
    # OEM/Lenovo Detection
    # ============================================================
    if proc.company and 'Lenovo' in proc.company:
        risks.append('lenovo_process')
    if proc.path and 'lenovo' in proc.path.lower():
        risks.append('lenovo_process')
    
    # ============================================================
    # Browser Process Detection
    # ============================================================
    browser_names = ['chrome.exe', 'firefox.exe', 'msedge.exe', 'brave.exe', 'opera.exe']
    if proc.name.lower() in browser_names:
        if proc.memory_private_mb > 500:
            risks.append('browser_high_memory')
        if proc.threads > 80:
            risks.append('browser_many_threads')
    
    return risks


def calculate_cpu_usage(processes: List[Process]) -> None:
    """
    Calculate CPU usage for all processes (requires second sample)
    
    Args:
        processes: List of processes to update
    """
    print("\n[3/5] Calculating CPU usage (waiting 1 second)...")
    time.sleep(1)  # Wait 1 second for delta
    
    count = 0
    for proc in processes:
        if proc.pid == 0:
            continue
            
        handle = OpenProcess(PROCESS_QUERY_INFORMATION, False, proc.pid)
        if handle:
            try:
                cpu_times = get_process_cpu_times(handle)
                if cpu_times:
                    # Store current times
                    current_times = {
                        'kernel_time': cpu_times['kernel_time'],
                        'user_time': cpu_times['user_time'],
                        'total_time': cpu_times['total_time'],
                    }
                    
                    # Calculate CPU percentage
                    # We need the previous sample from first collection
                    # Since we have it stored in the process object
                    # For now, use the stored times
                    if proc.cpu_total_time > 0:
                        delta = cpu_times['total_time'] - proc.cpu_total_time
                        if delta > 0:
                            # Convert to percentage (approximate)
                            proc.cpu_percent = round(min((delta / 10000000.0) * 100, 100.0), 1)
                    
                    # Update stored times
                    proc.cpu_kernel_time = cpu_times['kernel_time']
                    proc.cpu_user_time = cpu_times['user_time']
                    proc.cpu_total_time = cpu_times['total_time']
                    
                    count += 1
            except Exception:
                pass
            finally:
                CloseHandle(handle)
        
        if count % 50 == 0:
            print(f"  Calculated CPU for {count} processes...")
    
    print(f"  ✓ CPU usage calculated for {count} processes")


def print_statistics(processes: List[Process]) -> None:
    """
    Print process statistics summary
    
    Args:
        processes: List of processes
    """
    total = len(processes)
    risky = [p for p in processes if p.risk_indicators]
    unsigned = [p for p in processes if p.path and not p.signed]
    signed = [p for p in processes if p.path and p.signed]
    high_memory = [p for p in processes if p.memory_private_mb > 1000]
    high_cpu = [p for p in processes if p.cpu_percent > 50]
    
    # Count by company
    company_counts = {}
    for proc in processes:
        if proc.company:
            company = proc.company
            company_counts[company] = company_counts.get(company, 0) + 1
    
    # Top companies
    top_companies = sorted(company_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    
    print(f"\n  📊 Process Statistics:")
    print(f"     Total processes:     {total}")
    print(f"     ⚠️  Risky:            {len(risky)}")
    print(f"     ✅ Signed:           {len(signed)}")
    print(f"     ❌ Unsigned:         {len(unsigned)}")
    print(f"     💾 High memory:      {len(high_memory)}")
    print(f"     🔥 High CPU:         {len(high_cpu)}")
    
    if top_companies:
        print(f"\n  🏢 Top Companies:")
        for company, count in top_companies:
            print(f"     - {company}: {count} processes")
    
    # Show top risky processes
    if risky:
        print(f"\n  ⚠️  Top Risky Processes:")
        risky_sorted = sorted(risky, key=lambda p: len(p.risk_indicators), reverse=True)
        for proc in risky_sorted[:5]:
            risks = ', '.join(proc.risk_indicators[:3])
            if len(proc.risk_indicators) > 3:
                risks += f" (+{len(proc.risk_indicators)-3} more)"
            print(f"     - {proc.name} (PID: {proc.pid}): {risks}")
    
    # Show unsigned system processes
    unsigned_system = [p for p in processes if p.username and p.username in ['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'] and p.path and not p.signed]
    if unsigned_system:
        print(f"\n  🔓 Unsigned System Processes:")
        for proc in unsigned_system[:5]:
            print(f"     - {proc.name} (PID: {proc.pid}): {proc.path}")


# ============================================================
# MAIN ENTRY POINT
# ============================================================

def main():
    """Main entry point for SysPilot-Ai"""
    
    print(r"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║    ███████╗██╗   ██╗███████╗██████╗  ██████╗ ██╗  ██╗       ║
    ║    ██╔════╝╚██╗ ██╔╝██╔════╝██╔══██╗██╔═══██╗██║ ██╔╝       ║
    ║    ███████╗ ╚████╔╝ █████╗  ██████╔╝██║   ██║█████╔╝        ║
    ║    ╚════██║  ╚██╔╝  ██╔══╝  ██╔═══╝ ██║   ██║██╔═██╗        ║
    ║    ███████║   ██║   ███████╗██║     ╚██████╔╝██║  ██╗       ║
    ║    ╚══════╝   ╚═╝   ╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝       ║
    ║                                                               ║
    ║         AI-Powered Windows System Inspection Tool             ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    start_time = time.time()
    
    try:
        # Step 1: Collect processes
        processes = collect_processes()
        
        if not processes:
            print("\n❌ No processes collected! Exiting.")
            return
        
        # Step 2: Calculate CPU usage
        calculate_cpu_usage(processes)
        
        # Step 3: Re-analyze risks with CPU data
        print("\n[4/5] Finalizing risk analysis...")
        for proc in processes:
            # Add CPU-based risks
            if proc.cpu_percent > 50:
                if 'high_cpu' not in proc.risk_indicators:
                    proc.risk_indicators.append('high_cpu')
            if proc.cpu_percent > 80:
                if 'critical_cpu' not in proc.risk_indicators:
                    proc.risk_indicators.append('critical_cpu')
        
        # Step 4: Generate reports
        print("\n[5/5] Generating reports...")
        
        # Create reports directory
        reports_dir = Path('reports')
        reports_dir.mkdir(exist_ok=True)
        
        # Generate text report
        txt_file = generate_text_report_file(processes)
        
        # Generate JSON report
        json_file = generate_json_report(processes)
        
        # Generate summary JSON (compact for AI)
        summary_file = reports_dir / f"summary_{time.strftime('%Y%m%d_%H%M%S')}.json"
        summary_data = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_processes': len(processes),
            'risky_processes': len([p for p in processes if p.risk_indicators]),
            'unsigned_processes': len([p for p in processes if p.path and not p.signed]),
            'high_memory_processes': len([p for p in processes if p.memory_private_mb > 1000]),
            'top_risks': [],
        }
        
        # Get top risks
        risk_counts = {}
        for proc in processes:
            for risk in proc.risk_indicators:
                risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        summary_data['top_risks'] = sorted(
            [{'risk': k, 'count': v} for k, v in risk_counts.items()],
            key=lambda x: x['count'],
            reverse=True
        )[:10]
        
        with open(summary_file, 'w') as f:
            json.dump(summary_data, f, indent=2)
        
        # Print statistics
        print_statistics(processes)
        
        elapsed = time.time() - start_time
        
        print(f"\n  📁 Reports saved to: {reports_dir}/")
        print(f"     📄 Text Report:  {txt_file.name}")
        print(f"     📊 JSON Report:  {json_file.name}")
        print(f"     📋 Summary JSON: {summary_file.name}")
        
        print(f"\n  ⏱️  Collection completed in {elapsed:.1f} seconds")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    print("\n" + "="*70)
    print("  ✅ SysPilot-Ai collection complete!")
    print("  📖 Reports ready for AI analysis")
    print("="*70 + "\n")


# ============================================================
# RUNNER
# ============================================================

if __name__ == "__main__":
    main()