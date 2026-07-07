# main.py
"""
SysPilot-Ai - Main Entry Point
AI-powered Windows system inspection tool
"""

import sys
import os
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'process_explorer'))

import ctypes
from process import Process
from winapi import *
from explorer import generate_text_report_file, generate_json_report

# Import collectors
from autoruns_collector import AutorunsCollector, generate_autorun_report, save_autorun_json
from network_collector import NetworkCollector, generate_network_report, save_network_json


def collect_processes() -> list[Process]:
    """Collect all running processes"""
    processes = []
    
    print("\n" + "=" * 70)
    print("  SysPilot-Ai - Process Data Collection")
    print("=" * 70)
    
    print("\n[1/4] Taking process snapshot...")
    
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
            
            if pid == 0:
                success = Process32NextW(snapshot, ctypes.byref(entry))
                continue
            
            path = get_process_path(pid)
            
            proc = Process(
                pid=pid,
                name=entry.szExeFile,
                parent_pid=entry.th32ParentProcessID,
                path=path,
                threads=entry.cntThreads,
            )
            
            if path:
                handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
                if handle:
                    try:
                        memory = get_process_memory(handle)
                        if memory:
                            proc.memory_private_mb = round(memory['private_mb'], 1)
                            proc.memory_working_set_mb = round(memory['working_set_mb'], 1)
                        
                        handles = get_process_handle_count(handle)
                        if handles is not None:
                            proc.handles = handles
                        
                        username = get_process_username(pid)
                        if username:
                            proc.username = username
                    finally:
                        CloseHandle(handle)
                
                version_info = get_file_version_info(path)
                if version_info:
                    proc.company = version_info.get('company')
                    proc.file_version = version_info.get('file_version')
                    proc.file_description = version_info.get('file_description')
                    proc.product_name = version_info.get('product_name')
                
                try:
                    proc.signed = check_digital_signature(path)
                except Exception:
                    proc.signed = False
            
            # Risk analysis
            if proc.memory_private_mb > 1000:
                proc.risk_indicators.append('high_memory')
            if proc.threads > 100:
                proc.risk_indicators.append('many_threads')
            if proc.handles and proc.handles > 1000:
                proc.risk_indicators.append('many_handles')
            if proc.path and not proc.signed:
                proc.risk_indicators.append('unsigned')
            
            processes.append(proc)
            count += 1
            
            if count % 50 == 0:
                print(f"  Processed {count} processes...")
            
            success = Process32NextW(snapshot, ctypes.byref(entry))
        
        print(f"\n  ✓ Collected {count} processes")
        
    finally:
        CloseHandle(snapshot)
    
    return processes


def calculate_cpu_usage(processes: list[Process]) -> None:
    """Calculate CPU usage for all processes"""
    print("\n[2/4] Calculating CPU usage (waiting 1 second)...")
    time.sleep(1)
    
    count = 0
    for proc in processes:
        if proc.pid == 0:
            continue
            
        handle = OpenProcess(PROCESS_QUERY_INFORMATION, False, proc.pid)
        if handle:
            try:
                cpu_times = get_process_cpu_times(handle)
                if cpu_times:
                    if proc.cpu_total_time > 0:
                        delta = cpu_times['total_time'] - proc.cpu_total_time
                        if delta > 0:
                            proc.cpu_percent = round(min((delta / 10000000.0) * 100, 100.0), 1)
                    
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


def print_statistics(processes: list[Process]) -> None:
    """Print process statistics"""
    total = len(processes)
    risky = [p for p in processes if p.risk_indicators]
    unsigned = [p for p in processes if p.path and not p.signed]
    signed = [p for p in processes if p.path and p.signed]
    
    print(f"\n  📊 Process Statistics:")
    print(f"     Total processes:     {total}")
    print(f"     ⚠️  Risky:            {len(risky)}")
    print(f"     ✅ Signed:           {len(signed)}")
    print(f"     ❌ Unsigned:         {len(unsigned)}")


def main():
    """Main entry point"""
    print(r"""
    ╔═══════════════════════════════════════════════════════════╗
    ║    ███████╗██╗   ██╗███████╗██████╗  ██████╗ ██╗  ██╗   ║
    ║    ██╔════╝╚██╗ ██╔╝██╔════╝██╔══██╗██╔═══██╗██║ ██╔╝   ║
    ║    ███████╗ ╚████╔╝ █████╗  ██████╔╝██║   ██║█████╔╝    ║
    ║    ╚════██║  ╚██╔╝  ██╔══╝  ██╔═══╝ ██║   ██║██╔═██╗    ║
    ║    ███████║   ██║   ███████╗██║     ╚██████╔╝██║  ██╗    ║
    ║    ╚══════╝   ╚═╝   ╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝    ║
    ║                                                          ║
    ║         AI-Powered Windows System Inspection Tool        ║
    ║                                                          ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    start_time = time.time()
    
    try:
        reports_dir = Path('reports')
        reports_dir.mkdir(exist_ok=True)
        
        # ============================================================
        # STEP 1: Collect processes
        # ============================================================
        processes = collect_processes()
        
        if not processes:
            print("\n❌ No processes collected! Exiting.")
            return
        
        # ============================================================
        # STEP 2: Calculate CPU usage
        # ============================================================
        calculate_cpu_usage(processes)
        
        # ============================================================
        # STEP 3: Generate process reports
        # ============================================================
        print("\n[3/6] Generating process reports...")
        
        txt_file = generate_text_report_file(processes)
        json_file = generate_json_report(processes)
        print(f"  ✅ Process reports generated")
        
        # ============================================================
        # STEP 4: Collect autoruns
        # ============================================================
        print("\n[4/6] Collecting autoruns...")
        
        autorun_entries = []
        try:
            collector = AutorunsCollector()
            autorun_entries = collector.collect()
            
            if autorun_entries:
                autorun_report = generate_autorun_report(autorun_entries)
                autorun_txt = reports_dir / f"autoruns_{time.strftime('%Y%m%d_%H%M%S')}.txt"
                with open(autorun_txt, 'w', encoding='utf-8') as f:
                    f.write(autorun_report)
                
                autorun_json = save_autorun_json(autorun_entries)
                print(f"  ✅ Autoruns: {len(autorun_entries)} entries found")
            else:
                print(f"  ⚠️ No autorun entries found")
            
        except FileNotFoundError as e:
            print(f"  ⚠️ {e}")
            print("  Skipping autoruns collection...")
        except Exception as e:
            print(f"  ⚠️ Error collecting autoruns: {e}")
            print("  Skipping autoruns collection...")
        
        # ============================================================
        # STEP 5: Collect network connections
        # ============================================================
        print("\n[5/6] Collecting network connections...")
        
        network_entries = []
        try:
            net_collector = NetworkCollector()
            network_entries = net_collector.collect()
            
            if network_entries:
                network_report = generate_network_report(network_entries)
                network_txt = reports_dir / f"network_{time.strftime('%Y%m%d_%H%M%S')}.txt"
                with open(network_txt, 'w', encoding='utf-8') as f:
                    f.write(network_report)
                
                network_json = save_network_json(network_entries)
                print(f"  ✅ Network: {len(network_entries)} connections found")
            else:
                print(f"  ⚠️ No network connections found")
            
        except FileNotFoundError as e:
            print(f"  ⚠️ {e}")
            print("  Skipping network collection...")
        except Exception as e:
            print(f"  ⚠️ Error collecting network: {e}")
            print("  Skipping network collection...")
        
        # ============================================================
        # STEP 6: Print statistics and summary
        # ============================================================
        print_statistics(processes)
        
        elapsed = time.time() - start_time
        
        print(f"\n  📁 Reports saved to: {reports_dir}/")
        print(f"     📄 Process Text:   {txt_file.name}")
        print(f"     📊 Process JSON:   {json_file.name}")
        
        if 'autorun_txt' in locals() and autorun_entries:
            print(f"     📄 Autorun Text:   {autorun_txt.name}")
        if 'autorun_json' in locals() and autorun_entries:
            print(f"     📊 Autorun JSON:   {autorun_json.name}")
        if 'network_txt' in locals() and network_entries:
            print(f"     📄 Network Text:   {network_txt.name}")
        if 'network_json' in locals() and network_entries:
            print(f"     📊 Network JSON:   {network_json.name}")
        
        # Summary
        print(f"\n  📊 Collection Summary:")
        print(f"     Processes:  {len(processes)}")
        print(f"     Autoruns:   {len(autorun_entries) if autorun_entries else 0}")
        print(f"     Network:    {len(network_entries) if network_entries else 0}")
        
        print(f"\n  ⏱️  Completed in {elapsed:.1f} seconds")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    print("\n" + "=" * 70)
    print("  ✅ SysPilot-Ai collection complete!")
    print("  📖 Reports ready for AI analysis")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()