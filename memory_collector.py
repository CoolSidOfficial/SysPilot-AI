# memory_collector.py
"""
Memory Collector for SysPilot-Ai
Uses psutil + Windows Performance Counters for memory analysis
"""

import psutil
import os
import subprocess
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict, field
import json


@dataclass
class MemoryProcess:
    """Memory information for a single process"""
    pid: int
    name: str
    private_mb: float
    working_set_mb: float
    shared_mb: float
    peak_working_set_mb: float
    pagefile_mb: float
    peak_pagefile_mb: float
    memory_percent: float
    risk_indicators: List[str] = field(default_factory=list)
    
    def to_dict(self):
        return asdict(self)


@dataclass
class SystemMemory:
    """System-wide memory information"""
    total_mb: float
    available_mb: float
    used_mb: float
    percent_used: float
    cached_mb: float
    paged_pool_mb: float
    non_paged_pool_mb: float
    commit_total_mb: float
    commit_limit_mb: float
    commit_percent: float
    page_faults_per_sec: int
    hard_faults_per_sec: int


class MemoryCollector:
    """Collects detailed memory information"""
    
    def __init__(self):
        self.processes: List[MemoryProcess] = []
        self.system: Optional[SystemMemory] = None
        
    def collect(self) -> Dict[str, Any]:
        """
        Collect all memory information
        
        Returns:
            Dictionary with system memory and process memory details
        """
        print("\n" + "=" * 70)
        print("  SysPilot-Ai - Memory Data Collection")
        print("=" * 70)
        
        print("\n[1/3] Collecting system memory information...")
        self.system = self._collect_system_memory()
        
        print("\n[2/3] Collecting process memory information...")
        self.processes = self._collect_process_memory()
        
        print("\n[3/3] Analyzing memory usage...")
        self._analyze_risks()
        
        # Generate report
        report = self._generate_report()
        self._save_report(report)
        
        return {
            'system': self.system,
            'processes': self.processes,
            'top_consumers': self._get_top_consumers(10)
        }
    
    def _collect_system_memory(self) -> SystemMemory:
        """Collect system-wide memory information"""
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        # Try to get page faults using typeperf
        page_faults = 0
        try:
            result = subprocess.run(
                ['typeperf', '"\\Memory\\Page Faults/sec"', '-sc', '1'],
                capture_output=True,
                text=True,
                shell=False,
                timeout=10
            )
            # Parse output
            lines = result.stdout.strip().splitlines()
            for line in lines:
                if '\\Memory\\Page Faults/sec' in line:
                    parts = line.split(',')
                    if len(parts) >= 2:
                        try:
                            value = parts[1].strip('"')
                            if value and value != ' ':
                                page_faults = int(float(value))
                        except:
                            pass
        except:
            pass
        
        return SystemMemory(
            total_mb=round(mem.total / (1024 * 1024), 1),
            available_mb=round(mem.available / (1024 * 1024), 1),
            used_mb=round(mem.used / (1024 * 1024), 1),
            percent_used=round(mem.percent, 1),
            cached_mb=round(mem.cached / (1024 * 1024), 1) if hasattr(mem, 'cached') else 0,
            paged_pool_mb=round(mem.paged / (1024 * 1024), 1) if hasattr(mem, 'paged') else 0,
            non_paged_pool_mb=round(mem.nonpaged / (1024 * 1024), 1) if hasattr(mem, 'nonpaged') else 0,
            commit_total_mb=round(swap.used / (1024 * 1024), 1),
            commit_limit_mb=round(swap.total / (1024 * 1024), 1),
            commit_percent=round(swap.percent, 1),
            page_faults_per_sec=page_faults,
            hard_faults_per_sec=0
        )
    
    def _collect_process_memory(self) -> List[MemoryProcess]:
        """Collect memory information for all processes"""
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'memory_percent']):
            try:
                info = proc.info
                mem = info.get('memory_info')
                
                if mem:
                    proc_mem = MemoryProcess(
                        pid=info['pid'],
                        name=info['name'] or "Unknown",
                        private_mb=round(mem.private / (1024 * 1024), 1) if hasattr(mem, 'private') else 0,
                        working_set_mb=round(mem.rss / (1024 * 1024), 1),
                        shared_mb=round(mem.shared / (1024 * 1024), 1) if hasattr(mem, 'shared') else 0,
                        peak_working_set_mb=round(mem.peak / (1024 * 1024), 1) if hasattr(mem, 'peak') else 0,
                        pagefile_mb=round(mem.vms / (1024 * 1024), 1) if hasattr(mem, 'vms') else 0,
                        peak_pagefile_mb=0,
                        memory_percent=round(info.get('memory_percent', 0), 1)
                    )
                    processes.append(proc_mem)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Sort by private memory (descending)
        processes.sort(key=lambda p: p.private_mb, reverse=True)
        return processes
    
    def _analyze_risks(self):
        """Analyze memory usage for risk indicators"""
        for proc in self.processes:
            risks = []
            
            # High memory usage
            if proc.private_mb > 1000:
                risks.append("high_memory_usage")
            if proc.private_mb > 2000:
                risks.append("very_high_memory_usage")
            
            # High working set
            if proc.working_set_mb > 1500:
                risks.append("high_working_set")
            
            # Memory percentage
            if proc.memory_percent > 10:
                risks.append(f"memory_percent_{proc.memory_percent:.0f}%")
            
            # Large gap between private and working set (potential memory leak)
            if proc.private_mb > 0 and proc.working_set_mb > 0:
                ratio = proc.working_set_mb / proc.private_mb if proc.private_mb > 0 else 0
                if ratio > 3:
                    risks.append("high_working_set_ratio")
            
            proc.risk_indicators = risks
    
    def _get_top_consumers(self, n: int) -> List[MemoryProcess]:
        """Get top N memory consumers"""
        return self.processes[:n]
    
    def _generate_report(self) -> str:
        """Generate human-readable memory report"""
        lines = []
        
        lines.append("=" * 100)
        lines.append("  SysPilot-Ai - Memory Analysis Report")
        lines.append("=" * 100)
        lines.append(f"  Generated: {datetime.now().isoformat()}")
        lines.append("=" * 100)
        lines.append("")
        
        # System Memory
        if self.system:
            lines.append("=" * 100)
            lines.append("  📊 SYSTEM MEMORY")
            lines.append("=" * 100)
            lines.append("")
            
            s = self.system
            lines.append(f"  Total Memory:         {s.total_mb:>10.1f} MB ({s.total_mb / 1024:.2f} GB)")
            lines.append(f"  Available Memory:     {s.available_mb:>10.1f} MB ({s.available_mb / 1024:.2f} GB)")
            lines.append(f"  Used Memory:          {s.used_mb:>10.1f} MB ({s.used_mb / 1024:.2f} GB)")
            lines.append(f"  Memory Usage:         {s.percent_used:>9.1f}%")
            lines.append("")
            lines.append(f"  Cached:               {s.cached_mb:>10.1f} MB")
            lines.append(f"  Paged Pool:           {s.paged_pool_mb:>10.1f} MB")
            lines.append(f"  Non-paged Pool:       {s.non_paged_pool_mb:>10.1f} MB")
            lines.append("")
            lines.append(f"  Commit Total:         {s.commit_total_mb:>10.1f} MB")
            lines.append(f"  Commit Limit:         {s.commit_limit_mb:>10.1f} MB")
            lines.append(f"  Commit Usage:         {s.commit_percent:>9.1f}%")
            lines.append("")
            lines.append(f"  Page Faults/sec:      {s.page_faults_per_sec}")
            lines.append("")
            
            # Memory pressure indicators
            lines.append("  💡 Memory Pressure Indicators:")
            if s.percent_used > 90:
                lines.append("    ⚠️ CRITICAL: Memory usage above 90%!")
            elif s.percent_used > 80:
                lines.append("    ⚠️ High memory usage (above 80%)")
            elif s.percent_used > 70:
                lines.append("    ⚠️ Elevated memory usage (above 70%)")
            else:
                lines.append("    ✅ Memory usage is normal")
            
            if s.commit_percent > 90:
                lines.append("    ⚠️ CRITICAL: Commit charge above 90%!")
            elif s.commit_percent > 80:
                lines.append("    ⚠️ High commit charge (above 80%)")
            lines.append("")
        
        # Top Memory Consumers
        lines.append("=" * 100)
        lines.append("  💾 TOP MEMORY CONSUMERS")
        lines.append("=" * 100)
        lines.append("")
        lines.append("  Rank  PID    Process Name                    Private( MB)  Working( MB)   % of RAM")
        lines.append("  ----- ------ ------------------------------  ------------  ------------  --------")
        
        for i, proc in enumerate(self.processes[:20], 1):
            name = proc.name[:30] if proc.name else "Unknown"
            lines.append(f"  {i:4}   {proc.pid:6}  {name:30}  {proc.private_mb:11.1f}   {proc.working_set_mb:11.1f}   {proc.memory_percent:6.1f}%")
        
        lines.append("")
        
        # Processes with Risks
        risky = [p for p in self.processes if p.risk_indicators]
        if risky:
            lines.append("=" * 100)
            lines.append("  ⚠️ PROCESSES WITH MEMORY RISKS")
            lines.append("=" * 100)
            lines.append("")
            
            for proc in risky[:15]:
                lines.append(f"  [{proc.name}] (PID: {proc.pid})")
                lines.append(f"    Private Memory: {proc.private_mb:.1f} MB")
                lines.append(f"    Working Set: {proc.working_set_mb:.1f} MB")
                lines.append(f"    Memory %: {proc.memory_percent:.1f}%")
                lines.append("    Risks:")
                for risk in proc.risk_indicators:
                    lines.append(f"      - {risk}")
                lines.append("")
        
        lines.append("=" * 100)
        lines.append("  END OF REPORT")
        lines.append("=" * 100)
        
        return '\n'.join(lines)
    
    def _save_report(self, report: str) -> Path:
        """Save the report to a file"""
        reports_dir = Path('reports')
        reports_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = reports_dir / f"memory_{timestamp}.txt"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"\n  ✅ Memory report saved to: {report_file}")
        return report_file


def save_memory_json(data: Dict[str, Any], output_dir: str = "reports") -> Path:
    """Save memory data as JSON"""
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = output_path / f"memory_{timestamp}.json"
    
    # Convert dataclasses to dicts
    json_data = {
        'timestamp': datetime.now().isoformat(),
        'system': asdict(data['system']) if data.get('system') else None,
        'processes': [p.to_dict() for p in data.get('processes', [])],
        'top_consumers': [p.to_dict() for p in data.get('top_consumers', [])]
    }
    
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2)
    
    return json_file


if __name__ == "__main__":
    print("Testing Memory Collector...")
    
    collector = MemoryCollector()
    data = collector.collect()
    
    # Save JSON
    json_file = save_memory_json(data)
    print(f"\n✅ JSON saved to: {json_file}")