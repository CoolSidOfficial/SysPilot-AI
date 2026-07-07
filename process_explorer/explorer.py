# process_explorer/explorer.py
"""
Process Explorer-style report generator for SysPilot-Ai
"""

import json
from datetime import datetime
from typing import List
from pathlib import Path

from process import Process


def generate_text_report(processes: List[Process]) -> str:
    """
    Generate comprehensive text report for AI analysis
    
    This contains ALL process data in a structured, readable format
    """
    lines = []
    
    # Header
    lines.append("=" * 90)
    lines.append("  SysPilot-Ai - Complete Process Data")
    lines.append("=" * 90)
    lines.append(f"  Report Generated: {datetime.now().isoformat()}")
    lines.append(f"  Total Processes: {len(processes)}")
    lines.append("=" * 90)
    lines.append("")
    
    # Process Details - Each process gets full detail
    for idx, proc in enumerate(processes, 1):
        lines.append("=" * 90)
        lines.append(f"PROCESS #{idx} - PID: {proc.pid}")
        lines.append("=" * 90)
        
        # Basic info
        lines.append(f"  Name:                 {proc.name}")
        lines.append(f"  Parent PID:           {proc.parent_pid}")
        lines.append(f"  Path:                 {proc.path or 'UNKNOWN'}")
        lines.append(f"  Command Line:         {proc.command_line or 'UNKNOWN'}")
        lines.append(f"  Username:             {proc.username or 'UNKNOWN'}")
        lines.append(f"  Create Time:          {proc.create_time or 'UNKNOWN'}")
        
        # Performance
        lines.append("")
        lines.append("  PERFORMANCE:")
        lines.append(f"    CPU Usage:           {proc.cpu_percent:.1f}%")
        lines.append(f"    Private Memory:      {proc.memory_private_mb:.1f} MB")
        lines.append(f"    Working Set:         {proc.memory_working_set_mb:.1f} MB")
        lines.append(f"    Threads:             {proc.threads}")
        lines.append(f"    Handles:             {proc.handles or 'UNKNOWN'}")
        
        # File info
        lines.append("")
        lines.append("  FILE INFORMATION:")
        lines.append(f"    Company:             {proc.company or 'UNKNOWN'}")
        lines.append(f"    File Version:        {proc.file_version or 'UNKNOWN'}")
        lines.append(f"    File Description:    {proc.file_description or 'UNKNOWN'}")
        lines.append(f"    Product Name:        {proc.product_name or 'UNKNOWN'}")
        lines.append(f"    Digitally Signed:    {'YES' if proc.signed else 'NO'}")
        if proc.signer:
            lines.append(f"    Signer:              {proc.signer}")
        
        # Risk indicators
        lines.append("")
        if proc.risk_indicators:
            lines.append("  ⚠️  RISK INDICATORS:")
            for risk in proc.risk_indicators:
                lines.append(f"    - {risk}")
        else:
            lines.append("  ✅ No risk indicators detected")
        
        lines.append("")
    
    # Summary
    lines.append("=" * 90)
    lines.append("SUMMARY STATISTICS")
    lines.append("=" * 90)
    
    # Risk statistics
    risky = [p for p in processes if p.risk_indicators]
    unsigned = [p for p in processes if p.path and not p.signed]
    high_memory = [p for p in processes if p.memory_private_mb > 1000]
    
    lines.append(f"  Total Processes:                 {len(processes)}")
    lines.append(f"  Processes with Risk Indicators:  {len(risky)}")
    lines.append(f"  Unsigned Executables:            {len(unsigned)}")
    lines.append(f"  High Memory (>1GB):              {len(high_memory)}")
    
    lines.append("")
    lines.append("=" * 90)
    lines.append("END OF REPORT")
    lines.append("=" * 90)
    
    return '\n'.join(lines)


def generate_json_report(processes: List[Process], output_dir: str = "reports") -> Path:
    """
    Generate JSON report for structured AI analysis
    """
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = output_path / f"processes_{timestamp}.json"
    
    data = {
        'report_type': 'process_analysis',
        'timestamp': datetime.now().isoformat(),
        'total_processes': len(processes),
        'processes': [proc.to_dict() for proc in processes]
    }
    
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    
    return json_file


def generate_text_report_file(processes: List[Process], output_dir: str = "reports") -> Path:
    """
    Generate text report file
    """
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_file = output_path / f"processes_{timestamp}.txt"
    
    report_text = generate_text_report(processes)
    
    with open(txt_file, 'w', encoding='utf-8') as f:
        f.write(report_text)
    
    return txt_file