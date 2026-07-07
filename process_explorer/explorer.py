# explorer.py
"""
Process Explorer-style report generator for SysPilot-Ai
Generates multiple report formats for AI analysis
"""

import json
import csv
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
from collections import Counter

from .process import Process


# ============================================================
# TEXT REPORT GENERATOR
# ============================================================

def generate_text_report(processes: List[Process]) -> str:
    """
    Generate comprehensive text report for AI analysis
    
    This contains ALL process data in a structured, readable format
    with sections for easy parsing by LLMs.
    
    Args:
        processes: List of Process objects
        
    Returns:
        Formatted text report
    """
    lines = []
    
    # ============================================================
    # HEADER
    # ============================================================
    lines.append("=" * 100)
    lines.append("  SysPilot-Ai - Complete Process Data Report")
    lines.append("=" * 100)
    lines.append(f"  Report Generated: {datetime.now().isoformat()}")
    lines.append(f"  Total Processes:  {len(processes)}")
    lines.append("=" * 100)
    lines.append("")
    
    # ============================================================
    # SUMMARY SECTION
    # ============================================================
    lines.append("=" * 100)
    lines.append("  SUMMARY STATISTICS")
    lines.append("=" * 100)
    
    # Basic counts
    signed = [p for p in processes if p.path and p.signed]
    unsigned = [p for p in processes if p.path and not p.signed]
    risky = [p for p in processes if p.risk_indicators]
    high_memory = [p for p in processes if p.memory_private_mb > 1000]
    high_cpu = [p for p in processes if p.cpu_percent > 50]
    
    lines.append(f"  Total Processes:                 {len(processes)}")
    lines.append(f"  Signed Executables:              {len(signed)}")
    lines.append(f"  Unsigned Executables:            {len(unsigned)}")
    lines.append(f"  Processes with Risk Indicators:  {len(risky)}")
    lines.append(f"  High Memory (>1GB):              {len(high_memory)}")
    lines.append(f"  High CPU (>50%):                 {len(high_cpu)}")
    lines.append("")
    
    # Company counts
    company_counts = Counter()
    for proc in processes:
        if proc.company:
            company_counts[proc.company] += 1
    
    if company_counts:
        lines.append("  Top Companies by Process Count:")
        for company, count in company_counts.most_common(10):
            lines.append(f"    - {company}: {count} processes")
    lines.append("")
    
    # Risk type counts
    risk_counts = Counter()
    for proc in processes:
        for risk in proc.risk_indicators:
            risk_counts[risk] += 1
    
    if risk_counts:
        lines.append("  Top Risk Indicators:")
        for risk, count in risk_counts.most_common(10):
            lines.append(f"    - {risk}: {count} processes")
    lines.append("")
    
    # ============================================================
    # RISK SUMMARY SECTION
    # ============================================================
    if risky:
        lines.append("=" * 100)
        lines.append("  ⚠️  PROCESSES WITH RISK INDICATORS")
        lines.append("=" * 100)
        lines.append("")
        
        # Sort by number of risks (most risky first)
        risky_sorted = sorted(risky, key=lambda p: len(p.risk_indicators), reverse=True)
        
        for proc in risky_sorted[:20]:  # Show top 20 risky processes
            lines.append(f"  [{proc.name}] (PID: {proc.pid})")
            lines.append(f"    Path: {proc.path or 'UNKNOWN'}")
            lines.append(f"    Company: {proc.company or 'UNKNOWN'}")
            lines.append(f"    Signed: {'YES' if proc.signed else 'NO'}")
            lines.append(f"    CPU: {proc.cpu_percent:.1f}%")
            lines.append(f"    Memory: {proc.memory_private_mb:.1f} MB")
            lines.append(f"    Threads: {proc.threads}")
            lines.append(f"    Handles: {proc.handles or 'UNKNOWN'}")
            lines.append("    Risks:")
            for risk in proc.risk_indicators:
                lines.append(f"      - {risk}")
            lines.append("")
    
    # ============================================================
    # UNSIGNED PROCESSES SECTION
    # ============================================================
    if unsigned:
        lines.append("=" * 100)
        lines.append("  🔓 UNSIGNED EXECUTABLES")
        lines.append("=" * 100)
        lines.append("")
        lines.append("  WARNING: These executables are not digitally signed.")
        lines.append("  They may be legitimate, but require additional scrutiny.")
        lines.append("")
        
        # Sort by location (system vs non-system)
        system_unsigned = [p for p in unsigned if p.path and '\\system32\\' in p.path.lower()]
        non_system_unsigned = [p for p in unsigned if p.path and '\\system32\\' not in p.path.lower()]
        
        if non_system_unsigned:
            lines.append("  Non-System Unsigned Executables (higher risk):")
            lines.append("  " + "-" * 80)
            for proc in non_system_unsigned[:10]:
                lines.append(f"    - {proc.name} (PID: {proc.pid})")
                lines.append(f"      Path: {proc.path}")
                lines.append(f"      Company: {proc.company or 'UNKNOWN'}")
                if proc.risk_indicators:
                    lines.append(f"      Risks: {', '.join(proc.risk_indicators[:3])}")
                lines.append("")
        
        if system_unsigned:
            lines.append("  System Unsigned Executables (may be legitimate):")
            lines.append("  " + "-" * 80)
            for proc in system_unsigned[:10]:
                lines.append(f"    - {proc.name} (PID: {proc.pid})")
                lines.append(f"      Path: {proc.path}")
                lines.append("")
    
    # ============================================================
    # PROCESSES WITH HIGH MEMORY
    # ============================================================
    if high_memory:
        lines.append("=" * 100)
        lines.append("  💾 PROCESSES WITH HIGH MEMORY USAGE (>1GB)")
        lines.append("=" * 100)
        lines.append("")
        lines.append("  These processes are consuming significant memory.")
        lines.append("  Consider closing unused applications or investigating memory leaks.")
        lines.append("")
        
        high_memory_sorted = sorted(high_memory, key=lambda p: p.memory_private_mb, reverse=True)
        for proc in high_memory_sorted[:10]:
            lines.append(f"  [{proc.name}] (PID: {proc.pid})")
            lines.append(f"    Memory: {proc.memory_private_mb:.1f} MB")
            lines.append(f"    Path: {proc.path or 'UNKNOWN'}")
            lines.append(f"    Company: {proc.company or 'UNKNOWN'}")
            lines.append(f"    Threads: {proc.threads}")
            if proc.risk_indicators:
                lines.append(f"    Risks: {', '.join(proc.risk_indicators)}")
            lines.append("")
    
    # ============================================================
    # PROCESSES WITH HIGH CPU
    # ============================================================
    if high_cpu:
        lines.append("=" * 100)
        lines.append("  🔥 PROCESSES WITH HIGH CPU USAGE (>50%)")
        lines.append("=" * 100)
        lines.append("")
        
        high_cpu_sorted = sorted(high_cpu, key=lambda p: p.cpu_percent, reverse=True)
        for proc in high_cpu_sorted[:10]:
            lines.append(f"  [{proc.name}] (PID: {proc.pid})")
            lines.append(f"    CPU: {proc.cpu_percent:.1f}%")
            lines.append(f"    Path: {proc.path or 'UNKNOWN'}")
            lines.append(f"    Company: {proc.company or 'UNKNOWN'}")
            lines.append(f"    Memory: {proc.memory_private_mb:.1f} MB")
            if proc.risk_indicators:
                lines.append(f"    Risks: {', '.join(proc.risk_indicators)}")
            lines.append("")
    
    # ============================================================
    # OEM/LENOVO PROCESSES SECTION
    # ============================================================
    lenovo_procs = [p for p in processes if 'lenovo' in (p.company or '').lower() or 
                    (p.path and 'lenovo' in p.path.lower())]
    if lenovo_procs:
        lines.append("=" * 100)
        lines.append("  💻 LENOVO / OEM PROCESSES")
        lines.append("=" * 100)
        lines.append("")
        lines.append("  These are Lenovo/OEM background services.")
        lines.append("  Some may be unnecessary and can be disabled.")
        lines.append("")
        
        for proc in lenovo_procs:
            lines.append(f"  [{proc.name}] (PID: {proc.pid})")
            lines.append(f"    Path: {proc.path or 'UNKNOWN'}")
            lines.append(f"    Memory: {proc.memory_private_mb:.1f} MB")
            lines.append(f"    CPU: {proc.cpu_percent:.1f}%")
            if proc.risk_indicators:
                lines.append(f"    Risks: {', '.join(proc.risk_indicators)}")
            lines.append("")
    
    # ============================================================
    # PROCESS HIERARCHY (Parent-Child Relationships)
    # ============================================================
    lines.append("=" * 100)
    lines.append("  🌳 PROCESS HIERARCHY (Top 10 Parent Processes)")
    lines.append("=" * 100)
    lines.append("")
    
    # Find processes with children
    parent_counts = Counter()
    for proc in processes:
        parent_counts[proc.parent_pid] += 1
    
    # Top parents
    top_parents = parent_counts.most_common(10)
    for parent_pid, child_count in top_parents:
        # Find the parent process name
        parent = next((p for p in processes if p.pid == parent_pid), None)
        parent_name = parent.name if parent else f"PID:{parent_pid}"
        lines.append(f"  {parent_name} (PID: {parent_pid}) -> {child_count} children")
        
        # Show children
        children = [p for p in processes if p.parent_pid == parent_pid]
        for child in children[:5]:  # Show first 5 children
            lines.append(f"    └── {child.name} (PID: {child.pid})")
        if len(children) > 5:
            lines.append(f"    └── ... and {len(children) - 5} more")
        lines.append("")
    
    # ============================================================
    # SVCHOST PROCESSES (Special Analysis)
    # ============================================================
    svchost_procs = [p for p in processes if p.name.lower() == 'svchost.exe']
    if svchost_procs:
        lines.append("=" * 100)
        lines.append("  🔧 SVCHOST.EXE PROCESSES ANALYSIS")
        lines.append("=" * 100)
        lines.append("")
        lines.append(f"  Total svchost.exe processes: {len(svchost_procs)}")
        lines.append("  (It's normal to have multiple svchost.exe instances)")
        lines.append("")
        
        # Check for suspicious svchost
        suspicious_svchost = [p for p in svchost_procs if '\\system32\\' not in (p.path or '').lower()]
        if suspicious_svchost:
            lines.append("  ⚠️  WARNING: svchost.exe not running from System32:")
            for proc in suspicious_svchost:
                lines.append(f"    - PID: {proc.pid}, Path: {proc.path}")
            lines.append("")
    
    # ============================================================
    # ALL PROCESSES DETAILED LIST
    # ============================================================
    lines.append("=" * 100)
    lines.append("  📋 ALL PROCESSES (Detailed List)")
    lines.append("=" * 100)
    lines.append("")
    lines.append("  PID   PPID   CPU%    Memory(MB)  Threads  Handles  Signed  Name")
    lines.append("  ----- ------ ------- ----------- -------- -------- ------- ---------------")
    
    # Sort by memory usage
    sorted_procs = sorted(processes, key=lambda p: p.memory_private_mb, reverse=True)
    
    for proc in sorted_procs:
        signed_str = "✓" if proc.signed else "✗"
        risk_marker = "⚠️" if proc.risk_indicators else " "
        lines.append(f"  {proc.pid:6} {proc.parent_pid:6} {proc.cpu_percent:6.1f}% {proc.memory_private_mb:10.1f} {proc.threads:8} {proc.handles or 'N/A':8} {signed_str:7} {proc.name}{risk_marker}")
    
    lines.append("")
    
    # ============================================================
    # FOOTER
    # ============================================================
    lines.append("=" * 100)
    lines.append("  END OF REPORT")
    lines.append("=" * 100)
    lines.append("")
    lines.append("  📖 Report Legend:")
    lines.append("    ✓ = Digitally Signed")
    lines.append("    ✗ = Not Signed")
    lines.append("    ⚠️ = Has Risk Indicators")
    lines.append("")
    lines.append("  💡 For AI Analysis:")
    lines.append("    - Focus on processes with risk indicators")
    lines.append("    - Check unsigned executables in non-system locations")
    lines.append("    - Review high memory/CPU usage patterns")
    lines.append("    - Examine Lenovo/OEM processes for optimization")
    lines.append("")
    lines.append("=" * 100)
    
    return '\n'.join(lines)


# ============================================================
# JSON REPORT GENERATOR
# ============================================================

def generate_json_report(processes: List[Process], output_dir: str = "reports") -> Path:
    """
    Generate JSON report for structured AI analysis
    
    Args:
        processes: List of Process objects
        output_dir: Directory to save the report
        
    Returns:
        Path to the generated JSON file
    """
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = output_path / f"processes_{timestamp}.json"
    
    # Prepare data
    data = {
        'report_type': 'process_analysis',
        'timestamp': datetime.now().isoformat(),
        'total_processes': len(processes),
        'statistics': {
            'signed_count': sum(1 for p in processes if p.path and p.signed),
            'unsigned_count': sum(1 for p in processes if p.path and not p.signed),
            'risky_count': sum(1 for p in processes if p.risk_indicators),
            'high_memory_count': sum(1 for p in processes if p.memory_private_mb > 1000),
            'high_cpu_count': sum(1 for p in processes if p.cpu_percent > 50),
        },
        'risk_summary': {},
        'company_summary': {},
        'processes': [proc.to_dict() for proc in processes]
    }
    
    # Build risk summary
    risk_counts = Counter()
    for proc in processes:
        for risk in proc.risk_indicators:
            risk_counts[risk] += 1
    data['risk_summary'] = dict(risk_counts.most_common())
    
    # Build company summary
    company_counts = Counter()
    for proc in processes:
        if proc.company:
            company_counts[proc.company] += 1
    data['company_summary'] = dict(company_counts.most_common(20))
    
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)
    
    return json_file


# ============================================================
# CSV REPORT GENERATOR
# ============================================================

def generate_csv_report(processes: List[Process], output_dir: str = "reports") -> Path:
    """
    Generate CSV report for spreadsheet analysis
    
    Args:
        processes: List of Process objects
        output_dir: Directory to save the report
        
    Returns:
        Path to the generated CSV file
    """
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_file = output_path / f"processes_{timestamp}.csv"
    
    # Define columns
    fields = [
        'pid', 'name', 'parent_pid', 'path', 'cpu_percent',
        'memory_private_mb', 'memory_working_set_mb', 'memory_pagefile_mb',
        'threads', 'handles', 'username', 'command_line',
        'company', 'file_version', 'file_description', 'product_name',
        'signed', 'signer', 'risk_indicators'
    ]
    
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        
        for proc in processes:
            row = proc.to_dict()
            # Convert lists to strings
            if 'risk_indicators' in row and isinstance(row['risk_indicators'], list):
                row['risk_indicators'] = '; '.join(row['risk_indicators'])
            writer.writerow(row)
    
    return csv_file


# ============================================================
# HTML REPORT GENERATOR
# ============================================================

def generate_html_report(processes: List[Process], output_dir: str = "reports") -> Path:
    """
    Generate HTML report for visual inspection
    
    Args:
        processes: List of Process objects
        output_dir: Directory to save the report
        
    Returns:
        Path to the generated HTML file
    """
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_file = output_path / f"processes_{timestamp}.html"
    
    # Count statistics
    signed_count = sum(1 for p in processes if p.path and p.signed)
    unsigned_count = sum(1 for p in processes if p.path and not p.signed)
    risky_count = sum(1 for p in processes if p.risk_indicators)
    
    # Build HTML
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>SysPilot-Ai Process Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat-box {{ background: #f8f9fa; padding: 15px; border-radius: 8px; border: 1px solid #dee2e6; min-width: 150px; }}
        .stat-number {{ font-size: 24px; font-weight: bold; color: #2c3e50; }}
        .stat-label {{ color: #6c757d; font-size: 14px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #2c3e50; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 8px; border-bottom: 1px solid #dee2e6; }}
        tr:hover {{ background: #f8f9fa; }}
        .risk {{ color: #e74c3c; font-weight: bold; }}
        .signed {{ color: #27ae60; }}
        .unsigned {{ color: #e74c3c; }}
        .high-memory {{ background: #ffe6e6; }}
        .summary {{ margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 8px; }}
    </style>
</head>
<body>
    <h1>🔍 SysPilot-Ai Process Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="stats">
        <div class="stat-box">
            <div class="stat-number">{len(processes)}</div>
            <div class="stat-label">Total Processes</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">{signed_count}</div>
            <div class="stat-label">Signed</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">{unsigned_count}</div>
            <div class="stat-label">Unsigned</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">{risky_count}</div>
            <div class="stat-label">Risky</div>
        </div>
    </div>
    
    <div class="summary">
        <h2>📊 Summary</h2>
        <ul>
            <li>High Memory (>1GB): {sum(1 for p in processes if p.memory_private_mb > 1000)}</li>
            <li>High CPU (>50%): {sum(1 for p in processes if p.cpu_percent > 50)}</li>
            <li>Many Threads (>100): {sum(1 for p in processes if p.threads > 100)}</li>
            <li>Many Handles (>1000): {sum(1 for p in processes if p.handles and p.handles > 1000)}</li>
        </ul>
    </div>
    
    <h2>📋 All Processes</h2>
    <table>
        <thead>
            <tr>
                <th>PID</th>
                <th>Name</th>
                <th>CPU%</th>
                <th>Memory (MB)</th>
                <th>Threads</th>
                <th>Handles</th>
                <th>Signed</th>
                <th>Company</th>
                <th>Risks</th>
            </tr>
        </thead>
        <tbody>
"""
    
    # Sort by memory
    sorted_procs = sorted(processes, key=lambda p: p.memory_private_mb, reverse=True)
    
    for proc in sorted_procs[:100]:  # Show top 100
        risk_class = 'risk' if proc.risk_indicators else ''
        memory_class = 'high-memory' if proc.memory_private_mb > 1000 else ''
        signed_str = '✓' if proc.signed else '✗'
        risks = ', '.join(proc.risk_indicators[:3])
        if len(proc.risk_indicators) > 3:
            risks += f' (+{len(proc.risk_indicators)-3})'
        
        html_content += f"""
            <tr class="{risk_class} {memory_class}">
                <td>{proc.pid}</td>
                <td>{proc.name}</td>
                <td>{proc.cpu_percent:.1f}%</td>
                <td>{proc.memory_private_mb:.1f}</td>
                <td>{proc.threads}</td>
                <td>{proc.handles or 'N/A'}</td>
                <td class="{'signed' if proc.signed else 'unsigned'}">{signed_str}</td>
                <td>{proc.company or 'N/A'}</td>
                <td>{risks or 'None'}</td>
            </tr>
        """
    
    html_content += """
        </tbody>
    </table>
    <p><em>Showing top 100 processes by memory usage</em></p>
    
    <hr>
    <p>Generated by SysPilot-Ai | AI-Powered Windows System Inspection Tool</p>
</body>
</html>
"""
    
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return html_file


# ============================================================
# MARKDOWN REPORT GENERATOR
# ============================================================

def generate_markdown_report(processes: List[Process], output_dir: str = "reports") -> Path:
    """
    Generate Markdown report for GitHub/README
    
    Args:
        processes: List of Process objects
        output_dir: Directory to save the report
        
    Returns:
        Path to the generated Markdown file
    """
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    md_file = output_path / f"processes_{timestamp}.md"
    
    lines = []
    
    # Header
    lines.append(f"# SysPilot-Ai Process Report")
    lines.append(f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
    lines.append("")
    
    # Statistics
    signed_count = sum(1 for p in processes if p.path and p.signed)
    unsigned_count = sum(1 for p in processes if p.path and not p.signed)
    risky_count = sum(1 for p in processes if p.risk_indicators)
    
    lines.append("## 📊 Statistics")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Total Processes | {len(processes)} |")
    lines.append(f"| Signed | {signed_count} |")
    lines.append(f"| Unsigned | {unsigned_count} |")
    lines.append(f"| Risky | {risky_count} |")
    lines.append(f"| High Memory (>1GB) | {sum(1 for p in processes if p.memory_private_mb > 1000)} |")
    lines.append(f"| High CPU (>50%) | {sum(1 for p in processes if p.cpu_percent > 50)} |")
    lines.append("")
    
    # Risk summary
    risk_counts = Counter()
    for proc in processes:
        for risk in proc.risk_indicators:
            risk_counts[risk] += 1
    
    if risk_counts:
        lines.append("### ⚠️ Risk Indicators")
        lines.append("")
        lines.append("| Risk | Count |")
        lines.append("|------|-------|")
        for risk, count in risk_counts.most_common(10):
            lines.append(f"| {risk} | {count} |")
        lines.append("")
    
    # Process table
    lines.append("## 📋 Processes")
    lines.append("")
    lines.append("| PID | Name | CPU% | Memory (MB) | Threads | Handles | Signed | Risks |")
    lines.append("|-----|------|------|-------------|---------|---------|--------|-------|")
    
    sorted_procs = sorted(processes, key=lambda p: p.memory_private_mb, reverse=True)
    for proc in sorted_procs[:50]:
        signed = "✅" if proc.signed else "❌"
        risks = ', '.join(proc.risk_indicators[:3])
        if len(proc.risk_indicators) > 3:
            risks += f' (+{len(proc.risk_indicators)-3})'
        lines.append(f"| {proc.pid} | {proc.name} | {proc.cpu_percent:.1f}% | {proc.memory_private_mb:.1f} | {proc.threads} | {proc.handles or 'N/A'} | {signed} | {risks or 'None'} |")
    
    lines.append("")
    lines.append("*Showing top 50 processes by memory usage*")
    
    # Footer
    lines.append("")
    lines.append("---")
    lines.append("*Generated by SysPilot-Ai - AI-Powered Windows System Inspection Tool*")
    
    with open(md_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    
    return md_file


# ============================================================
# MAIN REPORT GENERATION FUNCTION
# ============================================================

def generate_all_reports(processes: List[Process], output_dir: str = "reports") -> Dict[str, Path]:
    """
    Generate all report formats
    
    Args:
        processes: List of Process objects
        output_dir: Directory to save reports
        
    Returns:
        Dictionary with report types and file paths
    """
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    reports = {}
    
    # Text report
    reports['text'] = generate_text_report_file(processes, output_dir)
    
    # JSON report
    reports['json'] = generate_json_report(processes, output_dir)
    
    # CSV report
    reports['csv'] = generate_csv_report(processes, output_dir)
    
    # HTML report
    reports['html'] = generate_html_report(processes, output_dir)
    
    # Markdown report
    reports['markdown'] = generate_markdown_report(processes, output_dir)
    
    return reports


# ============================================================
# COMPATIBILITY FUNCTIONS (for main.py)
# ============================================================

def generate_text_report_file(processes: List[Process], output_dir: str = "reports") -> Path:
    """
    Generate text report file (compatibility wrapper)
    
    Args:
        processes: List of Process objects
        output_dir: Directory to save the report
        
    Returns:
        Path to the generated text file
    """
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_file = output_path / f"processes_{timestamp}.txt"
    
    report_text = generate_text_report(processes)
    
    with open(txt_file, 'w', encoding='utf-8') as f:
        f.write(report_text)
    
    return txt_file


def generate_json_report_file(processes: List[Process], output_dir: str = "reports") -> Path:
    """
    Generate JSON report file (compatibility wrapper)
    
    Args:
        processes: List of Process objects
        output_dir: Directory to save the report
        
    Returns:
        Path to the generated JSON file
    """
    return generate_json_report(processes, output_dir)


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":
    # Create sample processes for testing
    from process import Process
    
    sample_procs = [
        Process(
            pid=1234,
            name="chrome.exe",
            parent_pid=892,
            path="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            cpu_percent=12.5,
            memory_private_mb=245.6,
            threads=45,
            handles=892,
            company="Google LLC",
            signed=True,
            signer="Google LLC",
            username="DESKTOP\\user",
            risk_indicators=["high_memory", "many_handles"]
        ),
        Process(
            pid=5678,
            name="explorer.exe",
            parent_pid=5678,
            path="C:\\Windows\\explorer.exe",
            cpu_percent=2.3,
            memory_private_mb=345.2,
            threads=28,
            handles=567,
            company="Microsoft Corporation",
            signed=True,
            signer="Microsoft Windows",
            username="DESKTOP\\user"
        ),
        Process(
            pid=9999,
            name="unknown.exe",
            parent_pid=1234,
            path="C:\\Users\\user\\Downloads\\unknown.exe",
            cpu_percent=0.0,
            memory_private_mb=12.3,
            threads=2,
            handles=45,
            company=None,
            signed=False,
            username="DESKTOP\\user",
            risk_indicators=["unsigned", "running_from_downloads"]
        ),
    ]
    
    # Generate all reports
    print("Generating test reports...")
    reports = generate_all_reports(sample_procs)
    
    for report_type, path in reports.items():
        print(f"  {report_type}: {path}")
    
    print("Done!")