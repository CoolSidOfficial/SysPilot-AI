# autoruns_collector.py
"""
Autoruns Collector for SysPilot-Ai
Runs Autorunsc.exe directly from command line
"""

import subprocess
import csv
import os
from pathlib import Path
from datetime import datetime
from typing import List, Optional
from dataclasses import dataclass, asdict, field


@dataclass
class AutorunEntry:
    """Represents a startup entry"""
    entry: str
    entry_location: str
    image_path: str
    signer: Optional[str] = None
    description: Optional[str] = None
    company: Optional[str] = None
    file_version: Optional[str] = None
    timestamp: Optional[str] = None
    enabled: bool = True
    category: str = "Unknown"
    risk_indicators: List[str] = field(default_factory=list)
    
    def to_dict(self):
        return asdict(self)


class AutorunsCollector:
    """Collects startup entries by running Autorunsc.exe"""
    
    def __init__(self, autorunsc_path: str = "tools/autorunsc64.exe"):
        self.autorunsc_path = autorunsc_path
        self.entries: List[AutorunEntry] = []
        
    def collect(self) -> List[AutorunEntry]:
        """Run Autorunsc and collect startup entries"""
        
        if not os.path.exists(self.autorunsc_path):
            raise FileNotFoundError(
                f"autorunsc64.exe not found at: {self.autorunsc_path}\n"
                "Please download from:\n"
                "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns\n"
                "And place it in the root directory."
            )
        
        print(f"\n  Running: {self.autorunsc_path} -accepteula -a * -c -s *")
        
        # Build command - exactly like you showed
        cmd = [
            self.autorunsc_path,
            "-accepteula",
            "-a", "*",
            "-c",
            "-s",
            "*"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=True,
                timeout=300
            )
            
            if result.returncode != 0:
                print(f"  ⚠️ Autorunsc returned: {result.returncode}")
            
            if not result.stdout.strip():
                print("  ⚠️ No output from Autorunsc")
                return []
            
            # Parse the CSV output
            self.entries = self._parse_csv(result.stdout)
            
            # Analyze risks
            for entry in self.entries:
                entry.risk_indicators = self._analyze_risks(entry)
            
            print(f"  ✓ Found {len(self.entries)} startup entries")
            return self.entries
            
        except subprocess.TimeoutExpired:
            print("  ⚠️ Autorunsc timed out after 300 seconds")
            return []
        except Exception as e:
            print(f"  ⚠️ Error running Autorunsc: {e}")
            return []
    
    def _parse_csv(self, csv_data: str) -> List[AutorunEntry]:
        """Parse CSV output from Autorunsc"""
        entries = []
        
        try:
            lines = csv_data.strip().splitlines()
            if not lines:
                return []
            
            # Find the header line
            header_index = -1
            for i, line in enumerate(lines):
                if "Time," in line and "Entry Location" in line and "Entry," in line:
                    header_index = i
                    break
            
            if header_index == -1:
                print("  ⚠️ Could not find CSV header")
                return []
            
            reader = csv.DictReader(lines[header_index:])
            for row in reader:
                entry_name = row.get("Entry", "").strip()
                image_path = row.get("Image Path", "").strip()
                
                # Skip empty entries
                if not entry_name and not image_path:
                    continue
                
                entry = AutorunEntry(
                    entry=entry_name,
                    entry_location=row.get("Entry Location", "").strip(),
                    image_path=image_path,
                    signer=row.get("Signer", "").strip(),
                    description=row.get("Description", "").strip(),
                    company=row.get("Company", "").strip(),
                    file_version=row.get("Version", "").strip(),
                    timestamp=row.get("Time", "").strip(),
                    enabled=row.get("Enabled", "enabled").lower() in ["enabled", "true", "yes"],
                    category=row.get("Category", "Unknown").strip(),
                )
                
                entries.append(entry)
                
        except Exception as e:
            print(f"  ⚠️ Error parsing CSV: {e}")
        
        return entries
    
    def _analyze_risks(self, entry: AutorunEntry) -> List[str]:
        """Analyze entry for risk indicators"""
        risks = []
        
        # Check for unsigned
        if entry.signer:
            if "Not verified" in entry.signer or "not verified" in entry.signer.lower():
                risks.append("unsigned")
        else:
            risks.append("unsigned")
        
        # Check for missing file
        if "file not found" in entry.image_path.lower():
            risks.append("missing_file")
        
        # Check for OEM
        if entry.company and "Lenovo" in entry.company:
            risks.append("lenovo_oem")
        if entry.image_path and "lenovo" in entry.image_path.lower():
            risks.append("lenovo_oem")
        
        # Check for unnecessary startup items
        if entry.entry:
            entry_lower = entry.entry.lower()
            unnecessary = ["jusched", "java update", "sunjava", "googleupdate", "microsoftedgeupdate"]
            for name in unnecessary:
                if name in entry_lower:
                    risks.append("unnecessary_startup")
                    break
        
        return risks


def generate_autorun_report(entries: List[AutorunEntry]) -> str:
    """Generate a human-readable report from autorun entries"""
    lines = []
    
    lines.append("=" * 100)
    lines.append("  SysPilot-Ai - Autoruns Report")
    lines.append("=" * 100)
    lines.append(f"  Generated: {datetime.now().isoformat()}")
    lines.append(f"  Total Startup Entries: {len(entries)}")
    lines.append("=" * 100)
    lines.append("")
    
    # Statistics
    risky = [e for e in entries if e.risk_indicators]
    unsigned = [e for e in entries if "unsigned" in e.risk_indicators if e.risk_indicators]
    lenovo = [e for e in entries if "lenovo_oem" in e.risk_indicators if e.risk_indicators]
    
    lines.append(f"  📊 Statistics:")
    lines.append(f"     Total entries:     {len(entries)}")
    lines.append(f"     Risky entries:     {len(risky)}")
    lines.append(f"     Unsigned:          {len(unsigned)}")
    lines.append(f"     Lenovo/OEM:        {len(lenovo)}")
    lines.append("")
    
    # Risky entries
    if risky:
        lines.append("=" * 100)
        lines.append("  ⚠️  SUSPICIOUS STARTUP ENTRIES")
        lines.append("=" * 100)
        lines.append("")
        
        for entry in risky[:20]:
            lines.append(f"  [{entry.entry or 'UNKNOWN'}]")
            lines.append(f"    Location: {entry.entry_location}")
            if entry.image_path:
                lines.append(f"    Path: {entry.image_path}")
            if entry.company:
                lines.append(f"    Company: {entry.company}")
            lines.append(f"    Signed: {'YES' if entry.signer else 'NO'}")
            lines.append("    Risks:")
            for risk in entry.risk_indicators:
                lines.append(f"      - {risk}")
            lines.append("")
    
    # Lenovo entries
    if lenovo:
        lines.append("=" * 100)
        lines.append("  💻 LENOVO / OEM STARTUP ENTRIES")
        lines.append("=" * 100)
        lines.append("")
        
        for entry in lenovo[:15]:
            lines.append(f"  [{entry.entry or 'UNKNOWN'}]")
            lines.append(f"    Location: {entry.entry_location}")
            if entry.image_path:
                lines.append(f"    Path: {entry.image_path}")
            lines.append("")
    
    # All entries (compact list)
    lines.append("=" * 100)
    lines.append("  📋 ALL STARTUP ENTRIES")
    lines.append("=" * 100)
    lines.append("")
    lines.append("  Entry                                     Location                          Signed")
    lines.append("  ----------------------------------------  --------------------------------  -------")
    
    for entry in sorted(entries, key=lambda e: e.entry)[:50]:
        signed = "✓" if entry.signer else "✗"
        name = entry.entry[:40] if entry.entry else "UNKNOWN"
        location = entry.entry_location[:32] if entry.entry_location else "UNKNOWN"
        lines.append(f"  {name:<40}  {location:<32}  {signed}")
    
    lines.append("")
    lines.append("=" * 100)
    lines.append("  END OF REPORT")
    lines.append("=" * 100)
    
    return '\n'.join(lines)


def save_autorun_json(entries: List[AutorunEntry], output_dir: str = "reports") -> Path:
    """Save autorun entries as JSON"""
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = output_path / f"autoruns_{timestamp}.json"
    
    data = {
        'timestamp': datetime.now().isoformat(),
        'total_entries': len(entries),
        'entries': [entry.to_dict() for entry in entries]
    }
    
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    
    return json_file


# For testing
if __name__ == "__main__":
    print("Testing Autoruns Collector...")
    
    collector = AutorunsCollector()
    entries = collector.collect()
    
    report = generate_autorun_report(entries)
    print(report)