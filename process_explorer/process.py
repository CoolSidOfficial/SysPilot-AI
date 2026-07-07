# process.py
"""
Process data model for SysPilot-Ai
Complete Windows process information for AI analysis
"""

from dataclasses import dataclass, asdict, field
from typing import List, Optional, Dict, Any


@dataclass
class Process:
    """
    Complete Windows process information
    
    Contains all data collected from Windows APIs for AI-powered diagnostics.
    """
    
    # ============================================================
    # Core Identification (Phase 1)
    # ============================================================
    pid: int                                      # Process ID
    name: str                                     # Process name
    parent_pid: int                               # Parent Process ID
    path: Optional[str] = None                    # Full executable path
    
    # ============================================================
    # Performance Metrics (Phase 2)
    # ============================================================
    cpu_percent: float = 0.0                      # CPU usage percentage
    cpu_kernel_time: int = 0                      # Kernel time (100-ns units)
    cpu_user_time: int = 0                        # User time (100-ns units)
    cpu_total_time: int = 0                       # Total time (100-ns units)
    
    memory_private_mb: float = 0.0                # Private memory in MB
    memory_working_set_mb: float = 0.0            # Working set in MB
    memory_pagefile_mb: float = 0.0               # Pagefile usage in MB
    memory_peak_working_set_mb: float = 0.0       # Peak working set in MB
    memory_peak_pagefile_mb: float = 0.0          # Peak pagefile in MB
    
    threads: int = 0                              # Number of threads
    handles: Optional[int] = None                 # Number of handles
    
    # ============================================================
    # Runtime Information (Phase 2/3)
    # ============================================================
    command_line: Optional[str] = None            # Full command line
    username: Optional[str] = None                # User who owns process
    create_time: Optional[str] = None             # Creation time (ISO format)
    
    # ============================================================
    # File Information (Priority 1)
    # ============================================================
    company: Optional[str] = None                 # Company name
    file_version: Optional[str] = None            # File version
    file_description: Optional[str] = None        # File description
    product_name: Optional[str] = None            # Product name
    product_version: Optional[str] = None         # Product version
    original_filename: Optional[str] = None       # Original filename
    internal_name: Optional[str] = None           # Internal name
    copyright: Optional[str] = None               # Copyright info
    trademarks: Optional[str] = None              # Trademark info
    
    # ============================================================
    # Digital Signature (Priority 1)
    # ============================================================
    signed: bool = False                          # Is digitally signed?
    signer: Optional[str] = None                  # Who signed it
    
    # ============================================================
    # Risk Analysis
    # ============================================================
    risk_indicators: List[str] = field(default_factory=list)
    
    # ============================================================
    # Methods
    # ============================================================
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for JSON serialization
        
        Returns:
            Dictionary with all process data
        """
        return asdict(self)
    
    @property
    def is_high_memory(self) -> bool:
        """Check if process uses high memory (>1GB private)"""
        return self.memory_private_mb > 1000.0
    
    @property
    def is_high_cpu(self) -> bool:
        """Check if process uses high CPU (>50%)"""
        return self.cpu_percent > 50.0
    
    @property
    def is_many_handles(self) -> bool:
        """Check if process has many handles (>1000)"""
        if self.handles:
            return self.handles > 1000
        return False
    
    @property
    def is_many_threads(self) -> bool:
        """Check if process has many threads (>100)"""
        return self.threads > 100
    
    @property
    def is_unsigned(self) -> bool:
        """Check if process is unsigned"""
        return not self.signed if self.path else False
    
    @property
    def is_system_process(self) -> bool:
        """Check if process is a system process"""
        if self.username:
            return self.username in ['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE']
        return False
    
    @property
    def is_microsoft_signed(self) -> bool:
        """Check if process is signed by Microsoft"""
        if self.signed and self.company:
            return 'Microsoft' in self.company
        return False
    
    def get_summary(self) -> str:
        """
        Get a human-readable summary of the process
        
        Returns:
            Short summary string
        """
        risk = ' ⚠️' if self.risk_indicators else ''
        return f"{self.pid:6} {self.cpu_percent:6.1f}% {self.memory_private_mb:10.1f}MB {self.threads:6} {self.name}{risk}"
    
    def get_risk_summary(self) -> str:
        """
        Get summary of risk indicators
        
        Returns:
            Comma-separated list of risks or "None"
        """
        if self.risk_indicators:
            return ', '.join(self.risk_indicators)
        return 'None'
    
    def to_short_dict(self) -> Dict[str, Any]:
        """
        Get a compact dictionary with key fields
        
        Useful for quick AI analysis
        """
        return {
            'pid': self.pid,
            'name': self.name,
            'parent_pid': self.parent_pid,
            'path': self.path,
            'cpu_percent': self.cpu_percent,
            'memory_private_mb': self.memory_private_mb,
            'threads': self.threads,
            'handles': self.handles,
            'company': self.company,
            'signed': self.signed,
            'username': self.username,
            'risk_indicators': self.risk_indicators,
        }


# ============================================================
# Factory function for creating Process from raw data
# ============================================================

def create_process_from_raw(
    pid: int,
    name: str,
    parent_pid: int,
    path: Optional[str] = None,
    **kwargs
) -> Process:
    """
    Factory function to create a Process from raw data
    
    Args:
        pid: Process ID
        name: Process name
        parent_pid: Parent process ID
        path: Executable path (optional)
        **kwargs: Additional fields
        
    Returns:
        Process instance
    """
    return Process(
        pid=pid,
        name=name,
        parent_pid=parent_pid,
        path=path,
        **kwargs
    )


# ============================================================
# Example Usage
# ============================================================

if __name__ == "__main__":
    # Create a sample process
    proc = Process(
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
        command_line='"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --profile-directory=Default',
    )
    
    # Add some risk indicators
    if proc.is_high_memory:
        proc.risk_indicators.append("high_memory")
    if proc.is_many_handles:
        proc.risk_indicators.append("many_handles")
    
    # Test properties
    print(f"Process: {proc.name} (PID: {proc.pid})")
    print(f"  High Memory: {proc.is_high_memory}")
    print(f"  Many Handles: {proc.is_many_handles}")
    print(f"  Microsoft Signed: {proc.is_microsoft_signed}")
    print(f"  Risks: {proc.get_risk_summary()}")
    print(f"  Summary: {proc.get_summary()}")
    
    # Test serialization
    import json
    print("\nJSON:")
    print(json.dumps(proc.to_dict(), indent=2))