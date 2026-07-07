# process_explorer/process.py
from dataclasses import dataclass, asdict, field
from typing import List, Optional

@dataclass
class Process:
    """Complete Windows process information"""
    
    # === Core Identification ===
    pid: int
    name: str
    parent_pid: int
    path: Optional[str] = None
    
    # === Performance Metrics ===
    cpu_percent: float = 0.0
    memory_private_mb: float = 0.0
    memory_working_set_mb: float = 0.0
    memory_pagefile_mb: float = 0.0
    threads: int = 0
    handles: Optional[int] = None
    
    # === Runtime Information ===
    command_line: Optional[str] = None
    username: Optional[str] = None
    create_time: Optional[str] = None
    
    # === File Information ===
    company: Optional[str] = None
    file_version: Optional[str] = None
    file_description: Optional[str] = None
    product_name: Optional[str] = None
    signed: bool = False
    signer: Optional[str] = None
    
    # === Risk Analysis ===
    risk_indicators: List[str] = field(default_factory=list)
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return asdict(self)