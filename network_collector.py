# network_collector.py
"""
Network Collector for SysPilot-Ai
Uses Sysinternals Tcpvcon to collect all network connections
"""
import json
import subprocess
import os
import re
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict
from dataclasses import dataclass, asdict, field


@dataclass
class NetworkConnection:
    """Represents a network connection"""
    protocol: str
    process_name: str
    pid: str
    state: str
    local_address: str
    local_port: str
    remote_address: str
    remote_port: str
    risk_indicators: List[str] = field(default_factory=list)
    
    def to_dict(self):
        return asdict(self)


class NetworkCollector:
    """Collects network connections using Sysinternals Tcpvcon"""
    
    def __init__(self, tcpvcon_path: str = "tools/tcpvcon64.exe"):
        self.tcpvcon_path = tcpvcon_path
        self.entries: List[NetworkConnection] = []
        
        # Check if tcpvcon exists
        if not os.path.exists(self.tcpvcon_path):
            alt_paths = [
                "tcpvcon64.exe",
                "tools/tcpvcon.exe",
                "tcpvcon.exe",
                "process_explorer/tcpvcon64.exe",
            ]
            for alt in alt_paths:
                if os.path.exists(alt):
                    self.tcpvcon_path = alt
                    break
        
    def collect(self) -> List[NetworkConnection]:
        """
        Run Tcpvcon and collect all network connections
        
        Command: tcpvcon64.exe -accepteula -a -n
        -a: Show all endpoints (TCP + UDP, all states)
        -n: Don't resolve addresses (faster)
        """
        
        if not os.path.exists(self.tcpvcon_path):
            raise FileNotFoundError(
                f"tcpvcon64.exe not found at: {self.tcpvcon_path}\n"
                "Please download from:\n"
                "https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview\n"
                "And place it in: SysPilot-Ai/tools/tcpvcon64.exe"
            )
        
        print(f"\n  Running: {os.path.basename(self.tcpvcon_path)} -accepteula -a -n")
        
        cmd = [
            self.tcpvcon_path,
            "-accepteula",
            "-a",      # Show all endpoints
            "-n",      # Don't resolve addresses
        ]
        
        try:
            # IMPORTANT: Use shell=False (no shell) to avoid path issues
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=False,
                timeout=30
            )
            
            if result.returncode != 0 and result.returncode != 1:
                print(f"  ⚠️ Tcpvcon returned: {result.returncode}")
            
            if not result.stdout.strip():
                print("  ⚠️ No output from Tcpvcon")
                return []
            
            # Parse the human-readable output
            self.entries = self._parse_output(result.stdout)
            
            # Analyze risks
            for entry in self.entries:
                entry.risk_indicators = self._analyze_risks(entry)
            
            # Count connections
            tcp_count = sum(1 for e in self.entries if "TCP" in e.protocol)
            udp_count = sum(1 for e in self.entries if "UDP" in e.protocol)
            listening = sum(1 for e in self.entries if e.state.upper() in ["LISTENING", "LISTEN"])
            established = sum(1 for e in self.entries if e.state.upper() == "ESTABLISHED")
            
            print(f"  ✓ Found {len(self.entries)} network connections")
            print(f"     TCP: {tcp_count}, UDP: {udp_count}")
            print(f"     Listening: {listening}, Established: {established}")
            return self.entries
            
        except subprocess.TimeoutExpired:
            print("  ⚠️ Tcpvcon timed out after 30 seconds")
            return []
        except Exception as e:
            print(f"  ⚠️ Error running Tcpvcon: {e}")
            return []
    
    def _parse_output(self, output: str) -> List[NetworkConnection]:
        """
        Parse Tcpvcon human-readable output
        
        Supports both formats:
        [TCPV6] chrome.exe     (with V6)
        [TCP] chrome.exe       (without V6)
        """
        entries = []
        lines = output.strip().splitlines()
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Check for protocol header: [TCP] process_name or [TCPV6] process_name
            match = re.match(r'^\[([A-Za-z0-9]+)\]\s+(.+)$', line)
            if match:
                protocol = match.group(1)
                process_name = match.group(2)
                
                # Initialize connection data
                conn = {
                    'protocol': protocol,
                    'process_name': process_name,
                    'pid': '',
                    'state': '',
                    'local_address': '',
                    'local_port': '',
                    'remote_address': '',
                    'remote_port': '',
                }
                
                # Parse the next lines (indented with spaces/tabs)
                j = i + 1
                while j < len(lines):
                    next_line = lines[j]
                    
                    # Check if this is a new connection start (starts with [)
                    if re.match(r'^\s*\[', next_line.strip()):
                        break
                    
                    # Parse indented fields
                    stripped = next_line.strip()
                    if stripped.startswith('PID:'):
                        conn['pid'] = stripped.replace('PID:', '').strip()
                    elif stripped.startswith('State:'):
                        conn['state'] = stripped.replace('State:', '').strip()
                    elif stripped.startswith('Local:'):
                        local = stripped.replace('Local:', '').strip()
                        # Parse IP:PORT or [IPv6]:PORT
                        conn['local_address'], conn['local_port'] = self._parse_address(local)
                    elif stripped.startswith('Remote:'):
                        remote = stripped.replace('Remote:', '').strip()
                        conn['remote_address'], conn['remote_port'] = self._parse_address(remote)
                    
                    j += 1
                
                # Only add if we have a PID
                if conn['pid']:
                    entry = NetworkConnection(
                        protocol=conn['protocol'],
                        process_name=conn['process_name'],
                        pid=conn['pid'],
                        state=conn['state'],
                        local_address=conn['local_address'],
                        local_port=conn['local_port'],
                        remote_address=conn['remote_address'],
                        remote_port=conn['remote_port'],
                    )
                    entries.append(entry)
                
                i = j
            else:
                i += 1
        
        return entries
    
    def _parse_address(self, addr_str: str) -> tuple:
        """
        Parse address string into (address, port)
        
        Examples:
        - "192.168.1.100:54321" -> ("192.168.1.100", "54321")
        - "[2405:201:3000:f178:e9e2:c15e:2716:4f5a]" -> ("2405:201:3000:f178:e9e2:c15e:2716:4f5a", "")
        - "[2405:201:3000:f178:e9e2:c15e:2716:4f5a]:443" -> ("2405:201:3000:f178:e9e2:c15e:2716:4f5a", "443")
        - "0.0.0.0" -> ("0.0.0.0", "")
        - "*" -> ("*", "")
        """
        if not addr_str or addr_str == '*':
            return ('*', '')
        
        # Handle IPv6 with brackets
        if addr_str.startswith('['):
            # Find the closing bracket
            bracket_end = addr_str.find(']')
            if bracket_end != -1:
                address = addr_str[1:bracket_end]
                # Check if there's a port after the bracket
                if bracket_end + 1 < len(addr_str) and addr_str[bracket_end + 1] == ':':
                    port = addr_str[bracket_end + 2:]
                    return (address, port)
                return (address, '')
        
        # Handle IPv4 or hostname:port
        if ':' in addr_str:
            # Check if it's IPv6 (multiple colons) without brackets
            if addr_str.count(':') > 1:
                return (addr_str, '')
            parts = addr_str.rsplit(':', 1)
            return (parts[0], parts[1])
        
        return (addr_str, '')
    
    def _analyze_risks(self, entry: NetworkConnection) -> List[str]:
        """Analyze connection for risk indicators"""
        risks = []
        
        # Check for listening ports
        if entry.state.upper() in ["LISTENING", "LISTEN"]:
            risks.append("listening_port")
            
            # Check for common ports
            common_ports = {
                "21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP",
                "53": "DNS", "80": "HTTP", "110": "POP3", "143": "IMAP",
                "443": "HTTPS", "445": "SMB", "3389": "RDP",
                "3306": "MySQL", "5432": "PostgreSQL", "27017": "MongoDB",
                "8080": "HTTP-Alt", "8443": "HTTPS-Alt"
            }
            if entry.local_port in common_ports:
                risks.append(f"port_{common_ports[entry.local_port].lower()}")
        
        # Check for external connections
        if entry.remote_address and entry.remote_address != '*':
            remote_ip = entry.remote_address.strip()
            
            # Skip if local
            if remote_ip not in ["0.0.0.0", "::", "127.0.0.1", "::1", "localhost"]:
                # Check if private IP
                private_prefixes = ["10.", "172.16.", "172.17.", "172.18.", "172.19.", 
                                   "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                                   "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                                   "172.30.", "172.31.", "192.168.", "127.", "::1",
                                   "fe80:", "fc00:", "fd00:"]
                
                is_private = any(remote_ip.startswith(prefix) for prefix in private_prefixes)
                
                if not is_private and entry.state.upper() == "ESTABLISHED":
                    risks.append("external_connection")
        
        # Check for suspicious processes listening
        if entry.state.upper() in ["LISTENING", "LISTEN"]:
            suspicious_services = ["python", "node", "java", "mongod", "mysql", "postgres"]
            for service in suspicious_services:
                if service in entry.process_name.lower():
                    risks.append(f"{service}_server")
        
        return risks


def generate_network_report(entries: List[NetworkConnection]) -> str:
    """Generate a human-readable report from network connections"""
    lines = []
    
    lines.append("=" * 100)
    lines.append("  SysPilot-Ai - Network Connections Report")
    lines.append("=" * 100)
    lines.append(f"  Generated: {datetime.now().isoformat()}")
    lines.append(f"  Total Connections: {len(entries)}")
    lines.append("=" * 100)
    lines.append("")
    
    # Statistics
    tcp = [e for e in entries if "TCP" in e.protocol]
    udp = [e for e in entries if "UDP" in e.protocol]
    listening = [e for e in entries if e.state.upper() in ["LISTENING", "LISTEN"]]
    established = [e for e in entries if e.state.upper() == "ESTABLISHED"]
    external = [e for e in entries if "external_connection" in e.risk_indicators]
    
    lines.append(f"  📊 Statistics:")
    lines.append(f"     Total connections:  {len(entries)}")
    lines.append(f"     TCP:                {len(tcp)}")
    lines.append(f"     UDP:                {len(udp)}")
    lines.append(f"     Listening ports:    {len(listening)}")
    lines.append(f"     Established:        {len(established)}")
    lines.append(f"     External:           {len(external)}")
    lines.append("")
    
    # Listening ports
    if listening:
        lines.append("=" * 100)
        lines.append("  🔌 LISTENING PORTS (Services Running)")
        lines.append("=" * 100)
        lines.append("")
        lines.append("  Port  Protocol  PID    Process")
        lines.append("  ----- --------  -----  ---------------")
        
        for entry in sorted(listening, key=lambda e: int(e.local_port) if e.local_port and e.local_port.isdigit() else 99999):
            port = entry.local_port or "*"
            lines.append(f"  {port:5}  {entry.protocol:8}  {entry.pid:5}  {entry.process_name}")
        lines.append("")
    
    # External connections
    if external:
        lines.append("=" * 100)
        lines.append("  🌐 EXTERNAL CONNECTIONS (Internet)")
        lines.append("=" * 100)
        lines.append("")
        lines.append("  Local -> Remote                    Process")
        lines.append("  ---------------------------------  ---------------")
        
        for entry in external[:20]:
            local = f"{entry.local_address}:{entry.local_port}" if entry.local_port else entry.local_address
            remote = f"{entry.remote_address}:{entry.remote_port}" if entry.remote_port else entry.remote_address
            lines.append(f"  {local:<33}  {entry.process_name}")
        lines.append("")
    
    # All connections by process
    lines.append("=" * 100)
    lines.append("  📋 CONNECTIONS BY PROCESS")
    lines.append("=" * 100)
    lines.append("")
    
    # Group by process
    process_connections = {}
    for entry in entries:
        key = f"{entry.process_name} (PID: {entry.pid})"
        if key not in process_connections:
            process_connections[key] = []
        process_connections[key].append(entry)
    
    for process, conns in sorted(process_connections.items()):
        lines.append(f"  {process}:")
        for conn in conns[:5]:
            if conn.protocol.startswith("UDP"):
                lines.append(f"    UDP  {conn.local_address}:{conn.local_port} -> {conn.remote_address}:{conn.remote_port}")
            else:
                lines.append(f"    TCP  {conn.local_address}:{conn.local_port} -> {conn.remote_address}:{conn.remote_port} [{conn.state}]")
        if len(conns) > 5:
            lines.append(f"    ... and {len(conns) - 5} more")
        lines.append("")
    
    lines.append("=" * 100)
    lines.append("  END OF REPORT")
    lines.append("=" * 100)
    
    return '\n'.join(lines)


def save_network_json(entries: List[NetworkConnection], output_dir: str = "reports") -> Path:
    """Save network connections as JSON"""
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = output_path / f"network_{timestamp}.json"
    
    data = {
        'timestamp': datetime.now().isoformat(),
        'total_connections': len(entries),
        'connections': [entry.to_dict() for entry in entries]
    }
    
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    
    return json_file


# For testing
if __name__ == "__main__":
    print("Testing Network Collector...")
    
    collector = NetworkCollector()
    entries = collector.collect()
    
    if entries:
        report = generate_network_report(entries)
        print(report)
        
        # Save reports
        json_file = save_network_json(entries)
        print(f"\n✅ JSON saved to: {json_file}")
    else:
        print("\n❌ No connections found!")