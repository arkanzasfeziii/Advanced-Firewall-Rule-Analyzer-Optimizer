#!/usr/bin/env python3
"""
Advanced Firewall Rule Analyzer & Optimizer
A comprehensive CLI tool for analyzing and optimizing firewall configurations.

Author: arkanzasfeziii
License: MIT
Version: 1.0.0
"""

# === Imports ===
import argparse
import ipaddress
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from pydantic import BaseModel, ValidationError, field_validator
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

try:
    import pyfiglet
    PYFIGLET_AVAILABLE = True
except ImportError:
    PYFIGLET_AVAILABLE = False


# === Constants ===
VERSION = "1.0.0"
AUTHOR = "arkanzasfeziii"

LEGAL_WARNING = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                            ⚠️  IMPORTANT WARNING ⚠️                           ║
╟──────────────────────────────────────────────────────────────────────────────╢
║ This tool performs static analysis of firewall configurations.              ║
║ For AUTHORIZED security testing and optimization of YOUR systems only.      ║
║                                                                              ║
║ Incorrect optimizations could impact security or availability.              ║
║ ALWAYS manually review suggestions before applying changes.                 ║
║                                                                              ║
║ Author (arkanzasfeziii) assumes NO liability for misuse or changes.         ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# Common dangerous ports
DANGEROUS_PORTS = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    445: "SMB",
    135: "RPC",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB"
}

# CIS benchmark recommendations
CIS_RECOMMENDATIONS = {
    "default_deny": "Implement default deny policy",
    "logging": "Enable logging for all rules",
    "stateful": "Use stateful inspection",
    "least_privilege": "Apply principle of least privilege",
    "review_cycle": "Review rules quarterly"
}


# === Enums ===
class FirewallFormat(str, Enum):
    """Supported firewall configuration formats."""
    IPTABLES = "iptables"
    NFTABLES = "nftables"
    UFW = "ufw"
    AWS_SG = "aws"
    AZURE_NSG = "azure"
    CISCO_ACL = "cisco"
    AUTO = "auto"


class RuleAction(str, Enum):
    """Firewall rule actions."""
    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"
    REJECT = "reject"
    LOG = "log"


class SeverityLevel(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Protocol(str, Enum):
    """Network protocols."""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ALL = "all"
    ANY = "any"


# === Data Models ===
@dataclass
class FirewallRule:
    """Represents a parsed firewall rule."""
    line_number: int
    action: RuleAction
    protocol: Protocol
    source_ip: str
    source_port: str
    destination_ip: str
    destination_port: str
    interface: str = ""
    chain: str = ""
    comment: str = ""
    counter: int = 0
    raw_rule: str = ""
    
    def matches_traffic(self, other: 'FirewallRule') -> bool:
        """Check if this rule matches same traffic as another rule."""
        return (
            self.protocol == other.protocol and
            self._ip_overlaps(self.source_ip, other.source_ip) and
            self._ip_overlaps(self.destination_ip, other.destination_ip) and
            self._port_overlaps(self.source_port, other.source_port) and
            self._port_overlaps(self.destination_port, other.destination_port)
        )
    
    def shadows(self, other: 'FirewallRule') -> bool:
        """Check if this rule shadows (completely covers) another rule."""
        return (
            self.protocol in [other.protocol, Protocol.ALL, Protocol.ANY] and
            self._ip_contains(self.source_ip, other.source_ip) and
            self._ip_contains(self.destination_ip, other.destination_ip) and
            self._port_contains(self.source_port, other.source_port) and
            self._port_contains(self.destination_port, other.destination_port)
        )
    
    def _ip_overlaps(self, ip1: str, ip2: str) -> bool:
        """Check if IP ranges overlap."""
        try:
            if ip1 == "any" or ip2 == "any" or ip1 == ip2:
                return True
            net1 = ipaddress.ip_network(ip1, strict=False)
            net2 = ipaddress.ip_network(ip2, strict=False)
            return net1.overlaps(net2)
        except:
            return ip1 == ip2
    
    def _ip_contains(self, container: str, contained: str) -> bool:
        """Check if one IP range contains another."""
        try:
            if container == "any":
                return True
            if contained == "any":
                return False
            net1 = ipaddress.ip_network(container, strict=False)
            net2 = ipaddress.ip_network(contained, strict=False)
            return net2.subnet_of(net1) or net1 == net2
        except:
            return container == contained
    
    def _port_overlaps(self, port1: str, port2: str) -> bool:
        """Check if port ranges overlap."""
        if port1 == "any" or port2 == "any" or port1 == port2:
            return True
        
        p1_set = self._parse_port_range(port1)
        p2_set = self._parse_port_range(port2)
        
        return bool(p1_set & p2_set)
    
    def _port_contains(self, container: str, contained: str) -> bool:
        """Check if one port range contains another."""
        if container == "any":
            return True
        if contained == "any":
            return False
        
        p1_set = self._parse_port_range(container)
        p2_set = self._parse_port_range(contained)
        
        return p2_set.issubset(p1_set)
    
    def _parse_port_range(self, port_str: str) -> Set[int]:
        """Parse port string into set of port numbers."""
        if port_str == "any":
            return set(range(1, 65536))
        
        ports = set()
        for part in port_str.split(','):
            part = part.strip()
            if ':' in part or '-' in part:
                # Range
                sep = ':' if ':' in part else '-'
                start, end = part.split(sep)
                ports.update(range(int(start), int(end) + 1))
            else:
                # Single port
                ports.add(int(part))
        
        return ports


@dataclass
class Finding:
    """Represents an analysis finding."""
    category: str
    title: str
    description: str
    severity: SeverityLevel
    rule_numbers: List[int]
    recommendation: str
    cis_reference: str = ""
    affected_rules: List[str] = field(default_factory=list)
    risk_score: int = 0


@dataclass
class AnalysisResult:
    """Complete analysis results."""
    total_rules: int
    findings: List[Finding] = field(default_factory=list)
    optimizations: List[str] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    rules: List[FirewallRule] = field(default_factory=list)


# === Utility Functions ===
def setup_logging(verbose: bool = False) -> logging.Logger:
    """
    Configure logging with rich handler.
    
    Args:
        verbose: Enable verbose logging
        
    Returns:
        Configured logger instance
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)]
    )
    return logging.getLogger("firewallanalyzer")


def is_dangerous_port(port: Union[int, str]) -> Tuple[bool, str]:
    """
    Check if port is commonly targeted.
    
    Args:
        port: Port number or string
        
    Returns:
        Tuple of (is_dangerous, service_name)
    """
    try:
        port_num = int(port)
        if port_num in DANGEROUS_PORTS:
            return True, DANGEROUS_PORTS[port_num]
    except (ValueError, TypeError):
        pass
    return False, ""


def calculate_risk_score(finding: Finding) -> int:
    """Calculate numeric risk score for a finding."""
    severity_scores = {
        SeverityLevel.CRITICAL: 10,
        SeverityLevel.HIGH: 7,
        SeverityLevel.MEDIUM: 5,
        SeverityLevel.LOW: 3,
        SeverityLevel.INFO: 1
    }
    return severity_scores.get(finding.severity, 1)


# === Rule Parsers ===
class RuleParser:
    """Base class for firewall rule parsers."""
    
    def parse(self, content: str) -> List[FirewallRule]:
        """Parse firewall configuration."""
        raise NotImplementedError


class IptablesParser(RuleParser):
    """Parser for iptables-save format."""
    
    def parse(self, content: str) -> List[FirewallRule]:
        """Parse iptables-save output."""
        rules = []
        line_num = 0
        current_chain = ""
        
        for line in content.splitlines():
            line = line.strip()
            line_num += 1
            
            if not line or line.startswith('#'):
                continue
            
            # Chain definition
            if line.startswith(':'):
                parts = line.split()
                if len(parts) >= 2:
                    current_chain = parts[0][1:]
                continue
            
            # Rule
            if line.startswith('-A'):
                rule = self._parse_iptables_rule(line, line_num, current_chain)
                if rule:
                    rules.append(rule)
        
        return rules
    
    def _parse_iptables_rule(self, line: str, line_num: int, chain: str) -> Optional[FirewallRule]:
        """Parse single iptables rule."""
        try:
            parts = line.split()
            
            action = RuleAction.ALLOW
            protocol = Protocol.ALL
            source_ip = "any"
            source_port = "any"
            dest_ip = "any"
            dest_port = "any"
            interface = ""
            comment = ""
            counter = 0
            
            i = 0
            while i < len(parts):
                if parts[i] == '-A':
                    chain = parts[i + 1]
                    i += 2
                elif parts[i] == '-p':
                    protocol = Protocol(parts[i + 1].lower())
                    i += 2
                elif parts[i] == '-s':
                    source_ip = parts[i + 1]
                    i += 2
                elif parts[i] == '-d':
                    dest_ip = parts[i + 1]
                    i += 2
                elif parts[i] == '--sport':
                    source_port = parts[i + 1]
                    i += 2
                elif parts[i] == '--dport':
                    dest_port = parts[i + 1]
                    i += 2
                elif parts[i] in ['-i', '--in-interface']:
                    interface = parts[i + 1]
                    i += 2
                elif parts[i] == '-j':
                    target = parts[i + 1].upper()
                    if target in ['ACCEPT', 'ALLOW']:
                        action = RuleAction.ALLOW
                    elif target in ['DROP', 'REJECT', 'DENY']:
                        action = RuleAction.DENY
                    elif target == 'LOG':
                        action = RuleAction.LOG
                    i += 2
                elif parts[i] == '-m' and i + 1 < len(parts) and parts[i + 1] == 'comment':
                    i += 2
                    if i < len(parts) and parts[i] == '--comment':
                        comment = ' '.join(parts[i + 1:]).strip('"')
                        break
                elif parts[i] == '-c' and i + 2 < len(parts):
                    try:
                        counter = int(parts[i + 1])
                    except ValueError:
                        pass
                    i += 3
                else:
                    i += 1
            
            return FirewallRule(
                line_number=line_num,
                action=action,
                protocol=protocol,
                source_ip=source_ip,
                source_port=source_port,
                destination_ip=dest_ip,
                destination_port=dest_port,
                interface=interface,
                chain=chain,
                comment=comment,
                counter=counter,
                raw_rule=line
            )
        except Exception as e:
            logging.debug(f"Failed to parse iptables rule at line {line_num}: {e}")
            return None


class NFTablesParser(RuleParser):
    """Parser for nftables format."""
    
    def parse(self, content: str) -> List[FirewallRule]:
        """Parse nftables configuration."""
        rules = []
        line_num = 0
        
        for line in content.splitlines():
            line = line.strip()
            line_num += 1
            
            if not line or line.startswith('#'):
                continue
            
            # Simple nftables rule parsing
            if any(keyword in line.lower() for keyword in ['accept', 'drop', 'reject']):
                rule = self._parse_nftables_rule(line, line_num)
                if rule:
                    rules.append(rule)
        
        return rules
    
    def _parse_nftables_rule(self, line: str, line_num: int) -> Optional[FirewallRule]:
        """Parse single nftables rule."""
        try:
            action = RuleAction.ALLOW
            if 'drop' in line.lower():
                action = RuleAction.DENY
            elif 'reject' in line.lower():
                action = RuleAction.REJECT
            elif 'accept' in line.lower():
                action = RuleAction.ALLOW
            
            protocol = Protocol.ALL
            if 'tcp' in line.lower():
                protocol = Protocol.TCP
            elif 'udp' in line.lower():
                protocol = Protocol.UDP
            elif 'icmp' in line.lower():
                protocol = Protocol.ICMP
            
            source_ip = "any"
            dest_ip = "any"
            source_port = "any"
            dest_port = "any"
            
            # Extract IPs
            ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)'
            ips = re.findall(ip_pattern, line)
            if len(ips) >= 1:
                source_ip = ips[0]
            if len(ips) >= 2:
                dest_ip = ips[1]
            
            # Extract ports
            port_pattern = r'dport\s+(\d+)'
            match = re.search(port_pattern, line)
            if match:
                dest_port = match.group(1)
            
            sport_pattern = r'sport\s+(\d+)'
            match = re.search(sport_pattern, line)
            if match:
                source_port = match.group(1)
            
            return FirewallRule(
                line_number=line_num,
                action=action,
                protocol=protocol,
                source_ip=source_ip,
                source_port=source_port,
                destination_ip=dest_ip,
                destination_port=dest_port,
                raw_rule=line
            )
        except Exception as e:
            logging.debug(f"Failed to parse nftables rule at line {line_num}: {e}")
            return None


class UFWParser(RuleParser):
    """Parser for UFW status output."""
    
    def parse(self, content: str) -> List[FirewallRule]:
        """Parse UFW status output."""
        rules = []
        line_num = 0
        
        for line in content.splitlines():
            line = line.strip()
            line_num += 1
            
            if not line or line.startswith('#') or 'Status:' in line or 'To' in line and 'Action' in line:
                continue
            
            rule = self._parse_ufw_rule(line, line_num)
            if rule:
                rules.append(rule)
        
        return rules
    
    def _parse_ufw_rule(self, line: str, line_num: int) -> Optional[FirewallRule]:
        """Parse single UFW rule."""
        try:
            # UFW format: To                         Action      From
            # or: 22/tcp                     ALLOW       Anywhere
            parts = line.split()
            
            if len(parts) < 3:
                return None
            
            dest = parts[0]
            action_str = parts[1].upper()
            source = parts[2] if len(parts) > 2 else "Anywhere"
            
            action = RuleAction.ALLOW if 'ALLOW' in action_str else RuleAction.DENY
            
            # Parse destination (port/protocol)
            protocol = Protocol.ALL
            dest_port = "any"
            
            if '/' in dest:
                port_str, proto_str = dest.split('/')
                dest_port = port_str
                protocol = Protocol(proto_str.lower())
            elif dest.isdigit():
                dest_port = dest
            
            # Parse source
            source_ip = source if source != "Anywhere" else "any"
            
            return FirewallRule(
                line_number=line_num,
                action=action,
                protocol=protocol,
                source_ip=source_ip,
                source_port="any",
                destination_ip="any",
                destination_port=dest_port,
                raw_rule=line
            )
        except Exception as e:
            logging.debug(f"Failed to parse UFW rule at line {line_num}: {e}")
            return None


class AWSSecurityGroupParser(RuleParser):
    """Parser for AWS Security Group JSON export."""
    
    def parse(self, content: str) -> List[FirewallRule]:
        """Parse AWS Security Group JSON."""
        rules = []
        
        try:
            data = json.loads(content)
            line_num = 0
            
            # Handle both single SG and list of SGs
            sgs = data if isinstance(data, list) else [data]
            
            for sg in sgs:
                if not isinstance(sg, dict):
                    continue
                
                # Ingress rules
                for perm in sg.get('IpPermissions', []):
                    line_num += 1
                    rule = self._parse_aws_permission(perm, line_num, RuleAction.ALLOW)
                    if rule:
                        rules.append(rule)
                
                # Egress rules
                for perm in sg.get('IpPermissionsEgress', []):
                    line_num += 1
                    rule = self._parse_aws_permission(perm, line_num, RuleAction.ALLOW)
                    if rule:
                        rules.append(rule)
        
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse AWS Security Group JSON: {e}")
        
        return rules
    
    def _parse_aws_permission(self, perm: Dict, line_num: int, action: RuleAction) -> Optional[FirewallRule]:
        """Parse single AWS permission."""
        try:
            protocol_str = perm.get('IpProtocol', '-1')
            protocol = Protocol.ALL
            
            if protocol_str == 'tcp':
                protocol = Protocol.TCP
            elif protocol_str == 'udp':
                protocol = Protocol.UDP
            elif protocol_str == 'icmp':
                protocol = Protocol.ICMP
            
            from_port = perm.get('FromPort', 'any')
            to_port = perm.get('ToPort', 'any')
            
            port_range = f"{from_port}-{to_port}" if from_port != 'any' and to_port != 'any' else "any"
            
            # Get source IPs
            source_ips = []
            for ip_range in perm.get('IpRanges', []):
                source_ips.append(ip_range.get('CidrIp', 'any'))
            
            for ipv6_range in perm.get('Ipv6Ranges', []):
                source_ips.append(ipv6_range.get('CidrIpv6', 'any'))
            
            source_ip = ','.join(source_ips) if source_ips else 'any'
            
            return FirewallRule(
                line_number=line_num,
                action=action,
                protocol=protocol,
                source_ip=source_ip,
                source_port="any",
                destination_ip="any",
                destination_port=port_range,
                raw_rule=json.dumps(perm)
            )
        except Exception as e:
            logging.debug(f"Failed to parse AWS permission: {e}")
            return None


class AzureNSGParser(RuleParser):
    """Parser for Azure NSG JSON export."""
    
    def parse(self, content: str) -> List[FirewallRule]:
        """Parse Azure NSG JSON."""
        rules = []
        
        try:
            data = json.loads(content)
            
            security_rules = []
            if isinstance(data, dict):
                security_rules = data.get('securityRules', [])
                security_rules.extend(data.get('defaultSecurityRules', []))
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        security_rules.extend(item.get('securityRules', []))
            
            for idx, rule_data in enumerate(security_rules, 1):
                rule = self._parse_azure_rule(rule_data, idx)
                if rule:
                    rules.append(rule)
        
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse Azure NSG JSON: {e}")
        
        return rules
    
    def _parse_azure_rule(self, rule_data: Dict, line_num: int) -> Optional[FirewallRule]:
        """Parse single Azure NSG rule."""
        try:
            props = rule_data.get('properties', {})
            
            action_str = props.get('access', 'Allow')
            action = RuleAction.ALLOW if action_str == 'Allow' else RuleAction.DENY
            
            protocol_str = props.get('protocol', '*').lower()
            protocol = Protocol.ALL
            if protocol_str == 'tcp':
                protocol = Protocol.TCP
            elif protocol_str == 'udp':
                protocol = Protocol.UDP
            elif protocol_str == 'icmp':
                protocol = Protocol.ICMP
            
            source_ip = props.get('sourceAddressPrefix', 'any')
            dest_ip = props.get('destinationAddressPrefix', 'any')
            source_port = str(props.get('sourcePortRange', 'any'))
            dest_port = str(props.get('destinationPortRange', 'any'))
            
            return FirewallRule(
                line_number=line_num,
                action=action,
                protocol=protocol,
                source_ip=source_ip,
                source_port=source_port,
                destination_ip=dest_ip,
                destination_port=dest_port,
                comment=rule_data.get('name', ''),
                raw_rule=json.dumps(rule_data)
            )
        except Exception as e:
            logging.debug(f"Failed to parse Azure NSG rule: {e}")
            return None


class CiscoACLParser(RuleParser):
    """Parser for basic Cisco ACL format."""
    
    def parse(self, content: str) -> List[FirewallRule]:
        """Parse Cisco ACL configuration."""
        rules = []
        line_num = 0
        
        for line in content.splitlines():
            line = line.strip()
            line_num += 1
            
            if not line or line.startswith('!'):
                continue
            
            if line.startswith(('permit', 'deny')):
                rule = self._parse_cisco_rule(line, line_num)
                if rule:
                    rules.append(rule)
        
        return rules
    
    def _parse_cisco_rule(self, line: str, line_num: int) -> Optional[FirewallRule]:
        """Parse single Cisco ACL rule."""
        try:
            parts = line.split()
            
            action = RuleAction.ALLOW if parts[0] == 'permit' else RuleAction.DENY
            protocol = Protocol(parts[1].lower()) if len(parts) > 1 else Protocol.ALL
            
            source_ip = "any"
            dest_ip = "any"
            source_port = "any"
            dest_port = "any"
            
            # Simple parsing: permit/deny protocol source dest
            if len(parts) >= 4:
                source_ip = parts[2] if parts[2] != 'any' else "any"
                dest_ip = parts[3] if parts[3] != 'any' else "any"
            
            # Look for port specifications
            if 'eq' in parts:
                eq_idx = parts.index('eq')
                if eq_idx + 1 < len(parts):
                    dest_port = parts[eq_idx + 1]
            
            return FirewallRule(
                line_number=line_num,
                action=action,
                protocol=protocol,
                source_ip=source_ip,
                source_port=source_port,
                destination_ip=dest_ip,
                destination_port=dest_port,
                raw_rule=line
            )
        except Exception as e:
            logging.debug(f"Failed to parse Cisco ACL rule at line {line_num}: {e}")
            return None


# === Format Detection ===
class FormatDetector:
    """Automatically detect firewall configuration format."""
    
    @staticmethod
    def detect(content: str) -> FirewallFormat:
        """Detect configuration format from content."""
        content_lower = content.lower()
        
        # Check for JSON formats first
        if content.strip().startswith('{') or content.strip().startswith('['):
            try:
                data = json.loads(content)
                if isinstance(data, dict):
                    if 'IpPermissions' in data or 'GroupId' in data:
                        return FirewallFormat.AWS_SG
                    if 'securityRules' in data or 'defaultSecurityRules' in data:
                        return FirewallFormat.AZURE_NSG
                elif isinstance(data, list) and len(data) > 0:
                    first = data[0]
                    if isinstance(first, dict):
                        if 'IpPermissions' in first:
                            return FirewallFormat.AWS_SG
                        if 'securityRules' in first or 'properties' in first:
                            return FirewallFormat.AZURE_NSG
            except json.JSONDecodeError:
                pass
        
        # Check for text-based formats
        if 'table inet' in content_lower or 'nft ' in content_lower:
            return FirewallFormat.NFTABLES
        
        if '-A ' in content and '-j ' in content:
            return FirewallFormat.IPTABLES
        
        if 'status:' in content_lower and 'action' in content_lower:
            return FirewallFormat.UFW
        
        if 'permit ' in content_lower or 'deny ' in content_lower:
            if 'access-list' in content_lower or 'ip access-list' in content_lower:
                return FirewallFormat.CISCO_ACL
        
        # Default to iptables
        return FirewallFormat.IPTABLES


# === Analysis Logic ===
class FirewallAnalyzer:
    """Core analysis engine for firewall rules."""
    
    def __init__(self, rules: List[FirewallRule], aggressive: bool = False):
        """
        Initialize analyzer.
        
        Args:
            rules: List of parsed firewall rules
            aggressive: Enable aggressive analysis mode
        """
        self.rules = rules
        self.aggressive = aggressive
        self.findings: List[Finding] = []
    
    def analyze(self) -> AnalysisResult:
        """
        Run complete analysis.
        
        Returns:
            Analysis results
        """
        self.findings = []
        
        self._detect_duplicates()
        self._detect_shadowed_rules()
        self._detect_overly_permissive()
        self._detect_conflicts()
        self._check_dangerous_exposures()
        self._check_unused_rules()
        
        if self.aggressive:
            self._deep_analysis()
        
        # Calculate statistics
        stats = self._calculate_statistics()
        
        # Generate optimizations
        optimizations = self._generate_optimizations()
        
        return AnalysisResult(
            total_rules=len(self.rules),
            findings=self.findings,
            optimizations=optimizations,
            statistics=stats,
            rules=self.rules
        )
    
    def _detect_duplicates(self) -> None:
        """Detect exact duplicate rules."""
        seen = {}
        
        for rule in self.rules:
            key = (
                rule.action,
                rule.protocol,
                rule.source_ip,
                rule.source_port,
                rule.destination_ip,
                rule.destination_port
            )
            
            if key in seen:
                self.findings.append(Finding(
                    category="Redundancy",
                    title="Duplicate Rule Detected",
                    description=f"Rule at line {rule.line_number} is identical to rule at line {seen[key]}",
                    severity=SeverityLevel.MEDIUM,
                    rule_numbers=[rule.line_number, seen[key]],
                    recommendation="Remove duplicate rule to simplify configuration and improve performance.",
                    affected_rules=[rule.raw_rule, self.rules[seen[key] - 1].raw_rule]
                ))
            else:
                seen[key] = rule.line_number
    
    def _detect_shadowed_rules(self) -> None:
        """Detect rules that are shadowed by earlier rules."""
        for i, rule in enumerate(self.rules):
            for j in range(i):
                earlier_rule = self.rules[j]
                
                if earlier_rule.shadows(rule) and earlier_rule.action == rule.action:
                    self.findings.append(Finding(
                        category="Shadowing",
                        title="Shadowed Rule Detected",
                        description=f"Rule at line {rule.line_number} will never match because "
                                   f"rule at line {earlier_rule.line_number} covers the same traffic",
                        severity=SeverityLevel.HIGH,
                        rule_numbers=[rule.line_number, earlier_rule.line_number],
                        recommendation="Remove shadowed rule or reorder rules if different action is intended.",
                        cis_reference="CIS: Review rule ordering",
                        affected_rules=[rule.raw_rule, earlier_rule.raw_rule]
                    ))
    
    def _detect_overly_permissive(self) -> None:
        """Detect overly permissive rules."""
        for rule in self.rules:
            if rule.action != RuleAction.ALLOW:
                continue
            
            issues = []
            severity = SeverityLevel.LOW
            
            # Check for any source
            if rule.source_ip in ["any", "0.0.0.0/0", "::/0"]:
                issues.append("any source IP")
                severity = SeverityLevel.MEDIUM
            
            # Check for any destination
            if rule.destination_ip in ["any", "0.0.0.0/0", "::/0"]:
                issues.append("any destination IP")
            
            # Check for any port
            if rule.destination_port == "any" and rule.protocol in [Protocol.TCP, Protocol.UDP]:
                issues.append("any port")
                severity = SeverityLevel.MEDIUM
            
            # Check for protocol any
            if rule.protocol in [Protocol.ALL, Protocol.ANY]:
                issues.append("any protocol")
                severity = SeverityLevel.HIGH
            
            if issues:
                self.findings.append(Finding(
                    category="Overly Permissive",
                    title="Overly Permissive Rule",
                    description=f"Rule at line {rule.line_number} allows {', '.join(issues)}",
                    severity=severity,
                    rule_numbers=[rule.line_number],
                    recommendation="Apply principle of least privilege. Restrict to specific IPs, "
                                  "ports, and protocols needed for legitimate traffic.",
                    cis_reference="CIS: Implement least privilege principle",
                    affected_rules=[rule.raw_rule]
                ))
    
    def _detect_conflicts(self) -> None:
        """Detect conflicting rules."""
        for i, rule in enumerate(self.rules):
            for j in range(i + 1, len(self.rules)):
                other_rule = self.rules[j]
                
                if (rule.matches_traffic(other_rule) and 
                    rule.action != other_rule.action):
                    
                    self.findings.append(Finding(
                        category="Conflicts",
                        title="Conflicting Rules Detected",
                        description=f"Rules at lines {rule.line_number} and {other_rule.line_number} "
                                   f"match same traffic but have different actions "
                                   f"({rule.action.value} vs {other_rule.action.value})",
                        severity=SeverityLevel.HIGH,
                        rule_numbers=[rule.line_number, other_rule.line_number],
                        recommendation="Review rule ordering and actions to ensure intended behavior. "
                                      "First matching rule will be applied.",
                        affected_rules=[rule.raw_rule, other_rule.raw_rule]
                    ))
    
    def _check_dangerous_exposures(self) -> None:
        """Check for dangerous port exposures."""
        for rule in self.rules:
            if rule.action != RuleAction.ALLOW:
                continue
            
            if rule.source_ip not in ["any", "0.0.0.0/0", "::/0"]:
                continue
            
            # Check if dangerous port is exposed
            try:
                if rule.destination_port.isdigit():
                    is_dangerous, service = is_dangerous_port(int(rule.destination_port))
                    if is_dangerous:
                        self.findings.append(Finding(
                            category="Security Risk",
                            title=f"Dangerous Port Exposed: {service}",
                            description=f"Rule at line {rule.line_number} exposes {service} "
                                       f"(port {rule.destination_port}) to any source",
                            severity=SeverityLevel.CRITICAL,
                            rule_numbers=[rule.line_number],
                            recommendation=f"Restrict access to {service} to specific trusted IPs only. "
                                          f"Consider using VPN or bastion host for administrative access.",
                            cis_reference="CIS: Restrict administrative access",
                            affected_rules=[rule.raw_rule]
                        ))
            except ValueError:
                pass
    
    def _check_unused_rules(self) -> None:
        """Check for potentially unused rules based on counters."""
        for rule in self.rules:
            if rule.counter == 0:
                self.findings.append(Finding(
                    category="Maintenance",
                    title="Potentially Unused Rule",
                    description=f"Rule at line {rule.line_number} has zero hits",
                    severity=SeverityLevel.INFO,
                    rule_numbers=[rule.line_number],
                    recommendation="Review if this rule is still needed. Remove if obsolete.",
                    affected_rules=[rule.raw_rule]
                ))
    
    def _deep_analysis(self) -> None:
        """Perform deep analysis (aggressive mode)."""
        # Check for default deny policy
        has_default_deny = False
        for rule in self.rules:
            if (rule.action == RuleAction.DENY and 
                rule.source_ip == "any" and 
                rule.destination_ip == "any"):
                has_default_deny = True
                break
        
        if not has_default_deny:
            self.findings.append(Finding(
                category="Best Practices",
                title="No Default Deny Policy",
                description="Firewall does not have an explicit default deny rule",
                severity=SeverityLevel.MEDIUM,
                rule_numbers=[],
                recommendation="Add a default deny rule at the end of your ruleset to block "
                              "all traffic not explicitly allowed.",
                cis_reference="CIS: Implement default deny"
            ))
    
    def _calculate_statistics(self) -> Dict[str, Any]:
        """Calculate firewall statistics."""
        stats = {
            "total_rules": len(self.rules),
            "allow_rules": sum(1 for r in self.rules if r.action == RuleAction.ALLOW),
            "deny_rules": sum(1 for r in self.rules if r.action in [RuleAction.DENY, RuleAction.DROP, RuleAction.REJECT]),
            "tcp_rules": sum(1 for r in self.rules if r.protocol == Protocol.TCP),
            "udp_rules": sum(1 for r in self.rules if r.protocol == Protocol.UDP),
            "icmp_rules": sum(1 for r in self.rules if r.protocol == Protocol.ICMP),
            "permissive_rules": sum(1 for r in self.rules if r.source_ip in ["any", "0.0.0.0/0"]),
            "findings_by_severity": {
                "critical": sum(1 for f in self.findings if f.severity == SeverityLevel.CRITICAL),
                "high": sum(1 for f in self.findings if f.severity == SeverityLevel.HIGH),
                "medium": sum(1 for f in self.findings if f.severity == SeverityLevel.MEDIUM),
                "low": sum(1 for f in self.findings if f.severity == SeverityLevel.LOW),
                "info": sum(1 for f in self.findings if f.severity == SeverityLevel.INFO)
            }
        }
        return stats
    
    def _generate_optimizations(self) -> List[str]:
        """Generate optimization suggestions."""
        optimizations = []
        
        # Suggest removing duplicates
        duplicate_findings = [f for f in self.findings if f.category == "Redundancy"]
        if duplicate_findings:
            optimizations.append(
                f"Remove {len(duplicate_findings)} duplicate rule(s) to reduce configuration size"
            )
        
        # Suggest removing shadowed rules
        shadowed_findings = [f for f in self.findings if f.category == "Shadowing"]
        if shadowed_findings:
            optimizations.append(
                f"Remove or reorder {len(shadowed_findings)} shadowed rule(s) for clarity"
            )
        
        # Suggest consolidating rules
        if len(self.rules) > 50:
            optimizations.append(
                "Consider consolidating rules where possible to improve performance"
            )
        
        # Suggest rule ordering for performance
        unused = [f for f in self.findings if f.category == "Maintenance"]
        if unused:
            optimizations.append(
                f"Consider removing {len(unused)} unused rule(s)"
            )
        
        return optimizations


# === Reporting ===
class Reporter:
    """Generate formatted analysis reports."""
    
    def __init__(self, console: Console):
        """Initialize reporter."""
        self.console = console
    
    def print_summary(self, result: AnalysisResult) -> None:
        """Print analysis summary to console."""
        self.console.print("\n" + "=" * 80)
        self.console.print("[bold cyan]Firewall Rule Analysis Summary[/bold cyan]")
        self.console.print("=" * 80 + "\n")
        
        # Statistics
        stats_table = Table(show_header=False, box=None)
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="white")
        
        stats_table.add_row("Total Rules", str(result.statistics.get('total_rules', 0)))
        stats_table.add_row("Allow Rules", str(result.statistics.get('allow_rules', 0)))
        stats_table.add_row("Deny Rules", str(result.statistics.get('deny_rules', 0)))
        stats_table.add_row("TCP Rules", str(result.statistics.get('tcp_rules', 0)))
        stats_table.add_row("UDP Rules", str(result.statistics.get('udp_rules', 0)))
        stats_table.add_row("Total Findings", str(len(result.findings)))
        
        self.console.print(stats_table)
        
        # Findings by severity
        if result.findings:
            self.console.print("\n[bold cyan]Findings by Severity[/bold cyan]\n")
            
            sev_counts = result.statistics.get('findings_by_severity', {})
            severity_table = Table(show_header=True, header_style="bold magenta")
            severity_table.add_column("Severity", style="yellow")
            severity_table.add_column("Count", justify="right", style="white")
            
            for severity in ["critical", "high", "medium", "low", "info"]:
                count = sev_counts.get(severity, 0)
                if count > 0:
                    color = self._get_severity_color(SeverityLevel(severity))
                    severity_table.add_row(
                        f"[{color}]{severity.upper()}[/{color}]",
                        str(count)
                    )
            
            self.console.print(severity_table)
            
            # Detailed findings
            self.console.print("\n[bold cyan]Detailed Findings[/bold cyan]\n")
            for i, finding in enumerate(sorted(result.findings, key=lambda x: self._severity_rank(x.severity)), 1):
                self._print_finding(finding, i)
        else:
            self.console.print("\n[bold green]✓ No security issues detected[/bold green]\n")
        
        # Optimizations
        if result.optimizations:
            self.console.print("\n[bold cyan]Optimization Recommendations[/bold cyan]\n")
            for opt in result.optimizations:
                self.console.print(f"[green]•[/green] {opt}")
        
        self.console.print("\n" + "=" * 80 + "\n")
    
    def _print_finding(self, finding: Finding, index: int) -> None:
        """Print detailed finding."""
        color = self._get_severity_color(finding.severity)
        
        panel_content = f"""[bold]Category:[/bold] {finding.category}
[bold]Severity:[/bold] [{color}]{finding.severity.value.upper()}[/{color}]
[bold]Affected Rules:[/bold] Lines {', '.join(map(str, finding.rule_numbers))}

[bold]Description:[/bold]
{finding.description}

[bold]Recommendation:[/bold]
{finding.recommendation}
"""
        
        if finding.cis_reference:
            panel_content += f"\n[bold]CIS Reference:[/bold] {finding.cis_reference}"
        
        if finding.affected_rules:
            panel_content += "\n\n[bold]Affected Rule(s):[/bold]"
            for rule in finding.affected_rules[:2]:  # Show max 2 rules
                panel_content += f"\n[dim]{rule[:100]}{'...' if len(rule) > 100 else ''}[/dim]"
        
        panel = Panel(
            panel_content,
            title=f"[bold]Finding #{index}: {finding.title}[/bold]",
            border_style=color
        )
        
        self.console.print(panel)
        self.console.print()
    
    def _get_severity_color(self, severity: SeverityLevel) -> str:
        """Get color for severity."""
        colors = {
            SeverityLevel.CRITICAL: "bold red",
            SeverityLevel.HIGH: "red",
            SeverityLevel.MEDIUM: "yellow",
            SeverityLevel.LOW: "blue",
            SeverityLevel.INFO: "cyan"
        }
        return colors.get(severity, "white")
    
    def _severity_rank(self, severity: SeverityLevel) -> int:
        """Get numeric rank for sorting."""
        ranks = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4
        }
        return ranks.get(severity, 5)
    
    def export_json(self, result: AnalysisResult, filepath: Path) -> None:
        """Export results to JSON."""
        data = {
            "total_rules": result.total_rules,
            "statistics": result.statistics,
            "findings": [
                {
                    "category": f.category,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "rule_numbers": f.rule_numbers,
                    "recommendation": f.recommendation,
                    "cis_reference": f.cis_reference,
                    "affected_rules": f.affected_rules
                }
                for f in result.findings
            ],
            "optimizations": result.optimizations
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        self.console.print(f"\n[green]✓ Results exported to {filepath}[/green]")
    
    def export_html(self, result: AnalysisResult, filepath: Path) -> None:
        """Export results to HTML."""
        html = self._generate_html_report(result)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        self.console.print(f"\n[green]✓ HTML report exported to {filepath}[/green]")
    
    def _generate_html_report(self, result: AnalysisResult) -> str:
        """Generate HTML report content."""
        findings_html = ""
        for i, finding in enumerate(result.findings, 1):
            severity_class = finding.severity.value
            findings_html += f"""
        <div class="finding {severity_class}">
            <h3>{i}. {finding.title} <span class="severity {severity_class}">{finding.severity.value.upper()}</span></h3>
            <p><strong>Category:</strong> {finding.category}</p>
            <p><strong>Affected Rules:</strong> Lines {', '.join(map(str, finding.rule_numbers))}</p>
            <p><strong>Description:</strong> {finding.description}</p>
            <p><strong>Recommendation:</strong> {finding.recommendation}</p>
"""
            if finding.cis_reference:
                findings_html += f"<p><strong>CIS Reference:</strong> {finding.cis_reference}</p>"
            
            findings_html += "</div>"
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Firewall Rule Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .summary {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .finding {{ margin: 20px 0; padding: 15px; border-left: 4px solid #95a5a6; background: #f8f9fa; }}
        .finding.critical {{ border-left-color: #e74c3c; }}
        .finding.high {{ border-left-color: #e67e22; }}
        .finding.medium {{ border-left-color: #f39c12; }}
        .finding.low {{ border-left-color: #3498db; }}
        .finding.info {{ border-left-color: #1abc9c; }}
        .severity {{ display: inline-block; padding: 3px 10px; border-radius: 3px; color: white; font-weight: bold; font-size: 12px; }}
        .severity.critical {{ background: #e74c3c; }}
        .severity.high {{ background: #e67e22; }}
        .severity.medium {{ background: #f39c12; }}
        .severity.low {{ background: #3498db; }}
        .severity.info {{ background: #1abc9c; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Firewall Rule Analysis Report</h1>
        
        <div class="summary">
            <h2>Summary</h2>
            <p><strong>Total Rules:</strong> {result.total_rules}</p>
            <p><strong>Total Findings:</strong> {len(result.findings)}</p>
            <p><strong>Allow Rules:</strong> {result.statistics.get('allow_rules', 0)}</p>
            <p><strong>Deny Rules:</strong> {result.statistics.get('deny_rules', 0)}</p>
        </div>
        
        <h2>Findings ({len(result.findings)})</h2>
        {findings_html}
        
        <div class="metadata">
            <p>Generated by Advanced Firewall Rule Analyzer v{VERSION} | Author: {AUTHOR}</p>
        </div>
    </div>
</body>
</html>
"""
        return html


# === Core Analyzer ===
class FirewallRuleAnalyzer:
    """Main analyzer orchestrating all components."""
    
    def __init__(self, config_path: Path, format_type: FirewallFormat, aggressive: bool):
        """Initialize analyzer."""
        self.config_path = config_path
        self.format_type = format_type
        self.aggressive = aggressive
        self.console = Console()
        self.logger = setup_logging(False)
    
    def run(self) -> AnalysisResult:
        """Run complete analysis."""
        self._print_banner()
        
        try:
            # Read configuration
            content = self._read_config()
            
            # Detect format if auto
            if self.format_type == FirewallFormat.AUTO:
                self.format_type = FormatDetector.detect(content)
                self.console.print(f"[cyan]Detected format:[/cyan] {self.format_type.value.upper()}\n")
            
            # Parse rules
            parser = self._get_parser(self.format_type)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                task = progress.add_task("Parsing rules...", total=None)
                rules = parser.parse(content)
                progress.remove_task(task)
            
            self.console.print(f"[green]✓ Parsed {len(rules)} rules[/green]\n")
            
            # Analyze
            analyzer = FirewallAnalyzer(rules, self.aggressive)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                task = progress.add_task("Analyzing rules...", total=None)
                result = analyzer.analyze()
                progress.remove_task(task)
            
            return result
            
        except Exception as e:
            self.logger.exception("Analysis failed")
            raise
    
    def _read_config(self) -> str:
        """Read configuration file."""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        except PermissionError:
            raise PermissionError(f"Permission denied reading: {self.config_path}")
        except Exception as e:
            raise Exception(f"Error reading configuration: {e}")
    
    def _get_parser(self, format_type: FirewallFormat) -> RuleParser:
        """Get appropriate parser for format."""
        parsers = {
            FirewallFormat.IPTABLES: IptablesParser(),
            FirewallFormat.NFTABLES: NFTablesParser(),
            FirewallFormat.UFW: UFWParser(),
            FirewallFormat.AWS_SG: AWSSecurityGroupParser(),
            FirewallFormat.AZURE_NSG: AzureNSGParser(),
            FirewallFormat.CISCO_ACL: CiscoACLParser()
        }
        return parsers.get(format_type, IptablesParser())
    
    def _print_banner(self) -> None:
        """Print application banner."""
        if PYFIGLET_AVAILABLE:
            banner = pyfiglet.figlet_format("Firewall Analyzer", font="slant")
            self.console.print(f"[bold cyan]{banner}[/bold cyan]")
        else:
            self.console.print("\n[bold cyan]" + "=" * 70 + "[/bold cyan]")
            self.console.print("[bold cyan]    Advanced Firewall Rule Analyzer v" + VERSION + "[/bold cyan]")
            self.console.print("[bold cyan]" + "=" * 70 + "[/bold cyan]\n")
        
        self.console.print(f"[dim]Author: {AUTHOR}[/dim]\n")


# === CLI ===
def print_examples() -> None:
    """Print usage examples."""
    console = Console()
    
    examples = """
[bold cyan]Usage Examples:[/bold cyan]

[bold yellow]1. Analyze iptables-save output:[/bold yellow]
   [green]python firewallruleanalyzer.py iptables-save.txt --format iptables[/green]

[bold yellow]2. Auto-detect format and analyze:[/bold yellow]
   [green]python firewallruleanalyzer.py firewall-config.txt --format auto[/green]

[bold yellow]3. Analyze UFW status:[/bold yellow]
   [green]ufw status verbose > ufw.txt[/green]
   [green]python firewallruleanalyzer.py ufw.txt --format ufw[/green]

[bold yellow]4. Analyze AWS Security Group (JSON export):[/bold yellow]
   [green]python firewallruleanalyzer.py security-group.json --format aws[/green]

[bold yellow]5. Analyze with aggressive mode and export:[/bold yellow]
   [green]python firewallruleanalyzer.py config.txt --aggressive --output report.html[/green]

[bold yellow]6. Export to JSON:[/bold yellow]
   [green]python firewallruleanalyzer.py config.txt --output results.json[/green]

[bold yellow]7. Analyze nftables configuration:[/bold yellow]
   [green]nft list ruleset > nftables.conf[/green]
   [green]python firewallruleanalyzer.py nftables.conf --format nftables[/green]
"""
    
    console.print(examples)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Advanced Firewall Rule Analyzer & Optimizer - Static analysis of firewall configurations",
        epilog=f"Author: {AUTHOR} | Version: {VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        'config',
        type=Path,
        help='Firewall configuration file or directory'
    )
    
    parser.add_argument(
        '--format',
        choices=['iptables', 'nftables', 'ufw', 'aws', 'azure', 'cisco', 'auto'],
        default='auto',
        help='Configuration format (default: auto-detect)'
    )
    
    parser.add_argument(
        '--aggressive',
        action='store_true',
        help='Enable aggressive deep analysis mode'
    )
    
    parser.add_argument(
        '--output',
        type=Path,
        help='Export results to file (.json or .html)'
    )
    
    parser.add_argument(
        '--examples',
        action='store_true',
        help='Show usage examples and exit'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    console = Console()
    
    # Show examples if requested
    if args.examples:
        print_examples()
        return 0
    
    # Display warning
    console.print(LEGAL_WARNING, style="bold yellow")
    
    if not args.config.exists():
        console.print(f"[red]Error: Configuration file not found: {args.config}[/red]")
        return 1
    
    try:
        # Run analysis
        analyzer = FirewallRuleAnalyzer(
            args.config,
            FirewallFormat(args.format),
            args.aggressive
        )
        result = analyzer.run()
        
        # Display results
        reporter = Reporter(console)
        reporter.print_summary(result)
        
        # Export if requested
        if args.output:
            if args.output.suffix == '.json':
                reporter.export_json(result, args.output)
            elif args.output.suffix == '.html':
                reporter.export_html(result, args.output)
            else:
                console.print("[yellow]Warning: Unknown output format, defaulting to JSON[/yellow]")
                reporter.export_json(result, args.output.with_suffix('.json'))
        
        # Return code based on findings
        critical_findings = sum(1 for f in result.findings if f.severity == SeverityLevel.CRITICAL)
        if critical_findings > 0:
            return 1
        
        return 0
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logging.exception("Fatal error")
        return 1


if __name__ == '__main__':
    sys.exit(main())
