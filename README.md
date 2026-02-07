# 🔥 Advanced Firewall Rule Analyzer & Optimizer

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A powerful CLI tool for static analysis and optimization of firewall configurations. Detect security issues, redundant rules, shadowed rules, and dangerous exposures across multiple firewall formats.

## ✨ Features

- 🔍 **Comprehensive Analysis**
  - Detect duplicate and shadowed rules
  - Identify overly permissive rules
  - Find conflicting rules
  - Detect dangerous port exposures
  - Identify unused rules
  
- 🛡️ **Security Focused**
  - CIS benchmark compliance checks
  - Dangerous port detection (SSH, RDP, SMB, etc.)
  - Least privilege principle validation
  
- 📊 **Multiple Output Formats**
  - Rich console output with color coding
  - JSON export for automation
  - HTML reports for documentation
  
- 🔧 **Multi-Format Support**
  - iptables
  - nftables
  - UFW (Uncomplicated Firewall)
  - AWS Security Groups
  - Azure NSG
  - Cisco ACL

## 🚀 Installation

```bash
# Clone repository
git clone https://github.com/yourusername/firewall-rule-analyzer.git
cd firewall-rule-analyzer

# Install dependencies
pip install -r requirements.txt
```
📖 Usage

Basic Analysis
```bash
# Auto-detect format and analyze
python firewallruleanalyzer.py firewall-config.txt --format auto

# Specific format
python firewallruleanalyzer.py iptables-save.txt --format iptables
```
Advanced Options
```bash
# Aggressive deep analysis mode
python firewallruleanalyzer.py config.txt --aggressive

# Export to JSON
python firewallruleanalyzer.py config.txt --output results.json

# Export to HTML
python firewallruleanalyzer.py config.txt --output report.html

# Verbose logging
python firewallruleanalyzer.py config.txt --verbose
```
🔒 Security Warning

⚠️ IMPORTANT: This tool performs static analysis only. Always manually review suggestions before applying changes. Incorrect optimizations could impact security or availability.
