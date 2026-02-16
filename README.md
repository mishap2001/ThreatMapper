# ThreatMapper

ThreatMapper is a Bash-based network vulnerability and attack surface assessment framework.  
It integrates port discovery, service enumeration, CVE correlation, and credential testing into a structured workflow.

---

## Overview

ThreatMapper supports two main scanning modes:

- Basic Scan  
  - Full TCP and UDP port discovery  
  - Service version detection  
  - Credential testing (Hydra)

- Full Scan  
  - Full TCP discovery  
  - Optional full UDP discovery  
  - Service version detection  
  - CVE correlation using Nmap Vulners script  
  - Credential testing  
  - Vulnerability classification by CVSS severity  

It also allows analysis of previously generated results.

---

## Capabilities

### Network Discovery
- IP range validation
- Live host detection
- Full TCP port scanning
- UDP port scanning

### Service Enumeration
- Service and version detection for open ports

### Vulnerability Assessment
- CVE correlation via Nmap + Vulners
- Classification by severity:
  - Low
  - Medium
  - High
  - Critical

### Credential Testing
- Hydra-based brute force for:
  - SSH
  - FTP
  - Telnet
  - RDP
- Default or custom username/password lists

### Results Handling
- Per-host structured output
- Interactive result analysis
- Automatic organization of findings
- ZIP archive generation

---

## Installation

Clone the repository:

```bash
git clone https://github.com/mishap2001/threat-mapper.git
cd threat-mapper
```

Install required dependencies:

```bash
sudo apt update
sudo apt install nmap hydra zip git
```

Ensure Seclists is installed (used for default username/password lists):

```bash
sudo apt install seclists
```

Make the script executable:

```bash
chmod +x Vulnerabilities\ Enumeration\ Tool.sh
```

---

## Usage

Run as root:

```bash
sudo bash Vulnerabilities\ Enumeration\ Tool.sh
```

The script will:

1. Validate root privileges  
2. Request IP range  
3. Discover live hosts  
4. Execute selected scan mode  
5. Perform service enumeration  
6. Run vulnerability assessment (Full mode)  
7. Perform credential testing  
8. Organize results and generate a ZIP archive  

---

## Output Structure

For each scan, a directory is created:

```
<scan_name>/
```

Each host receives its own results folder:

```
<ip>_res/
```

Generated files may include:

- Port discovery results  
- Service enumeration results  
- Vulnerability reports  
- CVSS-classified findings  
- Weak credential findings  

A final archive is generated:

```
<scan_name>.zip
```

---

## Author

Michael Pritsert  
GitHub: https://github.com/mishap2001  
LinkedIn: https://www.linkedin.com/in/michael-pritsert-8168bb38a  
