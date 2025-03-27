# DarkLynx Network Toolkit

**Unseen. Unstoppable. Uncover every port.**  
Advanced network reconnaissance and service analysis suite written in Python.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## Installation

```bash
git clone https://github.com/luizgaf/DarkLynx
cd DarkLynx
```

**Features**
⚡ Multi-threaded port scanning (100 threads)

🔍 Service fingerprinting and banner grabbing (HTTP/HTTPS, FTP, SSH, SMTP)

🌐 HTML parsing with automatic domain extraction

📡 DNS resolution with reverse IP lookup

📊 Clean, color-formatted terminal output

⏱️ Real-time progress tracking

Usage
Command	Description	Example
```bash
ps	Port scanning	python darklynx.py ps 192.168.1.1 [start end]
bg	Banner grabbing	python darklynx.py bg 192.168.1.1 80
dr	DNS resolution	python darklynx.py dr example.com
hp	HTML parsing	python darklynx.py hp 192.168.1.1 [port]
```
Examples
1. Comprehensive Port Scan
```bash
# Scan top 1024 ports
python darklynx.py ps 192.168.1.1

# Scan custom range with verbose output
python darklynx.py ps 192.168.1.1 20 443 -v
```
2. Service Interrogation
```bash
# HTTP banner grabbing
python darklynx.py bg 192.168.1.1 80

# HTTPS with SSL handshake
python darklynx.py bg 192.168.1.1 443
```
**Sample Output**
```bash
PORT SCAN RESULTS for 192.168.1.1
----------------------------------------------------
PORT    STATUS   SERVICE           BANNER
----------------------------------------------------
80/tcp  OPEN     http              Apache/2.4.41 (Ubuntu)
22/tcp  OPEN     ssh               SSH-2.0-OpenSSH_8.2p1
443/tcp OPEN     https             nginx/1.18.0 (Ubuntu)
----------------------------------------------------
Scanned 1024 ports in 14.2 seconds (87 open ports)
```
   
Legal Notice
This tool is intended for:

Authorized penetration testing

Network security research

Educational purposes

Always obtain proper authorization before scanning any network. The developers assume no liability for misuse of this software.

License
MIT License - See LICENSE for full text.
