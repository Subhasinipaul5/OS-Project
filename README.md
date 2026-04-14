## OS project
## Team Members

- Vanshika  
- Shaheen  
- Subhashini  
##  Objective

The goal of this project is to design a security framework that detects multiple types of vulnerabilities in an operating system environment using a combination of rule-based detection and machine learning techniques.
# OS Security Vulnerability Detection Framework
### National Security AI Protection Layer — v2.0

---
## Key Features

- Real-time system monitoring  
- Detection of multiple attack types  
- Machine Learning-based anomaly detection  
- Interactive web dashboard  
- Lightweight and efficient scanning  
## Project Structure

```

security_framework/
├── security_vulnerability_framework.py   ← Python backend (all 8 modules)
├── index.html                            ← Frontend dashboard
├── style.css                             ← Dark military cyber aesthetic
├── script.js                             ← All JS logic (bugs fixed)
├── requirements.txt                      ← Python dependencies
└── README.md
```
updated  by vanshika - finaltest

---

## What Was Fixed From Original Code

| Original Bug | Fix Applied |
|---|---|
| `import psutilfrom datetime` — missing newline | Split into `import psutil` and `from datetime import datetime` |
| `logging` used before `import logging` | Added `import logging` at top |
| `event_handler` used in `monitor_trapdoor()` before being created | Instantiate `TrapdoorFileHandler()` inside the function |
| `net.bytes_sent` used before `net` was defined in `collect_system_features` | Added `net = psutil.net_io_counters()` |
| JS: `prefix > randomIP.startsWith(prefix)` — comparison operator instead of arrow function | Fixed to `prefix => ip.startsWith(prefix)` |
| JS: `.output` div never closed in CSS | Added closing `}` |
| No `import logging` statement | Added |
| No `import stat` in privilege checks | Added inline imports |

---

## Python Backend Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run full scan (interactive mode)
python security_vulnerability_framework.py

# 3. Run with elevated privileges for full checks (Linux)
sudo python security_vulnerability_framework.py
```

---

## Frontend (Web Dashboard) Setup

No server required — just open in browser:

```bash
# Option 1: Direct open
open index.html        # macOS
xdg-open index.html    # Linux

# Option 2: Local HTTP server (recommended)
python -m http.server 8080
# Then visit: http://localhost:8080
```

---

## Modules

| # | Module | Detects |
|---|---|---|
| 1 | Buffer Overflow | Input length attacks, NOP sleds, shellcode patterns |
| 2 | Trapdoor / Backdoor | Suspicious file creation, file integrity violations |
| 3 | DNS Cache Poisoning | Resolved IPs outside known-good prefixes |
| 4 | Malicious Processes | Offensive tools (nc, metasploit, hydra, etc.) |
| 5 | ML Anomaly Detection | Isolation Forest on CPU/RAM/Network/Disk metrics |
| 6 | Privilege Escalation | SUID binaries, world-writable files, sudoers perms |
| 7 | Network Intrusion | Suspicious connections, data exfiltration spikes |
| 8 | Log Tampering | Log file size shrinkage, cleared security logs |

---

## Requirements

- Python 3.8+
- psutil, watchdog, dnspython, pandas, numpy, scikit-learn
- Modern browser (Chrome, Firefox, Edge) for frontend

---

*For educational and research purposes only.*