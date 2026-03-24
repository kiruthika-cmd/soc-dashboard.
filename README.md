# 🛡️ SOC Log Analyzer & Threat Dashboard

A real-time Security Operations Center (SOC) dashboard that automatically parses Windows Event Logs, detects cyber threats using MITRE ATT&CK based rules, and visualizes security events on an interactive dashboard.

---

## 🚀 Features

- 📋 **Windows Event Log Parsing** — Extracts critical security events (Event IDs: 4625, 4672, 4688, 1102, etc.)
- 🔍 **Anomaly Detection Engine** — Detects brute force, privilege escalation, suspicious processes
- 🧠 **Advanced Threat Detection** — MITRE ATT&CK framework based rules
- 📊 **Live Dashboard** — Real-time threat visualization using Chart.js
- 🗄️ **SQLite Database** — Persistent event and alert storage
- 🌐 **Flask REST API** — Backend API for dashboard data

---

## 🎯 Detection Rules

| Rule | MITRE ATT&CK | Severity |
|------|-------------|----------|
| Brute Force Detection | T1110 | 🔴 CRITICAL |
| Privilege Escalation | T1078 | 🔴 CRITICAL |
| Audit Log Cleared | T1070 | 🔴 CRITICAL |
| Lateral Movement | T1021 | 🟠 HIGH |
| Persistence Mechanism | T1053 / T1543 | 🟠 HIGH |
| Off-Hours Login | T1078 | 🟡 MEDIUM |
| Impossible Travel | T1078 | 🔴 CRITICAL |
| Suspicious Process | T1059 | 🟠 HIGH |

---

## 🏗️ Architecture

```
Windows Event Logs (.evtx)
        ↓
Log Parser (Python)
        ↓
Anomaly Detection Engine (Phase 1 + Phase 2)
        ↓
SQLite Database
        ↓
Flask REST API
        ↓
Live Dashboard (HTML + Chart.js)
```

---

## 🛠️ Tech Stack

- **Backend:** Python, Flask, SQLite
- **Frontend:** HTML, CSS, JavaScript, Chart.js
- **Log Parsing:** python-evtx, regex
- **Detection:** Custom rule engine (MITRE ATT&CK mapped)

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/kiruthika-cmd/soc-dashboard.git
cd soc-dashboard

# Install dependencies
python -m pip install flask python-evtx pandas

# Run log parser
python log_parser.py

# Run Phase 2 advanced detection
python phase2_detection.py

# Start dashboard
python app.py
```

Open browser: `http://localhost:5000`

---

## 📊 Dashboard Preview

- **Event Timeline** — Hourly event distribution chart
- **Severity Distribution** — Donut chart (Critical / High / Medium / Low)
- **Active Alerts Table** — Real-time threat alerts
- **Top Source IPs** — Most active IP addresses

---

## 🧪 Sample Data

The tool comes with built-in sample attack scenarios including:
- Brute force attack simulation (8 failed logins → successful login)
- Privilege escalation chain
- Backdoor user creation from external IP
- Security log clearing (attacker cover-up)
- PowerShell execution post-compromise

---

## 📁 Project Structure

```
soc-dashboard/
├── log_parser.py          # Phase 1: Log parsing + basic detection
├── phase2_detection.py    # Phase 2: Advanced MITRE ATT&CK detection
├── app.py                 # Flask backend API
├── requirements.txt       # Dependencies
├── soc_report.json        # Generated threat report
├── soc_events.db          # SQLite database
└── dashboard/
    └── index.html         # SOC Dashboard UI
```

---

## 👩‍💻 Author

**Kiruthika** — B.E Cyber Security, 2nd Year

---

## 📌 Use Cases

- SOC Analyst training and simulation
- Internship portfolio project
- SIEM tool prototype
- Security awareness demonstration
