"""
SOC Log Analyzer - Phase 1: Log Parser
Author: Your Name
Description: Parses Windows Event Logs (.evtx) and extracts security-relevant events
"""

import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path

# Try importing evtx parser
try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False
    print("[!] python-evtx not installed. Using sample log mode.")
    print("[!] Install with: pip install python-evtx")

# ─────────────────────────────────────────────
# CRITICAL EVENT IDs TO MONITOR
# ─────────────────────────────────────────────
CRITICAL_EVENT_IDS = {
    4624: {"name": "Successful Login",        "severity": "LOW"},
    4625: {"name": "Failed Login",             "severity": "HIGH"},
    4634: {"name": "Logoff",                   "severity": "LOW"},
    4648: {"name": "Explicit Credential Login","severity": "MEDIUM"},
    4672: {"name": "Admin Privilege Assigned", "severity": "HIGH"},
    4688: {"name": "New Process Created",      "severity": "MEDIUM"},
    4698: {"name": "Scheduled Task Created",   "severity": "HIGH"},
    4720: {"name": "User Account Created",     "severity": "HIGH"},
    4726: {"name": "User Account Deleted",     "severity": "HIGH"},
    1102: {"name": "Audit Log Cleared",        "severity": "CRITICAL"},
    7045: {"name": "New Service Installed",    "severity": "HIGH"},
}

SUSPICIOUS_PROCESSES = [
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "net.exe", "whoami.exe", "mimikatz.exe"
]


# ─────────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────────
def init_database(db_path="soc_events.db"):
    """Initialize SQLite database with required tables"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            event_name TEXT,
            severity TEXT,
            timestamp TEXT,
            username TEXT,
            source_ip TEXT,
            process_name TEXT,
            raw_message TEXT,
            parsed_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            severity TEXT,
            description TEXT,
            username TEXT,
            source_ip TEXT,
            event_count INTEGER,
            first_seen TEXT,
            last_seen TEXT,
            created_at TEXT
        )
    """)

    conn.commit()
    conn.close()
    print("[+] Database initialized: soc_events.db")


# ─────────────────────────────────────────────
# EVTX PARSER
# ─────────────────────────────────────────────
def parse_evtx_file(evtx_path):
    """Parse a Windows .evtx file and extract security events"""
    if not EVTX_AVAILABLE:
        print("[!] python-evtx not available. Use generate_sample_logs() instead.")
        return []

    events = []
    print(f"[*] Parsing: {evtx_path}")

    try:
        with Evtx(evtx_path) as log:
            for xml_str, record in evtx_file_xml_view(log.get_file_header()):
                event = parse_xml_event(xml_str)
                if event:
                    events.append(event)
    except Exception as e:
        print(f"[!] Error parsing {evtx_path}: {e}")

    print(f"[+] Extracted {len(events)} relevant events")
    return events


def parse_xml_event(xml_str):
    """Extract fields from XML event string"""
    try:
        # Extract Event ID
        event_id_match = re.search(r'<EventID[^>]*>(\d+)</EventID>', xml_str)
        if not event_id_match:
            return None

        event_id = int(event_id_match.group(1))
        if event_id not in CRITICAL_EVENT_IDS:
            return None

        # Extract Timestamp
        time_match = re.search(r'SystemTime="([^"]+)"', xml_str)
        timestamp = time_match.group(1) if time_match else "Unknown"

        # Extract Username
        user_match = re.search(r'<Data Name="TargetUserName">([^<]+)</Data>', xml_str)
        username = user_match.group(1) if user_match else "Unknown"

        # Extract Source IP
        ip_match = re.search(r'<Data Name="IpAddress">([^<]+)</Data>', xml_str)
        source_ip = ip_match.group(1) if ip_match else "-"

        # Extract Process Name
        proc_match = re.search(r'<Data Name="NewProcessName">([^<]+)</Data>', xml_str)
        process_name = proc_match.group(1) if proc_match else "-"

        event_info = CRITICAL_EVENT_IDS[event_id]

        return {
            "event_id": event_id,
            "event_name": event_info["name"],
            "severity": event_info["severity"],
            "timestamp": timestamp,
            "username": username,
            "source_ip": source_ip,
            "process_name": process_name,
            "raw_message": xml_str[:500]
        }
    except Exception:
        return None


# ─────────────────────────────────────────────
# SAMPLE LOG GENERATOR (for testing)
# ─────────────────────────────────────────────
def generate_sample_logs():
    """Generate realistic sample logs for testing without .evtx file"""
    import random

    print("[*] Generating sample logs for testing...")

    sample_users = ["admin", "john.doe", "jane.smith", "svc_account", "guest"]
    attacker_ips = ["192.168.1.105", "10.0.0.55", "172.16.0.22", "203.0.113.42"]
    normal_ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]

    events = []
    base_time = datetime(2024, 3, 15, 8, 0, 0)

    # Simulate brute force attack
    for i in range(8):
        events.append({
            "event_id": 4625,
            "event_name": "Failed Login",
            "severity": "HIGH",
            "timestamp": base_time.replace(minute=i*2).isoformat(),
            "username": "admin",
            "source_ip": "203.0.113.42",
            "process_name": "-",
            "raw_message": f"Failed login attempt {i+1} from external IP"
        })

    # Simulate successful login after brute force
    events.append({
        "event_id": 4624,
        "event_name": "Successful Login",
        "severity": "LOW",
        "timestamp": base_time.replace(minute=20).isoformat(),
        "username": "admin",
        "source_ip": "203.0.113.42",
        "process_name": "-",
        "raw_message": "Successful login - possible compromise after brute force"
    })

    # Privilege escalation
    events.append({
        "event_id": 4672,
        "event_name": "Admin Privilege Assigned",
        "severity": "HIGH",
        "timestamp": base_time.replace(minute=21).isoformat(),
        "username": "admin",
        "source_ip": "203.0.113.42",
        "process_name": "-",
        "raw_message": "Admin privileges assigned shortly after suspicious login"
    })

    # Suspicious process
    events.append({
        "event_id": 4688,
        "event_name": "New Process Created",
        "severity": "MEDIUM",
        "timestamp": base_time.replace(minute=22).isoformat(),
        "username": "admin",
        "source_ip": "-",
        "process_name": "powershell.exe",
        "raw_message": "PowerShell spawned after privilege escalation"
    })

    # Log cleared - critical!
    events.append({
        "event_id": 1102,
        "event_name": "Audit Log Cleared",
        "severity": "CRITICAL",
        "timestamp": base_time.replace(minute=25).isoformat(),
        "username": "admin",
        "source_ip": "-",
        "process_name": "-",
        "raw_message": "CRITICAL: Security audit log was cleared!"
    })

    # Normal activity
    for i in range(10):
        events.append({
            "event_id": 4624,
            "event_name": "Successful Login",
            "severity": "LOW",
            "timestamp": base_time.replace(hour=9, minute=i*5).isoformat(),
            "username": random.choice(sample_users),
            "source_ip": random.choice(normal_ips),
            "process_name": "-",
            "raw_message": "Normal login activity"
        })

    # New user created
    events.append({
        "event_id": 4720,
        "event_name": "User Account Created",
        "severity": "HIGH",
        "timestamp": base_time.replace(hour=10, minute=5).isoformat(),
        "username": "backdoor_user",
        "source_ip": "203.0.113.42",
        "process_name": "-",
        "raw_message": "New user account created from suspicious IP"
    })

    print(f"[+] Generated {len(events)} sample log events")
    return events


# ─────────────────────────────────────────────
# ANOMALY DETECTOR
# ─────────────────────────────────────────────
def detect_anomalies(events):
    """Run anomaly detection rules on parsed events"""
    alerts = []

    # Rule 1: Brute Force Detection (5+ failed logins from same IP in short time)
    failed_logins = {}
    for event in events:
        if event["event_id"] == 4625:
            ip = event["source_ip"]
            if ip not in failed_logins:
                failed_logins[ip] = []
            failed_logins[ip].append(event["timestamp"])

    for ip, timestamps in failed_logins.items():
        if len(timestamps) >= 5:
            alerts.append({
                "alert_type": "BRUTE_FORCE",
                "severity": "CRITICAL",
                "description": f"Brute force attack detected: {len(timestamps)} failed logins",
                "username": "Multiple",
                "source_ip": ip,
                "event_count": len(timestamps),
                "first_seen": timestamps[0],
                "last_seen": timestamps[-1]
            })

    # Rule 2: Privilege Escalation after Failed Login
    failed_ips = set(failed_logins.keys())
    for event in events:
        if event["event_id"] == 4672 and event["source_ip"] in failed_ips:
            alerts.append({
                "alert_type": "PRIVILEGE_ESCALATION",
                "severity": "CRITICAL",
                "description": "Privilege escalation detected after failed login attempts",
                "username": event["username"],
                "source_ip": event["source_ip"],
                "event_count": 1,
                "first_seen": event["timestamp"],
                "last_seen": event["timestamp"]
            })

    # Rule 3: Audit Log Cleared
    for event in events:
        if event["event_id"] == 1102:
            alerts.append({
                "alert_type": "LOG_CLEARED",
                "severity": "CRITICAL",
                "description": "Security audit log was cleared - possible cover-up attempt",
                "username": event["username"],
                "source_ip": "-",
                "event_count": 1,
                "first_seen": event["timestamp"],
                "last_seen": event["timestamp"]
            })

    # Rule 4: Suspicious Process Detection
    for event in events:
        if event["event_id"] == 4688:
            proc = event["process_name"].lower()
            for suspicious in SUSPICIOUS_PROCESSES:
                if suspicious in proc:
                    alerts.append({
                        "alert_type": "SUSPICIOUS_PROCESS",
                        "severity": "HIGH",
                        "description": f"Suspicious process launched: {event['process_name']}",
                        "username": event["username"],
                        "source_ip": event["source_ip"],
                        "event_count": 1,
                        "first_seen": event["timestamp"],
                        "last_seen": event["timestamp"]
                    })

    # Rule 5: New User Created from External IP
    for event in events:
        if event["event_id"] == 4720:
            ip = event["source_ip"]
            if not ip.startswith("192.168") and not ip.startswith("10."):
                alerts.append({
                    "alert_type": "SUSPICIOUS_USER_CREATION",
                    "severity": "HIGH",
                    "description": f"New user '{event['username']}' created from external IP",
                    "username": event["username"],
                    "source_ip": ip,
                    "event_count": 1,
                    "first_seen": event["timestamp"],
                    "last_seen": event["timestamp"]
                })

    print(f"[!] Detected {len(alerts)} alerts")
    return alerts


# ─────────────────────────────────────────────
# SAVE TO DATABASE
# ─────────────────────────────────────────────
def save_events_to_db(events, db_path="soc_events.db"):
    """Save parsed events to SQLite database"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    now = datetime.now().isoformat()

    for event in events:
        cursor.execute("""
            INSERT INTO events 
            (event_id, event_name, severity, timestamp, username, source_ip, process_name, raw_message, parsed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event["event_id"], event["event_name"], event["severity"],
            event["timestamp"], event["username"], event["source_ip"],
            event["process_name"], event["raw_message"], now
        ))

    conn.commit()
    conn.close()
    print(f"[+] Saved {len(events)} events to database")


def save_alerts_to_db(alerts, db_path="soc_events.db"):
    """Save detected alerts to SQLite database"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    now = datetime.now().isoformat()

    for alert in alerts:
        cursor.execute("""
            INSERT INTO alerts
            (alert_type, severity, description, username, source_ip, event_count, first_seen, last_seen, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert["alert_type"], alert["severity"], alert["description"],
            alert["username"], alert["source_ip"], alert["event_count"],
            alert["first_seen"], alert["last_seen"], now
        ))

    conn.commit()
    conn.close()
    print(f"[+] Saved {len(alerts)} alerts to database")


# ─────────────────────────────────────────────
# REPORT GENERATOR
# ─────────────────────────────────────────────
def generate_report(events, alerts):
    """Generate a simple text report"""
    print("\n" + "="*60)
    print("       SOC LOG ANALYSIS REPORT")
    print("="*60)
    print(f"Total Events Parsed : {len(events)}")
    print(f"Total Alerts        : {len(alerts)}")

    severity_counts = {}
    for event in events:
        sev = event["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("\n[ Event Severity Breakdown ]")
    for sev, count in sorted(severity_counts.items()):
        print(f"  {sev:<10} : {count}")

    print("\n[ Active Alerts ]")
    for alert in alerts:
        print(f"  [{alert['severity']}] {alert['alert_type']} - {alert['description']}")
        print(f"         IP: {alert['source_ip']} | User: {alert['username']}")
        print()

    print("="*60)

    # Save JSON report
    report = {
        "generated_at": datetime.now().isoformat(),
        "total_events": len(events),
        "total_alerts": len(alerts),
        "severity_breakdown": severity_counts,
        "alerts": alerts
    }

    with open("soc_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print("[+] Report saved: soc_report.json")


# ─────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────
def main():
    print("="*60)
    print("  SOC Log Analyzer - Phase 1")
    print("="*60)

    # Initialize DB
    init_database()

    # Parse logs
    evtx_files = list(Path(".").glob("*.evtx"))

    if evtx_files and EVTX_AVAILABLE:
        events = []
        for f in evtx_files:
            events.extend(parse_evtx_file(str(f)))
    else:
        print("[*] No .evtx files found. Using sample data...")
        events = generate_sample_logs()

    # Detect anomalies
    alerts = detect_anomalies(events)

    # Save to DB
    save_events_to_db(events)
    save_alerts_to_db(alerts)

    # Generate report
    generate_report(events, alerts)

    print("\n[✓] Phase 1 Complete! Run Flask backend for dashboard.")


if __name__ == "__main__":
    main()