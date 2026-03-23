"""
SOC Log Analyzer - Phase 2: Advanced Detection Rules
Add this to your existing log_parser.py OR run standalone.

MITRE ATT&CK Techniques covered:
- T1078  Valid Accounts (Off-hours login)
- T1021  Lateral Movement
- T1053  Scheduled Task Persistence
- T1550  Pass-the-Hash / Impossible Travel
"""

from datetime import datetime, time
from collections import defaultdict


# ─────────────────────────────────────────────
# RULE 1: OFF-HOURS LOGIN DETECTION
# T1078 - Valid Accounts
# ─────────────────────────────────────────────
def detect_off_hours_login(events):
    """
    Alert if login happens outside business hours.
    Business hours: Monday-Friday, 8AM - 8PM
    """
    alerts = []
    BUSINESS_START = 8   # 8 AM
    BUSINESS_END   = 20  # 8 PM

    for event in events:
        if event["event_id"] not in [4624, 4648]:
            continue

        try:
            ts = datetime.fromisoformat(event["timestamp"].replace("Z", ""))
        except Exception:
            continue

        hour    = ts.hour
        weekday = ts.weekday()  # 0=Mon, 6=Sun

        is_weekend   = weekday >= 5
        is_off_hours = hour < BUSINESS_START or hour >= BUSINESS_END

        if is_weekend or is_off_hours:
            day_name  = ts.strftime("%A")
            time_str  = ts.strftime("%H:%M")
            reason    = "Weekend login" if is_weekend else f"Off-hours login at {time_str}"

            alerts.append({
                "alert_type": "OFF_HOURS_LOGIN",
                "severity":   "MEDIUM",
                "description": f"{reason} by '{event['username']}' on {day_name}",
                "username":   event["username"],
                "source_ip":  event["source_ip"],
                "event_count": 1,
                "first_seen": event["timestamp"],
                "last_seen":  event["timestamp"],
                "mitre":      "T1078 - Valid Accounts"
            })

    return alerts


# ─────────────────────────────────────────────
# RULE 2: LATERAL MOVEMENT DETECTION
# T1021 - Remote Services
# ─────────────────────────────────────────────
def detect_lateral_movement(events):
    """
    Alert if same user logs in from 3+ different IPs
    within a short window — possible lateral movement.
    """
    alerts = []
    user_ips = defaultdict(set)

    for event in events:
        if event["event_id"] != 4624:
            continue
        user = event["username"]
        ip   = event["source_ip"]

        if ip in ["-", "Unknown", "::1", "127.0.0.1"]:
            continue

        user_ips[user].add(ip)

    for user, ips in user_ips.items():
        if len(ips) >= 3:
            alerts.append({
                "alert_type":  "LATERAL_MOVEMENT",
                "severity":    "HIGH",
                "description": f"User '{user}' logged in from {len(ips)} different IPs: {', '.join(ips)}",
                "username":    user,
                "source_ip":   ", ".join(ips),
                "event_count": len(ips),
                "first_seen":  "N/A",
                "last_seen":   "N/A",
                "mitre":       "T1021 - Remote Services"
            })

    return alerts


# ─────────────────────────────────────────────
# RULE 3: PERSISTENCE DETECTION
# T1053 - Scheduled Task / T1543 - New Service
# ─────────────────────────────────────────────
def detect_persistence(events):
    """
    Alert on new scheduled tasks or services installed.
    Common attacker persistence mechanisms.
    """
    alerts = []

    PERSISTENCE_EVENT_IDS = {
        4698: "Scheduled Task Created",
        4702: "Scheduled Task Modified",
        7045: "New Service Installed",
        4720: "New User Account Created",
    }

    for event in events:
        if event["event_id"] not in PERSISTENCE_EVENT_IDS:
            continue

        name = PERSISTENCE_EVENT_IDS[event["event_id"]]

        # Extra suspicion if from external IP
        ip = event["source_ip"]
        is_external = ip not in ["-", "Unknown"] and \
                      not ip.startswith("192.168") and \
                      not ip.startswith("10.") and \
                      not ip.startswith("172.16")

        severity = "CRITICAL" if is_external else "HIGH"

        alerts.append({
            "alert_type":  "PERSISTENCE_MECHANISM",
            "severity":    severity,
            "description": f"{name} by '{event['username']}'" +
                           (" from EXTERNAL IP!" if is_external else ""),
            "username":    event["username"],
            "source_ip":   event["source_ip"],
            "event_count": 1,
            "first_seen":  event["timestamp"],
            "last_seen":   event["timestamp"],
            "mitre":       "T1053 - Scheduled Task / T1543 - New Service"
        })

    return alerts


# ─────────────────────────────────────────────
# RULE 4: IMPOSSIBLE TRAVEL DETECTION
# T1078 - Valid Accounts (Credential Abuse)
# ─────────────────────────────────────────────
def detect_impossible_travel(events):
    """
    Alert if same user logs in from 2 very different IPs
    within 10 minutes — impossible to physically travel.
    """
    alerts = []
    user_logins = defaultdict(list)

    for event in events:
        if event["event_id"] != 4624:
            continue
        ip = event["source_ip"]
        if ip in ["-", "Unknown", "::1", "127.0.0.1"]:
            continue

        try:
            ts = datetime.fromisoformat(event["timestamp"].replace("Z", ""))
            user_logins[event["username"]].append({
                "ip": ip,
                "time": ts
            })
        except Exception:
            continue

    for user, logins in user_logins.items():
        if len(logins) < 2:
            continue

        # Sort by time
        logins.sort(key=lambda x: x["time"])

        for i in range(len(logins) - 1):
            a = logins[i]
            b = logins[i + 1]

            # Different IPs
            if a["ip"] == b["ip"]:
                continue

            # Within 10 minutes
            diff_minutes = (b["time"] - a["time"]).total_seconds() / 60

            if diff_minutes <= 10:
                # Different IP subnet = suspicious
                subnet_a = ".".join(a["ip"].split(".")[:2])
                subnet_b = ".".join(b["ip"].split(".")[:2])

                if subnet_a != subnet_b:
                    alerts.append({
                        "alert_type":  "IMPOSSIBLE_TRAVEL",
                        "severity":    "CRITICAL",
                        "description": f"User '{user}' logged in from {a['ip']} then {b['ip']} within {diff_minutes:.1f} mins!",
                        "username":    user,
                        "source_ip":   f"{a['ip']} → {b['ip']}",
                        "event_count": 2,
                        "first_seen":  a["time"].isoformat(),
                        "last_seen":   b["time"].isoformat(),
                        "mitre":       "T1078 - Valid Accounts (Credential Abuse)"
                    })

    return alerts


# ─────────────────────────────────────────────
# PHASE 2 MASTER RUNNER
# ─────────────────────────────────────────────
def run_phase2_detection(events):
    """Run all Phase 2 detection rules"""
    print("\n[Phase 2] Running advanced detection rules...")

    all_alerts = []

    r1 = detect_off_hours_login(events)
    print(f"  [+] Off-Hours Login    : {len(r1)} alerts")
    all_alerts.extend(r1)

    r2 = detect_lateral_movement(events)
    print(f"  [+] Lateral Movement   : {len(r2)} alerts")
    all_alerts.extend(r2)

    r3 = detect_persistence(events)
    print(f"  [+] Persistence        : {len(r3)} alerts")
    all_alerts.extend(r3)

    r4 = detect_impossible_travel(events)
    print(f"  [+] Impossible Travel  : {len(r4)} alerts")
    all_alerts.extend(r4)

    print(f"\n  [!] Total Phase 2 Alerts: {len(all_alerts)}")
    return all_alerts


# ─────────────────────────────────────────────
# STANDALONE TEST
# ─────────────────────────────────────────────
if __name__ == "__main__":
    # Import from Phase 1
    from log_parser import generate_sample_logs, save_alerts_to_db, init_database

    print("="*55)
    print("  SOC Log Analyzer - Phase 2 Advanced Detection")
    print("="*55)

    init_database()
    events  = generate_sample_logs()
    alerts  = run_phase2_detection(events)

    save_alerts_to_db(alerts)

    print("\n[ Phase 2 Alerts Summary ]")
    for a in alerts:
        print(f"  [{a['severity']}] {a['alert_type']}")
        print(f"         {a['description']}")
        print(f"         MITRE: {a.get('mitre','N/A')}")
        print()

    print("[✓] Phase 2 Complete!")