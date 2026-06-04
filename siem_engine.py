import json
from collections import defaultdict

FAILED_THRESHOLD = 3
PORT_SCAN_THRESHOLD = 3

failed_logins = defaultdict(int)
port_activity = defaultdict(set)
alerts = []


def load_logs():
    with open("logs.json", "r") as f:
        return json.load(f)


def generate_alert(user, ip, severity, attack_type, details):
    alert = {
        "user": user,
        "ip": ip,
        "severity": severity,
        "attack_type": attack_type,
        "details": details
    }
    alerts.append(alert)

    print("\n🚨 ALERT GENERATED 🚨")
    print(json.dumps(alert, indent=4))


# -------------------------
# SIEM DETECTION ENGINE
# -------------------------
def process_logs(logs):
    print("\n--- SIEM ANALYSIS STARTED ---\n")

    for log in logs:
        user = log.get("user")
        ip = log.get("ip")
        event = log.get("event")

        print(f"[LOG] {user} | {ip} | {event}")

        # -------------------------
        # BRUTE FORCE DETECTION
        # -------------------------
        if event == "login_failed":
            failed_logins[user] += 1

            if failed_logins[user] >= FAILED_THRESHOLD:
                generate_alert(
                    user,
                    ip,
                    "HIGH",
                    "Brute Force Attack",
                    f"{failed_logins[user]} failed login attempts"
                )

        if event == "login_success":
            failed_logins[user] = 0

        # -------------------------
        # PORT SCANNING DETECTION
        # -------------------------
        if "port_scan" in event:
            port = event.split("_")[-1]
            port_activity[ip].add(port)

            if len(port_activity[ip]) >= PORT_SCAN_THRESHOLD:
                generate_alert(
                    user,
                    ip,
                    "CRITICAL",
                    "Port Scanning Detected",
                    f"Ports scanned: {list(port_activity[ip])}"
                )

        # -------------------------
        # PHISHING DETECTION
        # -------------------------
        if event == "email_click":
            url = log.get("url", "")

            suspicious_keywords = [
                "fake", "login", "secure", "verify", "bank"
            ]

            if any(word in url for word in suspicious_keywords):
                generate_alert(
                    user,
                    ip,
                    "HIGH",
                    "Phishing Attempt",
                    f"Suspicious URL clicked: {url}"
                )

    print("\n--- ANALYSIS COMPLETE ---\n")
    return alerts


def save_alerts():
    with open("alerts.json", "w") as f:
        json.dump(alerts, f, indent=4)

    print("Alerts saved to alerts.json")
