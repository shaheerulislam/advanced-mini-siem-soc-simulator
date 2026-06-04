# Advanced Mini SIEM + Attack Simulator (Python)

## Overview
This project is a lightweight Security Information and Event Management (SIEM) simulation system designed to replicate real-world Security Operations Center (SOC) workflows. It processes security logs and detects multiple cyber threats using rule-based correlation logic similar to SIEM tools used in enterprise SOC environments.


##  Detected Attack Types

### 1. Brute Force Attack
Detects multiple failed login attempts from the same user.

###  2. Port Scanning Detection
Identifies reconnaissance activity based on multiple port access attempts from the same IP.

###  3. Phishing Detection
Detects suspicious URL patterns in email click events.


##  Features
- Log ingestion from JSON files
- Rule-based detection engine
- Multi-attack simulation (Brute Force, Port Scan, Phishing)
- SOC-style alert generation
- Incident classification (LOW / HIGH / CRITICAL)
- Structured security event processing



##  SOC Concepts Demonstrated
- SIEM log correlation
- Threat detection rules
- Incident response simulation
- Network security monitoring
- Authentication attack detection
- Event-driven security analytics



## Technologies Used
- Python
- JSON data processing
- Dictionaries & Sets
- Rule-based logic engine


## How to Run

bash
python main.py

Results
The simulator successfully processes security logs and generates alerts based on predefined detection rules.

Example Alerts Generated

Brute Force Detection

User: bob
Severity: HIGH
Reason: Multiple failed login attempts detected

Port Scan Detection

Source IP: 192.168.1.10
Severity: CRITICAL
Reason: Multiple ports scanned from the same IP address

Phishing Detection

User: eve
Severity: HIGH
Reason: Suspicious URL interaction detected

Output

Security events analyzed in real time
Alerts generated and classified by severity
Alert records exported to alerts.json
Demonstrates SOC-style monitoring and incident detection workflows

Future Improvements

MITRE ATT&CK technique mapping
Real-time log streaming
Threat intelligence integration
Dashboard visualization using Streamlit
Elasticsearch/Kibana integration

Author

Shaheer ul islam
Cyber Security Enthusiast | SOC Analyst | Python Developer


License

This project is intended for educational and portfolio purposes.
