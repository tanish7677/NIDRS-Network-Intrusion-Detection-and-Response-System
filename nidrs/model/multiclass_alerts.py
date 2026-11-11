import pandas as pd
import joblib
import sqlite3
import sys
from pathlib import Path
from datetime import datetime

# NOTE: this script is nearly identical to auto_alerts.py — consider
# keeping only one of them in your final submission to avoid confusion
# about which is the "real" pipeline.

model = joblib.load("multiclass_model.pkl")
encoder = joblib.load("multiclass_label_encoder.pkl")

# FIX: reuse the SAVED encoders instead of fitting new ones on this file
# (see auto_alerts.py for the full explanation of why this matters).
protocol_encoder = joblib.load("protocol_encoder.pkl")
service_encoder = joblib.load("service_encoder.pkl")
flag_encoder = joblib.load("flag_encoder.pkl")

# FIX (email gap): wire up the same email_alert / generate_pdf modules
# the dashboard uses, so Critical (U2R) dataset alerts also trigger
# an email — same fix as auto_alerts.py.
_BASE_DIR = Path(__file__).resolve().parent.parent
_DASHBOARD_DIR = str(_BASE_DIR / "dashboard")
_REPORTS_DIR = str(_BASE_DIR / "dashboard" / "reports")

for _p in (_DASHBOARD_DIR, _REPORTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from email_alert import send_alert_email
from generate_pdf import create_incident_report

# automatic enrichment (MITRE ATT&CK mapping; dataset alerts carry no IP)
_RESPONSE_DIR = str(_BASE_DIR / "response")
if _RESPONSE_DIR not in sys.path:
    sys.path.insert(0, _RESPONSE_DIR)

from enrichment import enrich_and_store

report_dir = _BASE_DIR / "dashboard" / "reports"
report_dir.mkdir(exist_ok=True)

df = pd.read_csv("KDDTest+.txt", header=None)

df[1] = protocol_encoder.transform(df[1])
df[2] = service_encoder.transform(df[2])
df[3] = flag_encoder.transform(df[3])

# FIX: drop BOTH label (41) and difficulty (42) columns — dropping only
# 41 left 42 features and crashed against the 41-feature model.
X = df.drop(columns=[41, 42])

predictions = model.predict(X.head(50))

conn = sqlite3.connect("../database/alerts.db")

cursor = conn.cursor()

detected_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

emails_sent = 0
emails_failed = 0

for pred in predictions:

    attack_name = encoder.inverse_transform([pred])[0]

    if attack_name != "Normal":

        severity = "Medium"

        if attack_name == "DoS":
            severity = "High"

        elif attack_name == "U2R":
            severity = "Critical"

        elif attack_name == "R2L":
            severity = "Low"

        cursor.execute(
            """
            INSERT INTO alerts(
            attack_type,
            severity,
            detected_at,
            status
            )
            VALUES(
            ?, ?, ?, ?
            )
            """,
            (attack_name, severity, detected_at, "New")
        )

        enrichment = enrich_and_store(
            conn,
            cursor.lastrowid,
            {"attack_type": attack_name}
        )

        if severity == "Critical":

            new_id = cursor.lastrowid

            alert_row = {
                "id": new_id,
                "attack_type": attack_name,
                "severity": severity,
                "src_ip": None,
                "dst_ip": None,
                "protocol": None,
                "packet_count": None,
                "total_bytes": None,
                "status": "New",
                "response_action": None,
                "detected_at": detected_at
            }

            alert_row.update(enrichment)

            report_path = str(
                report_dir / f"Incident_{new_id}.pdf"
            )

            create_incident_report(alert_row, report_path)

            if send_alert_email(alert_row, report_path):
                emails_sent += 1
            else:
                emails_failed += 1

conn.commit()

conn.close()

print("Alerts Generated")

if emails_sent or emails_failed:
    print(f"Critical Alert Emails Sent: {emails_sent}")
    print(f"Critical Alert Emails Failed: {emails_failed}")
