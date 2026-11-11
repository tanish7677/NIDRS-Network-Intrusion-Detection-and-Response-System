import pandas as pd
import joblib
import sqlite3
import sys
from pathlib import Path
from datetime import datetime

model = joblib.load("multiclass_model.pkl")
encoder = joblib.load("multiclass_label_encoder.pkl")

# FIX: previously fit a BRAND NEW LabelEncoder on this file only, which
# assigns completely different numeric codes than the ones the model was
# actually trained with (e.g. "http" was 24 at training time but became
# 22 when re-fit on the test file). Reusing the SAVED encoders keeps the
# encoding identical to what the model learned.
protocol_encoder = joblib.load("protocol_encoder.pkl")
service_encoder = joblib.load("service_encoder.pkl")
flag_encoder = joblib.load("flag_encoder.pkl")

# FIX (email gap): U2R dataset attacks are severity="Critical" too, but
# this script never sent an email for them — only the dashboard's "Run
# Live Detection" button did, and only for Live Anomaly rows. This wires
# up the same email_alert / generate_pdf modules the dashboard uses.
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

# FIX: was `df.drop(columns=[41])` only, which left the "difficulty"
# column (42) in X. The model expects exactly 41 features, so this
# crashed with: "X has 42 features, but RandomForestClassifier is
# expecting 41 features as input." Dropping both label (41) and
# difficulty (42) matches how multiclass_model.py trained the model.
X = df.drop(columns=[41, 42])

print("X Shape:", X.shape)

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

        elif attack_name == "Probe":
            severity = "Medium"

        elif attack_name == "R2L":
            severity = "Low"

        elif attack_name == "U2R":
            severity = "Critical"

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

        # FIX (email gap): send an email + PDF for every Critical
        # dataset alert, same as the live-detection path does.
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

print("Alerts Generated Successfully")

if emails_sent or emails_failed:
    print(f"Critical Alert Emails Sent: {emails_sent}")
    print(f"Critical Alert Emails Failed: {emails_failed}")
