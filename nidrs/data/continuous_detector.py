"""
NIDRS — Continuous Live Monitoring (UPGRADE — Tier 2)
=======================================================
Runs the same Isolation Forest detection logic as live_detector.py,
but in a LOOP — capturing a rolling window of traffic every cycle
instead of a single fixed 500-packet run. This is meant to be
launched by the dashboard as a background process (subprocess.Popen,
non-blocking) so the UI stays responsive while this keeps watching
traffic.

STOP MECHANISM: Streamlit + cross-platform (Windows/Linux/Mac) process
control is messy, so instead of killing the process by PID, this
script just checks for a small "stop flag" file every cycle and exits
cleanly when it appears. The dashboard creates that file to request a
stop; this script deletes it (and its own lock file) on the way out.

USAGE (manual, for testing outside the dashboard):
    python continuous_detector.py [--cycle-seconds 10]
"""

from scapy.all import sniff, IP, TCP, UDP
import joblib
import sqlite3
import time
import os
import sys
import argparse
from pathlib import Path
import pandas as pd
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "live_anomaly_model.pkl"
SCALER_PATH = BASE_DIR / "live_scaler.pkl"
FEATURES_PATH = BASE_DIR / "live_features.pkl"
DATABASE_PATH = BASE_DIR.parent / "database" / "alerts.db"

LOCK_FILE = BASE_DIR / ".continuous_monitor.lock"
STOP_FLAG_FILE = BASE_DIR / ".continuous_monitor.stop"

# email + PDF wiring (same modules the dashboard / auto_alerts.py use)
_DASHBOARD_DIR = str(BASE_DIR.parent / "dashboard")
_REPORTS_DIR = str(BASE_DIR.parent / "dashboard" / "reports")
for _p in (_DASHBOARD_DIR, _REPORTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# automatic enrichment (MITRE ATT&CK + GeoIP + AbuseIPDB), response/enrichment.py
_RESPONSE_DIR = str(BASE_DIR.parent / "response")
if _RESPONSE_DIR not in sys.path:
    sys.path.insert(0, _RESPONSE_DIR)

try:
    from enrichment import enrich_and_store
except ImportError:
    def enrich_and_store(conn, alert_id, alert, do_lookups=True):
        return {}

try:
    from email_alert import send_alert_email
    from generate_pdf import create_incident_report
    _EMAIL_AVAILABLE = True
except ImportError:
    _EMAIL_AVAILABLE = False


model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
feature_columns = joblib.load(FEATURES_PATH)


def write_heartbeat(cycles_completed, anomalies_found):
    """Lets the dashboard know this process is alive and its progress."""

    LOCK_FILE.write_text(
        f"pid={os.getpid()}\n"
        f"last_heartbeat={datetime.now().isoformat()}\n"
        f"cycles_completed={cycles_completed}\n"
        f"anomalies_found={anomalies_found}\n"
    )


def stop_requested():
    return STOP_FLAG_FILE.exists()


def process_one_cycle(cycle_seconds):
    """
    Captures traffic for `cycle_seconds`, builds flows, scores each
    with the Isolation Forest model, and inserts + emails any Critical
    anomalies found. Returns the number of anomalies inserted.
    """

    flows = {}

    def process_packet(packet):
        if IP not in packet:
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        protocol = "Other"
        src_port = 0
        dst_port = 0

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        endpoint1 = (src_ip, src_port)
        endpoint2 = (dst_ip, dst_port)

        flow_key = (
            (endpoint1, endpoint2, protocol)
            if endpoint1 <= endpoint2
            else (endpoint2, endpoint1, protocol)
        )

        packet_size = len(packet)
        current_time = time.time()

        if flow_key not in flows:
            flows[flow_key] = {
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": src_port, "dst_port": dst_port,
                "protocol": protocol, "packet_count": 1,
                "total_bytes": packet_size,
                "start_time": current_time, "end_time": current_time
            }
        else:
            flows[flow_key]["packet_count"] += 1
            flows[flow_key]["total_bytes"] += packet_size
            flows[flow_key]["end_time"] = current_time

    # capture a rolling window instead of a fixed packet count
    sniff(prn=process_packet, timeout=cycle_seconds, store=False)

    anomalies_inserted = 0

    conn = sqlite3.connect(str(DATABASE_PATH))
    cursor = conn.cursor()

    for flow in flows.values():

        duration = flow["end_time"] - flow["start_time"]

        if flow["packet_count"] < 5 or duration < 0.01:
            continue

        packets_per_second = flow["packet_count"] / duration
        bytes_per_second = flow["total_bytes"] / duration
        average_packet_size = flow["total_bytes"] / flow["packet_count"]

        input_data = pd.DataFrame([{
            "packet_count": flow["packet_count"],
            "total_bytes": flow["total_bytes"],
            "duration": duration,
            "packets_per_second": packets_per_second,
            "bytes_per_second": bytes_per_second,
            "average_packet_size": average_packet_size
        }])[feature_columns]

        scaled_data = scaler.transform(input_data)
        prediction = model.predict(scaled_data)[0]

        if prediction != -1:
            continue

        score = model.decision_function(scaled_data)[0]

        if score <= -0.30:
            severity = "Critical"
        elif score <= -0.20:
            severity = "High"
        elif score <= -0.10:
            severity = "Medium"
        else:
            severity = "Low"

        detected_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute(
            """
            INSERT INTO alerts (
                attack_type, severity, src_ip, dst_ip, src_port, dst_port,
                protocol, packet_count, total_bytes, duration,
                packets_per_second, bytes_per_second, average_packet_size,
                detected_at, status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "Live Anomaly", severity, flow["src_ip"], flow["dst_ip"],
                flow["src_port"], flow["dst_port"], flow["protocol"],
                flow["packet_count"], flow["total_bytes"], duration,
                packets_per_second, bytes_per_second, average_packet_size,
                detected_at, "New"
            )
        )

        anomalies_inserted += 1

        # store MITRE ATT&CK + GeoIP + AbuseIPDB enrichment on the new row
        enrichment = enrich_and_store(
            conn,
            cursor.lastrowid,
            {
                "attack_type": "Live Anomaly",
                "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"],
                "packets_per_second": packets_per_second,
            }
        )

        if severity == "Critical" and _EMAIL_AVAILABLE:

            new_id = cursor.lastrowid

            alert_row = {
                "id": new_id, "attack_type": "Live Anomaly",
                "severity": severity, "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"], "protocol": flow["protocol"],
                "packet_count": flow["packet_count"],
                "total_bytes": flow["total_bytes"], "status": "New",
                "response_action": None, "detected_at": detected_at
            }

            alert_row.update(enrichment)

            try:
                report_dir = Path(_DASHBOARD_DIR) / "reports"
                report_dir.mkdir(exist_ok=True)
                report_path = str(report_dir / f"Incident_{new_id}.pdf")
                create_incident_report(alert_row, report_path)
                send_alert_email(alert_row, report_path)
            except Exception as e:
                print(f"[continuous_detector] Email/PDF error: {e}")

    conn.commit()
    conn.close()

    return anomalies_inserted


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--cycle-seconds", type=int, default=10,
        help="How many seconds of traffic to capture per cycle."
    )
    args = parser.parse_args()

    # clear any stale stop flag from a previous run before starting
    if STOP_FLAG_FILE.exists():
        STOP_FLAG_FILE.unlink()

    print("NIDRS Continuous Monitoring Started...")
    print(f"Cycle length: {args.cycle_seconds}s. Stop flag: {STOP_FLAG_FILE}")

    cycles_completed = 0
    anomalies_found = 0

    write_heartbeat(cycles_completed, anomalies_found)

    try:
        while not stop_requested():

            found = process_one_cycle(args.cycle_seconds)

            cycles_completed += 1
            anomalies_found += found

            write_heartbeat(cycles_completed, anomalies_found)

            print(
                f"Cycle {cycles_completed} complete — "
                f"{found} anomaly(ies) this cycle, "
                f"{anomalies_found} total."
            )

    finally:
        for f in (LOCK_FILE, STOP_FLAG_FILE):
            if f.exists():
                f.unlink()

        print("NIDRS Continuous Monitoring Stopped.")


if __name__ == "__main__":
    main()
