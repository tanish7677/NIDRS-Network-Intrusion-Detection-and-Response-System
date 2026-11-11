from scapy.all import sniff, IP, TCP, UDP
import joblib
import sqlite3
import time
import os
import pandas as pd
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# automatic enrichment (MITRE ATT&CK + GeoIP + AbuseIPDB), response/enrichment.py
import sys
_RESPONSE_DIR = os.path.join(BASE_DIR, "..", "response")
if _RESPONSE_DIR not in sys.path:
    sys.path.insert(0, _RESPONSE_DIR)

try:
    from enrichment import enrich_and_store
except ImportError:
    def enrich_and_store(conn, alert_id, alert, do_lookups=True):
        return {}

MODEL_PATH = os.path.join(
    BASE_DIR,
    "live_anomaly_model.pkl"
)

SCALER_PATH = os.path.join(
    BASE_DIR,
    "live_scaler.pkl"
)

FEATURES_PATH = os.path.join(
    BASE_DIR,
    "live_features.pkl"
)

DATABASE_PATH = os.path.join(
    BASE_DIR,
    "..",
    "database",
    "alerts.db"
)

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
feature_columns = joblib.load(FEATURES_PATH)

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

    endpoint1 = (
        src_ip,
        src_port
    )

    endpoint2 = (
        dst_ip,
        dst_port
    )

    if endpoint1 <= endpoint2:
        flow_key = (
            endpoint1,
            endpoint2,
            protocol
        )

    else:
        flow_key = (
            endpoint2,
            endpoint1,
            protocol
        )

    packet_size = len(packet)
    current_time = time.time()

    if flow_key not in flows:
        flows[flow_key] = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_count": 1,
            "total_bytes": packet_size,
            "start_time": current_time,
            "end_time": current_time
        }

    else:
        flows[flow_key]["packet_count"] += 1

        flows[flow_key]["total_bytes"] += (
            packet_size
        )

        flows[flow_key]["end_time"] = (
            current_time
        )

def insert_anomaly(flow, severity):
    conn = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = conn.cursor()

    detected_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cursor.execute(
        """
        INSERT INTO alerts
        (
            attack_type,
            severity,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            packet_count,
            total_bytes,
            duration,
            packets_per_second,
            bytes_per_second,
            average_packet_size,
            detected_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "Live Anomaly",
            severity,
            flow["src_ip"],
            flow["dst_ip"],
            flow["src_port"],
            flow["dst_port"],
            flow["protocol"],
            flow["packet_count"],
            flow["total_bytes"],
            flow["duration"],
            flow["packets_per_second"],
            flow["bytes_per_second"],
            flow["average_packet_size"],
            detected_at
        )
    )

    # store MITRE ATT&CK + GeoIP + AbuseIPDB enrichment on the new row
    enrich_and_store(
        conn,
        cursor.lastrowid,
        {
            "attack_type": "Live Anomaly",
            "src_ip": flow["src_ip"],
            "dst_ip": flow["dst_ip"],
            "packets_per_second": flow["packets_per_second"],
        }
    )

    conn.commit()
    conn.close()

    print(
        "Alert Timestamp:",
        detected_at
    )

print("NIDRS Live Detector Started...")
print("Capturing 500 packets...\n")

sniff(
    prn=process_packet,
    count=500,
    store=False
)

print("Packet Capture Completed")

print("\n========================================")
print("NIDRS LIVE ANOMALY DETECTION")
print("========================================\n")

normal_count = 0
anomaly_count = 0
skipped_count = 0
inserted_alerts = 0

flow_id = 1

for flow in flows.values():
    duration = (
        flow["end_time"]
        -
        flow["start_time"]
    )

    print(
        f"Flow ID: {flow_id}"
    )

    print(
        "Connection:",
        f'{flow["src_ip"]}:{flow["src_port"]}',
        "->",
        f'{flow["dst_ip"]}:{flow["dst_port"]}'
    )

    print(
        "Protocol:",
        flow["protocol"]
    )

    print(
        "Packet Count:",
        flow["packet_count"]
    )

    print(
        "Duration:",
        round(duration, 4)
    )

    if (
        flow["packet_count"] < 5
        or duration < 0.01
    ):
        print(
            "AI Status: SKIPPED - SHORT FLOW"
        )

        print("-" * 70)

        skipped_count += 1
        flow_id += 1

        continue

    packets_per_second = (
        flow["packet_count"]
        /
        duration
    )

    bytes_per_second = (
        flow["total_bytes"]
        /
        duration
    )

    average_packet_size = (
        flow["total_bytes"]
        /
        flow["packet_count"]
    )

    flow["duration"] = duration

    flow["packets_per_second"] = (
        packets_per_second
    )

    flow["bytes_per_second"] = (
        bytes_per_second
    )

    flow["average_packet_size"] = (
        average_packet_size
    )

    input_data = pd.DataFrame(
        [
            {
                "packet_count":
                    flow["packet_count"],

                "total_bytes":
                    flow["total_bytes"],

                "duration":
                    duration,

                "packets_per_second":
                    packets_per_second,

                "bytes_per_second":
                    bytes_per_second,

                "average_packet_size":
                    average_packet_size
            }
        ]
    )

    input_data = input_data[
        feature_columns
    ]

    scaled_data = scaler.transform(
        input_data
    )

    prediction = model.predict(
        scaled_data
    )[0]

    print(
        "Total Bytes:",
        flow["total_bytes"]
    )

    print(
        "Packets / Second:",
        round(
            packets_per_second,
            2
        )
    )

    print(
        "Bytes / Second:",
        round(
            bytes_per_second,
            2
        )
    )

    print(
        "Average Packet Size:",
        round(
            average_packet_size,
            2
        )
    )

    if prediction == -1:

        score = model.decision_function(
            scaled_data
        )[0]

        if score <= -0.30:
            severity = "Critical"
        elif score <= -0.20:
            severity = "High"
        elif score <= -0.10:
            severity = "Medium"
        else:
            severity = "Low"

        print(
            "AI Status: ANOMALOUS"
        )
        print(
            "AI Score:",
            round(score,4)
        )
        print(
            "Severity:",
            severity
        )

        anomaly_count += 1

        insert_anomaly(
            flow,
            severity
        )

        inserted_alerts += 1

    else:
        print(
            "AI Status: NORMAL"
        )

        normal_count += 1

    print("-" * 70)

    flow_id += 1

print("\n========================================")
print("LIVE DETECTION SUMMARY")
print("========================================")

print(
    "Total Flows:",
    len(flows)
)

print(
    "Normal Flows:",
    normal_count
)

print(
    "Anomalous Flows:",
    anomaly_count
)

print(
    "Skipped Short Flows:",
    skipped_count
)

print(
    "Anomalous Alerts Inserted:",
    inserted_alerts
)

print("========================================")

print(
    "\nLive Detection Completed"
)