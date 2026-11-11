from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from datetime import datetime
import pandas as pd
import time
import os

flows = defaultdict(
    lambda: {
        "packet_count": 0,
        "total_bytes": 0,
        "start_time": None,
        "last_time": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": 0,
        "dst_port": 0,
        "protocol": "Other"
    }
)

def get_flow_key(packet):
    if IP not in packet:
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol = "TCP"
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        protocol = "UDP"
    else:
        src_port = 0
        dst_port = 0
        protocol = "Other"

    endpoint1 = (src_ip, src_port)
    endpoint2 = (dst_ip, dst_port)

    if endpoint1 <= endpoint2:
        return endpoint1, endpoint2, protocol

    return endpoint2, endpoint1, protocol

def packet_handler(packet):
    if IP not in packet:
        return

    flow_key = get_flow_key(packet)

    if flow_key is None:
        return

    current_time = time.time()

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol = "TCP"
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        protocol = "UDP"
    else:
        src_port = 0
        dst_port = 0
        protocol = "Other"

    flow = flows[flow_key]

    if flow["start_time"] is None:
        flow["start_time"] = current_time
        flow["src_ip"] = src_ip
        flow["dst_ip"] = dst_ip
        flow["src_port"] = src_port
        flow["dst_port"] = dst_port
        flow["protocol"] = protocol

    flow["packet_count"] += 1
    flow["total_bytes"] += len(packet)
    flow["last_time"] = current_time

def save_flows():
    flow_records = []

    for flow in flows.values():
        duration = flow["last_time"] - flow["start_time"]

        if duration > 0:
            packets_per_second = flow["packet_count"] / duration
            bytes_per_second = flow["total_bytes"] / duration
        else:
            packets_per_second = 0
            bytes_per_second = 0

        average_packet_size = (
            flow["total_bytes"] / flow["packet_count"]
        )

        flow_records.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": flow["src_ip"],
            "dst_ip": flow["dst_ip"],
            "src_port": flow["src_port"],
            "dst_port": flow["dst_port"],
            "protocol": flow["protocol"],
            "packet_count": flow["packet_count"],
            "total_bytes": flow["total_bytes"],
            "duration": round(duration, 6),
            "packets_per_second": round(packets_per_second, 2),
            "bytes_per_second": round(bytes_per_second, 2),
            "average_packet_size": round(average_packet_size, 2)
        })

    df = pd.DataFrame(flow_records)

    file_name = "live_flows.csv"

    if os.path.exists(file_name):
        df.to_csv(
            file_name,
            mode="a",
            header=False,
            index=False
        )
    else:
        df.to_csv(
            file_name,
            index=False
        )

    print("\nFlows Saved Successfully")
    print("Flows Captured:", len(df))
    print("File:", file_name)

    print("\nCaptured Flow Data:")
    print(df)

print("NIDRS Live Flow Logger Started...")
print("Capturing 1000 packets...")

sniff(
    prn=packet_handler,
    store=False,
    count=1000
)

save_flows()

print("\nLive Flow Logging Completed")