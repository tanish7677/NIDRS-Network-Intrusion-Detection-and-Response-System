from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time


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

        return (
            endpoint1,
            endpoint2,
            protocol
        )

    return (
        endpoint2,
        endpoint1,
        protocol
    )


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


def display_flows():

    print("\n")
    print("=" * 90)

    print("NIDRS NETWORK FLOW FEATURES")

    print("=" * 90)

    for flow_id, flow in enumerate(
        flows.values(),
        start=1
    ):

        duration = (
            flow["last_time"]
            -
            flow["start_time"]
        )

        if duration > 0:

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

        else:

            packets_per_second = 0
            bytes_per_second = 0

        average_packet_size = (
            flow["total_bytes"]
            /
            flow["packet_count"]
        )

        print("\nFLOW ID:", flow_id)

        print(
            "Source:",
            flow["src_ip"],
            ":",
            flow["src_port"]
        )

        print(
            "Destination:",
            flow["dst_ip"],
            ":",
            flow["dst_port"]
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
            "Total Bytes:",
            flow["total_bytes"]
        )

        print(
            "Duration:",
            round(duration, 4),
            "seconds"
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

        print("-" * 90)


print(
    "NIDRS Live Network Feature Extractor Started..."
)

print(
    "Capturing 100 packets..."
)


sniff(
    prn=packet_handler,
    store=False,
    count=100
)


display_flows()


print(
    "\nFeature Extraction Completed"
)