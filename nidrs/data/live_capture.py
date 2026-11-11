from scapy.all import sniff, IP, TCP, UDP
def packet_handler(packet):

    print("\n-----------------------------")
    print("New Packet Captured")
    print("-----------------------------")

    if IP in packet:

        print("Source IP:", packet[IP].src)
        print("Destination IP:", packet[IP].dst)

        if TCP in packet:

            print("Protocol: TCP")
            print("Source Port:", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        elif UDP in packet:

            print("Protocol: UDP")
            print("Source Port:", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        else:

            print("Protocol: Other")


print("NIDRS Live Packet Capture Started...")

sniff(
    prn=packet_handler,
    store=False,
    count=20
)

print("Packet Capture Completed")