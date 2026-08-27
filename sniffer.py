from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime


packet_count = 0


def get_protocol(packet):
    if TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    elif ICMP in packet:
        return "ICMP"
    else:
        return "Other"


def packet_callback(packet):
    global packet_count

    if IP not in packet:
        return

    packet_count += 1

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    protocol = get_protocol(packet)
    packet_size = len(packet)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    source_port = "-"
    destination_port = "-"

    if TCP in packet:
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    payload_info = "No payload"

    if Raw in packet:
        payload_size = len(packet[Raw].load)
        payload_info = f"{payload_size} bytes"

    print("\n" + "=" * 55)
    print(f"Packet #{packet_count}")
    print("=" * 55)
    print(f"Time        : {timestamp}")
    print(f"Source      : {source_ip}")
    print(f"Destination : {destination_ip}")
    print(f"Protocol    : {protocol}")
    print(f"Source Port : {source_port}")
    print(f"Dest Port   : {destination_port}")
    print(f"Packet Size : {packet_size} bytes")
    print(f"Payload     : {payload_info}")


print("=" * 55)
print("        BASIC NETWORK SNIFFER")
print("=" * 55)
print("Capturing packets...")
print("Press CTRL+C to stop.")
print("=" * 55)

try:
    sniff(prn=packet_callback, store=False)

except KeyboardInterrupt:
    print("\n\nPacket capture stopped.")
    print(f"Total packets captured: {packet_count}")
