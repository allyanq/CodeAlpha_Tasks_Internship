from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
from collections import Counter
import signal
import sys

packet_count = 0
protocol_counts = Counter()

def packet_callback(packet):
    global packet_count, protocol_counts

    if IP not in packet:
        return

    packet_count += 1
    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    packet_size = len(packet)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
    elif ICMP in packet:
        protocol = "ICMP"
        source_port = "-"
        destination_port = "-"
    else:
        protocol = "Other"
        source_port = "-"
        destination_port = "-"

    protocol_counts[protocol] += 1

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

def show_summary():
    print("\n" + "=" * 55)
    print("              CAPTURE SUMMARY")
    print("=" * 55)
    print(f"Total packets captured: {packet_count}")
    print("\nProtocol Statistics:")
    if protocol_counts:
        for protocol, count in protocol_counts.items():
            print(f"{protocol:<10}: {count}")
    else:
        print("No IP packets captured.")
    print("=" * 55)
    print("Packet capture stopped.")
    print("=" * 55)

def handle_exit(sig, frame):
    show_summary()
    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)

print("=" * 55)
print("       CODEALPHA BASIC NETWORK SNIFFER")
print("=" * 55)
print("Capturing packets...")
print("Press CTRL+C to stop.")
print("=" * 55)

sniff(prn=packet_callback, store=False)
