from scapy.all import *

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        print("Packet Information:")
        print(f"    Source IP: {src_ip}")
        print(f"    Destination IP: {dst_ip}")
        print(f"    Protocol: {'TCP' if proto == 6 else 'UDP'}")

        if TCP in packet:
            payload = packet[TCP].payload
            print("    TCP Payload:")
            print("\n".join(["        " + line for line in str(payload).split("\n")]))
        elif UDP in packet:
            payload = packet[UDP].payload
            print("    UDP Payload:")
            print("\n".join(["        " + line for line in str(payload).split("\n")]))
        print()

print("Starting packet sniffer...")
sniff(prn=packet_callback, filter="ip", store=0)
