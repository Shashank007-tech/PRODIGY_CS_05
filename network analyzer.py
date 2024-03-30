!pip install scapy

from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        
        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {proto}")
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"Source Port: {src_port}, Destination Port: {dst_port}")
            print(f"TCP Data: {packet[TCP].payload}")
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"Source Port: {src_port}, Destination Port: {dst_port}")
            print(f"UDP Data: {packet[UDP].payload}")
        else:
            print("Non-TCP/UDP packet")

# Sniff packets
sniff(prn=packet_callback, count=10)  # Change count as needed
