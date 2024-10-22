#!/usr/bin/env python3

from scapy.all import sniff, IP, TCP, ICMP
import time
from collections import defaultdict  # Import defaultdict

# Initialize scan tracking with defaultdict
scan_tracker = defaultdict(list)
TIME_WINDOW = 10  # 10 seconds for port scan detection threshold
THRESHOLD_PORT_SCANS = 10  # Threshold for port scans

# DoS attack tracking using defaultdict
dos_tracker = defaultdict(list)
THRESHOLD_DOS = 100  # Threshold for packet flood in a time window
TIME_WINDOW_DOS = 5  # Time window for DoS detection in seconds

# IP spoofing tracking
spoofed_ips = set()  # Known spoofed IPs

# Detect port scanning attacks
def detect_port_scan(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):  # Focus on TCP packets
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        current_time = time.time()

        # With defaultdict, no need to initialize scan_tracker[src_ip]
        scan_tracker[src_ip] = [
            (timestamp, port) for timestamp, port in scan_tracker[src_ip] 
            if current_time - timestamp < TIME_WINDOW
        ]

        scan_tracker[src_ip].append((current_time, dst_port))

        unique_ports = len(set(port for _, port in scan_tracker[src_ip]))
        if unique_ports >= THRESHOLD_PORT_SCANS:
            print(f"Port scanning detected from IP: {src_ip}")

# Detect DoS attacks
def detect_dos_attack(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        current_time = time.time()

        # No need to manually initialize dos_tracker[src_ip]
        dos_tracker[src_ip] = [
            timestamp for timestamp in dos_tracker[src_ip] 
            if current_time - timestamp < TIME_WINDOW_DOS
        ]

        dos_tracker[src_ip].append(current_time)

        if len(dos_tracker[src_ip]) > THRESHOLD_DOS:
            print(f"DoS attack detected from IP: {src_ip}")

# Detect IP spoofing attacks
def detect_ip_spoofing(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        if src_ip in spoofed_ips:
            print(f"IP spoofing detected from IP: {src_ip}")
        else:
            # Example of tracking spoofed IPs (you can extend this logic)
            if is_suspicious_ip(src_ip):
                spoofed_ips.add(src_ip)
                print(f"Suspicious IP (possible spoofing) added: {src_ip}")

# Example logic for detecting suspicious IPs (this is a placeholder)
def is_suspicious_ip(src_ip):
    # Assume IPs in the private range are suspicious for this example
    return src_ip.startswith("192.168.")

# Main function to combine all detections
def detect_all_attacks(packet):
    detect_port_scan(packet)
    detect_dos_attack(packet)
    detect_ip_spoofing(packet)

# Start sniffing for all attacks
sniff(filter="ip", prn=detect_all_attacks)
