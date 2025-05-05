import os
import socket
from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest

# Clean the terminal
def clear_terminal():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')
clear_terminal()

# This function returns my own IP address:
def get_ip_address():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(('8.8.8.8', 80))  # Use Google's public DNS server for connectivity
        ip_address = s.getsockname()[0]
    except Exception as e:
        ip_address = f"Error: {e}"
    finally:
        s.close()
    return ip_address

# IP-based rules
IP_rules = [
    # Website 1:
    {"src_ip": "192.168.1.10", "dest_ip": get_ip_address(), "action": "ALLOW"},
    {"src_ip": get_ip_address(), "dest_ip": "192.168.1.10", "action": "BLOCK"},
    # Website 2:
    {"src_ip": "192.168.1.10", "dest_ip": get_ip_address(), "action": "ALLOW"},
    {"src_ip": get_ip_address(), "dest_ip": "192.168.1.10", "action": "BLOCK"},
]

# Protocol-based rules
Protocol_rules = [
    # UDP protocol:
    {"protocol": 17, "action": "ALLOW"},
    {"protocol": 6, "action": "ALLOW"},  # TCP protocol
    {"protocol": "HTTP", "action": "ALLOW"},  # HTTP protocol
    {"protocol": "HTTPS", "action": "ALLOW"},  # HTTPS protocol
    # you can add more rules here.
]

# This function checks if the packet has an HTTP Request Layer or not:
def packet_handler(packet):
    return packet.haslayer(HTTPRequest)

# Check if the packet matches the firewall IP rules:
def check_packet_IP(packet, IP_rules):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst       
        for rule in IP_rules:
            if rule_matches_packet(src_ip, dest_ip, rule):
                return rule["action"]    
    return "ALLOW"  # Default action

# This function checks if the packet matches the firewall protocol rules
def check_Protocol(packet, Protocol_rules):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        is_http = packet_handler(packet)
        for rule in Protocol_rules:
            if rule["protocol"] == ip_layer.proto or (rule["protocol"] == "HTTP" and is_http) or (rule["protocol"] == "HTTPS" and is_http):
                return rule["action"] 
    return "ALLOW"

# Helper function to match IP rules
def rule_matches_packet(src_ip, dest_ip, rule):
    return src_ip == rule["src_ip"] and dest_ip == rule["dest_ip"]

# Check if a packet is fragmented
def is_fragmented(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        if ip_layer.flags & 0x1 or ip_layer.frag != 0:
            return True
    return False

# This function turns the IP address into a readable string like DNS does:
def get_domain_name(ip_address):
    try:
        host, alias, ip_list = socket.gethostbyaddr(ip_address)
        return host
    except socket.herror:
        return ip_address
    
# Main algorithm:
def process_packet(packet):
    # Deny fragmented packets
    if is_fragmented(packet):
        print(f"Fragmented packet from {get_domain_name(packet[IP].src)} to {get_domain_name(packet[IP].dst)} blocked.")
        return
    
    action_ip = check_packet_IP(packet, IP_rules)
    action_protocol = check_Protocol(packet, Protocol_rules)
    
    if action_ip == "ALLOW" and action_protocol == "ALLOW":
        print(f"Packet from {get_domain_name(packet[IP].src)} to {get_domain_name(packet[IP].dst)} allowed.")  # Forward the packet to its destination (not implemented here)
    else:
        print(f"Packet from {get_domain_name(packet[IP].src)} to {get_domain_name(packet[IP].dst)} blocked.")

# Start sniffing packets
sniff(prn=process_packet, count= 20)
print("Program finished!")