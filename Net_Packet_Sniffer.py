from scapy.all import sniff
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP
import os
from datetime import datetime

def clear_screen():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

# Clear the screen at the start
clear_screen()

def capture_packets(packet):
    captured_data = []  # List to hold the captured data for saving
    try:
        # Check if the packet contains an HTTP request
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]  # Get the HTTP layer.
            request_info = f"HTTP Request: {http_layer.Method.decode()} {http_layer.Host.decode()}{http_layer.Path.decode()}"
            print(request_info)
            captured_data.append(request_info)
        
        # Check if the packet contains an IP layer
        if packet.haslayer(IP):
            ip_layer = packet[IP]  # Get the IP layer.
            ip_info = f"Source IP: {ip_layer.src} -> Destination IP: {ip_layer.dst}"
            print(ip_info)
            captured_data.append(ip_info)
    except Exception as e:
        error_message = f"Error processing packet: {e}"
        print(error_message)
        captured_data.append(error_message)
    
    return captured_data  # Return the captured data to save it later

# Saving the results in a txt file:
def save(captured_data, protocol):
    # Specify the file path (use raw string to handle backslashes)
    file_path = r"C:/sniffing"

    # Ensure the directory exists before attempting to write
    if not os.path.exists(file_path):
        os.makedirs(file_path)  # Create the directory if it doesn't exist

    # Get the current date and time
    formatted_date = datetime.now().strftime("%Y-%m-%d")

    # Specify the full file name with path
    filename = os.path.join(file_path, f"{protocol}_{formatted_date}.txt")

    # Get the current time (for each text entry)
    current_time = datetime.now().strftime("%H:%M:%S")
    
    # Check if a file for the specified protocol already exists
    mode = 'a' if os.path.exists(filename) else 'w'
    with open(filename, mode) as file:
        # Write the captured data with timestamps
        file.write(f"\n{current_time} - {formatted_date}\n")
        for data in captured_data:
            file.write(f"{data}\n")

# Checking the system to specify the interface: 
if os.name == 'nt':
    interface = "Wi-Fi"
else:
    interface = "eth0"

# Specify the protocol
print("\nTo specify the protocol desired, type 'TCP' for 'tcp port 80', or type 'UDP' for 'udp port 443'")
protocol = input("Please enter the desired protocol: ")

# Set the filter based on the protocol input
if protocol.upper() == "TCP":
    filter_protocol = "tcp port 80"
elif protocol.upper() == "UDP":
    filter_protocol = "udp port 443"
else:
    print("Invalid protocol. Exiting.")
    exit()

# Start sniffing packets on the specified interface
print("Analyzing packets might take some time, please wait until the program finishes.\n")
print("Starting packet capture...")
captured_packets = sniff(iface=interface, prn=capture_packets, filter=filter_protocol, count=10)

# Extract captured data from the packets
captured_data = []
for packet in captured_packets:
    captured_data.extend(capture_packets(packet))  # Append each packet's data to the list

# Save the captured data, if any
if captured_data:
    save(captured_data, protocol)
    print("\nData saved successfully. Program finished.")
else:
    print("\nNo data captured. Program finished.")
