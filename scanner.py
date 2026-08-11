# scanner.py
# Main script for our home network logger project.

# ANSI escape codes let us print colored text to the terminal.
GREEN = "\033[92m"
RESET = "\033[0m"
ORANGE = "\033[38;5;208m"
YELLOW = "\033[93m"
RED = "\033[91m"

# Print a test message
print(f"{GREEN}[SUCCESS] Environment Initialized. Scanner is ready to build.{RESET}")

# Import scapy's tools for building and sending ARP requests
from scapy.all import ARP, Ether, srp
from datetime import datetime
from mac_vendor_lookup import MacLookup
import csv
import os

# Define the network range we want to scan.
TARGET_IP_RANGE = "192.168.1.0/24"
LOG_FILE = "network_log.csv"

# Create a lookup tool that can turn MAC addresses into vendor/manufacturer names.
mac_lookup = MacLookup()

# Download the vendor database if we don't have it cached locally.
mac_lookup.update_vendors()

# Build ARP request packet
arp_request = ARP(pdst=TARGET_IP_RANGE)

# Ethernet frames need a destination MAC address.
ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

# Combine the Ethernet frame and ARP request into one packet and send.
packet = ether_frame / arp_request

# Send the packet and capture the responses.
try:
    answered_devices, unanswered_devices = srp(packet, timeout=2, verbose=False)
except PermissionError:
    print(f"{RED}[ERROR] Permission denied. Please run this script with elevated privileges (e.g., using 'sudo').{RESET}")
    exit(1)

# Capture the current dte and time as soon as the scan finishes
scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Print an orange header showing when this scan ran and how many devices were found
print(f"{ORANGE}--- Scan completed at {scan_time} | {len(answered_devices)} devices found ---{RESET}")

# Build a list of every MAC address we've logged in previous scans
known_macs = set()

# Only try reading the file if it actually exists
if os.path.isfile(LOG_FILE):
    with open(LOG_FILE, mode="r", newline="") as existing_file:
        reader = csv.reader(existing_file)
        next(reader, None) # Skip header row
        for row in reader:
            known_macs.add(row[2])

# Check if the log file already exists
file_already_exists = os.path.isfile(LOG_FILE)

# Open CSV in "append" mode
with open(LOG_FILE, mode="a", newline="") as file:
    writer = csv.writer(file)

    # Only write the header row if this is a brand new file
    if not file_already_exists:
        writer.writerow(["Timestamp", "IP Address", "MAC Address", "Vendor"])

    # Loop through every device that responded to ARP request
    for sent_packet, received_packet in answered_devices:
        ip = received_packet.psrc
        mac = received_packet.hwsrc

        # Try to look up manufacturer/vendor name for this MAC address
        try: 
            vendor = mac_lookup.lookup(mac)
        except Exception:
            vendor = "Unknown"


        # Check if this MAC address has never appeared in any previous scan
        if mac not in known_macs:
            print(f"{YELLOW}[NEW DEVICE] IP: {ip}|MAC: {mac}|Vendor: {vendor}{RESET}")
        else:
            print(f"IP: {ip}|MAC: {mac}|Vendor: {vendor}")

        # Write the same info as a row in the CSV file
        writer.writerow([scan_time, ip, mac, vendor])








#                __
#             .-'. \   .-.
#      .-._    \  _ \_ \  \
#     /-   '..--''_.- ''---\.._
#     '--._,' / /  ,.--..  \   '-._
#        /( o/  \  '-..-'  }   )   '.
#     _.-' .'__..--'---.._/__-'      \
#    /  /    ''-.____     /   '-.__  !
#   /.-{  (O)    /   '''---...____ ' )
#      !'-.__.-'(                 ''/
#  .-''\         \_
#  \_.-'_   (O) / '--.._
#       '-..___/  O  .' '.
#           _.-''--../    \
#         .'\ _.--'-.'  _._\
#       .'_.''        \/    '
#      /. /           ! ,'. )
#     {__{            )'   \'
#     ' . \         -'  O  /
#      \_ /'-.__.-''      /
#        '. . ' . \ O _.-'
#          '-.\_..--''   