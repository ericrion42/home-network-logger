# scanner.py
# Main script for our home network logger project.

# ANSI escape codes let us print colored text to the terminal.
GREEN = "\033[92m"
RESET = "\033[0m"
ORANGE = "\033[38;5;208m"

# Print a test message
print(f"{GREEN}[SUCCESS] Environment Initialized. Scanner is ready to build.{RESET}")

# Import scapy's tools for building and sending ARP requests
from scapy.all import ARP, Ether, srp
from datetime import datetime
import csv
import os

# Define the network range we want to scan.
TARGET_IP_RANGE = "192.168.1.0/24"
LOG_FILE = "network_log.csv"

# Build ARP request packet
arp_request = ARP(pdst=TARGET_IP_RANGE)

# Ethernet frames need a destination MAC address.
ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

# Combine the Ethernet frame and ARP request into one packet and send.
packet = ether_frame / arp_request

# Send the packet and capture the responses.
answered_devices, unanswered_devices = srp(packet, timeout=2, verbose=False)

# Capture the current dte and time as soon as the scan finishes
scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Print an orange header showing when this scan ran and how many devices were found
print(f"{ORANGE}--- Scan completed at {scan_time} | {len(answered_devices)} devices found ---{RESET}")

# Check if the log file already exists
file_already_exists = os.path.isfile(LOG_FILE)

# Open CSV in "append" mode
with open(LOG_FILE, mode="a", newline="") as file:
    writer = csv.writer(file)

    # Only write the header row if this is a brand new file
    if not file_already_exists:
        writer.writerow(["Timestamp", "IP Address", "MAC Address"])

    # Loop through every device that responded to ARP request
    for sent_packet, received_packet in answered_devices:
        ip = received_packet.psrc
        mac = received_packet.hwsrc

        # Print to terminal
        print(f"IP: {ip}    MAC: {mac}")

        # Write the same info as a row in the CSV file
        writer.writerow([scan_time, ip, mac])













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