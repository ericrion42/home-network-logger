# scanner.py
# Main script for our home network logger project.

# ANSI escape codes let us print colored text to the terminal.
GREEN = "\033[92m"
RESET = "\033[0m"

# Print a test message
print(f"{GREEN}[SUCCESS] Environment Initialized. Scanner is ready to build.{RESET}")

# Import scapy's tools for building and sending ARP requests
from scapy.all import ARP, Ether, srp

# Define the network range we want to scan.
TARGET_IP_RANGE = "192.168.1.0/24"

# Build ARP request packet
arp_request = ARP(pdst=TARGET_IP_RANGE)

# Ethernet frames need a destination MAC address.
ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

# Combine the Ethernet frame and ARP request into one packet and send.
packet = ether_frame / arp_request

# Send the packet and capture the responses.
answered_devices, unanswered_devices = srp(packet, timeout=2, verbose=False)

# Loop through every device that responded and print its IP and MAC address.
for sent_packet, received_packet in answered_devices:
    print(f"IP: {received_packet.psrc}     MAC: {received_packet.hwsrc}")














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