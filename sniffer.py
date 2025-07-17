from scapy.all import sniff, IP
from datetime import datetime
from colorama import init, Fore

# Initialize colorama for colored output
init()

# Counter for packets
packet_count = 0

# Function to display packet info
def show_packet(packet):
    global packet_count

    if IP in packet:
        packet_count += 1
        time_now = datetime.now().strftime("%H:%M:%S")
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto

        # Choose protocol name
        if proto == 6:
            proto_name = "TCP"
        elif proto == 17:
            proto_name = "UDP"
        elif proto == 1:
            proto_name = "ICMP"
        else:
            proto_name = "Other"

        # Print in color
        print(Fore.CYAN + f"[{time_now}] Packet #{packet_count}")
        print(Fore.YELLOW + f"    From: {src} --> To: {dst}")
        print(Fore.MAGENTA + f"    Protocol: {proto_name} ({proto})")
        print(Fore.WHITE)

# Start sniffing
print(Fore.GREEN + "\n💫 Sniffing started... Press Ctrl+C to stop.\n")
sniff(prn=show_packet, store=False, filter="ip")