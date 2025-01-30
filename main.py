import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP
from colorama import init
from termcolor import colored

init()
THRESHOLD = 40      # packets per minute
print(colored(f"Packet Threshold: {THRESHOLD} packets/minute", 'light_blue'))


def packet_callback(packet):
    src_ip = packet[IP].src
    packet_count[src_ip] += 1
    current_time = time.time()
    interval = current_time - start_time[0]

    if interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / interval

            # print(f"IP: {ip}, Packet rate: {packet_rate}")        # verbose
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(colored(f"Blocked IP: {ip}, Packet rate: {packet_rate}", 'red'))
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                blocked_ips.add(ip)

        packet_count.clear()
        start_time[0] = current_time






def main():
    if os.geteuid() != 0:       # checking root
        print("This script requires root privileges.")
        sys.exit(1)

    global packet_count = defaultdict(int)
    global start_time = [time.time()]
    global blocked_ips = set()

    print(colored("\nAnalyzing network traffic...", "light_blue"))
    sniff(filter="ip", prn=packet_callback)


if __name__ == "__main__":
    main()