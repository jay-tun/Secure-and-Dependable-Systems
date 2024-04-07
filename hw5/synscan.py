#!/usr/bin/env python3
from scapy.all import *

def syn_scan(target):
    open_ports = {}
    closed_ports = {}
    ans, unans = sr(IP(dst=target)/TCP(dport=(1, 1024), flags="S"), timeout=2, verbose=False)

    for send, recv in ans:
        if TCP in recv and IP in recv:
            port = recv[TCP].sport
            if recv[TCP].flags == 0x12:  # SYN-ACK
                open_ports[port] = "SA (open)"
            elif recv[TCP].flags == 0x14:  # RST-ACK
                closed_ports[port] = "RA (closed)"

    print(f"Received {len(ans) + len(unans)} packets, got {len(ans)} answers, remaining {len(unans)} packets")
    print("IP Address\tPort\tTCP Flags\tStatus")
    for port in range(1, 1025):
        status = "RA (closed)" if port not in open_ports else open_ports[port]
        print(f"{target}\t{port}\t{status}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target IP>")
        sys.exit(1)
    target = sys.argv[1]
    syn_scan(target)

