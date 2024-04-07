#!/usr/bin/env python3
from scapy.all import *

def icmp_scan(ip_prefix):
    ans, unans = sr(IP(dst=ip_prefix)/ICMP(), timeout=2, verbose=False)
    print(f"Received {len(ans) + len(unans)} packets, got {len(ans)} answers, remaining {len(unans)} packets")
    for send, recv in ans:
        print(f"{recv[IP].src}\t{recv[ICMP].type}\t{recv[ICMP].code}\t(alive)")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <IP prefix>")
        sys.exit(1)
    ip_prefix = sys.argv[1]
    icmp_scan(ip_prefix)
