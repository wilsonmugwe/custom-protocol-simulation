#!/usr/bin/env python3
from custom_protocol import demo

if __name__ == "__main__":
    # Send to loopback (127.0.0.1). To target a peer, pass their IP (ensure routing/firewall).
    demo(dst_ip="127.0.0.1", out_pcap="custom_demo.pcap", count=6)
