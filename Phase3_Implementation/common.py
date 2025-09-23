from scapy.all import IP, UDP, Raw

# Default UDP destination port used by your custom protocol
DEFAULT_DPORT = 5555

def scapy_udp_pkt(
    src_ip="127.0.0.1",   # Source IP address (default = localhost)
    dst_ip="127.0.0.1",   # Destination IP address (default = localhost)
    src_port=40000,       # Source UDP port (arbitrary high port)
    dst_port=DEFAULT_DPORT, # Destination UDP port (default = 5555)
    payload_bytes=b""     # Payload data (raw bytes)
):
    """
    Build a Scapy UDP packet with raw payload.
    Layers:
      - IP (src, dst)
      - UDP (sport, dport)
      - Raw (application payload)
    """
    return (
        IP(src=src_ip, dst=dst_ip) /       # IP header
        UDP(sport=src_port, dport=dst_port) /  # UDP header
        Raw(load=payload_bytes)            # Raw payload data
    )
