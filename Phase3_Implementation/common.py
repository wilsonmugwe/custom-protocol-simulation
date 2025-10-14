from scapy.all import IP, UDP, Raw

# Default UDP destination port used by the custom protocol
DEFAULT_DPORT = 5555

def scapy_udp_pkt(
    src_ip="127.0.0.1",       # Source IP address (default: localhost)
    dst_ip="127.0.0.1",       # Destination IP address (default: localhost)
    src_port=40000,           # Source UDP port (arbitrary high port number)
    dst_port=DEFAULT_DPORT,   # Destination UDP port (default: 5555, used by protocol)
    payload_bytes=b""         # Payload data (raw bytes passed into packet)
):
    """
    Build a Scapy UDP packet with a raw payload.

    Packet Layers:
      - IP   (sets source and destination IP addresses)
      - UDP  (sets source and destination UDP ports)
      - Raw  (carries the protocol/application payload as raw bytes)

    Returns:
        A Scapy packet object that can be sent or written into a PCAP file.
    """

    # Construct packet by stacking layers:
    #   IP header -> UDP header -> Raw payload
    return (
        IP(src=src_ip, dst=dst_ip) /         # IP layer with source/destination IPs
        UDP(sport=src_port, dport=dst_port) /# UDP layer with source/destination ports
        Raw(load=payload_bytes)              # Raw layer containing application data
    )


# ------------------------
# References
# ------------------------
"""
Scapy documentation (layers, Raw, UDP, IP, wrpcap/rdpcap):
- https://scapy.readthedocs.io/

General UDP/IP reference (IETF):
- UDP (RFC 768): https://www.rfc-editor.org/rfc/rfc768
- Internet Protocol (RFC 791): https://www.rfc-editor.org/rfc/rfc791
"""