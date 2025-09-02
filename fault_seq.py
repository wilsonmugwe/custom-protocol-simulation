from custom_protocol import build_packet, save_pcap, CUSTOM_PROTO_PORT
dst = "127.0.0.1"
pkts = [
    build_packet(dst, 0x01, 0, b"hello"),  # HELLO seq=0
    build_packet(dst, 0x02, 1, b"d1"),     # DATA seq=1
    build_packet(dst, 0x02, 3, b"d3"),     # DATA seq=3 (gap: missing 2)
    build_packet(dst, 0x03, 4, b"ack"),    # ACK seq=4
]
save_pcap(pkts, "fault_seq_gap.pcap")
print("Wrote fault_seq_gap.pcap")
