from custom_protocol import CustomProto, save_pcap, CUSTOM_PROTO_PORT
from scapy.all import IP, UDP
dst = "127.0.0.1"
bad = IP(dst=dst)/UDP(dport=CUSTOM_PROTO_PORT, sport=CUSTOM_PROTO_PORT)/CustomProto(
    version=1, msg_type=0x02, seq=1, flags=0, length=999, data=b"abc"
)
save_pcap([bad], "fault_len_mismatch.pcap")
print("Wrote fault_len_mismatch.pcap")
