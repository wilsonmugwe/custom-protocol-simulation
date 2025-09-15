from scapy.all import rdpcap, Raw
import binascii

EXPECTED = bytes.fromhex("01 00 03 e9 00 02 48 69 3c f7".replace(" ",""))

for pcap in ["Phase3_Implementation/encodings/hi_proto.pcap",
             "Phase3_Implementation/encodings/hi_asn1.pcap"]:
    pkts = rdpcap(pcap)
    if not pkts:
        print(pcap, "-> no packets")
        continue
    raw = bytes(pkts[0].load) if Raw in pkts[0] else bytes(pkts[0][Raw].load) if pkts[0].haslayer(Raw) else b""
    print(pcap, "RAW:", binascii.hexlify(raw).decode())
    print("Matches expected?", raw == EXPECTED)
