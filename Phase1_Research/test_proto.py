import sys
sys.path.append(".")

import cusproto_pb2 as pb

# Simple CRC16 (CCITT-FALSE)
def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) & 0xFFFF) ^ 0x1021
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF

def hex_bytes(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

# Build a message
payload = b"Hi"
m = pb.Message()
m.header.version = 1
m.header.type = pb.REQUEST
m.header.seq = 1001
m.header.length = len(payload)
m.payload = payload

# Serialize header + payload manually
header = bytes([
    m.header.version,
    int(m.header.type),
]) + m.header.seq.to_bytes(2, "big") + m.header.length.to_bytes(2, "big")

body = header + m.payload
crc = crc16_ccitt_false(body)
m.crc16 = crc
packet = body + crc.to_bytes(2, "big")

print("=== Protobuf object ===")
print(m)
print("\n=== Header+Payload (hex) ===")
print(hex_bytes(body))
print("\nCRC16: 0x%04X" % crc)
print("\n=== FULL PACKET (hex) ===")
print(hex_bytes(packet))

with open("Phase3_Implementation/encodings/hi_proto.bin", "wb") as f:
    f.write(packet)   # 'data' is your Protobuf encoded packet
print("Saved: Phase3_Implementation/encodings/hi_proto.bin")

