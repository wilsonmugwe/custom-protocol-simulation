# Phase1_Research/test_asn1.py
import binascii
import asn1tools  # make sure you installed with: pip install asn1tools

# CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF)
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

# 1) Compile the ASN.1 spec using DER
codec = asn1tools.compile_files("specs/cusproto.asn", "der")

# 2) Build the same message as in Protobuf
payload = b"Hi"
header_bytes = bytes([
    1,  # version
    0   # type=request
]) + (1001).to_bytes(2, "big") + (len(payload)).to_bytes(2, "big")

body_for_crc = header_bytes + payload
crc = crc16_ccitt_false(body_for_crc)

msg = {
    "header": {
        "version": 1,
        "type": "request",
        "seq": 1001,
        "length": len(payload)
    },
    "payload": payload,
    "crc16": crc
}

# 3) Encode with DER
encoded = codec.encode("Message", msg)

print("=== ASN.1 DER Encoded (hex) ===")
print(hex_bytes(encoded))

# 4) Decode back
decoded = codec.decode("Message", encoded)
print("\n=== Decoded ===")
print(decoded)

# 5) Save the encoded output for later Wireshark demo
out_path = "Phase1_Research/hi_asn1.der"
with open(out_path, "wb") as f:
    f.write(encoded)
print(f"\nSaved: {out_path} ({len(encoded)} bytes)")
