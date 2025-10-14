# Encoding Comparison: Protobuf vs ASN.1 (DER)

This document compares wire encodings for the same semantic message using **Protocol Buffers** and **ASN.1 DER**, and provides a practical troubleshooting guide for building, converting, and inspecting packets in Wireshark.

---

## Semantic Message (common for both)

| Field    | Value                                  |
|----------|----------------------------------------|
| version  | 1                                      |
| type     | REQUEST                                |
| seq      | 1001                                   |
| length   | 2                                      |
| payload  | "Hi"                                   |
| crc16    | CRC-16/CCITT-FALSE(header + payload)   |

---

## Protobuf (from `test.py`)

- **Header + Payload (hex):** `01 00 03 E9 00 02 48 69`  
- **CRC16:** `0x3CF7`  
- **Full Packet:** `01 00 03 E9 00 02 48 69 3C F7`

## ASN.1 DER (from `test_asn1.py`)

- **Encoded file:** `Phase1_Research/hi_asn1.der` (Tag–Length–Value format)
- **Decoded object:** matches the semantic fields above
- **Note:** DER is explicit and standardized; each field is wrapped in a TLV structure.

---

## Quick Comparison

| Aspect            | Protobuf                               | ASN.1 (DER)                 |
|------------------|-----------------------------------------|-----------------------------|
| Structure        | Compact binary with varints/field nums  | Explicit Tag–Length–Value   |
| Wire size        | Smaller                                 | Larger                      |
| Human readability| Low                                     | Moderate (TLV aids parsing) |
| Typical use      | Lightweight modern systems              | Formal/standardized systems |

**Summary:** Same semantics, different wire by design—Protobuf optimizes for compactness; DER prioritizes explicit structure and interoperability.

---

## Troubleshooting: Encoding & Decoding

### A) Environment & Tools

```bash
# Install Protocol Buffers 
brew install protobuf
protoc --version   # expect ≥ 3.21

# Python deps
pip install protobuf asn1crypto pycrc scapys

# Wireshark & helpers (includes text2pcap)
brew install wireshark
which text2pcap


## Common Issues & Fixes

| Problem | Fix |
|----------|-----|
| `protoc` not found | `brew install protobuf` |
| `cusproto_pb2` import fails | Run script from repo root or `sys.path.append(os.getcwd())` |
| DER file empty | Ensure encoder prints “Saved:” message |
| CRC mismatch | Use CRC-16/CCITT-FALSE (init=0xFFFF, poly=0x1021) |
| `text2pcap` outputs 0 packets | Ensure spaced hex via `xxd -p | sed 's/../& /g'` |
