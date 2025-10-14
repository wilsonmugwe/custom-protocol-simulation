from __future__ import annotations
from typing import Literal, Tuple, Dict, Any
import struct

# Allowed encodings
Encoding = Literal["proto", "asn1"]

# CRC-16/CCITT-FALSE parameters
POLY = 0x1021
INIT = 0xFFFF

# ---------------------------
# CRC + header packing
# ---------------------------

def crc16_ccitt(data: bytes, poly: int = POLY, init_val: int = INIT) -> int:
    """
    Compute CRC-16/CCITT-FALSE checksum for given data.
    - Polynomial: 0x1021
    - Initial value: 0xFFFF
    This is used for both Protobuf and ASN.1 encodings to maintain consistency.
    """
    crc = init_val
    for b in data:
        crc ^= (b << 8) & 0xFFFF
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ poly) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF

def _pack_header(version: int, type_int: int, seq: int, length: int) -> bytes:
    """
    Pack a header into network byte order.
    Format: [version:uint32][type:uint32][seq:uint32][length:uint32]
    - This is the same for both encodings (proto, asn1).
    - Ensures CRC calculation uses identical structure across encodings.
    """
    return struct.pack("!IIII", int(version), int(type_int), int(seq), int(length))

# ---------------------------
# Common enums / validation
# ---------------------------

# Valid message types across both encodings
_VALID_TYPES = {"REQUEST", "ACK", "RESPONSE", "ERROR"}

# Mapping between string types (Protobuf style) and ASN.1 symbols
ASN1_STR_TO_ENUM = {"REQUEST": "request", "ACK": "ack", "RESPONSE": "response", "ERROR": "error"}
ASN1_ENUM_TO_INT = {"request": 0, "ack": 1, "response": 2, "error": 3}

def _ensure_valid_type(msg_type: str) -> None:
    """
    Ensure msg_type is valid.
    Raises ValueError if an unknown type is provided.
    """
    if msg_type not in _VALID_TYPES:
        raise ValueError(f"Unknown msg_type '{msg_type}'. Expected one of {_VALID_TYPES}.")

# ---------------------------
# Protobuf encode/decode
# ---------------------------

def encode_message_proto(version: int, msg_type: str, seq: int, payload: bytes) -> bytes:
    """
    Encode a message into Protobuf format.
    - Builds Header
    - Computes CRC over packed header + payload
    - Serializes using cusproto_pb2.Message
    """
    _ensure_valid_type(msg_type)
    from cusproto_pb2 import Message, Header, MsgType  # imported here to avoid hard dependency on load
    try:
        t = getattr(MsgType, msg_type)
    except AttributeError as e:
        raise ValueError(f"Protobuf MsgType missing '{msg_type}'.") from e

    hdr = Header(version=int(version), type=int(t), seq=int(seq), length=len(payload))
    crc = crc16_ccitt(_pack_header(hdr.version, hdr.type, hdr.seq, hdr.length) + payload)
    return Message(header=hdr, payload=payload, crc16=int(crc)).SerializeToString()

def decode_message_proto(raw: bytes) -> Tuple[Dict[str, int], bytes, int]:
    """
    Decode a Protobuf-encoded message.
    Returns:
      - header dict (version, type, seq, length)
      - payload as bytes
      - crc16 value
    """
    from cusproto_pb2 import Message
    m = Message()
    try:
        m.ParseFromString(raw)
    except Exception as e:
        raise ValueError(f"Protobuf decode failed: {e}") from e

    h = m.header
    header = {
        "version": int(h.version),
        "type": int(h.type),
        "seq": int(h.seq),
        "length": int(h.length),
    }
    return header, bytes(m.payload), int(m.crc16)

# ---------------------------
# ASN.1 (UPER) encode/decode
# ---------------------------

# Cached ASN.1 module (so we don’t recompile for every packet)
_ASN1_MOD = None

def _asn1_compile():
    """
    Compile ASN.1 schema (cusproto.asn) using asn1tools with UPER encoding.
    - Compiled once and cached in _ASN1_MOD
    - Reused across all encode/decode calls for performance
    """
    global _ASN1_MOD
    if _ASN1_MOD is None:
        import asn1tools
        _ASN1_MOD = asn1tools.compile_files("cusproto.asn", codec="uper")
    return _ASN1_MOD

def encode_message_asn1(version: int, msg_type: str, seq: int, payload: bytes) -> bytes:
    """
    Encode a message into ASN.1 (UPER).
    - Builds header dict
    - Computes CRC over packed header + payload
    - Uses compiled ASN.1 schema to encode
    """
    _ensure_valid_type(msg_type)
    mod = _asn1_compile()
    sym = ASN1_STR_TO_ENUM[msg_type]
    hdr = {"version": int(version), "type": sym, "seq": int(seq), "length": len(payload)}
    crc = crc16_ccitt(_pack_header(version, ASN1_ENUM_TO_INT[sym], seq, len(payload)) + payload)
    try:
        return mod.encode("Message", {"header": hdr, "payload": payload, "crc16": int(crc)})
    except Exception as e:
        raise ValueError(f"ASN.1 encode failed: {e}") from e

def decode_message_asn1(raw: bytes) -> Tuple[Dict[str, int], bytes, int]:
    """
    Decode an ASN.1 (UPER)-encoded message.
    Returns:
      - header dict (version, type, seq, length)
      - payload as bytes
      - crc16 value
    """
    mod = _asn1_compile()
    try:
        m: Dict[str, Any] = mod.decode("Message", raw)
    except Exception as e:
        raise ValueError(f"ASN.1 decode failed: {e}") from e

    h = m["header"]
    t_sym = h["type"]  # e.g., 'request'
    try:
        t_int = ASN1_ENUM_TO_INT[t_sym]
    except KeyError as e:
        raise ValueError(f"Unknown ASN.1 type symbol '{t_sym}'.") from e

    header = {
        "version": int(h["version"]),
        "type": int(t_int),
        "seq": int(h["seq"]),
        "length": int(h["length"]),
    }
    return header, bytes(m["payload"]), int(m["crc16"])

# ---------------------------
# Unified public API
# ---------------------------

def encode_message(enc: Encoding, version: int, msg_type: str, seq: int, payload: bytes) -> bytes:
    """
    Unified encoder.
    Dispatches to either Protobuf or ASN.1 depending on `enc`.
    """
    if enc == "proto":
        return encode_message_proto(version, msg_type, seq, payload)
    if enc == "asn1":
        return encode_message_asn1(version, msg_type, seq, payload)
    raise ValueError(f"Unknown encoding: {enc}")

def decode_message(enc: Encoding, raw: bytes):
    """
    Unified decoder.
    Dispatches to either Protobuf or ASN.1 depending on `enc`.
    """
    if enc == "proto":
        return decode_message_proto(raw)
    if enc == "asn1":
        return decode_message_asn1(raw)
    raise ValueError(f"Unknown encoding: {enc}")

# Exported symbols for clarity
__all__ = [
    "Encoding",
    "crc16_ccitt",
    "encode_message",
    "decode_message",
    "encode_message_proto",
    "decode_message_proto",
    "encode_message_asn1",
    "decode_message_asn1",
]



# ---------------------------
# References
# ---------------------------
"""
External references and inspirations used for this implementation:

1. CRC-16/CCITT-FALSE algorithm
   - StackOverflow: “CRC-CCITT 16-bit Python Manual Calculation”
     https://stackoverflow.com/questions/25239423/crc-ccitt-16-bit-python-manual-calculation
   - PyCRC library (Python implementations of CRC algorithms)
     https://github.com/alexbutirskiy/PyCRC
   - ranelcom/crc16 (Python CRC-16 CCITT-FALSE implementation)
     https://github.com/ranelcom/crc16

2. ASN.1 encoding/decoding
   - asn1tools documentation (UPER codec)
     https://pypi.org/project/asn1tools/
   - Nick vs Networking blog: “ASN.1 IRL”
     https://nickvsnetworking.com/asn-1/
   - ShareTechnote: Python ASN.1 with asn1tools
     https://www.sharetechnote.com/html/Python_ASN.html

3. Protobuf encoding/decoding
   - Google Protobuf Python API reference
     https://developers.google.com/protocol-buffers/docs/pythontutorial
"""