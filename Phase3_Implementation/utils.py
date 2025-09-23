from __future__ import annotations
from typing import Literal
import struct

Encoding = Literal["proto", "asn1"]

POLY = 0x1021
INIT = 0xFFFF

def crc16_ccitt(data: bytes, poly: int = POLY, init_val: int = INIT) -> int:
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
    return struct.pack("!IIII", int(version), int(type_int), int(seq), int(length))

# ---------- Protobuf ----------
def encode_message_proto(version: int, msg_type: str, seq: int, payload: bytes) -> bytes:
    from cusproto_pb2 import Message, Header, MsgType
    t = getattr(MsgType, msg_type)
    hdr = Header(version=version, type=t, seq=seq, length=len(payload))
    crc = crc16_ccitt(_pack_header(hdr.version, hdr.type, hdr.seq, hdr.length) + payload)
    return Message(header=hdr, payload=payload, crc16=crc).SerializeToString()

def decode_message_proto(raw: bytes):
    from cusproto_pb2 import Message
    m = Message(); m.ParseFromString(raw)
    h = m.header
    header = {"version": int(h.version), "type": int(h.type), "seq": int(h.seq), "length": int(h.length)}
    return header, bytes(m.payload), int(m.crc16)

# ---------- ASN.1 (UPER) ----------
def _asn1_compile():
    import asn1tools
    return asn1tools.compile_files("cusproto.asn", codec="uper")

ASN1_STR_TO_ENUM = {"REQUEST":"request","ACK":"ack","RESPONSE":"response","ERROR":"error"}
ASN1_ENUM_TO_INT = {"request":0,"ack":1,"response":2,"error":3}

def encode_message_asn1(version: int, msg_type: str, seq: int, payload: bytes) -> bytes:
    mod = _asn1_compile()
    sym = ASN1_STR_TO_ENUM[msg_type]
    hdr = {"version": int(version), "type": sym, "seq": int(seq), "length": len(payload)}
    crc = crc16_ccitt(_pack_header(version, ASN1_ENUM_TO_INT[sym], seq, len(payload)) + payload)
    return mod.encode("Message", {"header": hdr, "payload": payload, "crc16": int(crc)})

def decode_message_asn1(raw: bytes):
    mod = _asn1_compile()
    m = mod.decode("Message", raw)
    h = m["header"]
    t_int = ASN1_ENUM_TO_INT[h["type"]]
    header = {"version": int(h["version"]), "type": t_int, "seq": int(h["seq"]), "length": int(h["length"])}
    return header, bytes(m["payload"]), int(m["crc16"])

# ---------- Unified API ----------
def encode_message(enc: Encoding, version: int, msg_type: str, seq: int, payload: bytes) -> bytes:
    if enc == "proto": return encode_message_proto(version, msg_type, seq, payload)
    if enc == "asn1":  return encode_message_asn1(version, msg_type, seq, payload)
    raise ValueError(f"Unknown encoding: {enc}")

def decode_message(enc: Encoding, raw: bytes):
    if enc == "proto": return decode_message_proto(raw)
    if enc == "asn1":  return decode_message_asn1(raw)
    raise ValueError(f"Unknown encoding: {enc}")
