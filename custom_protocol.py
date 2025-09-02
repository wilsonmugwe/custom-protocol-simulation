#!/usr/bin/env python3
"""
custom_protocol.py
Phase 2: Scapy implementation for the Custom Protocol Simulation project.

Header layout (byte offsets within the CustomProto header):
  0: version   (1 byte, enum)
  1: msg_type  (1 byte, enum)  {0x01=HELLO, 0x02=DATA, 0x03=ACK, 0x04=ERROR}
  2..3: seq    (2 bytes, uint16)
  4: flags     (1 byte, bit flags F0..F7)
  5..6: length (2 bytes, uint16) -> auto from len(data) via FieldLenField
  7..(7+length-1): data (variable)

Demo flow (send_sequence):
  HELLO seq=0 -> DATA seq=1..N -> ACK seq=N+1

Outputs:
  - Packet summary printed to stdout
  - Validation checks (structure + sequence/state)
  - PCAP written via wrpcap()
"""

from scapy.all import (
    Packet, ByteEnumField, ShortField, FlagsField, StrLenField, FieldLenField,
    bind_layers, UDP, IP,
    send, sniff, wrpcap, rdpcap
)
from typing import Optional, List
import sys
import time

# -----------------------------
# Protocol constants (edit as needed)
# -----------------------------
CUSTOM_PROTO_PORT = 5555
VERSION_ENUM = {1: "v1"}

MSG_TYPES = {
    0x01: "HELLO",
    0x02: "DATA",
    0x03: "ACK",
    0x04: "ERROR",
}

# -----------------------------
# Custom Protocol Header
# -----------------------------
class CustomProto(Packet):
    name = "CustomProto"
    fields_desc = [
        ByteEnumField("version", 1, VERSION_ENUM),
        ByteEnumField("msg_type", 0x01, MSG_TYPES),
        ShortField("seq", 0),
        FlagsField("flags", 0x00, 8, ["F0","F1","F2","F3","F4","F5","F6","F7"]),
        # Auto-compute `length` from the size of `data`
        FieldLenField("length", None, length_of="data", fmt="H"),
        # Size `data` from the `length` field
        StrLenField("data", b"", length_from=lambda pkt: pkt.length),
    ]

# Bind protocol to UDP on chosen port (both directions)
bind_layers(UDP, CustomProto, dport=CUSTOM_PROTO_PORT)
bind_layers(UDP, CustomProto, sport=CUSTOM_PROTO_PORT)

# -----------------------------
# Builders & Send helpers
# -----------------------------
def build_packet(dst_ip: str,
                 msg_type: int = 0x01,
                 seq: int = 0,
                 payload: bytes = b"hello",
                 flags: int = 0x00,
                 dport: int = CUSTOM_PROTO_PORT):
    """Build an IP/UDP/CustomProto packet."""
    cp = CustomProto(version=1, msg_type=msg_type, seq=seq, flags=flags, data=payload)
    pkt = IP(dst=dst_ip)/UDP(dport=dport, sport=dport)/cp
    return pkt

def send_one(dst_ip: str, msg_type: int, seq: int, payload: bytes, dport: int = CUSTOM_PROTO_PORT):
    pkt = build_packet(dst_ip, msg_type, seq, payload, dport=dport)
    send(pkt, verbose=False)  # Layer-3 send (IP/UDP)
    return pkt

def send_sequence(dst_ip: str, count: int = 5, dport: int = CUSTOM_PROTO_PORT) -> List:
    """
    Send a short sequence: HELLO, DATA x (count-2), ACK.
    ACK uses "next" sequence number after the last DATA.
    """
    sent = []
    if count < 3:
        count = 3
    # HELLO seq=0
    sent.append(send_one(dst_ip, 0x01, 0, b"hello", dport))
    # DATA frames seq=1..(count-2)
    for i in range(1, count - 1):
        payload = f"data-{i}".encode()
        sent.append(send_one(dst_ip, 0x02, i, payload, dport))
        time.sleep(0.02)
    # ACK seq=(count-1) == last_data_seq+1
    sent.append(send_one(dst_ip, 0x03, count - 1, b"ack", dport))
    return sent

# -----------------------------
# Sniff & PCAP helpers
# -----------------------------
def capture_filter(dport: int = CUSTOM_PROTO_PORT) -> str:
    return f"udp port {dport}"

def sniff_custom(timeout: int = 5, dport: int = CUSTOM_PROTO_PORT) -> List:
    # Return a plain list so we can concat with normal lists
    return list(sniff(timeout=timeout, filter=capture_filter(dport)))

def save_pcap(packets: List, path: str):
    wrpcap(path, packets)

def load_pcap(path: str) -> List:
    return rdpcap(path)

# -----------------------------
# Validation & Summary
# -----------------------------
class SequenceError(Exception): ...
class LengthMismatchError(Exception): ...
class HandshakeError(Exception): ...

def _custom_layers(packets: List) -> List[CustomProto]:
    cps = []
    for p in packets:
        cp = p.getlayer(CustomProto)
        if cp:
            cps.append(cp)
    return cps

def validate_packet_structure(packets: List) -> None:
    """version/msg_type known; length == len(data)"""
    for idx, p in enumerate(packets):
        cp = p.getlayer(CustomProto)
        if not cp:
            continue
        if int(cp.version) not in VERSION_ENUM:
            raise ValueError(f"pkt#{idx}: unknown version {cp.version}")
        if int(cp.msg_type) not in MSG_TYPES:
            raise ValueError(f"pkt#{idx}: unknown msg_type {cp.msg_type}")
        data_len = len(cp.data or b"")
        # FieldLenField may be None on in-memory packets; use data_len in that case
        field_len = int(cp.length) if getattr(cp, "length", None) is not None else data_len
        if field_len != data_len:
            raise LengthMismatchError(
                f"pkt#{idx}: length field {field_len} != actual data bytes {data_len}"
            )

def validate_sequence_state_machine(packets: List) -> None:
    """HELLO seq=0 → DATA seq=1..N → ACK seq=N+1"""
    cps = _custom_layers(packets)
    if not cps:
        raise HandshakeError("no CustomProto packets found")

    first = cps[0]
    if int(first.msg_type) != 0x01 or int(first.seq) != 0:
        raise HandshakeError(f"first packet must be HELLO seq=0 (got type={first.msg_type}, seq={first.seq})")

    expected = 0
    last_data_seq = None
    for cp in cps[:-1]:
        if int(cp.msg_type) in (0x01, 0x02):
            if int(cp.seq) != expected:
                raise SequenceError(f"expected seq={expected}, got {cp.seq} for type={MSG_TYPES.get(int(cp.msg_type))}")
            if int(cp.msg_type) == 0x02:
                last_data_seq = expected
            expected += 1

    last = cps[-1]
    if int(last.msg_type) != 0x03:
        raise HandshakeError(f"last packet must be ACK (got type={last.msg_type})")

    ack_expected = 1 if last_data_seq is None else last_data_seq + 1
    if int(last.seq) != ack_expected:
        raise SequenceError(f"ACK seq must be {ack_expected}, got {last.seq}")

def summarize_packets(packets: List) -> str:
    lines = []
    for p in packets:
        cp = p.getlayer(CustomProto)
        if not cp:
            continue
        src = p[IP].src if IP in p else "?"
        dst = p[IP].dst if IP in p else "?"
        sport = p[UDP].sport if UDP in p else "?"
        dport = p[UDP].dport if UDP in p else "?"
        try:
            flags_hex = f"0x{int(cp.flags):02x}"
        except Exception:
            flags_hex = str(cp.flags)
        # If FieldLenField hasn't populated on the object yet, compute from data
        length_val = int(cp.length) if getattr(cp, "length", None) is not None else len(cp.data or b"")
        lines.append(
            f"{src}:{sport} -> {dst}:{dport} | "
            f"type={MSG_TYPES.get(int(cp.msg_type), hex(int(cp.msg_type)))} "
            f"seq={int(cp.seq)} len={length_val} flags={flags_hex} data={cp.data!r}"
        )
    return "\n".join(lines)

# -----------------------------
# CLI demo
# -----------------------------
def demo(dst_ip: str = "127.0.0.1", out_pcap: Optional[str] = "custom_demo.pcap", count: int = 6) -> int:
    print(f"[+] Sending {count} packets to {dst_ip}:{CUSTOM_PROTO_PORT}")
    sent = send_sequence(dst_ip, count=count)

    print("[+] Sniffing for replies/loopback…")
    captured = sniff_custom(timeout=3)

    all_pkts = sent + captured
    print(f"[+] Total packets (sent + captured): {len(all_pkts)}")
    print(summarize_packets(all_pkts))

    ok = True
    try:
        validate_packet_structure(all_pkts)
        print("[✓] Structure validation passed")
    except Exception as e:
        ok = False
        print(f"[!] Structure validation FAILED: {e}")

    try:
        validate_sequence_state_machine(all_pkts)
        print("[✓] Sequence/state validation passed")
    except Exception as e:
        ok = False
        print(f"[!] Sequence/state validation FAILED: {e}")

    if out_pcap:
        save_pcap(all_pkts, out_pcap)
        print(f"[+] Saved PCAP -> {out_pcap}")

    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(demo())
