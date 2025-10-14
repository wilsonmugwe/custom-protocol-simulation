#!/usr/bin/env python3
import argparse, os, yaml
from scapy.all import wrpcap
from utils import encode_message
from common import scapy_udp_pkt

def from_spec(spec):
    """
    Build a list of UDP packets based on a YAML specification.
    The spec describes a sequence of protocol flows such as handshakes,
    request/response exchanges, and injected errors.
    """
    # Pick encoding scheme and protocol version (defaults if missing in YAML)
    enc = spec.get("encoding", "proto")
    version = int(spec.get("version", 1))
    flows = spec.get("flows", [])
    pkts = []  # list to collect generated Scapy packets

    # ----------------------
    # Helper functions
    # ----------------------

    def handshake(seq):
        """Simulate a simple handshake (ClientHello -> ServerHelloAck)."""
        # Client sends request
        pkts.append(scapy_udp_pkt(
            payload_bytes=encode_message(enc, version, "REQUEST", seq, b"ClientHello")))
        # Server replies with acknowledgment
        pkts.append(scapy_udp_pkt(
            payload_bytes=encode_message(enc, version, "ACK", seq, b"ServerHelloAck")))

    def request_response(count, start_seq, req_prefix, ack_prefix):
        """
        Generate a series of request/response packet pairs.
        - count: number of pairs to create
        - start_seq: starting sequence number
        - req_prefix: prefix string for request payloads
        - ack_prefix: prefix string for response payloads
        """
        seq = int(start_seq)
        for i in range(count):
            # Build request with incrementing sequence
            pkts.append(scapy_udp_pkt(payload_bytes=encode_message(
                enc, version, "REQUEST", seq, f"{req_prefix}{i}".encode())))
            # Build corresponding response
            pkts.append(scapy_udp_pkt(payload_bytes=encode_message(
                enc, version, "RESPONSE", seq, f"{ack_prefix}{i}".encode())))
            seq += 1

    # ----------------------
    # Flow execution
    # ----------------------

    for step in flows:
        # Each step is a dict like {"handshake": {...}}
        key = next(iter(step))
        args = step[key]

        if key == "handshake":
            handshake(args.get("seq", 1))

        elif key == "request_response":
            request_response(
                args["count"],
                args["start_seq"],
                args.get("req_prefix", "REQ-"),
                args.get("ack_prefix", "ACK-")
            )

        elif key == "goodbye":
            # End session with a BYE request
            pkts.append(scapy_udp_pkt(payload_bytes=encode_message(
                enc, version, "REQUEST", args["seq"], b"BYE")))

        elif key == "error_truncated":
            # Deliberately add a malformed/truncated packet
            pkts.append(scapy_udp_pkt(payload_bytes=b"\x08\x01"))

        elif key == "error_tampered_tail":
            # Encode a normal packet, then chop off last 2 bytes
            msg = encode_message(
                enc, version, "RESPONSE", args["seq"], args.get("payload", "PAY").encode())
            pkts.append(scapy_udp_pkt(payload_bytes=msg[:-2]))

        elif key == "error_out_of_order":
            # Inject requests with deliberately out-of-order sequence numbers
            for s in args["seqs"]:
                pkts.append(scapy_udp_pkt(payload_bytes=encode_message(
                    enc, version, "REQUEST", int(s), b"O")))

        elif key == "error_bad_version":
            # Generate a packet with the wrong protocol version (offset by delta)
            seq = int(args["seq"])
            delta = int(args.get("version_delta", 99))
            pkts.append(scapy_udp_pkt(payload_bytes=encode_message(
                enc, version + delta, "REQUEST", seq, b"BadVersion")))

        else:
            # If YAML contains an unknown flow type
            raise ValueError(f"Unknown step: {key}")

    return pkts


def main():
    """Entry point: parse YAML spec, generate packets, and write PCAP file."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", required=True, help="YAML specification describing packet flow")
    ap.add_argument("--out", required=True, help="Output PCAP file path")
    args = ap.parse_args()

    # Load YAML spec from file
    with open(args.spec, "r") as f:
        spec = yaml.safe_load(f)

    # Generate packets from spec
    pkts = from_spec(spec)

    # Ensure output directory exists, then write packets to PCAP
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    wrpcap(args.out, pkts)

    print("[OK] wrote {} packets -> {}".format(len(pkts), args.out))


if __name__ == "__main__":
    main()


# ------------------------
# References
# ------------------------
"""
YAML parsing:
- PyYAML documentation: https://pyyaml.org/wiki/PyYAMLDocumentation

Packet crafting / PCAP I/O:
- Scapy docs (layers, Raw, UDP/IP, wrpcap): https://scapy.readthedocs.io/

Custom payload encoding/decoding (used by this tool):
- Google Protocol Buffers (Python): https://developers.google.com/protocol-buffers/docs/pythontutorial
- asn1tools (UPER codec) docs: https://pypi.org/project/asn1tools/

General UDP/IP reference (IETF):
- UDP (RFC 768): https://www.rfc-editor.org/rfc/rfc768
- Internet Protocol (RFC 791): https://www.rfc-editor.org/rfc/rfc791
"""