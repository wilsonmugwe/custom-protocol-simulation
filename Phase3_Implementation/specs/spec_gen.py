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
    # Default encoding and version if not provided
    enc = spec.get("encoding","proto")
    version = int(spec.get("version",1))
    flows = spec.get("flows",[])
    pkts = []

    # ----------------------
    # Helper functions
    # ----------------------

    def handshake(seq):
        """Simulate a simple handshake (ClientHello -> ServerHelloAck)."""
        pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", seq, b"ClientHello")))
        pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "ACK",     seq, b"ServerHelloAck")))

    def request_response(count, start_seq, req_prefix, ack_prefix):
        """
        Generate a series of request/response packet pairs.
        - count: how many pairs to create
        - start_seq: first sequence number
        - req_prefix: prefix for request payloads
        - ack_prefix: prefix for response payloads
        """
        seq = int(start_seq)
        for i in range(count):
            pkts.append(scapy_udp_pkt(payload_bytes=encode_message(
                enc, version, "REQUEST", seq, f"{req_prefix}{i}".encode())))
            pkts.append(scapy_udp_pkt(payload_bytes=encode_message(
                enc, version, "RESPONSE", seq, f"{ack_prefix}{i}".encode())))
            seq += 1

    # ----------------------
    # Flow execution
    # ----------------------

    for step in flows:
        key = next(iter(step))   # e.g. "handshake", "request_response"
        args = step[key]

        if key == "handshake":
            handshake(args.get("seq",1))

        elif key == "request_response":
            request_response(
                args["count"],
                args["start_seq"],
                args.get("req_prefix","REQ-"),
                args.get("ack_prefix","ACK-")
            )

        elif key == "goodbye":
            # End session with a BYE request
            pkts.append(scapy_udp_pkt(payload_bytes=encode_message(
                enc, version, "REQUEST", args["seq"], b"BYE")))

        elif key == "error_truncated":
            # Malformed / truncated packet
            pkts.append(scapy_udp_pkt(payload_bytes=b"\x08\x01"))

        elif key == "error_tampered_tail":
            # Encode normally, then cut off bytes from the tail
            msg = encode_message(enc, version, "RESPONSE", args["seq"], args.get("payload","PAY").encode())
            pkts.append(scapy_udp_pkt(payload_bytes=msg[:-2]))

        elif key == "error_out_of_order":
            # Inject packets with out-of-order sequence numbers
            for s in args["seqs"]:
                pkts.append(scapy_udp_pkt(payload_bytes=encode_message(
                    enc, version, "REQUEST", int(s), b"O")))

        elif key == "error_bad_version":
            # Use an incorrect protocol version by applying a delta
            seq = int(args["seq"])
            delta = int(args.get("version_delta",99))
            pkts.append(scapy_udp_pkt(payload_bytes=encode_message(
                enc, version+delta, "REQUEST", seq, b"BadVersion")))

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

    # Load YAML spec file
    with open(args.spec,"r") as f:
        spec = yaml.safe_load(f)

    # Generate packets
    pkts = from_spec(spec)

    # Ensure directory exists and write PCAP
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    wrpcap(args.out, pkts)

    print("[OK] wrote {} packets -> {}".format(len(pkts), args.out))

if __name__ == "__main__":
    main()
