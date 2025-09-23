#!/usr/bin/env python3
import argparse, os, json, random, hashlib, csv, datetime
from scapy.all import wrpcap, rdpcap, Raw
from utils import encode_message, decode_message
from common import scapy_udp_pkt

# ------------------------
# Utility functions
# ------------------------

def write_pcap(path, pkts):
    """Write a list of Scapy packets to a PCAP file."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)  # Ensure directory exists
    wrpcap(path, pkts)
    print("[OK] {} ({} pkts)".format(path, len(pkts)))

def checksum_sha256(path):
    """Compute SHA256 checksum of a file (used for manifest)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):  # Read file in 64KB chunks
            h.update(chunk)
    return h.hexdigest()

# ------------------------
# Commands
# ------------------------

def cmd_manifest(args):
    """Generate a manifest with SHA256 and file size for given files."""
    out = {}
    for p in args.files:
        out[p] = {"sha256": checksum_sha256(p), "bytes": os.path.getsize(p)}
    print(json.dumps(out, indent=2))

def gen_session(enc, version, msgs):
    """
    Generate a normal request/response session.
    - Starts with ClientHello and ServerHelloAck
    - Followed by 'msgs' request/response pairs
    - Ends with a BYE message
    """
    seq = 1
    pkts = []
    # Handshake
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", seq, b"ClientHello")))
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "ACK",     seq, b"ServerHelloAck")))
    seq += 1
    # Request/response pairs
    for i in range(msgs):
        pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", seq, f"REQ-{i}".encode())))
        pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "RESPONSE", seq, f"ACK-{i}".encode())))
        seq += 1
    # Session close
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", seq, b"BYE")))
    return pkts

def gen_errors(enc, version):
    """Generate packets with errors (malformed, wrong sequence, bad version, etc.)."""
    pkts = []
    pkts.append(scapy_udp_pkt(payload_bytes=b"\x08\x01\x12"))  # Truncated
    good = encode_message(enc, version, "REQUEST", 2, b"HELLO")
    pkts.append(scapy_udp_pkt(payload_bytes=good[:-3]))        # Tail truncated
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", 1, b"First")))
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", 99, b"Jump")))  # Jump sequence
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", 2, b"Second")))
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version+99, "REQUEST", 3, b"BadVersion")))
    return pkts

def gen_mixed(enc, version):
    """Generate a mix of valid session, malformed packets, and tampered responses."""
    pkts = []
    pkts += gen_session(enc, version, msgs=5)
    pkts.append(scapy_udp_pkt(payload_bytes=b"\x08\x01"))  # malformed
    tamper = encode_message(enc, version, "RESPONSE", 7, b"PAY")
    pkts.append(scapy_udp_pkt(payload_bytes=tamper[:-2])) # truncated
    # Continue with more normal exchanges
    for seq in range(8, 11):
        pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", seq, f"REQ-{seq}".encode())))
        pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "RESPONSE", seq, f"ACK-{seq}".encode())))
    return pkts

# CLI commands mapping to generation functions
def cmd_session(args): write_pcap(args.out, gen_session(args.enc, args.version, args.msgs))
def cmd_errors(args):  write_pcap(args.out, gen_errors(args.enc, args.version))
def cmd_mixed(args):   write_pcap(args.out, gen_mixed(args.enc, args.version))

def cmd_stress(args):
    """
    Generate a stress test PCAP with random good/bad packets.
    - 70%: normal random payloads
    - 15%: malformed
    - 10%: truncated
    - 5%: repeated/old sequence numbers
    """
    enc, version, count, seed = args.enc, args.version, args.count, args.seed
    random.seed(seed)
    pkts = []
    seq = 1
    for _ in range(count):
        r = random.random()
        if r < 0.7:
            # Normal request with random payload
            payload = os.urandom(random.randint(1,50))
            pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", seq, payload)))
            seq += 1
        elif r < 0.85:
            # Malformed short packet
            pkts.append(scapy_udp_pkt(payload_bytes=b"\x08\x01"))
        elif r < 0.95:
            # Truncated response
            msg = encode_message(enc, version, "RESPONSE", seq, b"PAY")
            pkts.append(scapy_udp_pkt(payload_bytes=msg[:-2]))
            seq += 1
        else:
            # Old/repeated sequence numbers
            back = random.randint(1, min(seq-1, 10)) if seq > 1 else 0
            rseq = max(1, seq - back)
            pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", rseq, b"R")))
    write_pcap(args.out, pkts)

# ------------------------
# PCAP analysis/reporting
# ------------------------

def analyze_pcap(enc, pcap_path):
    """Analyze a PCAP: decode packets and flag issues (sequence errors, len mismatches)."""
    pkts = rdpcap(pcap_path)
    rows = []
    last_seq = None
    for i, p in enumerate(pkts, start=1):
        raw = bytes(p[Raw].load) if Raw in p else b""
        rec = {"frame": i, "len": len(raw), "decoded": False}
        try:
            hdr, payload, crc = decode_message(enc, raw)
            rec.update({"decoded": True,
                        "header": hdr,
                        "payload_utf8": payload.decode("utf-8", "replace"),
                        "crc": crc})
            issues = []
            # Check declared length vs. actual length
            if hdr["length"] != len(payload):
                issues.append(f"LEN_MISMATCH:{hdr['length']}!={len(payload)}")
            # Check sequence monotonicity
            if last_seq is not None and hdr["seq"] != last_seq + 1:
                issues.append(f"SEQ_NON_MONOTONIC:{last_seq}->{hdr['seq']}")
            last_seq = hdr["seq"]
            rec["issues"] = issues
        except Exception as e:
            rec["error"] = f"DECODE_FAIL:{type(e).__name__}:{e}"
        rows.append(rec)
    return rows

def cmd_report(args):
    """
    Analyze PCAP and generate:
    - JSON (per-frame detail)
    - CSV (tabular view)
    - HTML (summary report)
    """
    rows = analyze_pcap(args.enc, args.pcap)
    # JSON output
    os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
    with open(args.json, "w", encoding="utf-8") as f: 
        json.dump(rows, f, indent=2, ensure_ascii=False)
    # CSV output
    os.makedirs(os.path.dirname(args.csv) or ".", exist_ok=True)
    with open(args.csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["frame","decoded","seq","len","issues","error","payload_utf8"])
        for r in rows:
            seq = r.get("header", {}).get("seq", "")
            w.writerow([r["frame"], r["decoded"], seq, r["len"], ";".join(r.get("issues", [])), r.get("error", ""), r.get("payload_utf8", "")])
    # HTML summary
    now = datetime.datetime.utcnow().isoformat() + "Z"
    total = len(rows)
    decoded = sum(1 for r in rows if r["decoded"])
    errcount = sum(1 for r in rows if ("error" in r) or r.get("issues"))
    html = "<!doctype html><html><head><meta charset='utf-8'><title>PCAP Report</title></head><body>"
    html += "<h1>PCAP Report</h1><p>File: {}</p><p>Generated: {}</p>".format(args.pcap, now)
    html += "<ul><li>Total frames: {}</li><li>Decoded: {}</li><li>Frames with issues/errors: {}</li></ul>".format(total, decoded, errcount)
    html += "<p>See CSV/JSON for per-frame details.</p></body></html>"
    os.makedirs(os.path.dirname(args.html) or ".", exist_ok=True)
    with open(args.html, "w", encoding="utf-8") as f: f.write(html)
    print("[OK] wrote {}, {}, {}".format(args.json, args.csv, args.html))

def cmd_validate(args):
    """Validate a PCAP quickly: PASS if no issues, FAIL otherwise."""
    rows = analyze_pcap(args.enc, args.pcap)
    bad = [r for r in rows if ("error" in r) or r.get("issues")]
    status = "PASS" if not bad else "FAIL"
    print(json.dumps({"status": status, "bad_frames": len(bad)}, indent=2))

# ------------------------
# CLI setup
# ------------------------

def build():
    """Build argument parser with subcommands."""
    p = argparse.ArgumentParser(prog="custool", description="Custom Protocol Suite v4.1 (proto + asn1)")
    sub = p.add_subparsers(dest="cmd", required=True)

    # Helper to add common args
    def com(sp):
        sp.add_argument("--enc", choices=["proto","asn1"], default="proto")
        sp.add_argument("--version", type=int, default=1)
        sp.add_argument("--out", required=True)

    # Subcommands
    sp = sub.add_parser("session"); com(sp); sp.add_argument("--msgs", type=int, default=10); sp.set_defaults(func=cmd_session)
    sp = sub.add_parser("errors");  com(sp); sp.set_defaults(func=cmd_errors)
    sp = sub.add_parser("mixed");   com(sp); sp.set_defaults(func=cmd_mixed)
    sp = sub.add_parser("stress");  com(sp); sp.add_argument("--count", type=int, default=2000); sp.add_argument("--seed", type=int, default=42); sp.set_defaults(func=cmd_stress)
    sp = sub.add_parser("manifest"); sp.add_argument("files", nargs="+"); sp.set_defaults(func=cmd_manifest)
    sp = sub.add_parser("report"); sp.add_argument("--enc", choices=["proto","asn1"], required=True); sp.add_argument("--pcap", required=True); sp.add_argument("--json", required=True); sp.add_argument("--csv", required=True); sp.add_argument("--html", required=True); sp.set_defaults(func=cmd_report)
    sp = sub.add_parser("validate"); sp.add_argument("--enc", choices=["proto","asn1"], required=True); sp.add_argument("--pcap", required=True); sp.set_defaults(func=cmd_validate)
    return p

def main():
    """Main entrypoint for CLI."""
    p = build()
    args = p.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
