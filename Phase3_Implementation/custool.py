#!/usr/bin/env python3
"""
custool: Custom Protocol Suite v4.1 (proto + asn1)
- Generates PCAPs for normal sessions, mixed traffic, and error cases
- Produces reports (JSON/CSV/HTML) by decoding packets
- Quick validation (PASS/FAIL) for a given PCAP
"""

import argparse, os, json, random, hashlib, csv, datetime
from scapy.all import wrpcap, rdpcap, Raw
from utils import encode_message, decode_message
from common import scapy_udp_pkt

# ------------------------
# Utility functions
# ------------------------

def write_pcap(path, pkts):
    """Write a list of Scapy packets to a PCAP file, ensuring the directory exists."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)  # Create parent dirs if needed
    wrpcap(path, pkts)                                       # Dump packets to disk
    print("[OK] {} ({} pkts)".format(path, len(pkts)))       # Simple success log

def checksum_sha256(path):
    """Return SHA256 hex digest for a file (used in manifests for integrity checks)."""
    h = hashlib.sha256()
    # Read the file in chunks to avoid loading large files fully into memory
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):  # stream in 64KB chunks
            h.update(chunk)
    return h.hexdigest()

# ------------------------
# Commands
# ------------------------

def cmd_manifest(args):
    """
    Print a JSON manifest mapping file path -> {sha256, bytes}.
    Useful for verifying generated artifacts haven’t changed.
    """
    out = {}
    for p in args.files:
        out[p] = {"sha256": checksum_sha256(p), "bytes": os.path.getsize(p)}
    print(json.dumps(out, indent=2))

# ------------------------
# Traffic generators
# ------------------------

def gen_session(enc, version, msgs):
    """
    Build a clean, happy-path request/response session:
    - 1 handshake REQUEST + ACK
    - N request/response pairs
    - A final REQUEST("BYE") to close
    """
    seq = 1
    pkts = []

    # Simple handshake (seq = 1)
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", seq, b"ClientHello")))
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "ACK",     seq, b"ServerHelloAck")))
    seq += 1  # Advance sequence after handshake

    # Request/response pairs with incrementing sequence
    for i in range(msgs):
        pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST",  seq, f"REQ-{i}".encode())))
        pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "RESPONSE", seq, f"ACK-{i}".encode())))
        seq += 1

    # Close signal (BYE)
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", seq, b"BYE")))
    return pkts

def gen_errors(enc, version):
    """
    Build a set of intentionally bad packets to exercise decoders:
    - truncated frames
    - tail-truncated valid message
    - sequence jumps / out-of-order
    - impossible protocol version
    """
    pkts = []

    # Totally truncated frame (arbitrary short bytes) -> should fail to decode
    pkts.append(scapy_udp_pkt(payload_bytes=b"\x08\x01\x12"))

    # Encode a valid frame, then truncate from the tail to break integrity
    good = encode_message(enc, version, "REQUEST", 2, b"HELLO")
    pkts.append(scapy_udp_pkt(payload_bytes=good[:-3]))  # remove last 3 bytes

    # Non-monotonic sequences & large jump to trigger ordering checks
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", 1,  b"First")))
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", 99, b"Jump")))  # big jump
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", 2,  b"Second")))

    # Bad version (version + 99) to exercise version checks
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version+99, "REQUEST", 3, b"BadVersion")))
    return pkts

def gen_mixed(enc, version):
    """
    Blend of valid traffic plus malformed/tampered frames.
    Useful for “realistic” capture with intermittent errors.
    """
    pkts = []

    # Start with a normal session (includes handshake + pairs + BYE)
    pkts += gen_session(enc, version, msgs=5)

    # Inject malformed/truncated frames in the middle of valid traffic
    pkts.append(scapy_udp_pkt(payload_bytes=b"\x08\x01"))      # clearly malformed short frame
    tamper = encode_message(enc, version, "RESPONSE", 7, b"PAY")
    pkts.append(scapy_udp_pkt(payload_bytes=tamper[:-2]))      # tail-truncated response for seq=7

    # Resume normal messages: a small follow-on sequence window
    for seq in range(8, 11):
        pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST",  seq, f"REQ-{seq}".encode())))
        pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "RESPONSE", seq, f"ACK-{seq}".encode())))
    return pkts

# ------------------------
# Command implementations
# ------------------------

def cmd_session(args): 
    """CLI wrapper: generate a normal session PCAP."""
    write_pcap(args.out, gen_session(args.enc, args.version, args.msgs))

def cmd_errors(args):  
    """CLI wrapper: generate an error-heavy PCAP."""
    write_pcap(args.out, gen_errors(args.enc, args.version))

def cmd_mixed(args):   
    """CLI wrapper: generate a mixed PCAP."""
    write_pcap(args.out, gen_mixed(args.enc, args.version))

def cmd_stress(args):
    """
    Generate a large randomized capture:
    - ~70% valid REQUESTs with random payload sizes
    - ~15% malformed (short) frames
    - ~10% truncated responses
    - ~5% back-sequenced requests (sequence rewinds)
    Re-seedable via --seed for reproducibility.
    """
    enc, version, count, seed = args.enc, args.version, args.count, args.seed
    random.seed(seed)
    pkts = []
    seq = 1

    for _ in range(count):
        r = random.random()

        if r < 0.7:
            # Valid REQUEST with random payload (1..50 bytes)
            payload = os.urandom(random.randint(1, 50))
            pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", seq, payload)))
            seq += 1

        elif r < 0.85:
            # Short garbage frame to provoke decode failure
            pkts.append(scapy_udp_pkt(payload_bytes=b"\x08\x01"))

        elif r < 0.95:
            # Truncated RESPONSE (cut off CRC/trailer, etc.)
            msg = encode_message(enc, version, "RESPONSE", seq, b"PAY")
            pkts.append(scapy_udp_pkt(payload_bytes=msg[:-2]))
            seq += 1

        else:
            # Sequence “rewind” to simulate duplicates/out-of-order delivery
            back = random.randint(1, min(seq - 1, 10)) if seq > 1 else 0
            rseq = max(1, seq - back)
            pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", rseq, b"R")))

    write_pcap(args.out, pkts)

def cmd_bundle(args):
    """
    Convenience: generate 3 captures (normal/errors/mixed) for BOTH encodings.
    Output files are placed under --outdir.
    """
    outdir  = args.outdir
    version = args.version
    msgs    = args.msgs
    os.makedirs(outdir, exist_ok=True)  # Make sure output directory exists

    def out(name): 
        return os.path.join(outdir, name)

    # Produce one of each for both encodings to help with comparisons
    for enc in ["proto", "asn1"]:
        write_pcap(out(f"normal_{enc}.pcap"), gen_session(enc, version, msgs))
        write_pcap(out(f"errors_{enc}.pcap"), gen_errors(enc, version))
        write_pcap(out(f"mixed_{enc}.pcap"),  gen_mixed(enc, version))

# ------------------------
# PCAP analysis/reporting
# ------------------------

def analyze_pcap(enc, pcap_path):
    """
    Decode each frame and record:
      - header (if decodable)
      - payload (UTF-8 best-effort)
      - CRC
      - issues: length mismatch, non-monotonic seq, etc.
      - or error if decoding fails
    Returns a list of per-frame dictionaries.
    """
    pkts = rdpcap(pcap_path)   # Load packets from PCAP
    rows = []                  # Accumulate per-frame analysis dicts
    last_seq = None            # Track sequence to detect ordering issues

    for i, p in enumerate(pkts, start=1):
        # Extract raw bytes from the UDP/Raw payload if present
        raw = bytes(p[Raw].load) if Raw in p else b""
        rec = {"frame": i, "len": len(raw), "decoded": False}

        try:
            # Attempt to decode the custom-protocol payload
            hdr, payload, crc = decode_message(enc, raw)
            rec.update({
                "decoded": True,
                "header": hdr,                                   # includes version/type/seq/length
                "payload_utf8": payload.decode("utf-8", "replace"),  # lossy-safe display
                "crc": crc
            })

            # Identify anomalies for downstream reports
            issues = []
            if hdr["length"] != len(payload):
                issues.append(f"LEN_MISMATCH:{hdr['length']}!={len(payload)}")
            if last_seq is not None and hdr["seq"] != last_seq + 1:
                issues.append(f"SEQ_NON_MONOTONIC:{last_seq}->{hdr['seq']}")

            last_seq = hdr["seq"]
            rec["issues"] = issues

        except Exception as e:
            # Any parsing/validation error is captured as a decode failure
            rec["error"] = f"DECODE_FAIL:{type(e).__name__}:{e}"

        rows.append(rec)

    return rows

def cmd_report(args):
    """
    Produce tri-format report for a PCAP:
      - JSON: full per-frame data
      - CSV: compact tabular summary (frame/decoded/seq/len/issues/error/payload)
      - HTML: quick summary page with counts and timestamps
    """
    rows = analyze_pcap(args.enc, args.pcap)

    # JSON output (verbose, machine-friendly)
    os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)

    # CSV output (quick glance + spreadsheet import)
    os.makedirs(os.path.dirname(args.csv) or ".", exist_ok=True)
    with open(args.csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["frame","decoded","seq","len","issues","error","payload_utf8"])
        for r in rows:
            seq = r.get("header", {}).get("seq", "")
            w.writerow([
                r["frame"], 
                r["decoded"], 
                seq, 
                r["len"],
                ";".join(r.get("issues", [])),
                r.get("error", ""), 
                r.get("payload_utf8", "")
            ])

    # Minimal HTML dashboard (human-friendly summary)
    now = datetime.datetime.utcnow().isoformat() + "Z"
    total = len(rows)
    decoded = sum(1 for r in rows if r["decoded"])
    errcount = sum(1 for r in rows if ("error" in r) or r.get("issues"))
    html = f"""<!doctype html><html><head><meta charset='utf-8'>
    <title>PCAP Report</title></head><body>
    <h1>PCAP Report</h1><p>File: {args.pcap}</p><p>Generated: {now}</p>
    <ul><li>Total frames: {total}</li><li>Decoded: {decoded}</li>
    <li>Frames with issues/errors: {errcount}</li></ul>
    <p>See CSV/JSON for per-frame details.</p></body></html>"""

    os.makedirs(os.path.dirname(args.html) or ".", exist_ok=True)
    with open(args.html, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[OK] wrote {args.json}, {args.csv}, {args.html}")

def cmd_validate(args):
    """
    Quick gate: print {"status": "PASS"/"FAIL", "bad_frames": N}
    PASS only when every frame decodes cleanly and has no issues.
    """
    rows = analyze_pcap(args.enc, args.pcap)
    bad = [r for r in rows if ("error" in r) or r.get("issues")]
    status = "PASS" if not bad else "FAIL"
    print(json.dumps({"status": status, "bad_frames": len(bad)}, indent=2))

# ------------------------
# CLI setup
# ------------------------

def build():
    """
    Configure argparse CLI with subcommands:
      session/errors/mixed/stress -> PCAP generation
      report/validate             -> analysis
      manifest                    -> file integrity metadata
      bundle                      -> generate sets for both encodings
    """
    p = argparse.ArgumentParser(prog="custool", description="Custom Protocol Suite v4.1 (proto + asn1)")
    sub = p.add_subparsers(dest="cmd", required=True)

    # Helper to add common generation args
    def com(sp):
        sp.add_argument("--enc", choices=["proto","asn1"], default="proto", help="Encoding to use")
        sp.add_argument("--version", type=int, default=1, help="Protocol version field")
        sp.add_argument("--out", required=True, help="Output PCAP path")

    # Generators
    sp = sub.add_parser("session", help="Generate a clean request/response session")
    com(sp)
    sp.add_argument("--msgs", type=int, default=10, help="Number of request/response pairs")
    sp.set_defaults(func=cmd_session)

    sp = sub.add_parser("errors", help="Generate malformed/out-of-order cases")
    com(sp)
    sp.set_defaults(func=cmd_errors)

    sp = sub.add_parser("mixed", help="Blend valid traffic with injected errors")
    com(sp)
    sp.set_defaults(func=cmd_mixed)

    # Stress (optional)
    sp = sub.add_parser("stress", help="Large randomized traffic for robustness testing")
    com(sp)
    sp.add_argument("--count", type=int, default=2000, help="Total frames to generate")
    sp.add_argument("--seed", type=int, default=42, help="PRNG seed for reproducibility")
    sp.set_defaults(func=cmd_stress)

    # Utilities
    sp = sub.add_parser("manifest", help="Emit SHA256 + size for files")
    sp.add_argument("files", nargs="+")
    sp.set_defaults(func=cmd_manifest)

    sp = sub.add_parser("report", help="Decode PCAP and export JSON/CSV/HTML")
    sp.add_argument("--enc", choices=["proto","asn1"], required=True)
    sp.add_argument("--pcap", required=True, help="Input PCAP path")
    sp.add_argument("--json", required=True, help="Output JSON path")
    sp.add_argument("--csv", required=True, help="Output CSV path")
    sp.add_argument("--html", required=True, help="Output HTML path")
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("validate", help="Print PASS/FAIL for a PCAP")
    sp.add_argument("--enc", choices=["proto","asn1"], required=True)
    sp.add_argument("--pcap", required=True)
    sp.set_defaults(func=cmd_validate)

    # Bundle (note: --outdir is a directory even though default looks like a file name)
    sp = sub.add_parser("bundle", help="Generate normal/errors/mixed PCAPs for both encodings")
    sp.add_argument("--outdir", default="captures.pcap", help="Output directory (default: captures.pcap)")
    sp.add_argument("--version", type=int, default=1, help="Protocol version")
    sp.add_argument("--msgs", type=int, default=10, help="Number of pairs in normal session")
    sp.set_defaults(func=cmd_bundle)

    return p

def main():
    """Entry point: parse args and dispatch to the selected subcommand."""
    p = build()
    args = p.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()


# ------------------------
# References
# ------------------------
"""
External references and inspirations related to this tool:

Protocol payload encoding/decoding:
- Google Protocol Buffers (Python): https://developers.google.com/protocol-buffers/docs/pythontutorial
- asn1tools (UPER codec) docs: https://pypi.org/project/asn1tools/
- ASN.1 usage walkthrough (Nick vs Networking): https://nickvsnetworking.com/asn-1/
- ShareTechnote (Python ASN.1 examples): https://www.sharetechnote.com/html/Python_ASN.html

Packet crafting / PCAP I/O:
- Scapy docs (layers, Raw, wrpcap/rdpcap): https://scapy.readthedocs.io/

CRC-16/CCITT-FALSE references:
- StackOverflow discussion/implementation notes: https://stackoverflow.com/questions/25239423/crc-ccitt-16-bit-python-manual-calculation
- PyCRC library: https://github.com/alexbutirskiy/PyCRC
- ranelcom/crc16 (CCITT-FALSE): https://github.com/ranelcom/crc16

General Python stdlib used:
- argparse (CLI): https://docs.python.org/3/library/argparse.html
- csv (tabular export): https://docs.python.org/3/library/csv.html
- hashlib (SHA256): https://docs.python.org/3/library/hashlib.html
"""