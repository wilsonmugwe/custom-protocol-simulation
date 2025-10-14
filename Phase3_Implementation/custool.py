#!/usr/bin/env python3
"""
custool: Custom Protocol Suite v4.1 (proto + asn1)

Purpose
-------
Generate PCAPs (packet capture files) that exercise:
- Normal custom-protocol sessions
- Mixed traffic (valid + injected errors)
- Error-heavy traffic (truncations, bad versions, out-of-order)
- Baseline standard Internet protocols (TCP/HTTP/DNS/ICMP) for comparison

Also provides:
- Report export (JSON/CSV/HTML) by decoding frames
- Quick validation (PASS/FAIL) gate on a PCAP

Notes & Intent
--------------
This tool is designed to support hands-on Wireshark lab activities by producing
repeatable captures that demonstrate protocol structure, decoding behavior, and
failure modes. The "BaselineNormal" PCAP centralizes common Internet protocols
to help students compare a custom UDP-based protocol against familiar traffic.

References (High level)
-----------------------
- Scapy (packet crafting & PCAP I/O): https://scapy.readthedocs.io/
- Google Protocol Buffers (Python): https://developers.google.com/protocol-buffers/docs/pythontutorial
- ASN.1 / asn1tools (UPER): https://pypi.org/project/asn1tools/
- TCP (RFC 793), HTTP/1.1 (RFC 2616 / RFC 7230+), DNS (RFC 1035), ICMP (RFC 792)
"""

import argparse, os, json, random, hashlib, csv, datetime
# Scapy imports: wrpcap/rdpcap for PCAP I/O, Raw for payload access,
# IP/TCP/UDP/DNS/ICMP layers for the BaselineNormal generator.
from scapy.all import wrpcap, rdpcap, Raw, IP, TCP, UDP, DNS, DNSQR, DNSRR, ICMP
# Project-local helpers: encode/decode the custom protocol payload,
# and scapy_udp_pkt to wrap raw bytes into a UDP/IP Scapy packet.
from utils import encode_message, decode_message
from common import scapy_udp_pkt

# ------------------------
# Utility functions
# ------------------------

def write_pcap(path, pkts):
    """
    Write a list of Scapy packets to a PCAP file.

    Implementation details:
    - Ensures the parent directory exists (idempotent).
    - Uses Scapy's wrpcap to serialize packets to disk.
    - Prints a small confirmation line for traceability in scripts.

    Reference:
    - Scapy wrpcap: https://scapy.readthedocs.io/en/latest/usage.html#reading-and-writing-pcaps
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    wrpcap(path, pkts)
    print("[OK] {} ({} pkts)".format(path, len(pkts)))

def checksum_sha256(path):
    """
    Compute SHA256 for a file (hex string).

    Why:
    - Manifests and integrity checks are useful when distributing lab artifacts
      or verifying that captures have not changed.

    Reference:
    - Python hashlib: https://docs.python.org/3/library/hashlib.html
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        # Stream in fixed-size chunks to support large files without high memory use.
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

# ------------------------
# Commands
# ------------------------

def cmd_manifest(args):
    """
    Emit a simple JSON manifest mapping file path -> {sha256, bytes}.

    Usage:
      custool manifest file1.pcap file2.pcap > manifest.json

    This can be attached to submissions or stored with releases for reproducibility.
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

    Sequence:
    - seq=1: REQUEST("ClientHello") / ACK("ServerHelloAck")
    - seq=2..(msgs+1): REQUEST("REQ-i") / RESPONSE("ACK-i") pairs
    - final seq: REQUEST("BYE")

    Rationale:
    - Provides a canonical well-ordered flow for decoder sanity checks and
      expected Wireshark visualizations.

    'enc' selects the encoder ('proto' or 'asn1'), and 'version' fills the
    protocol header version field used by the decoder.
    """
    seq = 1
    pkts = []
    # Initial handshake pair on seq=1
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", seq, b"ClientHello")))
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "ACK",     seq, b"ServerHelloAck")))
    seq += 1
    # N request/response pairs with monotonically increasing seq
    for i in range(msgs):
        pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST",  seq, f"REQ-{i}".encode())))
        pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "RESPONSE", seq, f"ACK-{i}".encode())))
        seq += 1
    # Closing signal
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", seq, b"BYE")))
    return pkts

def gen_errors(enc, version):
    """
    Intentionally generate malformed/problematic frames to exercise decoders:

    Cases included:
    - Very short/truncated frames that should fail decoding.
    - Valid frame crafted and then tail-truncated to break integrity.
    - Non-monotonic sequence numbers (1 -> 99 -> 2) to flag ordering issues.
    - Impossible protocol version (version+99) to trigger version checks.

    Tip:
    - These are useful for worksheets: students can identify why decoding fails
      (e.g., mismatched length, CRC, version mismatch, or sequence anomalies).
    """
    pkts = []
    pkts.append(scapy_udp_pkt(payload_bytes=b"\x08\x01\x12"))  # clearly too short -> decode failure
    good = encode_message(enc, version, "REQUEST", 2, b"HELLO")
    pkts.append(scapy_udp_pkt(payload_bytes=good[:-3]))        # tail-truncate a valid message
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", 1,  b"First")))
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", 99, b"Jump")))  # large jump
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", 2,  b"Second")))
    pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version+99, "REQUEST", 3, b"BadVersion")))
    return pkts

def gen_mixed(enc, version):
    """
    Blend a valid session with intermittent injected errors:

    Layout:
    - Start with a normal session (handshake + pairs + BYE).
    - Inject a malformed short frame and a tail-truncated response.
    - Continue with a few valid pairs.

    Goal:
    - Mimic "realistic" captures where corruption or partial frames appear amid
      otherwise normal traffic.
    """
    pkts = []
    pkts += gen_session(enc, version, msgs=5)
    # Malformed tiny frame (decode should fail)
    pkts.append(scapy_udp_pkt(payload_bytes=b"\x08\x01"))
    # Tail-truncate a valid response to break integrity checks
    tamper = encode_message(enc, version, "RESPONSE", 7, b"PAY")
    pkts.append(scapy_udp_pkt(payload_bytes=tamper[:-2]))
    # Resume valid flow with a short sequence window
    for seq in range(8, 11):
        pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST",  seq, f"REQ-{seq}".encode())))
        pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "RESPONSE", seq, f"ACK-{seq}".encode())))
    return pkts

def gen_baseline_std():
    """
    Baseline standard protocols (all-in-one PCAP) used in the worksheet:
      - TCP 3-way handshake + HTTP GET/200 OK
      - DNS query/answer (example.com)
      - ICMP echo request/reply

    Why:
    - Provides familiar traffic patterns to compare with the custom protocol.
    - Useful for reinforcing TCP sequencing/ACKing vs. our UDP custom protocol.

    References:
    - TCP: RFC 793
    - HTTP/1.1: RFC 2616 (superseded in parts by RFC 7230+; kept here for lab familiarity)
    - DNS: RFC 1035
    - ICMP: RFC 792
    - Scapy layers: https://scapy.readthedocs.io/
    """
    pkts = []

    # ----------------------
    # TCP 3-way handshake + HTTP
    # ----------------------
    # SYN from client (seq=100) -> SYN/ACK from server (ack=101) -> ACK from client (ack=201)
    syn    = IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=1024, dport=80, flags="S",  seq=100)
    synack = IP(src="192.168.1.20", dst="192.168.1.10")/TCP(sport=80,   dport=1024, flags="SA", seq=200, ack=101)
    ack    = IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=1024, dport=80, flags="A",  seq=101, ack=201)

    # HTTP request (minimal GET)
    http_req_payload = b"GET /index.html HTTP/1.1\r\nHost: 192.168.1.20\r\n\r\n"
    http_req = IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=1024, dport=80, flags="PA", seq=101, ack=201)/Raw(load=http_req_payload)

    # HTTP response (200 OK with tiny HTML body)
    http_res_payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Hello</html>"
    http_res_seq = 201
    http_res_ack = 101 + len(http_req_payload)  # mirror request length into server's ACK
    http_res = IP(src="192.168.1.20", dst="192.168.1.10")/TCP(sport=80, dport=1024, flags="PA", seq=http_res_seq, ack=http_res_ack)/Raw(load=http_res_payload)

    pkts += [syn, synack, ack, http_req, http_res]

    # ----------------------
    # DNS: simple A record query/answer for example.com
    # ----------------------
    dns_q = IP(src="192.168.1.30", dst="192.168.1.40")/UDP(sport=12345, dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))
    # Use the same DNS transaction ID as the query, set qr=1 for response, aa=1 for authoritative
    dns_a = IP(src="192.168.1.40", dst="192.168.1.30")/UDP(sport=53,    dport=12345)/DNS(id=dns_q[DNS].id, qr=1, aa=1, qd=dns_q[DNS].qd, an=DNSRR(rrname="example.com", rdata="93.184.216.34"))
    pkts += [dns_q, dns_a]

    # ----------------------
    # ICMP echo (ping) request/reply
    # ----------------------
    icmp_req = IP(src="192.168.1.50", dst="192.168.1.60")/ICMP(type="echo-request", id=0x1234, seq=1)
    icmp_rep = IP(src="192.168.1.60", dst="192.168.1.50")/ICMP(type="echo-reply",   id=0x1234, seq=1)
    pkts += [icmp_req, icmp_rep]

    return pkts

# ------------------------
# Command implementations
# ------------------------

def cmd_session(args):
    """CLI wrapper: generate a normal (happy-path) session PCAP."""
    write_pcap(args.out, gen_session(args.enc, args.version, args.msgs))

def cmd_errors(args):
    """CLI wrapper: generate an error-heavy PCAP (truncations, bad versions, out-of-order)."""
    write_pcap(args.out, gen_errors(args.enc, args.version))

def cmd_mixed(args):
    """CLI wrapper: generate a mixed PCAP (valid traffic + injected failures)."""
    write_pcap(args.out, gen_mixed(args.enc, args.version))

def cmd_stress(args):
    """
    Large randomized capture for robustness testing.

    Distribution (approx):
    - 70% valid REQUESTs with random payload sizes (1..50 bytes)
    - 15% malformed short frames (decode fails)
    - 10% tail-truncated RESPONSES (integrity fail)
    - 5% sequence rewinds/duplicates (non-monotonic seq)

    Reproducibility:
    - Controlled via --seed to make stochastic runs repeatable.
    """
    enc, version, count, seed = args.enc, args.version, args.count, args.seed
    random.seed(seed)
    pkts = []
    seq = 1
    for _ in range(count):
        r = random.random()
        if r < 0.7:
            payload = os.urandom(random.randint(1, 50))
            pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", seq, payload)))
            seq += 1
        elif r < 0.85:
            pkts.append(scapy_udp_pkt(payload_bytes=b"\x08\x01"))
        elif r < 0.95:
            msg = encode_message(enc, version, "RESPONSE", seq, b"PAY")
            pkts.append(scapy_udp_pkt(payload_bytes=msg[:-2]))
            seq += 1
        else:
            back = random.randint(1, min(seq - 1, 10)) if seq > 1 else 0
            rseq = max(1, seq - back)
            pkts.append(scapy_udp_pkt(payload_bytes=encode_message(enc, version, "REQUEST", rseq, b"R")))
    write_pcap(args.out, pkts)

def cmd_baseline(args):
    """
    Generate the BaselineNormal PCAP with TCP/HTTP/DNS/ICMP in a single file.

    This makes it easy to keep “all the standard protocols used in the worksheet”
    under one PCAP for side-by-side comparison with custom-protocol captures.
    """
    write_pcap(args.out, gen_baseline_std())

def cmd_bundle(args):
    """
    Generate normal/errors/mixed for BOTH encodings (original six),
    PLUS BaselineNormal.pcap (standard protocols in one file).

    Output layout (under --outdir):
      - normal_proto.pcap, errors_proto.pcap, mixed_proto.pcap
      - normal_asn1.pcap,  errors_asn1.pcap, mixed_asn1.pcap
      - BaselineNormal.pcap
    """
    outdir  = args.outdir
    version = args.version
    msgs    = args.msgs
    os.makedirs(outdir, exist_ok=True)

    def out(name):
        return os.path.join(outdir, name)

    for enc in ["proto", "asn1"]:
        write_pcap(out(f"normal_{enc}.pcap"), gen_session(enc, version, msgs))
        write_pcap(out(f"errors_{enc}.pcap"), gen_errors(enc, version))
        write_pcap(out(f"mixed_{enc}.pcap"),  gen_mixed(enc, version))

    # Standard protocols all in one PCAP for the worksheet
    write_pcap(out("BaselineNormal.pcap"), gen_baseline_std())

# ------------------------
# PCAP analysis/reporting
# ------------------------

def analyze_pcap(enc, pcap_path):
    """
    Decode frames from a PCAP and record per-frame details.

    For each frame:
      - Attempt custom-protocol decode -> header dict (includes version/type/seq/length)
      - Capture payload as UTF-8 (errors='replace' for robustness)
      - Record CRC from the decoder
      - Flag issues:
          * Payload length mismatch vs header 'length'
          * Non-monotonic sequence compared to previous decoded frame
      - If decoding fails, store an error string (DECODE_FAIL:Type:Message)

    Returns:
      List of dicts for downstream report/export.

    Implementation notes:
      - Uses Scapy rdpcap to read frames.
      - Extracts payload bytes from Raw layer if present (custom protocol is UDP-based).
    """
    pkts = rdpcap(pcap_path)
    rows = []
    last_seq = None
    for i, p in enumerate(pkts, start=1):
        raw = bytes(p[Raw].load) if Raw in p else b""
        rec = {"frame": i, "len": len(raw), "decoded": False}
        try:
            hdr, payload, crc = decode_message(enc, raw)
            rec.update({
                "decoded": True,
                "header": hdr,
                "payload_utf8": payload.decode("utf-8", "replace"),
                "crc": crc
            })
            issues = []
            if hdr["length"] != len(payload):
                issues.append(f"LEN_MISMATCH:{hdr['length']}!={len(payload)}")
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
    Export a tri-format analysis of a PCAP:

      JSON:
        - Full per-frame dictionaries (easy to parse in scripts)
      CSV:
        - Compact tabular overview for spreadsheets or quick inspection
      HTML:
        - Minimal human-readable summary (counts + timestamp)

    Tip:
      - The CSV columns mirror common worksheet needs: frame, decoded, seq,
        length, issues, error, and payload snippet.
    """
    rows = analyze_pcap(args.enc, args.pcap)

    # JSON (machine-readable, verbose)
    os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)

    # CSV (tabular, compact)
    os.makedirs(os.path.dirname(args.csv) or ".", exist_ok=True)
    with open(args.csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["frame","decoded","seq","len","issues","error","payload_utf8"])
        for r in rows:
            seq = r.get("header", {}).get("seq", "")
            w.writerow([r["frame"], r["decoded"], seq, r["len"],
                        ";".join(r.get("issues", [])), r.get("error", ""), r.get("payload_utf8", "")])

    # HTML (quick-glance summary)
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
    Quick PASS/FAIL gate for a PCAP:
      PASS -> all frames decode AND no 'issues' were found
      FAIL -> any frame fails to decode OR has issues recorded

    Output:
      {"status": "PASS"/"FAIL", "bad_frames": N}
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
    Define argparse CLI with the following subcommands:

      Generation:
        - session   : clean request/response session
        - errors    : decoder-challenging cases
        - mixed     : normal traffic with injected failures
        - stress    : large randomized capture for robustness
        - baseline  : TCP/HTTP/DNS/ICMP baseline for comparison

      Analysis:
        - report    : export JSON/CSV/HTML summaries
        - validate  : quick PASS/FAIL check

      Utility:
        - manifest  : file integrity metadata (sha256, size)

      Bundle:
        - bundle    : original six (normal/errors/mixed for proto+asn1)
                      + BaselineNormal.pcap
    """
    p = argparse.ArgumentParser(prog="custool", description="Custom Protocol Suite v4.1 (proto + asn1)")
    sub = p.add_subparsers(dest="cmd", required=True)

    # Helper to add common options for generation commands
    def com(sp):
        sp.add_argument("--enc", choices=["proto","asn1"], default="proto", help="Encoding to use")
        sp.add_argument("--version", type=int, default=1, help="Protocol version field")
        sp.add_argument("--out", required=True, help="Output PCAP path")

    # Generators
    sp = sub.add_parser("session", help="Generate a clean request/response session")
    com(sp); sp.add_argument("--msgs", type=int, default=10, help="Number of request/response pairs")
    sp.set_defaults(func=cmd_session)

    sp = sub.add_parser("errors", help="Generate malformed/out-of-order cases")
    com(sp); sp.set_defaults(func=cmd_errors)

    sp = sub.add_parser("mixed", help="Blend valid traffic with injected errors")
    com(sp); sp.set_defaults(func=cmd_mixed)

    sp = sub.add_parser("stress", help="Large randomized traffic for robustness testing")
    com(sp); sp.add_argument("--count", type=int, default=2000, help="Total frames to generate")
    sp.add_argument("--seed", type=int, default=42, help="PRNG seed for reproducibility")
    sp.set_defaults(func=cmd_stress)

    # Baseline (standard protocols)
    sp = sub.add_parser("baseline", help="Generate BaselineNormal (TCP/HTTP/DNS/ICMP in one PCAP)")
    sp.add_argument("--out", default="captures.pcap/BaselineNormal.pcap", help="Output PCAP path")
    sp.set_defaults(func=cmd_baseline)

    # Utility
    sp = sub.add_parser("manifest", help="Emit SHA256 + size for files")
    sp.add_argument("files", nargs="+")
    sp.set_defaults(func=cmd_manifest)

    # Reporting / validation
    sp = sub.add_parser("report", help="Decode PCAP and export JSON/CSV/HTML")
    sp.add_argument("--enc", choices=["proto","asn1"], required=True)
    sp.add_argument("--pcap", required=True)
    sp.add_argument("--json", required=True)
    sp.add_argument("--csv", required=True)
    sp.add_argument("--html", required=True)
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("validate", help="Print PASS/FAIL for a PCAP")
    sp.add_argument("--enc", choices=["proto","asn1"], required=True)
    sp.add_argument("--pcap", required=True)
    sp.set_defaults(func=cmd_validate)

    # Bundle everything commonly needed for the worksheet
    sp = sub.add_parser("bundle", help="Generate normal/errors/mixed for both encodings + BaselineNormal")
    sp.add_argument("--outdir", default="captures.pcap", help="Output directory (default: captures.pcap)")
    sp.add_argument("--version", type=int, default=1, help="Protocol version")
    sp.add_argument("--msgs", type=int, default=10, help="Number of pairs in normal session")
    sp.set_defaults(func=cmd_bundle)

    return p

def main():
    """Parse CLI arguments and execute the selected subcommand."""
    p = build()
    args = p.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()

# ------------------------
# References
# ------------------------
"""
-This script was developed with assistance from OpenAI GPT.

External references & further reading (keep with submissions for transparency):

Packet crafting / PCAP I/O
- Scapy documentation (layers, Raw, wrpcap/rdpcap):
  https://scapy.readthedocs.io/

Custom protocol encoding/decoding
- Google Protocol Buffers (Python):
  https://developers.google.com/protocol-buffers/docs/pythontutorial
- asn1tools (UPER) docs:
  https://pypi.org/project/asn1tools/
- ASN.1 background:
  RFC 5912 (profiles), Nick vs Networking (walkthrough): https://nickvsnetworking.com/asn-1/

Standard Internet protocols (BaselineNormal)
- TCP: RFC 793
- HTTP/1.1: RFC 2616 (see also RFC 7230+ for updated specs)
- DNS: RFC 1035
- ICMP: RFC 792

Python stdlib used
- argparse: https://docs.python.org/3/library/argparse.html
- csv: https://docs.python.org/3/library/csv.html
- hashlib: https://docs.python.org/3/library/hashlib.html
- datetime: https://docs.python.org/3/library/datetime.html
"""
