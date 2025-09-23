
## `docs/LAB_WORKSHEET_TEMPLATE.md`
```markdown
# Wireshark Lab Worksheet – Deep Inspection of Custom Protocol (v4.1)

## Objectives
- Inspect PCAPs (proto + asn1) and **annotate** findings.
- Compare **expected vs observed** structures.
- Provide **5+ annotated screenshots**.
- Write **clear student steps** + **troubleshooting**.
- Confirm **consistent decoding** across cases.

## Expected vs Observed
| Case | Expected | Observed (Wireshark & CSV) | Notes |
|------|----------|-----------------------------|-------|
| Handshake | seq=1 REQUEST / seq=1 ACK |  |  |
| Normal flow | seq increases by +1; paired REQUEST/RESPONSE |  |  |
| Truncated | decode fail |  |  |
| Tampered tail | LEN_MISMATCH and/or CRC issue |  |  |
| Out-of-order | SEQ_NON_MONOTONIC |  |  |

## Steps
1. Generate PCAPs (proto & asn1).
2. Open in Wireshark (`udp.port == 5555`).
3. Run analyses and produce JSON/CSV/HTML:
   ```bash
   ./custool.py report --enc proto --pcap pcaps/normal_proto.pcap --json reports/normal.json --csv reports/normal.csv --html reports/normal.html
   ./custool.py report --enc asn1  --pcap pcaps/normal_asn1.pcap  --json reports/normal_a.json --csv reports/normal_a.csv --html reports/normal_a.html
