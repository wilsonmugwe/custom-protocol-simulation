# Validation Report — Custom Protocol (Phase 2)

Date: <YYYY-MM-DD>
Tester: <Your Name>
PCAPs: `custom_demo.pcap`, `fault_seq_gap.pcap`, `fault_len_mismatch.pcap`

## 1. Header Conformance (custom_demo.pcap)
- [ ] Version byte at offset 0 equals `1`
- [ ] Msg types map to {HELLO=0x01, DATA=0x02, ACK=0x03}
- [ ] `seq` increments from 0 for HELLO then through DATA
- [ ] `length` equals actual bytes in `data`
- [ ] Flags captured and within expected range

**Screenshots:**  
- Wireshark view of first HELLO (expand bytes)  
- One DATA frame showing length == len(data)

## 2. Sequence / State Machine
Expected: HELLO seq=0 → DATA seq=1..N → ACK seq=N+1

- [ ] No gaps in HELLO/DATA sequence
- [ ] Final ACK seq equals last DATA seq + 1

**Result:** Passed / Failed  
**Evidence:** paste CLI validator output

## 3. Fault: Sequence Gap (fault_seq_gap.pcap)
- [ ] Identify the exact gap (which seq is missing)
- [ ] Explain how this would be detected/handled

**Screenshot:** DATA with seq jump visible

## 4. Fault: Length Mismatch (fault_len_mismatch.pcap)
- [ ] Show header `length` vs actual `data` bytes
- [ ] Explain detection (programmatic & in Wireshark)

**Screenshot:** Bytes pane highlighting mismatch

## 5. Conclusions
- Protocol encoding matches spec ✔ / ✖  
- Next steps: <e.g., add checksum field, extend ACK rules, etc.>
