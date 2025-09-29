# Custom Protocol Simulation & Wireshark Analysis (v4.1)

This project simulates a custom UDP protocol with two encodings:  
- **Protobuf (`proto`)**
- **ASN.1 (`asn1`)**

It generates PCAP files, analyzes them, and produces structured reports (JSON, CSV, HTML) for deep inspection in Wireshark.  

---

## Setup

### Windows (PowerShell)fng
```powershell
python -m venv .venv
. .\.venv\Scripts\Activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
---

### MacOS/Linux (PowerShell)
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
---

###Generate PCAPs
Generate all standard PCAPs in one step:
python custool.py bundle