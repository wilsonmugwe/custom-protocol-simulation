# Custom Protocol Simulation (Scapy) + Wireshark Lab

This repository implements a custom protocol in Python/Scapy (Phase 2) and generates `.pcap` files for Wireshark analysis (Phase 3).

## Prerequisites (Windows)
1. Python 3.10+ (check **Add Python to PATH** at install)
2. Npcap (enable **WinPcap API-compatible mode**)
3. (Optional) Wireshark

## Setup
```powershell
py -m venv .venv
. .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
