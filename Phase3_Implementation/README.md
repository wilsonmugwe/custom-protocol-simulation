# Custom Protocol Suite v4.1 — Protobuf + ASN.1 (Config-driven, Lab-ready)

## Install
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
# Protobuf path only:
python -m grpc_tools.protoc -I. --python_out=. cusproto.proto
