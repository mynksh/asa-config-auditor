# ASA Config Auditor

Python CLI to **parse Cisco ASA running-configs** and produce a quick **security audit**:
- Interfaces, subinterfaces & VLANs
- ACLs + inbound *access-group* bindings
- `object` and `object-group` (network/service/protocol/icmp-type), with **safe recursive expansion**
- Flags **allow-all**, **duplicate**, and **potentially dangerous** rules
- Prints a readable report and writes a JSON file

> Designed for ASA 55xx family (works on most ASA configs). Best-effort parser; tolerant of messy dumps.

---

## Features
- 🔎 Extracts **interfaces**, **VLANs**, **ACLs**, and **bindings**
- 📦 Lists **objects** (`object network/service`) and **object-groups** with expansion
- 🚨 Detects **allow-all** (e.g., `permit ip any any`) and common **risky services** exposed from `any`
- 🧭 Duplicate ACE detection within the same ACL
- 📤 Saves `asa_audit_report.json` for further analysis

---

## Quick start

```bash
# 1) Clone
git clone https://github.com/<your-org>/asa-config-auditor.git
cd asa-config-auditor

# 2) Run (Python 3.9+)
python asa_audit.py path/to/running-config.txt
