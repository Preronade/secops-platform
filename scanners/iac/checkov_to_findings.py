import json
import os
import sys
from pathlib import Path

import requests

HERE = Path(__file__).parent
SRC = HERE / os.getenv("CHECKOV_JSON", "checkov_results.json")
WEBHOOK = os.getenv("WEBHOOK_URL", "")
MAX_SEND = int(os.getenv("MAX_SEND", "3"))
SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
HIGH_KEYS = ["0.0.0.0", "public", "ssh", "rdp", "port 22", "port 3389"]
MED_KEYS = ["encrypt", "kms", "logging", "versioning", "mfa", "imds"]


def severity(name):
    n = name.lower()
    if any(k in n for k in HIGH_KEYS):
        return "HIGH"
    if any(k in n for k in MED_KEYS):
        return "MEDIUM"
    return "LOW"


raw = json.loads(SRC.read_text())
blocks = raw if isinstance(raw, list) else [raw]
failed = [c for b in blocks for c in b.get("results", {}).get("failed_checks", [])]

findings = []
for i, c in enumerate(failed, 1):
    lines = c.get("file_line_range") or ["?", "?"]
    findings.append({
        "id": f"iac-{i}",
        "type": "IaCMisconfiguration",
        "severity": severity(c["check_name"]),
        "title": f"{c['check_name']} [{c['resource']}]",
        "description": f"{c['check_id']} failed for {c['resource']} in "
                       f"{c['file_path']} lines {lines[0]}-{lines[1]}.",
    })

findings.sort(key=lambda f: SEV_ORDER[f["severity"]])
for f in findings:
    print(f"[{f['severity']:6}] {f['title']}")
counts = {s: sum(f["severity"] == s for f in findings) for s in SEV_ORDER}
print(f"\n--- Summary --- HIGH: {counts['HIGH']} | MEDIUM: {counts['MEDIUM']} | LOW: {counts['LOW']}")
(HERE / "findings_iac.json").write_text(json.dumps(findings, indent=2))
print("Saved: findings_iac.json")

if WEBHOOK:
    highs = [f for f in findings if f["severity"] == "HIGH"]
    for f in highs[:MAX_SEND]:
        requests.post(WEBHOOK, json=f, timeout=300)
        print("Sent to webhook:", f["title"])
    if len(highs) > MAX_SEND:
        print(f"({len(highs) - MAX_SEND} more HIGH findings not sent; raise MAX_SEND)")
