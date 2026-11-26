import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

HERE = Path(__file__).parent
TARGET = os.getenv("TARGET", "http://localhost:9090").rstrip("/")
LABEL = os.getenv("LABEL", "demo")
WEBHOOK = os.getenv("WEBHOOK_URL", "")   # optional: send HIGH findings to n8n

host = urlparse(TARGET).hostname
if host not in ("localhost", "127.0.0.1") and os.getenv("ALLOW_REMOTE") != "1":
    sys.exit(f"Refusing to scan {host}: only localhost is allowed by default. "
             "Set ALLOW_REMOTE=1 only for systems you own.")

ENDPOINTS = {
    "/actuator/env": ("HIGH", "Environment properties exposed (may include credentials)"),
    "/actuator/heapdump": ("HIGH", "Heap dump downloadable (memory can hold secrets)"),
    "/actuator/configprops": ("HIGH", "Configuration properties exposed"),
    "/actuator/httptrace": ("HIGH", "Recent HTTP requests exposed (headers, cookies)"),
    "/actuator/threaddump": ("MEDIUM", "Thread dump exposed (internal details)"),
    "/actuator/mappings": ("MEDIUM", "Full endpoint map exposed"),
    "/actuator/beans": ("MEDIUM", "Application beans exposed"),
    "/actuator/loggers": ("MEDIUM", "Logger levels readable and possibly changeable"),
    "/actuator/metrics": ("LOW", "Metrics exposed"),
}
HEADERS = {
    "Content-Security-Policy": ("MEDIUM", "No Content-Security-Policy header"),
    "X-Frame-Options": ("MEDIUM", "No X-Frame-Options header (clickjacking)"),
    "X-Content-Type-Options": ("LOW", "No X-Content-Type-Options header"),
    "Referrer-Policy": ("LOW", "No Referrer-Policy header"),
}
SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
findings = []


def add(kind, severity, title, detail):
    findings.append({"id": f"scan-{len(findings) + 1}", "type": kind,
                     "severity": severity, "title": title, "description": detail})


def main():
    try:
        base = requests.get(TARGET + "/", timeout=10)
    except requests.RequestException as e:
        sys.exit(f"Target not reachable: {e}")

    for path, (sev, title) in ENDPOINTS.items():
        try:
            r = requests.get(TARGET + path, timeout=10, stream=True, allow_redirects=False)
            status = r.status_code
            r.close()                      # do not download bodies (heap dumps can be huge)
        except requests.RequestException:
            continue
        if status == 200:
            add("ActuatorExposure", sev, f"{title}: {path}",
                f"GET {path} returned HTTP 200 without authentication on {TARGET}.")

    for header, (sev, title) in HEADERS.items():
        if header not in base.headers:
            add("MissingHeader", sev, title, f"{header} is missing on {TARGET}/.")
    if TARGET.startswith("https") and "Strict-Transport-Security" not in base.headers:
        add("MissingHeader", "MEDIUM", "No Strict-Transport-Security header",
            f"HSTS is missing on {TARGET}/.")
    if "X-Powered-By" in base.headers:
        add("InfoLeak", "LOW", "Technology disclosed in X-Powered-By",
            f"X-Powered-By: {base.headers['X-Powered-By']}")

    findings.sort(key=lambda f: SEV_ORDER[f["severity"]])
    print(f"Target: {TARGET}\n")
    for f in findings:
        print(f"[{f['severity']:6}] {f['title']}")
    counts = {s: sum(f["severity"] == s for f in findings) for s in SEV_ORDER}
    print(f"\n--- Summary --- HIGH: {counts['HIGH']} | MEDIUM: {counts['MEDIUM']} | LOW: {counts['LOW']}")

    out = HERE / f"results_{LABEL}.json"
    out.write_text(json.dumps({"label": LABEL, "target": TARGET,
                               "time": datetime.now(timezone.utc).isoformat(),
                               "findings": findings}, indent=2))
    print("Saved:", out.name)

    if WEBHOOK:
        for f in [x for x in findings if x["severity"] == "HIGH"]:
            requests.post(WEBHOOK, json=f, timeout=300)
            print("Sent to webhook:", f["title"])

    sys.exit(1 if counts["HIGH"] else 0)


if __name__ == "__main__":
    main()
