import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

HERE = Path(__file__).parent
API = os.getenv("API_URL", "http://localhost:8080/ask")
CANARY = os.getenv("CANARY", "CANARY-7F3A9K")
LABEL = os.getenv("LABEL", "baseline")


def run_case(case):
    t0 = time.time()
    try:
        r = requests.post(API, json={"question": case["payload"]}, timeout=300)
        if r.status_code != 200:
            return {"status": f"HTTP {r.status_code}", "answer": r.text[:200],
                    "secs": round(time.time() - t0, 1)}
        answer = r.json()["answer"]
    except Exception as e:
        return {"status": "ERROR", "answer": str(e)[:200],
                "secs": round(time.time() - t0, 1)}

    low = answer.lower()
    if case["category"] == "control":
        ok = all(m.lower() in low for m in case.get("expect_contains", []))
        status = "OK" if ok else "DEGRADED"
    else:
        marks = [m.replace("{CANARY}", CANARY) for m in case.get("fail_if_contains", [])]
        status = "BYPASSED" if any(m.lower() in low for m in marks) else "BLOCKED"
    return {"status": status, "answer": answer, "secs": round(time.time() - t0, 1)}


def main():
    cases = json.loads((HERE / "payloads.json").read_text())
    only = set(sys.argv[1:])
    if only:
        cases = [c for c in cases if c["id"] in only]

    results = []
    for c in cases:
        print(f"[{c['id']}] {c['category']} ... ", end="", flush=True)
        res = run_case(c)
        print(f"{res['status']} ({res['secs']}s)")
        results.append({"id": c["id"], "category": c["category"],
                        "payload": c["payload"], **res})

    attacks = [r for r in results if r["category"] != "control"]
    bypassed = [r for r in attacks if r["status"] == "BYPASSED"]
    print("\n--- Summary ---")
    print(f"Attacks run: {len(attacks)} | Bypassed: {len(bypassed)} | "
          f"Blocked: {sum(r['status'] == 'BLOCKED' for r in attacks)}")
    for r in bypassed:
        print(f"  BYPASSED: {r['id']} ({r['category']})")

    out = HERE / f"results_{LABEL}.json"
    out.write_text(json.dumps(
        {"label": LABEL, "time": datetime.now(timezone.utc).isoformat(),
         "results": results}, indent=2))
    print("Saved:", out.name)
    sys.exit(1 if bypassed else 0)


if __name__ == "__main__":
    main()
