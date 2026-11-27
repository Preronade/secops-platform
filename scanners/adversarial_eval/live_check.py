import json
import os
import sys
import time
from pathlib import Path

import numpy as np
import requests
import torch
import torch.nn as nn
from art.attacks.evasion import ProjectedGradientDescent
from art.estimators.classification import PyTorchClassifier

HERE = Path(__file__).parent
API_DIR = Path(os.getenv("ADV_API_DIR", Path.home() / "projects" / "adv-secure-api"))
API_URL = os.getenv("API_URL", "http://localhost:8001").rstrip("/")
WEBHOOK = os.getenv("WEBHOOK_URL", "")
MAX_SEND = int(os.getenv("MAX_SEND", "2"))
K = int(os.getenv("K", "10"))
MODEL = os.getenv("MODEL", "standard")
EPS = float(os.getenv("EPS", "0.2"))
PASSWORD = os.environ.get("API_PASSWORD")
if not PASSWORD:
    sys.exit("API_PASSWORD is not set (run: set -a; source .env; set +a)")

sys.path.insert(0, str(API_DIR / "src"))
from model import SmallCNN  # noqa: E402

RAW = API_DIR / "data" / "MNIST" / "raw"
imgs = np.frombuffer((RAW / "t10k-images-idx3-ubyte").read_bytes(), np.uint8, offset=16).reshape(-1, 28, 28)
labs = np.frombuffer((RAW / "t10k-labels-idx1-ubyte").read_bytes(), np.uint8, offset=8)
x = (imgs[:200].astype("float32") / 255.0)[:, None]
y = labs[:200].astype("int64")

m = SmallCNN()
m.load_state_dict(torch.load(API_DIR / "models" / f"{MODEL}.pt", map_location="cpu", weights_only=True))
m.eval()


def labels(a):
    with torch.no_grad():
        return m(torch.tensor(a)).argmax(1).numpy()


def flags(a):
    return labels(a) != labels((a > 0.5).astype("float32"))


clf = PyTorchClassifier(m, nn.CrossEntropyLoss(), input_shape=(1, 28, 28),
                        nb_classes=10, clip_values=(0, 1))
adv = ProjectedGradientDescent(clf, eps=EPS, eps_step=EPS / 4, max_iter=20, verbose=False).generate(x)
pc, pa = labels(x), labels(adv)
good = np.where((pc == y) & (pa != y))[0][:K]      # attacks that really fool the model
if len(good) == 0:
    sys.exit("No successful adversarial examples found")

cases = []
for i in good:
    cases.append(("clean", int(i), x[i]))
    cases.append(("adv", int(i), adv[i]))
arr = np.stack([c[2] for c in cases])
off_label, off_flag = labels(arr), flags(arr)

s = requests.Session()
r = s.post(f"{API_URL}/token", data={"username": "analyst", "password": PASSWORD}, timeout=30)
r.raise_for_status()
s.headers["Authorization"] = "Bearer " + r.json()["access_token"]

rows = []
for n, (kind, i, a) in enumerate(cases):
    for attempt in range(3):
        r = s.post(f"{API_URL}/predict", params={"model": MODEL},
                   json={"image": a[0].tolist()}, timeout=60)
        if r.status_code == 429:
            print("rate limited, waiting 30s ...")
            time.sleep(30)
            continue
        break
    r.raise_for_status()
    d = r.json()
    rows.append({"idx": i, "kind": kind, "true": int(y[i]),
                 "api_label": d["label"], "api_flag": bool(d["suspicious_input"]),
                 "confidence": d["confidence"],
                 "offline_label": int(off_label[n]), "offline_flag": bool(off_flag[n])})
    time.sleep(2.5)

print(f"\nmodel={MODEL}  attack=PGD eps={EPS}  (adversarial images all fooled the model offline)\n")
print(f"{'img':5}{'kind':7}{'true':6}{'api':5}{'flag':7}{'offl':6}{'oflag':7}{'agree'}")
for r_ in rows:
    ok = r_["api_label"] == r_["offline_label"] and r_["api_flag"] == r_["offline_flag"]
    print(f"{r_['idx']:<5}{r_['kind']:7}{r_['true']:<6}{r_['api_label']:<5}{str(r_['api_flag']):7}"
          f"{r_['offline_label']:<6}{str(r_['offline_flag']):7}{'yes' if ok else 'NO'}")

clean = [r_ for r_ in rows if r_["kind"] == "clean"]
advr = [r_ for r_ in rows if r_["kind"] == "adv"]
agree = sum(r_["api_label"] == r_["offline_label"] and r_["api_flag"] == r_["offline_flag"] for r_ in rows)
print(f"\n--- Summary --- clean flagged: {sum(r_['api_flag'] for r_ in clean)}/{len(clean)} | "
      f"adversarial flagged: {sum(r_['api_flag'] for r_ in advr)}/{len(advr)} | "
      f"API matches offline: {agree}/{len(rows)}")

(HERE / "results_live.json").write_text(json.dumps(
    {"api": API_URL, "model": MODEL, "eps": EPS, "rows": rows}, indent=2))
print("Saved: results_live.json")

if WEBHOOK:
    sent = 0
    for r_ in rows:
        if r_["api_flag"] and sent < MAX_SEND:
            finding = {
                "id": f"adv-{r_['idx']}-{r_['kind']}",
                "type": "AdversarialInputSuspected",
                "severity": "MEDIUM",
                "title": f"Possible adversarial input flagged on /predict (model={MODEL})",
                "description": (f"The feature-squeezing detector flagged an input to the {MODEL} model. "
                                f"Predicted label {r_['api_label']} with confidence {r_['confidence']}. "
                                "The prediction changed after 1-bit squeezing, which is typical of "
                                "adversarial perturbation."),
            }
            requests.post(WEBHOOK, json=finding, timeout=300)
            sent += 1
            print("Sent to webhook:", finding["title"])
