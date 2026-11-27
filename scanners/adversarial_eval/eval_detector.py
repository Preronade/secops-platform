import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from art.attacks.evasion import FastGradientMethod, ProjectedGradientDescent
from art.estimators.classification import PyTorchClassifier

HERE = Path(__file__).parent
API_DIR = Path(os.getenv("ADV_API_DIR", Path.home() / "projects" / "adv-secure-api"))
N = int(os.getenv("N", "500"))
sys.path.insert(0, str(API_DIR / "src"))
from model import SmallCNN  # noqa: E402

RAW = API_DIR / "data" / "MNIST" / "raw"
imgs = np.frombuffer((RAW / "t10k-images-idx3-ubyte").read_bytes(), np.uint8, offset=16).reshape(-1, 28, 28)
labs = np.frombuffer((RAW / "t10k-labels-idx1-ubyte").read_bytes(), np.uint8, offset=8)
x = (imgs.astype("float32") / 255.0)[:N, None]
y = labs[:N].astype("int64")


def load(name):
    m = SmallCNN()
    m.load_state_dict(torch.load(API_DIR / "models" / f"{name}.pt",
                                 map_location="cpu", weights_only=True))
    m.eval()
    return m


def labels(m, a):
    with torch.no_grad():
        return m(torch.tensor(a)).argmax(1).numpy()


def flagged(m, a):
    # same rule as api.py: binarize at 0.5, flag if the prediction changes
    sq = (a > 0.5).astype("float32")
    return labels(m, a) != labels(m, sq)


ATTACKS = [("FGSM", e) for e in (0.05, 0.1, 0.2, 0.3)] + [("PGD", e) for e in (0.1, 0.2, 0.3)]
rows = []
for name in ("standard", "robust"):
    m = load(name)
    clf = PyTorchClassifier(m, nn.CrossEntropyLoss(), input_shape=(1, 28, 28),
                            nb_classes=10, clip_values=(0, 1))
    pred = labels(m, x)
    correct = pred == y
    fl = flagged(m, x)
    rows.append({"model": name, "attack": "clean", "eps": 0.0,
                 "accuracy": round(float(correct.mean()), 3),
                 "fooled": 0, "detection_rate": None,
                 "false_positive_rate": round(float(fl[correct].mean()), 3),
                 "flag_rate_all": round(float(fl.mean()), 3)})
    for atk, eps in ATTACKS:
        if atk == "FGSM":
            gen = FastGradientMethod(clf, eps=eps)
        else:
            gen = ProjectedGradientDescent(clf, eps=eps, eps_step=eps / 4,
                                           max_iter=20, verbose=False)
        adv = gen.generate(x)
        ap = labels(m, adv)
        fooled = correct & (ap != y)
        fa = flagged(m, adv)
        rows.append({"model": name, "attack": atk, "eps": eps,
                     "accuracy": round(float((ap == y).mean()), 3),
                     "fooled": int(fooled.sum()),
                     "detection_rate": round(float(fa[fooled].mean()), 3) if fooled.any() else None,
                     "false_positive_rate": None,
                     "flag_rate_all": round(float(fa.mean()), 3)})

print(f"\nN={N} test images. detection = flagged among attacks that fooled the model;"
      " FPR = flagged among correctly classified clean images\n")
print(f"{'model':9}{'attack':7}{'eps':6}{'acc':7}{'fooled':8}{'detect':8}{'FPR':7}{'flag_all':8}")
for r in rows:
    f = lambda v: "-" if v is None else v
    print(f"{r['model']:9}{r['attack']:7}{r['eps']:<6}{r['accuracy']:<7}{r['fooled']:<8}"
          f"{f(r['detection_rate']):<8}{f(r['false_positive_rate']):<7}{r['flag_rate_all']:<8}")

(HERE / "results_detector.json").write_text(json.dumps(
    {"time": datetime.now(timezone.utc).isoformat(), "n": N, "rows": rows}, indent=2))
print("\nSaved: results_detector.json")
