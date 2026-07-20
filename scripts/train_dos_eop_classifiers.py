#!/usr/bin/env python3
"""
Train Random Forest classifiers per CIC-IDS2018 attack category: Denial of
Service (02-15-2018.csv), Elevation of Privilege / web-attack
(02-22-2018.csv), Credential attack (02-14-2018.csv), Infiltration
(02-28-2018.csv).

Uses a train/validation/test split (scripts/simulator/data_split.py) so
reported test-set numbers are honest out-of-sample performance. The live
simulator draws only from the "test" split for these files, so there is no
leakage between training and live evaluation.

Usage: python3 scripts/train_dos_eop_classifiers.py
Writes: scripts/models/{dos,eop,credential,infiltration}_classifier.joblib
"""
import csv
import json
import math
import os
import sys

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_score, f1_score, roc_auc_score, roc_curve

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "simulator"))
from data_split import split_bucket  # noqa: E402

DATA_DIR = os.environ.get("CIC2018_DIR", "datasets/cic2018")

# Non-feature / identifier columns excluded from the feature matrix.
EXCLUDE = {"Label", "Timestamp", "Flow ID", "Src IP", "Dst IP", "Src Port"}

# TCP-stack/OS-configuration fingerprint columns, excluded deliberately: these
# are near-categorical splits driven by which host generated the traffic in
# CIC-IDS2018's testbed, not by attack behavior, so a classifier trained on
# them would learn "which host produced this flow" rather than generalizing.
ARTIFACT_PRONE = {
    "Init Fwd Win Byts", "Init Bwd Win Byts", "Fwd Seg Size Min",
    "Fwd Header Len", "Bwd Header Len",
}
EXCLUDE |= ARTIFACT_PRONE

TASKS = {
    "dos": {
        "file": "02-15-2018.csv",
        "attack_match": lambda lab: "DOS" in lab.upper() or "DDOS" in lab.upper(),
    },
    "eop": {
        "file": "02-22-2018.csv",
        "attack_match": lambda lab: lab.upper() != "BENIGN" and lab.upper() != "LABEL",
    },
    "credential": {
        "file": "02-14-2018.csv",
        "attack_match": lambda lab: lab.upper() != "BENIGN" and lab.upper() != "LABEL",
    },
    "infiltration": {
        "file": "02-28-2018.csv",
        "attack_match": lambda lab: "INFIL" in lab.upper() or "BOT" in lab.upper(),
    },
}


def load_rows(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def to_float(v):
    try:
        x = float(v)
        if math.isnan(x) or math.isinf(x):
            return 0.0
        return x
    except (TypeError, ValueError):
        return 0.0


def build_xy(rows, feature_names, attack_match):
    X, y = [], []
    for r in rows:
        lab = (r.get("Label") or "").strip()
        if not lab or lab.upper() == "LABEL":
            continue
        X.append([to_float(r.get(f)) for f in feature_names])
        y.append(1 if attack_match(lab) else 0)
    return np.array(X, dtype=np.float64), np.array(y, dtype=np.int64)


def run_task(name, cfg):
    path = os.path.join(DATA_DIR, cfg["file"])
    print(f"[{name}] loading {path}")
    rows = load_rows(path)
    print(f"[{name}] {len(rows)} rows loaded")

    header = [k for k in rows[0].keys() if k not in EXCLUDE]

    train_rows, val_rows, test_rows = [], [], []
    for i, r in enumerate(rows):
        bucket = split_bucket(i)
        (train_rows if bucket == "train" else val_rows if bucket == "val" else test_rows).append(r)
    print(f"[{name}] split: train={len(train_rows)} val={len(val_rows)} test={len(test_rows)}")

    X_train, y_train = build_xy(train_rows, header, cfg["attack_match"])
    X_val, y_val = build_xy(val_rows, header, cfg["attack_match"])
    X_test, y_test = build_xy(test_rows, header, cfg["attack_match"])
    print(f"[{name}] train positives={y_train.sum()}/{len(y_train)}  "
          f"val positives={y_val.sum()}/{len(y_val)}  test positives={y_test.sum()}/{len(y_test)}")

    clf = RandomForestClassifier(
        n_estimators=200, max_depth=12, min_samples_leaf=5,
        class_weight="balanced", random_state=42, n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    # Freeze the operating point from validation ROC only: maximize recall
    # while holding validation FPR to at most 1%. Test remains untouched.
    val_proba = clf.predict_proba(X_val)[:, 1]
    val_fpr, val_tpr, val_thresholds = roc_curve(y_val, val_proba)
    eligible = np.where(val_fpr <= 0.01)[0]
    best_index = int(eligible[np.argmax(val_tpr[eligible])]) if len(eligible) else int(np.argmax(val_tpr - val_fpr))
    best_thr = float(val_thresholds[best_index])
    val_pred = (val_proba >= best_thr).astype(int)
    best_f1 = f1_score(y_val, val_pred, zero_division=0)
    print(f"[{name}] ROC operating point (validation): threshold={best_thr:.6f} "
          f"TPR={val_tpr[best_index]:.4f} FPR={val_fpr[best_index]:.4f} F1={best_f1:.4f}")

    # Final, honest, held-out evaluation — test set was untouched until now.
    test_proba = clf.predict_proba(X_test)[:, 1]
    test_pred = (test_proba >= best_thr).astype(int)
    tp = int(((test_pred == 1) & (y_test == 1)).sum())
    fp = int(((test_pred == 1) & (y_test == 0)).sum())
    tn = int(((test_pred == 0) & (y_test == 0)).sum())
    fn = int(((test_pred == 0) & (y_test == 1)).sum())
    tpr = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    precision = precision_score(y_test, test_pred, zero_division=0)
    f1 = f1_score(y_test, test_pred, zero_division=0)
    auc = roc_auc_score(y_test, test_proba)

    print(f"[{name}] === HELD-OUT TEST RESULT === "
          f"n={len(y_test)} tp={tp} fp={fp} tn={tn} fn={fn}")
    print(f"[{name}] TPR={tpr:.4f} FPR={fpr:.4f} Precision={precision:.4f} F1={f1:.4f} AUC={auc:.4f}")

    importances = sorted(zip(header, clf.feature_importances_), key=lambda x: -x[1])[:10]
    print(f"[{name}] top-10 features: {[(f, round(v,4)) for f,v in importances]}")

    os.makedirs("scripts/models", exist_ok=True)
    out_path = f"scripts/models/{name}_classifier.joblib"
    joblib.dump({
        "model": clf,
        "feature_names": header,
        "threshold": best_thr,
        "threshold_selection": "max_validation_tpr_subject_to_fpr_lte_0.01",
        "validation_operating_point": {
            "tpr": round(float(val_tpr[best_index]), 6),
            "fpr": round(float(val_fpr[best_index]), 6),
            "f1": round(float(best_f1), 6),
        },
        "test_metrics": {"n": len(y_test), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
                          "tpr": round(tpr, 4), "fpr": round(fpr, 4),
                          "precision": round(precision, 4), "f1": round(f1, 4), "auc": round(auc, 4)},
        "top_features": [(f, round(float(v), 4)) for f, v in importances],
    }, out_path)
    print(f"[{name}] saved to {out_path}")
    return {"tpr": tpr, "fpr": fpr, "precision": precision, "f1": f1, "auc": auc, "n_test": len(y_test)}


def main():
    results = {}
    for name, cfg in TASKS.items():
        results[name] = run_task(name, cfg)
    with open("scripts/models/held_out_test_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\n=== SUMMARY (held-out test) ===")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
