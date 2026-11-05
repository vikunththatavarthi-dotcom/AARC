import gc
import json
from collections import Counter
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from aarc_eval_config import DATA, OUT, NUM, CAT, build_preprocessor
from aarc_eval_models import evaluate_fold
from aarc_eval_pipeline import calculate_metrics

print("Loading ToN_IoT...", flush=True)
df = pd.read_csv(
    DATA, usecols=NUM + CAT + ["label", "src_ip"],
    dtype={c: "category" for c in CAT + ["src_ip"]},
    low_memory=False
)

for c in NUM:
    df[c] = pd.to_numeric(df[c], errors="coerce")

df["total_bytes"] = df.src_bytes.fillna(0) + df.dst_bytes.fillna(0)
df["total_packets"] = df.src_pkts.fillna(0) + df.dst_pkts.fillna(0)
duration = df.duration.replace(0, np.nan)
packets = df.total_packets.replace(0, np.nan)

df["bytes_per_sec"] = (df.total_bytes / duration).replace(
    [np.inf, -np.inf], np.nan).fillna(0)
df["packets_per_sec"] = (df.total_packets / duration).replace(
    [np.inf, -np.inf], np.nan).fillna(0)
df["avg_bytes_per_packet"] = (df.total_bytes / packets).replace(
    [np.inf, -np.inf], np.nan).fillna(0)

X = df[NUM + ["total_bytes", "total_packets", "bytes_per_sec", "packets_per_sec", "avg_bytes_per_packet"] + CAT].copy()
X[NUM] = X[NUM].astype("float32")
X[CAT] = X[CAT].astype("category")
X = X.reset_index(drop=True)

y = pd.to_numeric(df.label).astype("int8").reset_index(drop=True)
groups = df.src_ip.astype("string").fillna("__MISSING__").astype(str)
groups = groups.reset_index(drop=True)
del df
gc.collect()

cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
splits = list(cv.split(X, y, groups))

oof = np.full(len(y), -1, dtype=np.int8)
alert_oof = np.full(len(y), -1, dtype=np.int8)
risk_oof = np.full(len(y), np.nan)
rf_oof = np.full(len(y), -1, dtype=np.int8)
alert_oof = np.full(len(y), -1, dtype=np.int8)
folds = []
decisions, contexts = Counter(), Counter()

for fold, (tr, te) in enumerate(splits, 1):
    overlap = set(groups.iloc[tr]) & set(groups.iloc[te])
    if overlap:
        raise RuntimeError("Source-host leakage detected")

    print(f"\nFold {fold}/5: train={len(tr)}, test={len(te)}", flush=True)
    prep = build_preprocessor()
    xt = prep.fit_transform(X.iloc[tr])
    xv = prep.transform(X.iloc[te])

    pred, risks, rf, dec, ctx = evaluate_fold(
        xt, y.iloc[tr].to_numpy(), xv, X.iloc[te]
    )

    oof[te], risk_oof[te], rf_oof[te] = pred, risks, rf
    alert_oof[te] = np.array(
        [int(d != "ALLOW") for d in dec], dtype=np.int8
    )
    decisions.update(dec)
    contexts.update(ctx)

    folds.append({
        "fold": fold,
        "train_records": len(tr),
        "test_records": len(te),
        "test_hosts": int(groups.iloc[te].nunique()),
        "host_overlap": len(overlap),
        "aarc": calculate_metrics(y.iloc[te], pred, risks)
    })

    print(f"Integrated accuracy: {accuracy_score(y.iloc[te], pred):.4f}", flush=True)
    del prep, xt, xv
    gc.collect()

if (oof < 0).any() or (alert_oof < 0).any() or np.isnan(risk_oof).any():
    raise RuntimeError("Incomplete out-of-fold predictions")

report = {
    "dataset": "ToN_IoT network 100K unique-row subset",
    "evaluation": "5-fold StratifiedGroupKFold by src_ip",
    "records": len(y),
    "source_hosts": int(groups.nunique()),
    "decision_mapping": {
        "attack": ["RESTRICT", "ISOLATE", "BLOCK + RESPONSE"],
        "non_blocking": ["ALLOW", "ALLOW + MONITOR"]
    },
    "telemetry_note": (
        "Unavailable user/device/application telemetry is excluded from risk components; available weights are renormalized. "
        "Ground-truth labels are never passed into the AARC pipeline."
    ),
    "zero_trust_enforcement_pooled_oof": calculate_metrics(y, oof, risk_oof),
    "zero_trust_monitoring_alert_pooled_oof": calculate_metrics(
        y, alert_oof, risk_oof
    ),
    "risk_score_ranking": {
        "roc_auc": float(__import__("sklearn.metrics", fromlist=["roc_auc_score"]).roc_auc_score(y, risk_oof)),
        "average_precision": float(__import__("sklearn.metrics", fromlist=["average_precision_score"]).average_precision_score(y, risk_oof)),
        "normal_mean_risk": float(risk_oof[y.to_numpy() == 0].mean()),
        "attack_mean_risk": float(risk_oof[y.to_numpy() == 1].mean())
    },
    "random_forest_pooled_oof": {
        "accuracy": float(accuracy_score(y, rf_oof)),
        "precision_macro": float(precision_score(y, rf_oof, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y, rf_oof, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y, rf_oof, average="macro", zero_division=0)),
        "confusion_matrix": confusion_matrix(y, rf_oof, labels=[0, 1]).tolist()
    },
    "zero_trust_decisions": dict(decisions),
    "adaptive_policy_contexts": dict(contexts),
    "folds": folds
}

OUT.write_text(json.dumps(report, indent=2))
print("\nAARC EVALUATION COMPLETE")
print("Zero Trust enforcement:", json.dumps(report["zero_trust_enforcement_pooled_oof"], indent=2))
print("Monitoring alerts:", json.dumps(report["zero_trust_monitoring_alert_pooled_oof"], indent=2))
print("Risk ranking:", json.dumps(report["risk_score_ranking"], indent=2))
print("RF comparison:", report["random_forest_pooled_oof"])
print("Zero Trust decisions:", dict(decisions))
print("Saved:", OUT)
