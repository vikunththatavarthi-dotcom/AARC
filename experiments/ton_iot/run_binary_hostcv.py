import gc, json, time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, OneHotEncoder, FunctionTransformer
from sklearn.impute import SimpleImputer
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    balanced_accuracy_score, roc_auc_score, confusion_matrix
)
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier

ROOT = Path("experiments/ton_iot")
DATA = Path("data/external/ton_iot_network_100k_unique.csv")
OUT = ROOT / "hostcv_metrics.json"

num = [
    "duration", "src_bytes", "dst_bytes", "missed_bytes", "src_pkts",
    "src_ip_bytes", "dst_pkts", "dst_ip_bytes", "dns_qclass", "dns_qtype",
    "dns_rcode", "http_request_body_len", "http_response_body_len", "http_status_code"
]
cat = [
    "dst_port", "proto", "service", "conn_state", "dns_AA", "dns_RD",
    "dns_RA", "dns_rejected", "ssl_version", "ssl_resumed", "ssl_established",
    "http_method", "http_version", "weird_name", "weird_notice"
]

print("Loading 100K rows; src_ip is used only for grouping...", flush=True)
df = pd.read_csv(DATA, usecols=num + cat + ["label", "src_ip"],
                 dtype={c: "category" for c in cat + ["src_ip"]},
                 low_memory=False)

for c in num:
    df[c] = pd.to_numeric(df[c], errors="coerce")

df["total_bytes"] = df.src_bytes.fillna(0) + df.dst_bytes.fillna(0)
df["total_packets"] = df.src_pkts.fillna(0) + df.dst_pkts.fillna(0)
dur = df.duration.replace(0, np.nan)
pkts = df.total_packets.replace(0, np.nan)
df["bytes_per_sec"] = (df.total_bytes / dur).replace([np.inf, -np.inf], np.nan).fillna(0)
df["packets_per_sec"] = (df.total_packets / dur).replace([np.inf, -np.inf], np.nan).fillna(0)
df["avg_bytes_per_packet"] = (df.total_bytes / pkts).replace([np.inf, -np.inf], np.nan).fillna(0)
num += ["total_bytes", "total_packets", "bytes_per_sec", "packets_per_sec", "avg_bytes_per_packet"]

X = df[num + cat].copy()
X[num] = X[num].astype("float32")
X[cat] = X[cat].astype("category")
y = pd.to_numeric(df.label).astype("int8").reset_index(drop=True)
groups = df.src_ip.astype("string").fillna("__MISSING_IP__").astype(str).reset_index(drop=True)
X = X.reset_index(drop=True)
del df
gc.collect()

print("Rows:", len(y), "| hosts:", groups.nunique(), "| labels:", y.value_counts().to_dict())
cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
splits = list(cv.split(X, y, groups))

names = ["logistic_regression", "decision_tree", "linear_svm", "random_forest"]
oof = {n: np.full(len(y), -1, dtype=np.int8) for n in names}
seen = np.zeros(len(y), dtype=np.int8)
folds = {n: [] for n in names}
fold_info = []

def build_preprocessor():
    npipe = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("log", FunctionTransformer(np.log1p)),
        ("scale", StandardScaler())
    ])
    cpipe = Pipeline([
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("onehot", OneHotEncoder(handle_unknown="ignore", min_frequency=100, dtype=np.float32))
    ])
    return ColumnTransformer(
        [("num", npipe, num), ("cat", cpipe, cat)], sparse_threshold=1.0
    )

def build_models():
    return [
        ("logistic_regression", LogisticRegression(
            solver="liblinear", max_iter=500, class_weight="balanced")),
        ("decision_tree", DecisionTreeClassifier(
            max_depth=12, min_samples_leaf=10, class_weight="balanced", random_state=42)),
        ("linear_svm", LinearSVC(
            C=0.5, class_weight="balanced", max_iter=3000, random_state=42)),
        ("random_forest", RandomForestClassifier(
            n_estimators=30, max_depth=12, min_samples_leaf=10, max_samples=0.6,
            n_jobs=1, class_weight="balanced_subsample", random_state=42))
    ]

def metrics(actual, pred, score=None):
    tn, fp, fn, tp = confusion_matrix(actual, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(actual, pred)),
        "precision_macro": float(precision_score(actual, pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(actual, pred, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(actual, pred, average="macro", zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(actual, pred)),
        "roc_auc": float(roc_auc_score(actual, score)) if score is not None and len(np.unique(actual)) == 2 else None,
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else None,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else None,
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]]
    }

for k, (tr, te) in enumerate(splits, 1):
    train_hosts, test_hosts = set(groups.iloc[tr]), set(groups.iloc[te])
    overlap = train_hosts & test_hosts
    if overlap:
        raise RuntimeError(f"Source-host overlap in fold {k}: {len(overlap)}")

    yt = y.iloc[tr]
    yv = y.iloc[te]
    fold_info.append({
        "fold": k, "train_records": len(tr), "test_records": len(te),
        "train_hosts": len(train_hosts), "test_hosts": len(test_hosts),
        "host_overlap": len(overlap),
        "train_labels": {str(a): int(b) for a, b in yt.value_counts().items()},
        "test_labels": {str(a): int(b) for a, b in yv.value_counts().items()}
    })

    print(f"\nFOLD {k}/5 | train={len(tr)} ({len(train_hosts)} hosts) "
          f"| test={len(te)} ({len(test_hosts)} hosts) "
          f"| test labels={yv.value_counts().to_dict()}", flush=True)

    prep = build_preprocessor()
    xt = prep.fit_transform(X.iloc[tr])
    xv = prep.transform(X.iloc[te])
    print("Encoded:", xt.shape, xv.shape, flush=True)

    for name, model in build_models():
        start = time.perf_counter()
        model.fit(xt, yt)
        train_sec = time.perf_counter() - start
        pred = model.predict(xv)
        score = model.predict_proba(xv)[:, 1] if hasattr(model, "predict_proba") else model.decision_function(xv)
        m = metrics(yv, pred, score)
        m.update({"fold": k, "training_time_seconds": float(train_sec),
                  "train_records": len(tr), "test_records": len(te),
                  "train_hosts": len(train_hosts), "test_hosts": len(test_hosts)})
        folds[name].append(m)
        oof[name][te] = pred

        print(f"{name}: acc={m['accuracy']:.4f}, macro-F1={m['f1_macro']:.4f}, "
              f"balanced-acc={m['balanced_accuracy']:.4f}, AUC={m['roc_auc']:.4f}",
              flush=True)
        del model, pred, score
        gc.collect()

    seen[te] += 1
    del prep, xt, xv
    gc.collect()

if not np.all(seen == 1) or any((v < 0).any() for v in oof.values()):
    raise RuntimeError("Out-of-fold predictions incomplete.")

report = {
    "dataset": "ToN_IoT network 100K stratified unique-row subset",
    "evaluation": "5-fold StratifiedGroupKFold grouped by source IP",
    "group_column": "src_ip (grouping only; not a model feature)",
    "random_state": 42, "records": len(y), "source_hosts": int(groups.nunique()),
    "folds": fold_info, "models": {}
}

for name in names:
    rows = folds[name]
    keys = ["accuracy", "precision_macro", "recall_macro", "f1_macro", "balanced_accuracy", "roc_auc"]
    means = {key: float(np.mean([r[key] for r in rows])) for key in keys}
    stds = {key: float(np.std([r[key] for r in rows])) for key in keys}
    pooled = metrics(y, oof[name])
    pooled.pop("roc_auc")

    report["models"][name] = {
        "per_fold": rows, "mean_fold_metrics": means,
        "std_fold_metrics": stds, "pooled_out_of_fold_metrics": pooled
    }

OUT.write_text(json.dumps(report, indent=2))
print("\nHOST-INDEPENDENT 5-FOLD COMPLETE")
print("Results saved to:", OUT)
print("No existing models or binary_metrics files were overwritten.")

for name in names:
    m = report["models"][name]["mean_fold_metrics"]
    p = report["models"][name]["pooled_out_of_fold_metrics"]
    print(f"{name}: mean-fold accuracy={m['accuracy']:.4f}, "
          f"mean-fold macro-F1={m['f1_macro']:.4f}, mean-fold AUC={m['roc_auc']:.4f}, "
          f"pooled OOF accuracy={p['accuracy']:.4f}, pooled OOF macro-F1={p['f1_macro']:.4f}")
