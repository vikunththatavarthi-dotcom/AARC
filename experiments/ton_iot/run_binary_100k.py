import gc
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, OneHotEncoder, FunctionTransformer
from sklearn.impute import SimpleImputer
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, balanced_accuracy_score, roc_auc_score,
    confusion_matrix
)
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier

ROOT = Path("experiments/ton_iot")
DATA = Path("data/external/ton_iot_network_100k_unique.csv")
MODEL_DIR = ROOT / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

numeric = [
    "duration", "src_bytes", "dst_bytes",
    "missed_bytes", "src_pkts", "src_ip_bytes",
    "dst_pkts", "dst_ip_bytes", "dns_qclass",
    "dns_qtype", "dns_rcode",
    "http_request_body_len", "http_response_body_len",
    "http_status_code"
]

categorical = [
    "dst_port", "proto", "service", "conn_state",
    "dns_AA", "dns_RD", "dns_RA", "dns_rejected",
    "ssl_version", "ssl_resumed", "ssl_established",
    "http_method", "http_version", "weird_name",
    "weird_notice"
]

print("Loading selected dataset columns...")

df = pd.read_csv(
    DATA,
    usecols=numeric + categorical + ["label"],
    dtype={c: "category" for c in categorical}
)

print("Loaded:", df.shape)

print("\nCreating network features...")

df["total_bytes"] = df["src_bytes"] + df["dst_bytes"]
df["total_packets"] = df["src_pkts"] + df["dst_pkts"]

df["bytes_per_sec"] = (
    df["total_bytes"] /
    df["duration"].replace(0, np.nan)
).fillna(0)

df["packets_per_sec"] = (
    df["total_packets"] /
    df["duration"].replace(0, np.nan)
).fillna(0)

df["avg_bytes_per_packet"] = (
    df["total_bytes"] /
    df["total_packets"].replace(0, np.nan)
).fillna(0)

numeric += [
    "total_bytes", "total_packets",
    "bytes_per_sec", "packets_per_sec",
    "avg_bytes_per_packet"
]

X = df[numeric + categorical].copy()
y = pd.to_numeric(df["label"]).astype("int8")

X[numeric] = X[numeric].apply(
    pd.to_numeric, errors="coerce"
).astype("float32")

X[categorical] = X[categorical].astype("category")


print("\nChecking duplicate feature groups...")

groups = pd.util.hash_pandas_object(X, index=False)

audit = pd.DataFrame({
    "group": groups.to_numpy(),
    "label": y.to_numpy()
})

label_counts = audit.groupby("group")["label"].nunique()
conflicts = set(label_counts[label_counts > 1].index)

conflict_mask = groups.isin(conflicts)
conflicting_rows = int(conflict_mask.sum())

# Remove only feature groups with contradictory labels.
keep = ~conflict_mask
X = X.loc[keep].reset_index(drop=True)
y = y.loc[keep].reset_index(drop=True)
groups = groups.loc[keep].reset_index(drop=True)

records = len(y)
group_count = int(groups.nunique())

print("Conflicting groups removed:", len(conflicts))
print("Conflicting rows removed:", conflicting_rows)
print("Usable records:", records)
print("Unique feature groups:", group_count)
print("Repeated observations retained:", records - group_count)

print("\nCreating stratified group split...")

splitter = StratifiedGroupKFold(
    n_splits=5,
    shuffle=True,
    random_state=42
)

train_idx, test_idx = next(splitter.split(X, y, groups))

X_train = X.iloc[train_idx].copy()
X_test = X.iloc[test_idx].copy()
y_train = y.iloc[train_idx].copy()
y_test = y.iloc[test_idx].copy()

overlap = set(groups.iloc[train_idx]) & set(groups.iloc[test_idx])

if overlap:
    raise RuntimeError("Feature-group leakage detected!")

print("Training records:", len(X_train))
print("Testing records:", len(X_test))
print("Train/test group overlap:", len(overlap))

metadata = {
    "dataset": "ToN_IoT network",
    "records": records,
    "conflicting_groups_removed": len(conflicts),
    "conflicting_rows_removed": conflicting_rows,
    "unique_feature_groups": group_count,
    "repeated_observations_retained": records - group_count,
    "training_records": len(X_train),
    "testing_records": len(X_test),
    "split_method": "StratifiedGroupKFold",
    "random_state": 42,
    "numeric_features": numeric,
    "categorical_features": categorical
}

del df, X, y, groups, audit, label_counts
gc.collect()

gc.collect()

metadata = {
    "dataset": "ToN_IoT network",
    "records": records,
    "conflicting_rows_removed": conflicting_rows,
    "training_records": len(X_train),
    "testing_records": len(X_test),
    "random_state": 42,
    "test_size": 0.20,
    "numeric_features": numeric,
    "categorical_features": categorical
}

print("\nBuilding preprocessing pipeline...")

num_pipe = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("log", FunctionTransformer(np.log1p)),
    ("scaler", StandardScaler())
])

cat_pipe = Pipeline([
    ("imputer", SimpleImputer(strategy="most_frequent")),
    ("encoder", OneHotEncoder(
        handle_unknown="ignore",
        min_frequency=100,
        dtype=np.float32
    ))
])

preprocessor = ColumnTransformer(
    transformers=[
        ("numeric", num_pipe, numeric),
        ("categorical", cat_pipe, categorical)
    ],
    sparse_threshold=1.0
)

print("Fitting preprocessing on training data...")

Xtr = preprocessor.fit_transform(X_train)
Xte = preprocessor.transform(X_test)

print("Encoded training shape:", Xtr.shape)
print("Encoded testing shape:", Xte.shape)

joblib.dump(
    preprocessor,
    MODEL_DIR / "preprocessor.joblib"
)

del X_train, X_test
gc.collect()

print("Preprocessor saved successfully.")

models = [
    ("logistic_regression", lambda: LogisticRegression(
        solver="liblinear",
        max_iter=500,
        class_weight="balanced"
    )),
    ("decision_tree", lambda: DecisionTreeClassifier(
        max_depth=12,
        min_samples_leaf=10,
        class_weight="balanced",
        random_state=42
    )),
    ("linear_svm", lambda: LinearSVC(
        C=0.5,
        class_weight="balanced",
        max_iter=3000,
        random_state=42
    )),
    ("random_forest", lambda: RandomForestClassifier(
        n_estimators=30,
        max_depth=12,
        min_samples_leaf=10,
        max_samples=0.6,
        n_jobs=1,
        class_weight="balanced_subsample",
        random_state=42
    ))
]

results = []

joblib.dump(preprocessor, MODEL_DIR / "preprocessor.joblib")

for name, create_model in models:
    print(f"\n========== {name} ==========", flush=True)

    clf = create_model()

    start = time.perf_counter()
    clf.fit(Xtr, y_train)
    training_time = time.perf_counter() - start

    pred = clf.predict(Xte)

    if hasattr(clf, "predict_proba"):
        scores = clf.predict_proba(Xte)[:, 1]
    else:
        scores = clf.decision_function(Xte)

    tn, fp, fn, tp = confusion_matrix(
        y_test, pred, labels=[0, 1]
    ).ravel()

    times = []
    for _ in range(3):
        start = time.perf_counter()
        clf.predict(Xte)
        times.append(time.perf_counter() - start)

    batch_ms = float(np.median(times) * 1000)

    metrics = {
        "model": name,
        "accuracy": float(accuracy_score(y_test, pred)),
        "precision_macro": float(
            precision_score(y_test, pred, average="macro")
        ),
        "recall_macro": float(
            recall_score(y_test, pred, average="macro")
        ),
        "f1_macro": float(
            f1_score(y_test, pred, average="macro")
        ),
        "balanced_accuracy": float(
            balanced_accuracy_score(y_test, pred)
        ),
        "roc_auc": float(roc_auc_score(y_test, scores)),
        "false_positive_rate": float(fp / (fp + tn)),
        "false_negative_rate": float(fn / (fn + tp)),
        "confusion_matrix": [
            [int(tn), int(fp)],
            [int(fn), int(tp)]
        ],
        "training_time_seconds": float(training_time),
        "inference_batch_ms": batch_ms,
        "inference_ms_per_record": batch_ms / len(y_test)
    }

    results.append(metrics)

    print("Accuracy:", round(metrics["accuracy"], 4))
    print("Macro F1:", round(metrics["f1_macro"], 4))
    print("Balanced accuracy:", round(metrics["balanced_accuracy"], 4))
    print("ROC-AUC:", round(metrics["roc_auc"], 4))
    print("FPR:", round(metrics["false_positive_rate"], 4))
    print("FNR:", round(metrics["false_negative_rate"], 4))
    print("Training time:", round(training_time, 2), "seconds")
    print("Confusion matrix:", metrics["confusion_matrix"])

    joblib.dump(clf, MODEL_DIR / f"{name}.joblib")

    partial = {**metadata, "results": results}
    (ROOT / "binary_metrics_partial.json").write_text(
        json.dumps(partial, indent=2)
    )

    del clf, pred, scores, metrics
    gc.collect()


output = {**metadata, "results": results}

path = ROOT / "binary_metrics.json"
path.write_text(json.dumps(output, indent=2))

print("\n================================")
print("EXTERNAL DATASET EXPERIMENT DONE")
print("Results:", path)
print("Models:", MODEL_DIR)
print("================================")

for result in results:
    print(
        result["model"],
        "| Accuracy:", round(result["accuracy"], 4),
        "| F1:", round(result["f1_macro"], 4),
        "| AUC:", round(result["roc_auc"], 4)
    )
