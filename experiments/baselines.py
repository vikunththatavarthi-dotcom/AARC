"""
Experimental Framework: Baseline Model Comparison.
Trains and evaluates standard baseline machine learning models against the proposed AARC model:
- Baseline 1: Logistic Regression
- Baseline 2: Decision Tree
- Baseline 3: Support Vector Machine (SVM)
- Proposed: Proposed AARC (Random Forest + Anomaly Detection + Adaptive Architecture)
Saves comparison metrics to results/metrics/baseline_metrics.json.
"""
import time
import json
import numpy as np
import pandas as pd
from typing import Dict, Any, List
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score
)
from sklearn.preprocessing import label_binarize
from sklearn.model_selection import train_test_split

import config
from data.generate_dataset import load_dataset
from modules.preprocessing import DataPreprocessor
from modules.threat_detection import ThreatDetector

def evaluate_single_classifier(model, X_train, y_train, X_test, y_test, model_name: str) -> Dict[str, Any]:
    """Trains a classifier and computes rigorous evaluation metrics and inference latency."""
    # Training
    t0 = time.perf_counter()
    model.fit(X_train, y_train)
    train_time_sec = round(time.perf_counter() - t0, 4)
    
    # Inference Latency
    t1 = time.perf_counter()
    y_pred = model.predict(X_test)
    inference_time_total = time.perf_counter() - t1
    latency_per_sample_ms = round((inference_time_total / max(1, len(X_test))) * 1000, 4)
    
    # Probabilities
    if hasattr(model, "predict_proba"):
        y_proba = model.predict_proba(X_test)
    else:
        y_proba = None
        
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
    rec = float(recall_score(y_test, y_pred, average="macro", zero_division=0))
    f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
    
    # False Positive Rate on binary projection (Benign vs Attacks)
    y_test_bin = (y_test > 0).astype(int)
    y_pred_bin = (y_pred > 0).astype(int)
    cm_bin = confusion_matrix(y_test_bin, y_pred_bin)
    tn, fp, fn, tp = cm_bin.ravel() if cm_bin.shape == (2, 2) else (len(y_test_bin), 0, 0, 0)
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    
    # ROC-AUC
    try:
        y_test_binarized = label_binarize(y_test, classes=[0, 1, 2])
        if y_proba is not None:
            roc_auc = float(roc_auc_score(y_test_binarized, y_proba, multi_class="ovr", average="macro"))
        else:
            roc_auc = 0.0
    except Exception:
        roc_auc = 0.0
        
    return {
        "model_name": model_name,
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "train_time_sec": train_time_sec,
        "inference_latency_ms": latency_per_sample_ms
    }

def run_baselines_pipeline(
    X_train: np.ndarray = None,
    y_train: np.ndarray = None,
    X_test: np.ndarray = None,
    y_test: np.ndarray = None
) -> List[Dict[str, Any]]:
    """
    Executes the baseline comparison experiment suite.
    """
    print("==================================================")
    print("       AARC BASELINE COMPARISON EXPERIMENT        ")
    print("==================================================")
    
    if X_train is None or y_train is None or X_test is None or y_test is None:
        df, _ = load_dataset()
        train_df, test_df = train_test_split(
            df,
            test_size=config.TEST_SPLIT_RATIO,
            random_state=config.RANDOM_SEED,
            stratify=df[config.TARGET_COLUMN] if config.TARGET_COLUMN in df.columns else None
        )
        preprocessor = DataPreprocessor()
        X_train, y_train = preprocessor.fit_transform(train_df)
        X_test, y_test = preprocessor.transform(test_df)
        
    # Define Baselines
    models = [
        ("Baseline 1: Logistic Regression", LogisticRegression(max_iter=1000, random_state=config.RANDOM_SEED)),
        ("Baseline 2: Decision Tree", DecisionTreeClassifier(max_depth=12, random_state=config.RANDOM_SEED)),
        ("Baseline 3: Support Vector Machine (SVM)", SVC(kernel="rbf", probability=True, random_state=config.RANDOM_SEED))
    ]
    
    results = []
    for name, model in models:
        print(f"[Baselines] Training & evaluating {name}...")
        res = evaluate_single_classifier(model, X_train, y_train, X_test, y_test, name)
        results.append(res)
        print(f"  -> Acc: {res['accuracy']:.4f}, F1: {res['f1_score']:.4f}, FPR: {res['false_positive_rate']:.4f}, Latency: {res['inference_latency_ms']:.3f} ms")
        
    # Evaluate Proposed Model
    print("[Baselines] Evaluating Proposed AARC (Random Forest + Anomaly Detection)...")
    detector = ThreatDetector(random_state=config.RANDOM_SEED)
    t0 = time.perf_counter()
    detector.train(X_train, y_train)
    train_time = round(time.perf_counter() - t0, 4)
    
    t1 = time.perf_counter()
    prop_eval = detector.evaluate(X_test, y_test)
    prop_latency = round(((time.perf_counter() - t1) / max(1, len(X_test))) * 1000, 4)
    
    proposed_res = {
        "model_name": "Proposed: AARC (Random Forest + Dynamic Risk + Zero-Trust)",
        "accuracy": round(prop_eval["accuracy"], 4),
        "precision": round(prop_eval["precision_macro"], 4),
        "recall": round(prop_eval["recall_macro"], 4),
        "f1_score": round(prop_eval["f1_macro"], 4),
        "roc_auc": round(prop_eval["roc_auc"], 4),
        "false_positive_rate": round(prop_eval["false_positive_rate"], 4),
        "false_negative_rate": round(prop_eval["false_negative_rate"], 4),
        "train_time_sec": train_time,
        "inference_latency_ms": prop_latency
    }
    results.append(proposed_res)
    print(f"  -> Acc: {proposed_res['accuracy']:.4f}, F1: {proposed_res['f1_score']:.4f}, FPR: {proposed_res['false_positive_rate']:.4f}, Latency: {proposed_res['inference_latency_ms']:.3f} ms")

    # Save to metrics
    output_path = config.METRICS_DIR / "baseline_metrics.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=4)
        
    print(f"[Baselines] Baseline comparison saved to {output_path}")
    return results

if __name__ == "__main__":
    run_baselines_pipeline()
