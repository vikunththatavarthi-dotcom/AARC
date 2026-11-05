import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, balanced_accuracy_score,
    confusion_matrix, roc_auc_score
)

def calculate_metrics(actual, predicted, scores):
    tn, fp, fn, tp = confusion_matrix(
        actual, predicted, labels=[0, 1]
    ).ravel()

    return {
        "accuracy": float(accuracy_score(actual, predicted)),
        "precision_macro": float(precision_score(
            actual, predicted, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(
            actual, predicted, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(
            actual, predicted, average="macro", zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(
            actual, predicted)),
        "roc_auc": float(roc_auc_score(actual, scores)),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else 0,
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]]
    }
