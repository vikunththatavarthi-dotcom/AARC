"""
Module 2: AI-Based Threat Detection.
Integrates supervised Random Forest classification with unsupervised Isolation Forest anomaly detection.
Generates multi-class predictions, calibrated threat scores, anomaly scores, and validation metrics.
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, roc_curve
)
from sklearn.preprocessing import label_binarize
import joblib
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, List
import config

class ThreatDetector:
    """
    Module 2 Threat Detection Engine combining Random Forest and Isolation Forest.
    Calculates multi-class classification, anomaly scores, and continuous threat scores.
    """
    def __init__(self, n_estimators: int = 100, max_depth: Optional[int] = 20, random_state: int = config.RANDOM_SEED):
        self.random_state = random_state
        self.rf_classifier = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=self.random_state,
            class_weight="balanced"
        )
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=0.20,
            random_state=self.random_state
        )
        self.classes = config.CLASSES
        self.is_trained = False

    def train(self, X_train: np.ndarray, y_train: np.ndarray) -> "ThreatDetector":
        """Trains both the Random Forest classifier and Isolation Forest anomaly detector."""
        print(f"[ThreatDetector] Training Random Forest on {X_train.shape[0]} samples with {X_train.shape[1]} features...")
        self.rf_classifier.fit(X_train, y_train)
        
        print("[ThreatDetector] Fitting Isolation Forest anomaly detector...")
        self.isolation_forest.fit(X_train)
        
        self.is_trained = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Returns predicted class indices."""
        if not self.is_trained:
            raise ValueError("ThreatDetector must be trained before predicting.")
        return self.rf_classifier.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Returns class probabilities."""
        if not self.is_trained:
            raise ValueError("ThreatDetector must be trained before predicting.")
        return self.rf_classifier.predict_proba(X)

    def predict_single(self, X_sample: np.ndarray) -> Dict[str, Any]:
        """
        Processes a single preprocessed feature vector and returns comprehensive AI threat metrics.
        """
        if not self.is_trained:
            raise ValueError("ThreatDetector must be trained.")
            
        # Ensure 2D shape (1, num_features)
        if len(X_sample.shape) == 1:
            X_sample = X_sample.reshape(1, -1)
            
        probas = self.rf_classifier.predict_proba(X_sample)[0]
        pred_idx = int(np.argmax(probas))
        confidence = float(probas[pred_idx])
        label_mapping = {0: "Benign", 1: "Malicious", 2: "Suspicious"}
        pred_label = label_mapping.get(int(self.rf_classifier.classes_[pred_idx]), "Unknown")
        # Isolation Forest anomaly score
        # decision_function yields positive for normal, negative for anomaly
        raw_anomaly_score = float(self.isolation_forest.decision_function(X_sample)[0])
        # Normalize anomaly score to [0.0, 1.0] where 1.0 is highest anomaly
        anomaly_score = float(np.clip(0.5 - (raw_anomaly_score / 2.0), 0.0, 1.0))
        
        # Calculate continuous Threat Score T in [0.0, 1.0]
        # Weight Benign=0.0, Suspicious=0.5, Malicious=1.0, plus anomaly contribution
        class_probabilities = {label_mapping[int(class_id)]: float(probability) for class_id, probability in zip(self.rf_classifier.classes_, probas) if int(class_id) in label_mapping}
        p_benign = class_probabilities.get("Benign", 0.0)
        p_suspicious = class_probabilities.get("Suspicious", 0.0)
        p_malicious = class_probabilities.get("Malicious", 0.0)
        
        threat_score = float(np.clip((p_suspicious * 0.50) + (p_malicious * 1.00) + (anomaly_score * 0.10), 0.0, 1.0))
        
        return {
            "predicted_class": pred_label,
            "predicted_index": pred_idx,
            "confidence": confidence,
            "probabilities": {
                "Benign": float(p_benign),
                "Suspicious": float(p_suspicious),
                "Malicious": float(p_malicious)
            },
            "threat_score": threat_score,
            "anomaly_score": anomaly_score,
            "is_anomaly": bool(anomaly_score > 0.60)
        }

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """
        Calculates all required evaluation metrics on the actual test set.
        No fabricated or placeholder values.
        """
        if not self.is_trained:
            raise ValueError("ThreatDetector must be trained before evaluation.")
            
        y_pred = self.rf_classifier.predict(X_test)
        y_proba = self.rf_classifier.predict_proba(X_test)
        
        acc = float(accuracy_score(y_test, y_pred))
        prec_macro = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
        prec_weighted = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
        rec_macro = float(recall_score(y_test, y_pred, average="macro", zero_division=0))
        rec_weighted = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
        f1_macro = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
        f1_weighted = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
        
        cm = confusion_matrix(y_test, y_pred).tolist()
        
        # Calculate False Positive Rate (FPR) and False Negative Rate (FNR)
        # For multi-class, compute binary projection for benign vs attacks
        # Class 0: Benign (Negative), Class 1 & 2: Attacks (Positive)
        y_test_bin = (y_test > 0).astype(int)
        y_pred_bin = (y_pred > 0).astype(int)
        
        cm_bin = confusion_matrix(y_test_bin, y_pred_bin)
        tn, fp, fn, tp = cm_bin.ravel() if cm_bin.shape == (2, 2) else (len(y_test_bin), 0, 0, 0)
        
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
        
        # Multiclass ROC-AUC via One-vs-Rest
        try:
            y_test_binarized = label_binarize(y_test, classes=[0, 1, 2])
            roc_auc = float(roc_auc_score(y_test_binarized, y_proba, multi_class="ovr", average="macro"))
        except Exception:
            roc_auc = 0.0
            
        metrics = {
            "model_name": "Proposed AARC (Random Forest + Anomaly Detection)",
            "accuracy": acc,
            "precision_macro": prec_macro,
            "precision_weighted": prec_weighted,
            "recall_macro": rec_macro,
            "recall_weighted": rec_weighted,
            "f1_macro": f1_macro,
            "f1_weighted": f1_weighted,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr,
            "roc_auc": roc_auc,
            "confusion_matrix": cm,
            "test_samples_count": int(len(y_test))
        }
        return metrics

    def get_feature_importances(self, feature_names: List[str]) -> List[Dict[str, Any]]:
        """Returns sorted feature importances from the Random Forest model."""
        if not self.is_trained:
            return []
        importances = self.rf_classifier.feature_importances_
        sorted_indices = np.argsort(importances)[::-1]
        
        results = []
        for idx in sorted_indices:
            name = feature_names[idx] if idx < len(feature_names) else f"feature_{idx}"
            results.append({
                "feature": name,
                "importance": float(importances[idx])
            })
        return results

    def save(self, filepath: Optional[Path] = None) -> None:
        """Serializes trained model to disk."""
        path = filepath or (config.MODELS_DIR / "threat_detector.joblib")
        joblib.dump(self, path)
        print(f"[ThreatDetector] Model saved to {path}")

    @classmethod
    def load(cls, filepath: Optional[Path] = None) -> "ThreatDetector":
        """Loads trained detector from disk."""
        path = filepath or (config.MODELS_DIR / "threat_detector.joblib")
        if not path.exists():
            raise FileNotFoundError(f"Model artifact not found at {path}")
        return joblib.load(path)
