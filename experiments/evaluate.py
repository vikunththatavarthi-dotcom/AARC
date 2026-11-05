"""
Experimental Framework: Proposed Model Evaluation.
Calculates Accuracy, Precision, Recall, F1-Score, ROC-AUC, FPR, FNR, and Confusion Matrix
on the actual test set. Results are saved to results/metrics/proposed_metrics.json.
"""
import json
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
from pathlib import Path
import config
from modules.preprocessing import DataPreprocessor
from modules.threat_detection import ThreatDetector
from data.generate_dataset import load_dataset
from sklearn.model_selection import train_test_split

def run_evaluation_pipeline(
    detector: ThreatDetector = None,
    preprocessor: DataPreprocessor = None,
    X_test: np.ndarray = None,
    y_test: np.ndarray = None,
    dataset_name: str = "DEMO_BENCHMARK_DATASET"
) -> Dict[str, Any]:
    """
    Evaluates the trained proposed model on the test dataset.
    """
    print("==================================================")
    print("      AARC PROPOSED MODEL EVALUATION             ")
    print("==================================================")
    
    if detector is None:
        detector = ThreatDetector.load()
    if preprocessor is None:
        preprocessor = DataPreprocessor.load()
        
    if X_test is None or y_test is None:
        df, dataset_name = load_dataset()
        _, test_df = train_test_split(
            df,
            test_size=config.TEST_SPLIT_RATIO,
            random_state=config.RANDOM_SEED,
            stratify=df[config.TARGET_COLUMN] if config.TARGET_COLUMN in df.columns else None
        )
        X_test, y_test = preprocessor.transform(test_df)
        
    metrics = detector.evaluate(X_test, y_test)
    metrics["dataset_source"] = dataset_name
    
    # Save metrics to JSON
    output_path = config.METRICS_DIR / "proposed_metrics.json"
    with open(output_path, "w") as f:
        json.dump(metrics, f, indent=4)
        
    print(f"[Evaluate] Proposed Model Results:")
    print(f"  - Accuracy:           {metrics['accuracy']:.4f}")
    print(f"  - Precision (Macro):  {metrics['precision_macro']:.4f}")
    print(f"  - Recall (Macro):     {metrics['recall_macro']:.4f}")
    print(f"  - F1-Score (Macro):   {metrics['f1_macro']:.4f}")
    print(f"  - ROC-AUC:            {metrics['roc_auc']:.4f}")
    print(f"  - False Positive Rate:{metrics['false_positive_rate']:.4f}")
    print(f"  - Confusion Matrix:   {metrics['confusion_matrix']}")
    print(f"[Evaluate] Metrics successfully saved to {output_path}")
    
    return metrics

if __name__ == "__main__":
    run_evaluation_pipeline()
