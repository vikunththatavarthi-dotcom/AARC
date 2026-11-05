"""
Experimental Framework: Model Training Pipeline.
Performs stratified train/test split, preprocessor fitting, and Random Forest + Isolation Forest training.
Saves serialized model artifacts to models/ for reproducible inference.
"""
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from typing import Tuple, Dict, Any
from pathlib import Path
import config
from data.generate_dataset import load_dataset, generate_synthetic_benchmark_dataset
from modules.preprocessing import DataPreprocessor
from modules.threat_detection import ThreatDetector

def run_training_pipeline(use_full_dataset: bool = False, random_state: int = config.RANDOM_SEED) -> Tuple[ThreatDetector, DataPreprocessor, np.ndarray, np.ndarray, np.ndarray, np.ndarray, str]:
    """
    Executes end-to-end model training:
    1. Loads dataset
    2. Performs stratified train/test split
    3. Fits preprocessing pipeline (StandardScaler + Imputer + LabelEncoder)
    4. Trains ThreatDetector (Random Forest + Isolation Forest)
    5. Saves serialized artifacts
    """
    print("==================================================")
    print("        AARC MODEL TRAINING PIPELINE             ")
    print("==================================================")
    
    # Ensure sample data exists
    if not config.SAMPLE_DATA_PATH.exists():
        generate_synthetic_benchmark_dataset(seed=random_state)
        
    df, dataset_name = load_dataset(use_full_dataset=use_full_dataset)
    print(f"[Train] Loaded dataset: {dataset_name} ({len(df)} records)")
    
    # Train / Test split
    train_df, test_df = train_test_split(
        df,
        test_size=config.TEST_SPLIT_RATIO,
        random_state=random_state,
        stratify=df[config.TARGET_COLUMN] if config.TARGET_COLUMN in df.columns else None
    )
    print(f"[Train] Train set: {len(train_df)} samples, Test set: {len(test_df)} samples")
    
    # Fit Preprocessor
    preprocessor = DataPreprocessor()
    X_train_scaled, y_train = preprocessor.fit_transform(train_df)
    X_test_scaled, y_test = preprocessor.transform(test_df)
    
    # Save Preprocessor
    preprocessor.save()
    
    # Train Threat Detector
    detector = ThreatDetector(random_state=random_state)
    detector.train(X_train_scaled, y_train)
    
    # Save Detector
    detector.save()
    
    print("[Train] Training completed successfully.")
    return detector, preprocessor, X_train_scaled, X_test_scaled, y_train, y_test, dataset_name

if __name__ == "__main__":
    run_training_pipeline()
