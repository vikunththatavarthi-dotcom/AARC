"""
Module 1: Preprocessing Pipeline for Cloud Telemetry Data.
Provides consistent, reusable data cleaning, imputation, scaling, and encoding
for training, offline evaluation, and live stream inference.
"""
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.impute import SimpleImputer
import joblib
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
import config

class DataPreprocessor:
    """
    Reusable Scikit-Learn data preprocessing pipeline for AARC.
    Ensures identical transformations during training, testing, and runtime inference.
    """
    def __init__(self, feature_columns=None, target_column=None):
        self.feature_columns = feature_columns or config.FEATURE_COLUMNS
        self.target_column = target_column or config.TARGET_COLUMN
        self.imputer = SimpleImputer(strategy="median")
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.is_fitted = False
        
    def fit(self, df: pd.DataFrame) -> "DataPreprocessor":
        """Fits the imputer, scaler, and label encoder on training data."""
        # Ensure only feature columns are used
        available_features = [col for col in self.feature_columns if col in df.columns]
        X = df[available_features].copy()
        
        # Replace inf/-inf with NaN
        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        
        # Fit imputer and scaler
        X_imputed = self.imputer.fit_transform(X)
        self.scaler.fit(X_imputed)
        
        # Fit label encoder if target is present
        if self.target_column in df.columns:
            self.label_encoder.fit(df[self.target_column].astype(str))
            
        self.is_fitted = True
        return self
        
    def transform(self, df: pd.DataFrame) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """Transforms features and encodes target if present."""
        if not self.is_fitted:
            raise ValueError("DataPreprocessor must be fitted before calling transform().")
            
        available_features = [col for col in self.feature_columns if col in df.columns]
        # Handle single-row dictionary/dataframe with missing columns
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0.0
                
        X = df[self.feature_columns].copy()
        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        
        X_imputed = self.imputer.transform(X)
        X_scaled = self.scaler.transform(X_imputed)
        
        y = None
        if self.target_column in df.columns and df[self.target_column].notna().any():
            try:
                y = self.label_encoder.transform(df[self.target_column].astype(str))
            except ValueError:
                # Handle unseen labels gracefully
                y = np.zeros(len(df), dtype=int)
                
        return X_scaled, y

    def fit_transform(self, df: pd.DataFrame) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """Fits and transforms the dataset in one step."""
        self.fit(df)
        return self.transform(df)

    def transform_single_event(self, event_dict: Dict[str, Any]) -> np.ndarray:
        """Transforms a single telemetry event dictionary into a normalized feature vector for inference."""
        df = pd.DataFrame([event_dict])
        X_scaled, _ = self.transform(df)
        return X_scaled

    def save(self, filepath: Optional[Path] = None) -> None:
        """Serializes the fitted preprocessor to disk."""
        path = filepath or (config.MODELS_DIR / "preprocessor.joblib")
        joblib.dump(self, path)
        print(f"[Preprocessor] Pipeline saved to {path}")

    @classmethod
    def load(cls, filepath: Optional[Path] = None) -> "DataPreprocessor":
        """Loads a preprocessor instance from disk."""
        path = filepath or (config.MODELS_DIR / "preprocessor.joblib")
        if not path.exists():
            raise FileNotFoundError(f"Preprocessor artifact not found at {path}")
        return joblib.load(path)
