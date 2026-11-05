"""
Experimental Framework: Hyperparameter Tuning Pipeline.
Executes systematic 5-fold Cross-Validated Grid Search for the primary Random Forest Threat Detection model.
Explores n_estimators, max_depth, min_samples_split, min_samples_leaf, and max_features.
Saves tuning metrics to results/metrics/tuning_metrics.json.
"""
import json
import time
import numpy as np
import pandas as pd
from typing import Dict, Any
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.ensemble import RandomForestClassifier

import config
from data.generate_dataset import load_dataset
from modules.preprocessing import DataPreprocessor

def run_hyperparameter_tuning_pipeline(
    X_train: np.ndarray = None,
    y_train: np.ndarray = None
) -> Dict[str, Any]:
    """
    Runs 5-fold GridSearchCV on Random Forest hyperparameters.
    """
    print("==================================================")
    print("    AARC HYPERPARAMETER TUNING (GRID SEARCH)      ")
    print("==================================================")
    
    if X_train is None or y_train is None:
        df, _ = load_dataset()
        train_df, _ = train_test_split(
            df,
            test_size=config.TEST_SPLIT_RATIO,
            random_state=config.RANDOM_SEED,
            stratify=df[config.TARGET_COLUMN] if config.TARGET_COLUMN in df.columns else None
        )
        preprocessor = DataPreprocessor()
        X_train, y_train = preprocessor.fit_transform(train_df)

    param_grid = {
        "n_estimators": [50, 100, 150],
        "max_depth": [10, 20, 30],
        "min_samples_split": [2, 5],
        "min_samples_leaf": [1, 2],
        "max_features": ["sqrt", "log2"]
    }
    
    rf = RandomForestClassifier(random_state=config.RANDOM_SEED, class_weight="balanced")
    
    print(f"[Tuning] Starting 5-fold Cross Validation over {len(param_grid['n_estimators']) * len(param_grid['max_depth']) * len(param_grid['min_samples_split']) * len(param_grid['min_samples_leaf']) * len(param_grid['max_features'])} parameter candidates...")
    t0 = time.perf_counter()
    
    grid_search = GridSearchCV(
        estimator=rf,
        param_grid=param_grid,
        cv=config.CV_FOLDS,
        scoring="f1_macro",
        n_jobs=-1,
        verbose=1,
        return_train_score=True
    )
    
    grid_search.fit(X_train, y_train)
    tuning_time_sec = round(time.perf_counter() - t0, 2)
    
    best_params = grid_search.best_params_
    best_score = float(grid_search.best_score_)
    
    print(f"[Tuning] Grid Search completed in {tuning_time_sec}s.")
    print(f"[Tuning] Best Cross-Validation F1 (Macro): {best_score:.4f}")
    print(f"[Tuning] Best Hyperparameters: {best_params}")
    
    # Extract parameter sensitivity summary for plotting
    cv_results = grid_search.cv_results_
    
    param_summary = []
    for param_name, search_range in param_grid.items():
        best_val = best_params[param_name]
        param_summary.append({
            "parameter": param_name,
            "search_range": str(search_range),
            "best_value": str(best_val) if best_val is not None else "None"
        })
        
    # Extract mean test scores across n_estimators and max_depth for visualization
    results_records = []
    for i in range(len(cv_results["params"])):
        results_records.append({
            "params": cv_results["params"][i],
            "n_estimators": cv_results["params"][i]["n_estimators"],
            "max_depth": str(cv_results["params"][i]["max_depth"]),
            "mean_test_score": float(cv_results["mean_test_score"][i]),
            "std_test_score": float(cv_results["std_test_score"][i]),
            "mean_train_score": float(cv_results["mean_train_score"][i])
        })

    tuning_data = {
        "best_score": round(best_score, 4),
        "best_params": best_params,
        "tuning_time_sec": tuning_time_sec,
        "cv_folds": config.CV_FOLDS,
        "parameters_table": param_summary,
        "cv_results_sample": results_records[:20]
    }
    
    # Save to metrics
    output_path = config.METRICS_DIR / "tuning_metrics.json"
    with open(output_path, "w") as f:
        json.dump(tuning_data, f, indent=4)
        
    print(f"[Tuning] Tuning results saved to {output_path}")
    return tuning_data

if __name__ == "__main__":
    run_hyperparameter_tuning_pipeline()
