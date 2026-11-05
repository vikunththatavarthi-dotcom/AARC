"""
Experimental Framework: Master Pipeline Runner.
Orchestrates the entire reproducible experiment suite:
1. Dataset ingestion / synthesis
2. Model training & serialization
3. Test set evaluation & metrics calculation
4. Baseline model comparison
5. 7-configuration ablation study
6. 5-fold cross-validated hyperparameter tuning
7. Generation of 11 publication-grade research figures
8. Compilation of 6 formatted research tables
9. Compilation of Section 4 Results & Discussion report
"""
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from data.generate_dataset import generate_synthetic_benchmark_dataset, load_dataset
from experiments.train import run_training_pipeline
from experiments.evaluate import run_evaluation_pipeline
from experiments.baselines import run_baselines_pipeline
from experiments.ablation import run_ablation_pipeline
from experiments.hyperparameter_tuning import run_hyperparameter_tuning_pipeline
from experiments.visualize import generate_all_figures
from experiments.tables import generate_all_tables
from experiments.section4_generator import generate_section4_report

def execute_complete_experimental_suite():
    """Executes the full end-to-end experimental pipeline."""
    start_total = time.perf_counter()
    print("=================================================================")
    print("    AARC RESEARCH PROTOTYPE: COMPLETE EXPERIMENTAL SUITE         ")
    print("=================================================================\n")
    
    # Step 1: Dataset
    print("[1/9] Ingesting & Verifying Dataset...")
    generate_synthetic_benchmark_dataset()
    
    # Step 2: Training
    print("\n[2/9] Training Proposed AARC Detection Models...")
    detector, preprocessor, X_train, X_test, y_train, y_test, ds_name = run_training_pipeline()
    
    # Step 3: Evaluation
    print("\n[3/9] Evaluating Proposed Model Metrics on Test Set...")
    run_evaluation_pipeline(detector, preprocessor, X_test, y_test, ds_name)
    
    # Step 4: Baselines
    print("\n[4/9] Running Baseline Classifier Comparison (LR, DT, SVM vs Proposed)...")
    run_baselines_pipeline(X_train, y_train, X_test, y_test)
    
    # Step 5: Ablation
    print("\n[5/9] Running 7-Configuration Ablation Study...")
    run_ablation_pipeline(X_train, y_train, X_test, y_test)
    
    # Step 6: Hyperparameter Tuning
    print("\n[6/9] Running Random Forest Hyperparameter Grid Search (5-Fold CV)...")
    run_hyperparameter_tuning_pipeline(X_train, y_train)
    
    # Step 7: Figures
    print("\n[7/9] Generating All 11 Publication-Quality Figures in results/figures/...")
    generate_all_figures()
    
    # Step 8: Tables
    print("\n[8/9] Compiling All 6 Research Tables in results/tables/...")
    generate_all_tables()
    
    # Step 9: Section 4 Report
    print("\n[9/9] Generating Section 4 (Results & Discussion) Draft...")
    generate_section4_report()
    
    elapsed = round(time.perf_counter() - start_total, 2)
    print("\n=================================================================")
    print(f"  ALL EXPERIMENTS COMPLETED SUCCESSFULLY IN {elapsed} SECONDS!  ")
    print("=================================================================")

if __name__ == "__main__":
    execute_complete_experimental_suite()
