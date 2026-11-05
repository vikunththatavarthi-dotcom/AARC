# AARC: Adaptive Autonomous Resilient Cloud Security Model
## Research Prototype for *"Adaptive and Autonomous Cloud Architectures for Secure AI and Cyber Defense"*

[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Reproducibility: 100%](https://img.shields.io/badge/Reproducibility-100%25-brightgreen.svg)]()

A comprehensive, fully functional, and reproducible research-paper prototype implementing the **Adaptive Autonomous Resilient Cloud Security Model (AARC)**. The system models an adaptive closed-loop cyber defense architecture that unifies continuous monitoring, AI threat classification, dynamic contextual risk assessment, adaptive Zero-Trust authorization, safety-constrained autonomous countermeasures, automated self-healing, and continuous feedback.

---

## 1. Architectural Overview & Closed-Loop Workflow

```
Continuous Telemetry Monitoring (Module 1)
                  ↓
       AI Threat Detection (Module 2)
                  ↓
    Dynamic Risk Assessment (Module 3)
                  ↓
    Adaptive Zero-Trust Control (Module 3)
                  ↓
   Safety-Constrained Response (Module 4)
                  ↓
         Self-Healing (Module 5)
                  ↓
   Continuous Learning Feedback (Module 5)
                  ↺
```

### The Five Research Modules:
1. **Module 1 — Cloud Monitoring & Data Acquisition** (`modules/monitoring.py`, `modules/preprocessing.py`, `data/generate_dataset.py`):
   - Multi-tier simulated cloud telemetry ingestor (User IDs, IPs, Login attempts, Failed Logins, Request Rates, Data Volume, Session Duration, Device Trust Posture, CPU/RAM utilization).
   - Reusable Scikit-Learn preprocessing pipeline (`StandardScaler`, missing value imputation, categorical label encoding).
   - Supports switching between demo benchmark dataset and full CICIDS-2017 dataset (`data/cicids2017_full.csv`).
2. **Module 2 — AI-Based Threat Detection** (`modules/threat_detection.py`):
   - Primary Classifier: Supervised **Random Forest** (multi-class: Benign, Suspicious, Malicious).
   - Anomaly Detection: Unsupervised **Isolation Forest** (out-of-distribution & zero-day probe detector).
   - Outputs: Predicted class, prediction probability, continuous Threat Score $T \in [0.0, 1.0]$, and Anomaly Score.
   - Computes authentic evaluation metrics on held-out test data (Accuracy, Macro/Weighted Precision, Recall, F1, ROC-AUC, FPR, FNR, Confusion Matrix).
3. **Module 3 — Dynamic Risk Assessment & Zero-Trust Access Control** (`modules/risk_engine.py`, `modules/zero_trust.py`):
   - Dynamic Risk Formulation: $R = w_1 U + w_2 D + w_3 N + w_4 B + w_5 T$, where $\sum w_i = 1.0$.
   - Configurable initial weights: User Risk $w_1 = 0.15$, Device Risk $w_2 = 0.15$, Network Risk $w_3 = 0.20$, Behaviour Risk $w_4 = 0.20$, Threat Score $w_5 = 0.30$.
   - Dynamic Zero-Trust Authorization Policy Mapping:
     - `[0.00 – 0.30)` &rarr; **ALLOW**
     - `[0.30 – 0.60)` &rarr; **ALLOW + MONITOR**
     - `[0.60 – 0.80)` &rarr; **RESTRICT**
     - `[0.80 – 0.90)` &rarr; **ISOLATE**
     - `[0.90 – 1.00]` &rarr; **BLOCK + RESPONSE**
   - Context-dependent evaluation: The same user profile receives different access tiers depending on dynamic environment risk.
4. **Module 4 — Safety-Constrained Autonomous Response** (`modules/safety_controller.py`, `modules/response_engine.py`):
   - Response Action Catalogue: `BLOCK_IP`, `REVOKE_SESSION`, `REVOKE_ACCESS`, `RATE_LIMIT`, `RESTRICT_API`, `ISOLATE_SERVICE`, `ROLLBACK_DEPLOYMENT`, `RESTART_SERVICE`, `RESTORE_HEALTHY_INSTANCE`.
   - Safety Control Plane: Evaluates potential blast radius, reversibility, risk score, and model confidence to decide: `EXECUTE`, `CONSTRAIN`, `REQUIRE_HUMAN_APPROVAL`, or `DENY`.
   - Human-in-the-loop interactive authorization queue for high-impact interventions.
5. **Module 5 — Self-Healing, Explainability & Feedback** (`modules/self_healing.py`, `modules/explainability.py`, `modules/feedback.py`):
   - Self-Healing State Machine: Quarantine &rarr; Spawn Clean Replica &rarr; Ingress Switchover &rarr; Synthetic Health Verification &rarr; Production Restored. Tracks Mean Time to Recovery (MTTR).
   - Explainability: Local additive risk breakdown, feature attributions, and plain-English narrative summaries.
   - Feedback Loop: Ingests incident outcomes to adaptively tune risk weightings and threat priors.

---

## 2. Algorithms Implemented

### **Algorithm 1: Dynamic Risk-Based Access Control**
1. **Input**: User Profile, Device Posture, Network Telemetry, Runtime Behaviour, AI Threat Score ($T$).
2. **Process**:
   - Normalize contextual features into risk sub-components: User Risk ($U$), Device Risk ($D$), Network Risk ($N$), Behaviour Risk ($B$).
   - Compute overall composite risk $R = w_1 U + w_2 D + w_3 N + w_4 B + w_5 T$.
   - Evaluate $R$ against Zero-Trust policy thresholds.
   - Assign authorization tier (`ALLOW`, `MONITOR`, `RESTRICT`, `ISOLATE`, `BLOCK`).
3. **Output**: Access Decision, Enforced Restrictions, and Explainability Rationale.

### **Algorithm 2: Autonomous Threat Response and Self-Healing**
1. **Input**: Detected Threat Event, Risk Score ($R$), Model Confidence ($C$).
2. **Process**:
   - Propose candidate tactical mitigation action from catalogue.
   - Pass candidate to Safety Controller for blast radius and confidence validation.
   - If Safety Decision is `REQUIRE_HUMAN_APPROVAL`, queue in Operator Approval Plane; if `EXECUTE`/`CONSTRAIN`, dispatch simulated cloud action immediately.
   - If a cloud microservice was quarantined/isolated, initiate automated 5-phase recovery.
   - Run synthetic health probes and verify healthy restoration.
   - Record incident resolution in continuous Feedback Loop and adapt operational priors.
3. **Output**: Mitigation Audit Log, MTTC, MTTR, and Recovery Verification Status.

---

## Persistence Across Restarts

The dashboard persists the five demo users' editable security profiles and their latest
AARC evaluation state in `data/user_state.json`. The bounded telemetry event history is
stored in `data/telemetry_events.json`. These files are created automatically when the
app records changes and restored on the next start. Keep the `data/` folder writable by
the account running Flask and back it up if the demo state matters.

This is prototype persistence using local JSON files, not a multi-instance database.
For a multi-worker or production deployment, use a shared database and appropriate access
controls. AWS monitoring remains read-only and requires AWS credentials/permissions.

## 3. Quickstart & Startup Instructions

### Prerequisites
- Python 3.10+ (Tested on Python 3.13)
- pip package manager

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Full Experimental Suite (Reproduce Paper Results)
```bash
python experiments/run_all.py
```
*This command executes the end-to-end experimental framework: training the models, computing evaluation metrics, benchmarking baselines, running all 7 ablation studies, performing 5-fold cross-validated hyperparameter grid search, generating all 11 publication figures, and compiling all 6 research tables.*

### 3. Run Automated Tests
```bash
python -m pytest tests/test_pipeline.py -v
```

### 4. Start the Interactive Web Dashboard
```bash
python app.py
```
Open your browser and navigate to: **`http://127.0.0.1:5000`**

---

## 4. Interactive Research Scenarios

The web dashboard includes 5 1-click demonstration scenarios:
- **Scenario 1: Normal Enterprise User** &rarr; Low Risk ($R < 0.30$) &rarr; Access: `ALLOW`.
- **Scenario 2: Suspicious Activity & Auth Probes** &rarr; Medium Risk ($0.30 \le R < 0.60$) &rarr; Access: `ALLOW + MONITOR` / `RESTRICT`.
- **Scenario 3: Aggressive DDoS SYN Flood** &rarr; Critical Threat ($R > 0.85$) &rarr; Access: `BLOCK + RESPONSE` &rarr; Action: `BLOCK_IP` executed.
- **Scenario 4: Compromised Microservice Recovery** &rarr; Infiltration detected &rarr; Service Quarantined &rarr; Autonomous Golden Replica Provisioned &rarr; Health Verified ($MTTR = 1.42s$).
- **Scenario 5: High-Impact AI Action with Safety Gate** &rarr; AI proposes `ISOLATE_SERVICE` / `ROLLBACK` on database &rarr; Safety Controller detects High Blast Radius &rarr; Action intercepted &rarr; Dispatched to **Human-in-the-Loop Approval Queue**.

---

## 5. Experimental Results, Figures & Tables

All experimental data is generated from live script execution (no fabricated values).

### Generated Figures (`results/figures/`):
- `figure1_architecture.png`: Proposed AARC Closed-Loop Architecture Diagram.
- `fig1_accuracy_comparison.png`: Accuracy comparison between baselines (LR, DT, SVM) and Proposed AARC.
- `fig2_precision_comparison.png`: Precision comparison across all models.
- `fig3_recall_comparison.png`: Recall comparison across all models.
- `fig4_f1_comparison.png`: Macro F1-Score comparison.
- `fig5_confusion_matrix.png`: Multi-class Confusion Matrix for Proposed Model.
- `fig6_roc_curve.png`: Multi-Class ROC Curves (One-vs-Rest) with AUC.
- `fig7_fpr_comparison.png`: False Positive Rate comparison (Lower is better).
- `fig8_ablation_comparison.png`: Performance across 7 ablation configurations (Exp A to Exp G).
- `fig9_hyperparameter_sensitivity.png`: Validation F1 across `n_estimators` and `max_depth`.
- `fig10_response_time_comparison.png`: Inference latency per telemetry sample (ms).
- `fig11_self_healing_recovery.png`: Autonomous Self-Healing MTTR across cloud services.

### Generated Tables (`results/tables/` - CSV, Markdown & HTML):
- **Table 1**: `table1_dataset_statistics` (Sample counts, train/test split, feature dimensions).
- **Table 2**: `table2_proposed_model_performance` (Accuracy, Precision, Recall, F1, ROC-AUC, FPR, FNR).
- **Table 3**: `table3_proposed_vs_baselines` (Comparison vs Logistic Regression, Decision Tree, SVM).
- **Table 4**: `table4_ablation_study` (Empirical contribution of each architectural module).
- **Table 5**: `table5_hyperparameter_tuning` (5-Fold CV hyperparameter grid search results).
- **Table 6**: `table6_response_and_self_healing` (Containment actions, MTTR, and health verification).

### Section 4 Draft Report:
- `results/SECTION_4_RESULTS_AND_DISCUSSION.md`: Ready-to-use LaTeX/Markdown Results and Discussion section populated with exact experimental numbers.

---

## 6. Codebase Structure

```
CAD Prototype/
├── app.py                      # Flask REST API backend & dashboard server
├── config.py                   # Central configuration, seeds, weights, thresholds
├── requirements.txt            # Python dependencies
├── README.md                   # Complete research documentation
│
├── data/                       # Telemetry datasets
│   ├── generate_dataset.py     # Benchmark dataset generator & CICIDS-2017 loader
│   └── sample_data.csv         # Clearly labelled benchmark dataset
│
├── models/                     # Serialized model artifacts
│   ├── preprocessor.joblib     # Preprocessing pipeline
│   └── threat_detector.joblib  # Trained Random Forest & Isolation Forest
│
├── modules/                    # The Five Core Research Modules
│   ├── monitoring.py           # Module 1: Continuous telemetry generator & monitor
│   ├── preprocessing.py        # Module 1: Reusable Scikit-Learn data pipeline
│   ├── threat_detection.py     # Module 2: AI threat & anomaly detection engine
│   ├── risk_engine.py          # Module 3: Dynamic Risk Engine (Algorithm 1)
│   ├── zero_trust.py           # Module 3: Adaptive Zero-Trust Access Controller
│   ├── safety_controller.py    # Module 4: Safety Control Plane guardrails
│   ├── response_engine.py      # Module 4: Autonomous response & human approval
│   ├── self_healing.py         # Module 5: Self-healing lifecycle (Algorithm 2)
│   ├── explainability.py       # Module 5: Local & global explainability engine
│   └── feedback.py             # Module 5: Closed-loop learning feedback
│
├── experiments/                # Experimental Framework & Paper Evaluation
│   ├── train.py                # Model training script
│   ├── evaluate.py             # Test set evaluation
│   ├── baselines.py            # Baseline models comparison (LR, DT, SVM vs Proposed)
│   ├── ablation.py             # 7-configuration ablation studies
│   ├── hyperparameter_tuning.py# 5-fold cross-validated grid search
│   ├── visualize.py            # Generates all 11 publication figures
│   ├── tables.py               # Generates all 6 paper tables (CSV, MD, HTML)
│   ├── section4_generator.py   # Compiles Section 4 Results & Discussion draft
│   └── run_all.py              # Master automated experiment runner
│
├── results/                    # Saved experimental outputs
│   ├── figures/                # 11 300-DPI publication figures
│   ├── tables/                 # 6 research tables in CSV, MD, HTML
│   ├── metrics/                # Raw JSON evaluation metrics
│   └── SECTION_4_RESULTS_AND_DISCUSSION.md
│
├── frontend/                   # Interactive Dashboard UI
│   ├── templates/index.html    # Cyber defense command center
│   └── static/
│       ├── css/style.css       # Custom dark-theme styling
│       └── js/app.js           # Real-time charts, scenario traces & approval gates
│
└── tests/
    └── test_pipeline.py        # Unit and integration test suite
```

---

## 7. Research Simulation Disclaimer

This software is an academic research prototype developed for experimental evaluation and verification of the AARC model. Cloud infrastructure, telemetry streams, and mitigation actions are simulated within the prototype's bounded environment. It does not perform destructive changes to host operating systems or require physical AWS/GCP/Azure subscriptions.
