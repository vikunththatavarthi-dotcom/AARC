"""
Configuration module for the AARC (Adaptive Autonomous Resilient Cloud Security Model) Research Prototype.
Contains model parameters, risk weights, decision thresholds, safety policies, and system paths.
"""
import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
RESULTS_DIR = BASE_DIR / "results"
FIGURES_DIR = RESULTS_DIR / "figures"
TABLES_DIR = RESULTS_DIR / "tables"
METRICS_DIR = RESULTS_DIR / "metrics"

# Ensure all directories exist
for d in [DATA_DIR, MODELS_DIR, RESULTS_DIR, FIGURES_DIR, TABLES_DIR, METRICS_DIR]:
    os.makedirs(d, exist_ok=True)

# Datasets
SAMPLE_DATA_PATH = DATA_DIR / "sample_data.csv"
FULL_DATA_PATH = DATA_DIR / "cicids2017_full.csv"

# Global Reproducibility Settings
RANDOM_SEED = 42
TEST_SPLIT_RATIO = 0.20
CV_FOLDS = 5

# Feature Scheme definition matching CICIDS-2017 style cloud telemetry
FEATURE_COLUMNS = [
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "packet_length_mean",
    "packet_length_std",
    "syn_flag_count",
    "ack_flag_count",
    "rst_flag_count",
    "login_attempts",
    "failed_logins",
    "request_frequency",
    "api_requests_count",
    "data_transferred_mb",
    "session_duration_sec",
    "device_trust_score",
    "cpu_usage_pct",
    "memory_usage_pct"
]

TARGET_COLUMN = "threat_category"
ATTACK_TYPE_COLUMN = "attack_type"

# Threat Categories for Multiclass & Binary Classification
CLASSES = ["Benign", "Suspicious", "Malicious"]

# Module 3: Dynamic Risk Assessment Formulation Parameters
# Formula: R = w1*U + w2*D + w3*N + w4*B + w5*T, sum(w) = 1.0
DEFAULT_RISK_WEIGHTS = {
    "user_risk": 0.15,       # w1 (U)
    "device_risk": 0.15,     # w2 (D)
    "network_risk": 0.20,    # w3 (N)
    "behaviour_risk": 0.20,  # w4 (B)
    "threat_score": 0.30     # w5 (T)
}

# Dynamic Risk Thresholds (Configurable)
RISK_THRESHOLDS = {
    "ALLOW": (0.00, 0.30),
    "ALLOW_MONITOR": (0.30, 0.60),
    "RESTRICT": (0.60, 0.80),
    "ISOLATE": (0.80, 0.90),
    "BLOCK_RESPONSE": (0.90, 1.00)
}

# Module 4: Response Actions & Safety Evaluation Policies
ACTION_CATALOGUE = {
    "BLOCK_IP": {
        "severity": "HIGH",
        "reversibility": "HIGH",
        "impact": "MEDIUM",
        "requires_human_approval_default": False
    },
    "REVOKE_SESSION": {
        "severity": "MEDIUM",
        "reversibility": "HIGH",
        "impact": "LOW",
        "requires_human_approval_default": False
    },
    "REVOKE_ACCESS": {
        "severity": "HIGH",
        "reversibility": "HIGH",
        "impact": "MEDIUM",
        "requires_human_approval_default": False
    },
    "RATE_LIMIT": {
        "severity": "LOW",
        "reversibility": "HIGH",
        "impact": "LOW",
        "requires_human_approval_default": False
    },
    "RESTRICT_API": {
        "severity": "MEDIUM",
        "reversibility": "HIGH",
        "impact": "MEDIUM",
        "requires_human_approval_default": False
    },
    "ISOLATE_SERVICE": {
        "severity": "CRITICAL",
        "reversibility": "MEDIUM",
        "impact": "HIGH",
        "requires_human_approval_default": True
    },
    "ROLLBACK_DEPLOYMENT": {
        "severity": "CRITICAL",
        "reversibility": "LOW",
        "impact": "CRITICAL",
        "requires_human_approval_default": True
    },
    "RESTART_SERVICE": {
        "severity": "MEDIUM",
        "reversibility": "HIGH",
        "impact": "MEDIUM",
        "requires_human_approval_default": False
    },
    "RESTORE_HEALTHY_INSTANCE": {
        "severity": "HIGH",
        "reversibility": "HIGH",
        "impact": "HIGH",
        "requires_human_approval_default": True
    }
}

# Safety Controller Constraints
SAFETY_CONSTRAINTS = {
    "high_impact_threshold": 0.75,       # Actions on critical infra require validation
    "min_confidence_for_auto_exec": 0.80 # ML confidence below this demands human-in-the-loop or constraint
}

# Hyperparameter Tuning Grid for Random Forest
RF_PARAM_GRID = {
    "n_estimators": [50, 100, 150],
    "max_depth": [10, 20, None],
    "min_samples_split": [2, 5],
    "min_samples_leaf": [1, 2],
    "max_features": ["sqrt", "log2"]
}

# Server Config
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5000
DEBUG = False
