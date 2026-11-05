import json
import shutil
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
METRICS = ROOT / "experiments/ton_iot/hostcv_metrics_rerun_20261105.json"
TABLE = ROOT / "results/tables/table3_proposed_vs_baselines.csv"
FIGURES = ROOT / "results/figures"

with open(METRICS) as f:
    report = json.load(f)

models = report["models"]

names = {
    "logistic_regression": "Logistic Regression",
    "decision_tree": "Decision Tree",
    "linear_svm": "Linear SVM",
    "random_forest": "Random Forest"
}

# Extract pooled out-of-fold metrics
data = {}
for key, name in names.items():
    data[name] = models[key]["pooled_out_of_fold_metrics"]

# ------------------------------------------------
# ADD EXTERNAL RANDOM FOREST ROW TO TABLE 3
# ------------------------------------------------
rf = models["random_forest"]

row = {
    "Model Architecture": "External ToN_IoT: Random Forest (Host-Grouped OOF)",
    "Accuracy (%)": f"{data['Random Forest']['accuracy']*100:.2f}%",
    "Precision (%)": f"{data['Random Forest']['precision_macro']*100:.2f}%",
    "Recall (%)": f"{data['Random Forest']['recall_macro']*100:.2f}%",
    "F1-Score (%)": f"{data['Random Forest']['f1_macro']*100:.2f}%",
    "ROC-AUC": f"{rf['mean_fold_metrics']['roc_auc']:.4f}",
    "FPR (%)": f"{data['Random Forest']['false_positive_rate']*100:.2f}%",
    "Latency (ms)": "N/A (5-fold CV)"
}

df = pd.read_csv(TABLE)

if row["Model Architecture"] not in df["Model Architecture"].values:
    shutil.copy2(TABLE, TABLE.with_suffix(".backup.csv"))
    df = pd.concat([df, pd.DataFrame([row])], ignore_index=True)

df.to_csv(TABLE, index=False)

# Update Markdown and HTML versions
md = ["### Table 3: Comparative Evaluation\n"]
md.append(df.to_markdown(index=False))
(TABLE.with_suffix(".md")).write_text("\n".join(md), encoding="utf-8")

(TABLE.with_suffix(".html")).write_text(
    "<h4>Table 3: Comparative Evaluation</h4>\n"
    + df.to_html(index=False, classes="table table-striped table-bordered"),
    encoding="utf-8"
)

print("[Table] External validation row added.")

# ------------------------------------------------
# PREPARE GRAPH DATA
# ------------------------------------------------
labels = list(data.keys())
colors = ["#4472C4", "#ED7D31", "#70AD47", "#A5A5A5"]

FIGURES.mkdir(parents=True, exist_ok=True)

def save_graph(filename):
    plt.tight_layout()
    plt.savefig(FIGURES / filename, dpi=300, bbox_inches="tight")
    plt.close()
    print("[Figure] Saved:", filename)

# FIGURE 12: Classification Performance
metrics = ["accuracy", "precision_macro", "recall_macro", "f1_macro"]
metric_labels = ["Accuracy", "Precision", "Recall", "F1-Score"]

x = np.arange(len(labels))
width = 0.19

plt.figure(figsize=(11, 6))

for i, (metric, label) in enumerate(zip(metrics, metric_labels)):
    values = [data[name][metric] * 100 for name in labels]
    plt.bar(x + (i - 1.5) * width, values, width, label=label)

plt.xticks(x, labels, rotation=12)
plt.ylabel("Score (%)")
plt.ylim(0, 105)
plt.title("Figure 12: ToN_IoT Classification Performance")
plt.legend()
save_graph("fig12_toniot_performance.png")

# FIGURE 13: Error Rates
plt.figure(figsize=(9, 5))

fpr = [data[n]["false_positive_rate"] * 100 for n in labels]
fnr = [data[n]["false_negative_rate"] * 100 for n in labels]

x = np.arange(len(labels))
width = 0.35

plt.bar(x - width/2, fpr, width, label="False Positive Rate")
plt.bar(x + width/2, fnr, width, label="False Negative Rate")

plt.xticks(x, labels, rotation=12)
plt.ylabel("Rate (%)")
plt.title("Figure 13: ToN_IoT False Positive and False Negative Rates")
plt.legend()
save_graph("fig13_toniot_error_rates.png")

# FIGURE 14: ROC-AUC
auc_values = [
    models[key]["mean_fold_metrics"]["roc_auc"] * 100
    for key in names
]

plt.figure(figsize=(9, 5))
bars = plt.bar(labels, auc_values, color=colors, edgecolor="black")

plt.ylabel("ROC-AUC (%)")
plt.ylim(0, 105)
plt.title("Figure 14: ToN_IoT Mean-Fold ROC-AUC Comparison")
plt.xticks(rotation=12)

for bar in bars:
    plt.text(
        bar.get_x() + bar.get_width()/2,
        bar.get_height() + 0.5,
        f"{bar.get_height():.2f}%",
        ha="center"
    )

save_graph("fig14_toniot_roc_auc.png")

print("\nExternal evaluation additions completed successfully.")
