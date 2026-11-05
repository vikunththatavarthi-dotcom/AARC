### Table 3: Comparative Evaluation

| Model Architecture                                         | Accuracy (%)   | Precision (%)   | Recall (%)   | F1-Score (%)   |   ROC-AUC | FPR (%)   | Latency (ms)    |
|:-----------------------------------------------------------|:---------------|:----------------|:-------------|:---------------|----------:|:----------|:----------------|
| Baseline 1: Logistic Regression                            | 100.00%        | 100.00%         | 100.00%      | 100.00%        |    1      | 0.00%     | 0.0             |
| Baseline 2: Decision Tree                                  | 99.90%         | 99.83%          | 99.83%       | 99.83%         |    0.999  | 0.00%     | 0.0             |
| Baseline 3: Support Vector Machine (SVM)                   | 100.00%        | 100.00%         | 100.00%      | 100.00%        |    1      | 0.00%     | 0.01            |
| Proposed: AARC (Random Forest + Dynamic Risk + Zero-Trust) | 100.00%        | 100.00%         | 100.00%      | 100.00%        |    1      | 0.00%     | 0.027           |
| External ToN_IoT: Random Forest (Host-Grouped OOF)         | 96.46%         | 97.01%          | 92.92%       | 94.77%         |    0.9883 | 13.61%    | N/A (5-fold CV) |