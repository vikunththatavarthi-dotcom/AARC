### Table 5: Random Forest 5-Fold Cross-Validation Hyperparameter Tuning

| Hyperparameter    | Search Space / Grid Values   | Optimal Value Found   |   Validation Score (F1 Macro) |
|:------------------|:-----------------------------|:----------------------|------------------------------:|
| n_estimators      | [50, 100, 150]               | 50                    |                             1 |
| max_depth         | [10, 20, 30]                 | 10                    |                             1 |
| min_samples_split | [2, 5]                       | 2                     |                             1 |
| min_samples_leaf  | [1, 2]                       | 1                     |                             1 |
| max_features      | ['sqrt', 'log2']             | sqrt                  |                             1 |
