import numpy as np
from modules.threat_detection import ThreatDetector
from modules.adaptive_policy import AdaptivePolicyEngine
from modules.risk_engine import DynamicRiskEngine
from modules.zero_trust import ZeroTrustController

def evaluate_fold(X_train, y_train, X_test, raw_test):
    detector = ThreatDetector()
    detector.train(X_train, y_train)

    probs = detector.rf_classifier.predict_proba(X_test)
    rf_pred = detector.rf_classifier.predict(X_test)

    anomaly = np.clip(
        0.5 - detector.isolation_forest.decision_function(X_test) / 2,
        0, 1
    )

    classes = list(detector.rf_classifier.classes_)
    attack_prob = probs[:, classes.index(1)]
    threat = np.clip(attack_prob + 0.10 * anomaly, 0, 1)

    policy = AdaptivePolicyEngine()
    risk_engine = DynamicRiskEngine()
    zero_trust = ZeroTrustController()

    predictions, risks, decisions, contexts = [], [], [], []

    for i in range(X_test.shape[0]):
        # Map actual ToN_IoT network telemetry.
        row = raw_test.iloc[i]
        event = {
            "flow_packets_per_sec": float(row["packets_per_sec"]),
            "flow_bytes_per_sec": float(row["bytes_per_sec"]),
            "data_transferred_mb": float(
                row["total_bytes"] / (1024.0 * 1024.0)
            ),
            "attack_type": "BENIGN"
        }

        threat_data = {
            "predicted_class": "Malicious" if rf_pred[i] == 1 else "Benign",
            "confidence": float(max(probs[i])),
            "threat_score": float(threat[i]),
            "anomaly_score": float(anomaly[i])
        }

        adapted = policy.adapt_policy({
            "event": event, "threat_data": threat_data
        })

        risk = risk_engine.assess_risk(
            event, threat_data["threat_score"],
            custom_weights=adapted["adaptive_weights"]
        )

        zt = zero_trust.evaluate_access(risk, event)
        decision = zt["access_decision"]

        # Binary mapping: restrictive decisions = attack.
        predictions.append(int(decision in {
            "RESTRICT", "ISOLATE", "BLOCK + RESPONSE"
        }))
        risks.append(risk["overall_risk"])
        decisions.append(decision)
        contexts.append(adapted["context_key"])

    risk_array = np.array(risks)

    print("\n--- AARC DIAGNOSTICS ---")
    print("Risk percentiles:",
          np.percentile(risk_array, [0, 25, 50, 75, 90, 95, 99, 100]))
    print("Adaptive contexts:")
    from collections import Counter
    print(Counter(contexts))
    print("Decisions:")
    print(Counter(decisions))
    print("Risk >= 0.30:", int((risk_array >= 0.30).sum()))
    print("Risk >= 0.60:", int((risk_array >= 0.60).sum()))
    print("Risk >= 0.80:", int((risk_array >= 0.80).sum()))

    return (
        np.array(predictions),
        risk_array,
        rf_pred,
        decisions,
        contexts
    )
