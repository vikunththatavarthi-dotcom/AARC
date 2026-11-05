"""
Module 3: Dynamic Risk Assessment Engine.
Calculates multi-dimensional contextual security risk using the weighted formulation:
R = w1*U + w2*D + w3*N + w4*B + w5*T
where sum(w_i) = 1.0.
"""
import numpy as np
from typing import Dict, Any, Optional
import config

class DynamicRiskEngine:
    """
    Module 3 Dynamic Risk Engine implementing Algorithm 1.
    Evaluates User Risk (U), Device Risk (D), Network Risk (N), Behaviour Risk (B),
    and AI Threat Score (T) to generate a composite risk metric R in [0.0, 1.0].
    """
    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = weights or config.DEFAULT_RISK_WEIGHTS.copy()
        self._validate_weights()

    def _validate_weights(self) -> None:
        """Validates that weights sum to approximately 1.0."""
        total = sum(self.weights.values())
        if not np.isclose(total, 1.0, atol=1e-3):
            # Normalize automatically
            for k in self.weights:
                self.weights[k] = self.weights[k] / total

    def update_weights(self, new_weights: Dict[str, float]) -> None:
        """Dynamically updates risk weights."""
        self.weights.update(new_weights)
        self._validate_weights()

    def compute_user_risk(self, event: Dict[str, Any]) -> Optional[float]:
        values = []
        weights = []

        failed = event.get("failed_logins")
        attempts = event.get("login_attempts")

        if failed is not None and attempts is not None and attempts > 0:
            values.append(min(1.0, failed / attempts))
            weights.append(0.60)

        if failed is not None:
            values.append(min(1.0, failed / 10.0))
            weights.append(0.30)

        role = event.get("role")
        if role is not None:
            values.append(0.05 if role in ["Developer", "Cloud Admin"] else 0.25)
            weights.append(0.10)

        if not values:
            return None

        return float(np.clip(
            sum(v * w for v, w in zip(values, weights)) / sum(weights),
            0.0, 1.0
        ))

    def compute_device_risk(self, event: Dict[str, Any]) -> Optional[float]:
        trust = event.get("device_trust_score")

        if trust is None:
            return None

        return float(np.clip(1.0 - float(trust), 0.0, 1.0))

    def compute_network_risk(self, event: Dict[str, Any]) -> Optional[float]:
        values = []
        weights = []

        fields = [
            ("syn_flag_count", 20.0, 0.40),
            ("rst_flag_count", 10.0, 0.20),
            ("flow_packets_per_sec", 150.0, 0.25),
            ("flow_bytes_per_sec", 80000.0, 0.15)
        ]

        for key, limit, weight in fields:
            value = event.get(key)
            if value is not None:
                values.append(min(1.0, max(0.0, float(value) / limit)))
                weights.append(weight)

        if not values:
            return None

        return float(np.clip(
            sum(v * w for v, w in zip(values, weights)) / sum(weights),
            0.0, 1.0
        ))

    def compute_behaviour_risk(self, event: Dict[str, Any]) -> Optional[float]:
        values = []
        weights = []

        fields = [
            ("request_frequency", 40.0, 0.35),
            ("api_requests_count", 100.0, 0.35)
        ]

        for key, limit, weight in fields:
            value = event.get(key)
            if value is not None:
                values.append(min(1.0, max(0.0, float(value) / limit)))
                weights.append(weight)

        if event.get("cpu_usage_pct") is not None:
            values.append(float(np.clip(
                (float(event["cpu_usage_pct"]) - 50.0) / 50.0, 0.0, 1.0
            )))
            weights.append(0.15)

        if event.get("memory_usage_pct") is not None:
            values.append(float(np.clip(
                (float(event["memory_usage_pct"]) - 60.0) / 40.0, 0.0, 1.0
            )))
            weights.append(0.15)

        if not values:
            return None

        return float(np.clip(
            sum(v * w for v, w in zip(values, weights)) / sum(weights),
            0.0, 1.0
        ))

    def assess_risk(self, event: Dict[str, Any], threat_score: float,
                    custom_weights: Optional[Dict[str, float]] = None) -> Dict[str, Any]:

        raw = {
            "user_risk": self.compute_user_risk(event),
            "device_risk": self.compute_device_risk(event),
            "network_risk": self.compute_network_risk(event),
            "behaviour_risk": self.compute_behaviour_risk(event),
            "threat_score": float(np.clip(threat_score, 0.0, 1.0))
        }

        base = custom_weights or self.weights
        active = {k: v for k, v in raw.items() if v is not None}
        total = sum(base[k] for k in active)

        if not active or total <= 0:
            raise ValueError("No valid risk signals available.")

        w = {k: base[k] / total for k in active}
        risk = float(np.clip(sum(w[k] * active[k] for k in active), 0, 1))

        if risk < 0.30:
            level = "LOW"
        elif risk < 0.60:
            level = "MEDIUM"
        elif risk < 0.80:
            level = "HIGH"
        else:
            level = "CRITICAL"

        labels = {
            "user_risk": ("User Risk (U)", "U"),
            "device_risk": ("Device Risk (D)", "D"),
            "network_risk": ("Network Risk (N)", "N"),
            "behaviour_risk": ("Behaviour Risk (B)", "B"),
            "threat_score": ("Threat Score (T)", "T")
        }

        contributions = {
            k: round(w[k] * active[k], 4) for k in active
        }

        table = []
        for k, (name, symbol) in labels.items():
            value = raw[k]
            weight = w.get(k, 0.0)
            table.append({
                "key": k,
                "name": name,
                "symbol": symbol,
                "value": round(value, 4) if value is not None else None,
                "weight": round(weight, 4),
                "weight_pct": f"{int(round(weight * 100))}%",
                "contribution": contributions.get(k, 0.0)
            })

        return {
            "overall_risk": round(risk, 4),
            "risk_level": level,
            "components": {
                labels[k][0]: round(v, 4) if v is not None else None
                for k, v in raw.items()
            },
            "raw_components": {
                k: round(v, 4) if v is not None else None
                for k, v in raw.items()
            },
            "weights": {k: round(v, 4) for k, v in w.items()},
            "contributions": contributions,
            "component_table": table,
            "formula": "R = " + " + ".join(
                f"{w[k]:.2f}*{labels[k][1]}" for k in active
            )
        }
