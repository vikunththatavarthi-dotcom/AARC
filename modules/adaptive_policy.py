"""
Module 3 / Extension: Adaptive Policy Engine for Dynamic Risk Weighting.
Observes the runtime security context (telemetry, threat predictions, anomaly scores,
and individual risk signals) and automatically adjusts the dynamic risk weights:
R = w_U*U + w_D*D + w_N*N + w_B*B + w_T*T, where sum(w_i) = 1.0.

Provides deterministic, explainable, and mathematically verified weight adaptations
for live academic demonstrations and peer-reviewed cyber defense architectures.
"""
from typing import Dict, Any, List, Optional
import numpy as np
import config

class AdaptivePolicyEngine:
    """
    Deterministic Adaptive Policy Engine.
    Maps observed security context to optimal risk weighting vectors.
    """
    def __init__(self, baseline_weights: Optional[Dict[str, float]] = None):
        self.baseline_weights = baseline_weights or config.DEFAULT_RISK_WEIGHTS.copy()
        self.current_weights = self.baseline_weights.copy()
        self.last_adaptation: Optional[Dict[str, Any]] = None

    def adapt_policy(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates security context and produces adapted risk weights, detected factors,
        and an explainable rationale.

        Context dictionary can contain:
        - raw_event / telemetry features: failed_logins, login_attempts, syn_flag_count,
          flow_packets_per_sec, flow_bytes_per_sec, request_frequency, api_requests_count,
          data_transferred_mb, device_trust_score, cpu_usage_pct, attack_type
        - risk components: user_risk (U), device_risk (D), network_risk (N), behaviour_risk (B)
        - threat detection: threat_score (T), anomaly_score, predicted_class, confidence
        """
        event = context.get("event", {})
        threat = context.get("threat_data", {})
        components = context.get("risk_components", {})

        # Extract primary signals
        failed_logins = event.get("failed_logins")
        login_attempts = event.get("login_attempts")
        syn_flags = event.get("syn_flag_count")
        pkts_per_sec = event.get("flow_packets_per_sec")
        bytes_per_sec = event.get("flow_bytes_per_sec")
        req_freq = event.get("request_frequency")
        api_count = event.get("api_requests_count")
        data_mb = event.get("data_transferred_mb")
        dev_trust = event.get("device_trust_score")
        cpu_pct = event.get("cpu_usage_pct")
        attack_type = event.get("attack_type", "BENIGN")

        threat_score = threat.get("threat_score", 0.0)
        anomaly_score = threat.get("anomaly_score", 0.0)
        pred_class = threat.get("predicted_class", "Benign")

        # Context Classification & Deterministic Weight Target Selection
        target_weights = self.baseline_weights.copy()
        context_key = "NORMAL_BASELINE"
        context_name = "Normal Enterprise Activity"
        triggering_factors: List[str] = []
        adaptation_reason = ""

        # Check Attack / Vector Signatures
        is_ddos = (
            (syn_flags is not None and syn_flags >= 20) or
            (pkts_per_sec is not None and pkts_per_sec >= 150.0) or
            "DDoS" in attack_type or "SYN_Flood" in attack_type
        )

        is_auth_attack = (
            (failed_logins is not None and failed_logins >= 3) or
            (login_attempts is not None and failed_logins is not None
             and login_attempts >= 3
             and failed_logins / max(1, login_attempts) >= 0.4) or
            "BruteForce" in attack_type or "Auth" in attack_type
        )

        is_data_exfil = (
            (data_mb is not None and data_mb >= 40.0) or
            (api_count is not None and api_count >= 80) or
            "SQLi" in attack_type or "Exfiltration" in attack_type
        )

        is_untrusted_device = (
            dev_trust is not None and dev_trust < 0.60
        )

        is_service_infiltration = (
            (cpu_pct is not None and req_freq is not None
             and cpu_pct >= 85.0 and req_freq >= 30.0) or
            "Infiltration" in attack_type or "Compromise" in attack_type
        )

        # Priority Cascade for Dominant Security Context
        if is_ddos and (threat_score >= 0.35 or (syn_flags is not None and syn_flags >= 20)):
            context_key = "DDOS_NETWORK_FLOOD"
            context_name = "Distributed Denial of Service (DDoS) / SYN Flood"
            target_weights = {
                "user_risk": 0.05,
                "device_risk": 0.05,
                "network_risk": 0.40,
                "behaviour_risk": 0.15,
                "threat_score": 0.35
            }
            if syn_flags is not None and syn_flags >= 5:
                triggering_factors.append(f"Abnormal SYN flag count detected ({syn_flags} SYN packets)")
            if pkts_per_sec is not None and pkts_per_sec >= 50:
                triggering_factors.append(f"Volumetric packet flow surge ({pkts_per_sec:.1f} pkts/s)")
            if threat_score >= 0.40:
                triggering_factors.append(f"AI Threat Detector computed elevated Threat Score ({threat_score:.2f})")
            if anomaly_score >= 0.40:
                triggering_factors.append(f"Isolation Forest marked high anomaly score ({anomaly_score:.2f})")
            adaptation_reason = (
                "Network and threat components were given dominant weighting (40% Network, 35% Threat) "
                "because the available telemetry indicates elevated network activity or SYN anomalies."
            )

        elif is_data_exfil and (threat_score >= 0.30 or (data_mb is not None and data_mb >= 50.0)):
            context_key = "DATA_EXFILTRATION_SQLI"
            context_name = "Data Exfiltration / API Abuse / SQL Injection"
            target_weights = {
                "user_risk": 0.05,
                "device_risk": 0.05,
                "network_risk": 0.15,
                "behaviour_risk": 0.40,
                "threat_score": 0.35
            }
            if data_mb is not None and data_mb >= 30:
                triggering_factors.append(f"Unusual data egress volume ({data_mb:.1f} MB transferred)")
            if api_count is not None and api_count >= 40:
                triggering_factors.append(f"Surge in API endpoint mutations ({api_count} requests)")
            if cpu_pct is not None and cpu_pct >= 70:
                triggering_factors.append(f"Elevated database/compute utilization ({cpu_pct:.1f}% CPU)")
            adaptation_reason = (
                "Behavioural Risk (40%) and Threat Score (35%) were prioritized to capture "
                "the available behavioural telemetry and potential data egress anomalies."
            )

        elif is_auth_attack and (threat_score >= 0.25 or (failed_logins is not None and failed_logins >= 3)):
            context_key = "AUTH_BRUTE_FORCE"
            context_name = "Authentication Attack / Credential Probing"
            target_weights = {
                "user_risk": 0.30,
                "device_risk": 0.05,
                "network_risk": 0.10,
                "behaviour_risk": 0.25,
                "threat_score": 0.30
            }
            if failed_logins is not None:
                triggering_factors.append(f"High failed login attempts recorded ({failed_logins} failed)")
            if login_attempts is not None and failed_logins is not None and login_attempts > 1:
                fail_pct = int((failed_logins / login_attempts) * 100)
                triggering_factors.append(f"Severe authentication failure ratio ({fail_pct}% failed)")
            if req_freq is not None and req_freq >= 8:
                triggering_factors.append(f"Elevated authentication probe rate ({req_freq:.1f} req/s)")
            adaptation_reason = (
                "User and Behaviour components were boosted (30% User, 25% Behaviour) to emphasize "
                "credential anomaly vectors and repeated authentication failure patterns."
            )

        elif is_service_infiltration and (threat_score >= 0.35 or (cpu_pct is not None and cpu_pct >= 90.0)):
            context_key = "SERVICE_INFILTRATION"
            context_name = "Microservice Infiltration / Lateral Movement"
            target_weights = {
                "user_risk": 0.05,
                "device_risk": 0.10,
                "network_risk": 0.15,
                "behaviour_risk": 0.35,
                "threat_score": 0.35
            }
            if cpu_pct is not None:
                triggering_factors.append(f"Severe compute resource saturation ({cpu_pct:.1f}% CPU)")
            if req_freq is not None:
                triggering_factors.append(f"Bursty inter-service request rate ({req_freq:.1f} req/s)")
            adaptation_reason = (
                "Behavioural and Threat components were boosted (35% Behaviour, 35% Threat) "
                "to isolate internal microservice compromise and prevent lateral movement."
            )

        elif is_untrusted_device:
            context_key = "COMPROMISED_DEVICE"
            context_name = "Compromised / Untrusted Device Posture"
            target_weights = {
                "user_risk": 0.15,
                "device_risk": 0.35,
                "network_risk": 0.10,
                "behaviour_risk": 0.10,
                "threat_score": 0.30
            }
            triggering_factors.append(f"Device trust posture degraded to {dev_trust:.2f} (baseline >= 0.85)")
            triggering_factors.append("Unverified client endpoint integrity and high risk of session hijacking")
            adaptation_reason = (
                "Device Risk weight was elevated to 35% because the connecting endpoint failed "
                "device posture verification, escalating client-side compromise probability."
            )

        else:
            context_key = "NORMAL_BASELINE"
            context_name = "Normal Enterprise Activity"
            target_weights = self.baseline_weights.copy()
            triggering_factors = [
                "No specialized attack context was established from available telemetry"
            ]
            if dev_trust is not None:
                triggering_factors.append(f"Device trust score ({dev_trust:.2f})")
            if failed_logins is not None and login_attempts is not None:
                triggering_factors.append(
                    f"Authentication telemetry ({failed_logins} failures / {login_attempts} attempts)"
                )
            adaptation_reason = (
                "Standard operational baseline: Baseline weighting applied across the configured risk dimensions, "
                "behavioural posture, and threat priors."
            )

        # Ensure exact sum to 1.0
        total = sum(target_weights.values())
        if not np.isclose(total, 1.0, atol=1e-4):
            for k in target_weights:
                target_weights[k] = round(target_weights[k] / total, 4)

        # Build comparison transitions (baseline -> adaptive)
        weight_transitions = {}
        for key in self.baseline_weights:
            base_val = self.baseline_weights[key]
            new_val = target_weights[key]
            delta = round(new_val - base_val, 4)
            weight_transitions[key] = {
                "baseline": round(base_val, 4),
                "adaptive": round(new_val, 4),
                "delta": delta,
                "percentage_baseline": f"{int(round(base_val * 100))}%",
                "percentage_adaptive": f"{int(round(new_val * 100))}%",
                "direction": "INCREASED" if delta > 0.001 else ("DECREASED" if delta < -0.001 else "UNCHANGED")
            }

        self.current_weights = target_weights.copy()

        result = {
            "context_key": context_key,
            "context_name": context_name,
            "baseline_weights": self.baseline_weights.copy(),
            "adaptive_weights": target_weights.copy(),
            "weight_transitions": weight_transitions,
            "triggering_factors": triggering_factors,
            "adaptation_reason": adaptation_reason,
            "is_adapted": context_key != "NORMAL_BASELINE"
        }

        self.last_adaptation = result
        return result
