"""
Module 5: Explainability Engine.
Provides local feature attribution and global model explainability
for security analysts, operators, and paper discussion sections.
"""
from typing import Dict, Any, List
import numpy as np

class ExplainabilityEngine:
    """
    Module 5 Explainability Engine.
    Generates local feature importance breakdowns and natural language explanations
    for risk scores and threat classification decisions.
    """
    def __init__(self, feature_names: List[str] = None):
        self.feature_names = feature_names or [
            "flow_duration", "total_fwd_packets", "total_bwd_packets", "flow_bytes_per_sec",
            "flow_packets_per_sec", "packet_length_mean", "packet_length_std", "syn_flag_count",
            "ack_flag_count", "rst_flag_count", "login_attempts", "failed_logins",
            "request_frequency", "api_requests_count", "data_transferred_mb", "session_duration_sec",
            "device_trust_score", "cpu_usage_pct", "memory_usage_pct"
        ]

    def explain_decision(
        self,
        event: Dict[str, Any],
        threat_data: Dict[str, Any],
        risk_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Synthesizes model predictions, risk components, and raw telemetry to produce
        a structured local explanation and human-readable narrative.
        """
        overall_risk = risk_data.get("overall_risk", 0.0)
        risk_components = risk_data.get("components", {})
        predicted_class = threat_data.get("predicted_class", "Unknown")
        confidence = threat_data.get("confidence", 0.0)
        
        # Determine top risk drivers
        sorted_components = sorted(
            risk_components.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        contributors = []
        for name, score in sorted_components:
            clean_name = name.split(" ")[0].replace("_", " ").title()
            if score > 0.40:
                contributors.append(f"High {clean_name} (score: {score:.2f})")
            elif score > 0.20:
                contributors.append(f"Moderate {clean_name} (score: {score:.2f})")

        # Specific telemetry anomaly flags
        telemetry_flags = []
        if event.get("failed_logins", 0) > 2:
            telemetry_flags.append(f"Abnormal authentication: {event.get('failed_logins')} failed logins recorded")
        if event.get("request_frequency", 0) > 15:
            telemetry_flags.append(f"High request frequency: {event.get('request_frequency'):.1f} req/s")
        if event.get("syn_flag_count", 0) > 5:
            telemetry_flags.append(f"Suspicious network flags: {event.get('syn_flag_count')} SYN packets")
        if event.get("device_trust_score", 1.0) < 0.60:
            telemetry_flags.append(f"Low device posture trust: {event.get('device_trust_score'):.2f}")
        if event.get("cpu_usage_pct", 0) > 80:
            telemetry_flags.append(f"Compute resource spike: {event.get('cpu_usage_pct'):.1f}% CPU")

        # Formulate human-readable narrative
        summary = (
            f"Overall Risk Score is {overall_risk:.2f} ({risk_data.get('risk_level', 'UNKNOWN')}). "
            f"AI Threat Detector classified telemetry as '{predicted_class}' with {confidence*100:.1f}% confidence. "
        )
        if contributors:
            summary += "Primary risk contributors are: " + ", ".join(contributors[:3]) + ". "
        if telemetry_flags:
            summary += "Key telemetry indicators: " + "; ".join(telemetry_flags[:3]) + "."

        return {
            "overall_risk": overall_risk,
            "threat_class": predicted_class,
            "confidence": confidence,
            "top_contributors": contributors,
            "telemetry_flags": telemetry_flags,
            "narrative_explanation": summary
        }
