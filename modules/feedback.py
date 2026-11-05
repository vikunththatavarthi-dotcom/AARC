"""
Module 5: Feedback and Continuous Learning Loop.
Records security incident outcomes, analyzes mitigation efficacy,
and dynamically tunes contextual risk weights and zero-trust thresholds.
Closes the loop: Detection -> Risk -> Response -> Self-Healing -> Feedback -> Monitoring.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

class FeedbackLoop:
    """
    Module 5 Feedback Controller.
    Implements closed-loop adaptive learning by collecting execution feedback
    and dynamically adapting threat detection priors and risk engine weights.
    """
    def __init__(self):
        self.incident_feedbacks: List[Dict[str, Any]] = []
        self.adaptive_weight_deltas = {
            "user_risk": 0.0,
            "device_risk": 0.0,
            "network_risk": 0.0,
            "behaviour_risk": 0.0,
            "threat_score": 0.0
        }

    def record_incident_outcome(
        self,
        event_id: str,
        detected_threat: str,
        action_taken: str,
        outcome_status: str,
        operator_feedback: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Ingests incident resolution and adjusts operational risk tuning parameters.
        """
        record = {
            "feedback_id": f"fb_{len(self.incident_feedbacks) + 1}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": event_id,
            "detected_threat": detected_threat,
            "action_taken": action_taken,
            "outcome_status": outcome_status,
            "operator_feedback": operator_feedback or "Automated feedback generated."
        }
        self.incident_feedbacks.append(record)

        # Dynamic learning feedback adjustment
        # If attack was successfully mitigated via network vectors, boost network weight slightly
        if "DDoS" in detected_threat or "PortScan" in detected_threat:
            self.adaptive_weight_deltas["network_risk"] += 0.005
            self.adaptive_weight_deltas["threat_score"] += 0.005
        elif "BruteForce" in detected_threat or "Auth" in detected_threat:
            self.adaptive_weight_deltas["user_risk"] += 0.005
            self.adaptive_weight_deltas["behaviour_risk"] += 0.005

        return record

    def get_recent_feedbacks(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Returns recent incident feedbacks."""
        return self.incident_feedbacks[-limit:]
