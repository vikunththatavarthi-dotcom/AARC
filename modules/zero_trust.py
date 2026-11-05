"""
Module 3: Adaptive Zero-Trust Access Control.
Enforces dynamic, continuous context-based access control decisions based on the risk score R.
Demonstrates context-adaptive authorization where identical credentials receive different access
postures depending on environmental and behavioral risk vectors.
"""
from typing import Dict, Any, Optional
import config

class ZeroTrustController:
    """
    Adaptive Zero-Trust Engine.
    Maps composite risk R to granular authorization policies:
    - ALLOW (0.00 - 0.30)
    - ALLOW + MONITOR (0.30 - 0.60)
    - RESTRICT (0.60 - 0.80)
    - ISOLATE (0.80 - 0.90)
    - BLOCK + RESPONSE (0.90 - 1.00)
    """
    def __init__(self, thresholds: Optional[Dict[str, tuple]] = None):
        self.thresholds = thresholds or config.RISK_THRESHOLDS.copy()

    def evaluate_access(self, risk_assessment: Dict[str, Any], user_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Evaluates risk score R against Zero-Trust policies and returns an actionable decision with explanation.
        """
        r = risk_assessment.get("overall_risk", 0.0)
        components = risk_assessment.get("components", {})
        
        # Determine Zero-Trust decision based on thresholds
        if r < 0.30:
            decision = "ALLOW"
            policy_action = "FULL_ACCESS"
            restrictions = []
            explanation = "Risk is within safe baseline. Full access granted to authorized cloud resources."
        elif r < 0.60:
            decision = "ALLOW + MONITOR"
            policy_action = "MONITORED_ACCESS"
            restrictions = ["Enable continuous telemetry logging", "Step-up MFA recommended for sensitive mutations"]
            explanation = "Moderate contextual risk detected. Access granted under enhanced session monitoring."
        elif r < 0.80:
            decision = "RESTRICT"
            policy_action = "RESTRICTED_ACCESS"
            restrictions = ["Enforce read-only permissions", "Rate-limit API requests to 5 req/s", "Disable admin endpoints"]
            explanation = "Elevated risk vectors identified. Privilege scoped down to least-privilege read-only mode."
        elif r < 0.90:
            decision = "ISOLATE"
            policy_action = "QUARANTINE_ACCESS"
            restrictions = ["Session quarantined in sandbox network", "Revoke microservice egress access", "Trigger live security alert"]
            explanation = "High risk threshold breached. Entity isolated from core cloud infrastructure."
        else:
            decision = "BLOCK + RESPONSE"
            policy_action = "IMMEDIATE_TERMINATION"
            restrictions = ["Terminate active token/session", "Block source IP at gateway firewall", "Trigger autonomous incident response"]
            explanation = "Critical threat detected. Access unconditionally blocked and autonomous countermeasures engaged."

        # Contextual explanation highlighting main contributing factor
        valid_components = {
            k: float(v) for k, v in components.items()
            if v is not None
        }
        top_factor = (
            max(valid_components.items(), key=lambda x: x[1])
            if valid_components else ("None", 0)
        )
        
        return {
            "access_decision": decision,
            "policy_action": policy_action,
            "risk_score": r,
            "risk_level": risk_assessment.get("risk_level", "UNKNOWN"),
            "restrictions": restrictions,
            "primary_driver": f"{top_factor[0]} (score: {top_factor[1]})",
            "explanation": explanation,
            "context_adaptive_audit": {
                "user_id": user_context.get("user_id", "anonymous") if user_context else "unknown",
                "role": user_context.get("role", "unknown") if user_context else "unknown",
                "evaluated_risk": r
            }
        }
