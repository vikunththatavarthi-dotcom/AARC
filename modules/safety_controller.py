"""
Module 4: Safety-Constrained Autonomous Response - Safety Control Plane.
Evaluates proposed automated countermeasure actions against safety guardrails,
potential cloud blast radius, model confidence, and policy constraints.
Enforces human-in-the-loop oversight for high-impact actions.
"""
from typing import Dict, Any, Optional
import config

class SafetyController:
    """
    Module 4 Safety Controller.
    Interposes between AI response propositions and the cloud infrastructure.
    Outputs:
    - EXECUTE: Safe, reversible, high-confidence automated action
    - CONSTRAIN: De-escalate to a lower-impact, bounded alternative
    - REQUIRE_HUMAN_APPROVAL: High-impact or critical blast-radius action requiring manual sign-off
    - DENY: Policy violation or unsafe operational state
    """
    def __init__(self, constraints: Optional[Dict[str, float]] = None):
        self.constraints = constraints or config.SAFETY_CONSTRAINTS.copy()
        self.action_catalog = config.ACTION_CATALOGUE

    def validate_action(
        self,
        proposed_action: str,
        risk_score: float,
        threat_severity: str,
        model_confidence: float,
        target_entity: str
    ) -> Dict[str, Any]:
        """
        Performs multi-criteria safety evaluation of a candidate response action.
        """
        action_meta = self.action_catalog.get(
            proposed_action,
            {"severity": "HIGH", "reversibility": "LOW", "impact": "HIGH", "requires_human_approval_default": True}
        )
        
        impact = action_meta["impact"]
        reversibility = action_meta["reversibility"]
        requires_approval_default = action_meta["requires_human_approval_default"]
        
        min_conf = self.constraints.get("min_confidence_for_auto_exec", 0.80)
        
        # Rule 1: High-impact or critical actions always require human approval
        if impact in ["HIGH", "CRITICAL"] or requires_approval_default:
            safety_decision = "REQUIRE_HUMAN_APPROVAL"
            safety_rationale = (
                f"Action '{proposed_action}' on target '{target_entity}' has {impact} operational impact. "
                "Safety policy mandates human-in-the-loop authorization before execution."
            )
            executable_now = False

        # Rule 2: Low model confidence on high/medium risk -> De-escalate / Constrain
        elif model_confidence < min_conf:
            safety_decision = "CONSTRAIN"
            safety_rationale = (
                f"Model confidence ({model_confidence:.2f}) is below safe execution threshold ({min_conf:.2f}). "
                "De-escalating to non-destructive rate-limiting and enhanced telemetry logging."
            )
            executable_now = True
            # Constrain to safer alternative
            proposed_action = "RATE_LIMIT"

        # Rule 3: Low or Medium impact reversible actions with high confidence -> Auto Execute
        elif risk_score >= 0.60 and model_confidence >= min_conf:
            safety_decision = "EXECUTE"
            safety_rationale = (
                f"Action '{proposed_action}' is reversible ({reversibility}), has acceptable impact ({impact}), "
                f"and model confidence ({model_confidence:.2f}) satisfies autonomous safety guardrails."
            )
            executable_now = True

        else:
            safety_decision = "DENY"
            safety_rationale = "Risk score does not warrant destructive automated intervention."
            executable_now = False

        return {
            "proposed_action": proposed_action,
            "safety_decision": safety_decision,
            "executable_now": executable_now,
            "action_metadata": action_meta,
            "evaluated_impact": impact,
            "evaluated_reversibility": reversibility,
            "confidence_checked": model_confidence,
            "safety_rationale": safety_rationale
        }
