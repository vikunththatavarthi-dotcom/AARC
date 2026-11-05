"""
Module 4: Autonomous Response Engine.
Selects candidate defense actions, coordinates with the Safety Controller,
and dispatches simulated mitigation actions across cloud resources.
Maintains a human approval queue for high-impact interventions.
"""
import time
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from modules.safety_controller import SafetyController
import config

class AutonomousResponseEngine:
    """
    Module 4 Autonomous Response Dispatcher.
    Maps detected threats and risk levels to tactical countermeasures,
    submits them to safety verification, and executes or queues for approval.
    """
    def __init__(self, safety_controller: Optional[SafetyController] = None):
        self.safety_controller = safety_controller or SafetyController()
        self.action_history: List[Dict[str, Any]] = []
        self.pending_approvals: List[Dict[str, Any]] = []
        self.mitigation_stats = {
            "total_actions_proposed": 0,
            "auto_executed": 0,
            "constrained": 0,
            "pending_approval": 0,
            "approved_by_human": 0,
            "rejected_by_human": 0
        }

    def propose_action(self, threat_data: Dict[str, Any], risk_data: Dict[str, Any], event: Dict[str, Any]) -> str:
        """
        Determines candidate defense action based on threat vector, attack type, and target asset.
        """
        pred_class = threat_data.get("predicted_class", "Benign")
        attack_type = event.get("attack_type", "BENIGN")
        risk = risk_data.get("overall_risk", 0.0)
        
        if pred_class == "Benign" or risk < 0.30:
            return "NO_ACTION"
            
        if "DDoS" in attack_type or "SYN_Flood" in attack_type:
            return "BLOCK_IP" if risk > 0.85 else "RATE_LIMIT"
            
        if "BruteForce" in attack_type or "Auth" in attack_type:
            return "REVOKE_SESSION" if risk < 0.85 else "BLOCK_IP"
            
        if "Infiltration" in attack_type or "Compromise" in attack_type:
            return "ISOLATE_SERVICE" if risk >= 0.70 else "RESTRICT_API"
            
        if "SQLi" in attack_type or "Exfiltration" in attack_type:
            return "ISOLATE_SERVICE" if risk >= 0.80 else "RESTRICT_API"
            
        if risk >= 0.80:
            return "ISOLATE_SERVICE"
        elif risk >= 0.60:
            return "RESTRICT_API"
        else:
            return "RATE_LIMIT"

    def handle_threat(
        self,
        event: Dict[str, Any],
        threat_data: Dict[str, Any],
        risk_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Coordinates full Autonomous Response workflow:
        1. Propose Action -> 2. Safety Validation -> 3. Execute / Queue Approval
        """
        start_time = time.perf_counter()
        
        proposed = self.propose_action(threat_data, risk_data, event)
        if proposed == "NO_ACTION":
            return {
                "action": "NO_ACTION",
                "safety_status": "NOT_REQUIRED",
                "execution_status": "SKIPPED",
                "message": "Activity deemed safe; no automated intervention required."
            }

        self.mitigation_stats["total_actions_proposed"] += 1
        
        risk_score = risk_data.get("overall_risk", 0.5)
        threat_severity = threat_data.get("predicted_class", "Suspicious")
        confidence = threat_data.get("confidence", 0.9)
        target = event.get("target_service", event.get("src_ip", "cloud_resource"))

        # Safety Validation
        safety_eval = self.safety_controller.validate_action(
            proposed_action=proposed,
            risk_score=risk_score,
            threat_severity=threat_severity,
            model_confidence=confidence,
            target_entity=target
        )

        action_id = f"act_{uuid.uuid4().hex[:8]}"
        response_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        
        record = {
            "action_id": action_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": event.get("event_id", "unknown"),
            "target": target,
            "service_id": event.get("service_id", "svc-unknown"),
            "proposed_action": proposed,
            "final_action": safety_eval["proposed_action"],
            "safety_decision": safety_eval["safety_decision"],
            "executable_now": safety_eval["executable_now"],
            "safety_rationale": safety_eval["safety_rationale"],
            "risk_score": risk_score,
            "confidence": confidence,
            "response_time_ms": response_time_ms,
            "status": "COMPLETED" if safety_eval["executable_now"] else "PENDING_APPROVAL"
        }

        if safety_eval["safety_decision"] == "REQUIRE_HUMAN_APPROVAL":
            self.mitigation_stats["pending_approval"] += 1
            self.pending_approvals.append(record)
        elif safety_eval["safety_decision"] == "CONSTRAIN":
            self.mitigation_stats["constrained"] += 1
            self.action_history.append(record)
        elif safety_eval["safety_decision"] == "EXECUTE":
            self.mitigation_stats["auto_executed"] += 1
            self.action_history.append(record)
        else:
            self.action_history.append(record)

        return record

    def resolve_pending_approval(self, action_id: str, approved: bool, operator: str = "Cloud_Admin") -> Optional[Dict[str, Any]]:
        """
        Handles human-in-the-loop decision to approve or reject a high-impact queued response.
        """
        for i, item in enumerate(self.pending_approvals):
            if item["action_id"] == action_id:
                record = self.pending_approvals.pop(i)
                record["resolved_at"] = datetime.now(timezone.utc).isoformat()
                record["operator"] = operator
                
                if approved:
                    record["status"] = "APPROVED_AND_EXECUTED"
                    record["execution_result"] = f"Simulated action '{record['final_action']}' successfully applied to {record['target']}."
                    self.mitigation_stats["approved_by_human"] += 1
                else:
                    record["status"] = "REJECTED_BY_OPERATOR"
                    record["execution_result"] = "Action rejected by security operator. Standby posture maintained."
                    self.mitigation_stats["rejected_by_human"] += 1
                    
                self.action_history.append(record)
                return record
        return None

    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Returns currently queued human approval requests."""
        return self.pending_approvals

    def get_action_history(self, limit: int = 30) -> List[Dict[str, Any]]:
        """Returns recent response action audit logs."""
        return self.action_history[-limit:]
