"""
Automated Test Suite for AARC Research Prototype.
Verifies all 5 modules, all 5 demonstration scenarios, algorithm formulations,
and experimental metrics pipelines.
"""
import pytest
import numpy as np
import pandas as pd
from pathlib import Path
import config
from data.generate_dataset import generate_synthetic_benchmark_dataset, load_dataset
from modules.preprocessing import DataPreprocessor
from modules.threat_detection import ThreatDetector
from modules.risk_engine import DynamicRiskEngine
from modules.zero_trust import ZeroTrustController
from modules.safety_controller import SafetyController
from modules.response_engine import AutonomousResponseEngine
from modules.self_healing import SelfHealingEngine
from modules.explainability import ExplainabilityEngine
from modules.feedback import FeedbackLoop

class TestAARCPipeline:
    
    @classmethod
    def setup_class(cls):
        """Generates dataset and fits models for testing."""
        cls.df = generate_synthetic_benchmark_dataset(num_samples=500, seed=42)
        cls.preprocessor = DataPreprocessor()
        cls.X_scaled, cls.y = cls.preprocessor.fit_transform(cls.df)
        cls.detector = ThreatDetector(random_state=42)
        cls.detector.train(cls.X_scaled, cls.y)

    def test_module1_dataset_and_preprocessing(self):
        """Module 1: Verifies dataset schema and preprocessing transformations."""
        assert len(self.df) == 500
        assert "threat_category" in self.df.columns
        assert self.X_scaled.shape[1] == len(config.FEATURE_COLUMNS)
        
        # Test single event transformation
        single_event = self.df.iloc[0].to_dict()
        X_single = self.preprocessor.transform_single_event(single_event)
        assert X_single.shape == (1, len(config.FEATURE_COLUMNS))

    def test_module2_threat_detection(self):
        """Module 2: Verifies AI threat detection, threat score, and anomaly score."""
        single_event = self.df.iloc[0].to_dict()
        X_single = self.preprocessor.transform_single_event(single_event)
        
        pred_res = self.detector.predict_single(X_single)
        assert "predicted_class" in pred_res
        assert pred_res["predicted_class"] in config.CLASSES
        assert 0.0 <= pred_res["threat_score"] <= 1.0
        assert 0.0 <= pred_res["anomaly_score"] <= 1.0
        assert 0.0 <= pred_res["confidence"] <= 1.0

        # Evaluate on batch
        metrics = self.detector.evaluate(self.X_scaled, self.y)
        assert metrics["accuracy"] >= 0.90
        assert metrics["f1_macro"] >= 0.90
        assert metrics["roc_auc"] >= 0.90
        assert 0.0 <= metrics["false_positive_rate"] <= 0.10

    def test_module3_dynamic_risk_engine(self):
        """Module 3: Verifies Algorithm 1 dynamic risk score formulation R = sum(wi * Xi)."""
        engine = DynamicRiskEngine()
        
        # Test Normal Event Risk
        normal_event = {
            "failed_logins": 0, "login_attempts": 1, "device_trust_score": 0.95,
            "flow_packets_per_sec": 5.0, "syn_flag_count": 0, "request_frequency": 1.0,
            "api_requests_count": 5, "cpu_usage_pct": 20.0, "memory_usage_pct": 30.0,
            "role": "Developer"
        }
        risk_normal = engine.assess_risk(normal_event, threat_score=0.05)
        assert risk_normal["overall_risk"] < 0.30
        assert risk_normal["risk_level"] == "LOW"

        # Test Malicious Event Risk
        mal_event = {
            "failed_logins": 25, "login_attempts": 30, "device_trust_score": 0.05,
            "flow_packets_per_sec": 450.0, "syn_flag_count": 500, "request_frequency": 180.0,
            "api_requests_count": 300, "cpu_usage_pct": 98.0, "memory_usage_pct": 95.0,
            "role": "External Attacker"
        }
        risk_mal = engine.assess_risk(mal_event, threat_score=0.98)
        assert risk_mal["overall_risk"] > 0.80
        assert risk_mal["risk_level"] in ["HIGH", "CRITICAL"]

    def test_module3_zero_trust_controller(self):
        """Module 3: Verifies dynamic mapping of risk score to Zero-Trust access decisions."""
        zt = ZeroTrustController()
        
        # Low risk -> ALLOW
        dec_low = zt.evaluate_access({"overall_risk": 0.15, "risk_level": "LOW", "components": {}})
        assert dec_low["access_decision"] == "ALLOW"
        
        # Medium risk -> ALLOW + MONITOR / RESTRICT
        dec_med = zt.evaluate_access({"overall_risk": 0.45, "risk_level": "MEDIUM", "components": {}})
        assert dec_med["access_decision"] == "ALLOW + MONITOR"
        
        # High risk -> ISOLATE / BLOCK
        dec_high = zt.evaluate_access({"overall_risk": 0.95, "risk_level": "CRITICAL", "components": {}})
        assert dec_high["access_decision"] == "BLOCK + RESPONSE"

    def test_module4_safety_controller_and_response(self):
        """Module 4: Verifies safety guardrail evaluation, action constraints, and approval queue."""
        safety = SafetyController()
        resp_engine = AutonomousResponseEngine(safety_controller=safety)

        # Reversible, low impact action with high confidence -> EXECUTE
        res_exec = safety.validate_action(
            proposed_action="RATE_LIMIT",
            risk_score=0.70,
            threat_severity="Suspicious",
            model_confidence=0.95,
            target_entity="10.0.1.2"
        )
        assert res_exec["safety_decision"] == "EXECUTE"
        assert res_exec["executable_now"] is True

        # Critical impact action (ISOLATE_SERVICE / ROLLBACK) -> REQUIRE_HUMAN_APPROVAL
        res_crit = safety.validate_action(
            proposed_action="ISOLATE_SERVICE",
            risk_score=0.92,
            threat_severity="Malicious",
            model_confidence=0.98,
            target_entity="svc-auth"
        )
        assert res_crit["safety_decision"] == "REQUIRE_HUMAN_APPROVAL"
        assert res_crit["executable_now"] is False

        # Test human approval resolution
        event = {"event_id": "evt_test", "target_service": "API Gateway", "attack_type": "Compromise"}
        threat_data = {"predicted_class": "Malicious", "confidence": 0.95}
        risk_data = {"overall_risk": 0.92}
        
        action_res = resp_engine.handle_threat(event, threat_data, risk_data)
        assert action_res["safety_decision"] == "REQUIRE_HUMAN_APPROVAL"
        assert len(resp_engine.get_pending_approvals()) > 0
        
        # Resolve approval
        resolved = resp_engine.resolve_pending_approval(action_res["action_id"], approved=True)
        assert resolved["status"] == "APPROVED_AND_EXECUTED"

    def test_module5_self_healing(self):
        """Module 5: Verifies 5-phase recovery state machine and recovery metrics."""
        healing = SelfHealingEngine()
        rec = healing.execute_recovery_pipeline("svc-pay", "Payment Microservice", "SQLi")
        
        assert rec["status"] == "SUCCESS"
        assert len(rec["phases"]) == 5
        assert rec["recovery_time_sec"] > 0
        assert rec["health_score"] >= 0.90
        assert healing.healing_stats["successful_recoveries"] == 1

    def test_module5_explainability_and_feedback(self):
        """Module 5: Verifies explanation narrative generation and feedback loop adjustment."""
        exp = ExplainabilityEngine()
        fb = FeedbackLoop()
        
        event = {"failed_logins": 8, "request_frequency": 35.0, "syn_flag_count": 12, "device_trust_score": 0.35}
        threat = {"predicted_class": "Malicious", "confidence": 0.96}
        risk = {"overall_risk": 0.88, "risk_level": "CRITICAL", "components": {"user_risk (U)": 0.85, "network_risk (N)": 0.90}}
        
        explanation = exp.explain_decision(event, threat, risk)
        assert "narrative_explanation" in explanation
        assert len(explanation["top_contributors"]) > 0

        # Feedback recording
        fb_rec = fb.record_incident_outcome("evt_101", "DDoS_SYN_Flood", "BLOCK_IP", "SUCCESS")
        assert fb_rec["outcome_status"] == "SUCCESS"
        assert fb.adaptive_weight_deltas["network_risk"] > 0.0

    def test_adaptive_policy_engine(self):
        """Module 3 Extension: Verifies deterministic context detection and adaptive weight shifts."""
        from modules.adaptive_policy import AdaptivePolicyEngine
        policy = AdaptivePolicyEngine()
        
        # Test Normal Context
        norm_res = policy.adapt_policy({
            "event": {"failed_logins": 0, "device_trust_score": 0.95, "syn_flag_count": 0, "request_frequency": 1.0},
            "threat_data": {"threat_score": 0.05, "predicted_class": "Benign"}
        })
        assert norm_res["context_key"] == "NORMAL_BASELINE"
        assert norm_res["adaptive_weights"]["threat_score"] == 0.30
        assert norm_res["adaptive_weights"]["user_risk"] == 0.15

        # Test Brute Force Auth Context -> User Risk & Behaviour Risk boost
        auth_res = policy.adapt_policy({
            "event": {"failed_logins": 8, "login_attempts": 9, "device_trust_score": 0.50, "request_frequency": 20.0},
            "threat_data": {"threat_score": 0.65, "predicted_class": "Suspicious"}
        })
        assert auth_res["context_key"] == "AUTH_BRUTE_FORCE"
        assert auth_res["adaptive_weights"]["user_risk"] == 0.30
        assert auth_res["adaptive_weights"]["behaviour_risk"] == 0.25
        assert np.isclose(sum(auth_res["adaptive_weights"].values()), 1.0)
        assert len(auth_res["triggering_factors"]) > 0

        # Test DDoS Context -> Network Risk boost to 40%
        ddos_res = policy.adapt_policy({
            "event": {"syn_flag_count": 450, "flow_packets_per_sec": 300.0, "device_trust_score": 0.10},
            "threat_data": {"threat_score": 0.95, "predicted_class": "Malicious"}
        })
        assert ddos_res["context_key"] == "DDOS_NETWORK_FLOOD"
        assert ddos_res["adaptive_weights"]["network_risk"] == 0.40
        assert ddos_res["adaptive_weights"]["threat_score"] == 0.35
        assert np.isclose(sum(ddos_res["adaptive_weights"].values()), 1.0)

    def test_user_manager_and_effective_permissions(self):
        """Verifies 5 demo users, editable security context, and dynamic effective permissions."""
        from modules.user_manager import UserManager
        um = UserManager()
        
        users = um.get_all_users()
        assert len(users) == 5
        
        # Verify User 3 Carol
        u3 = um.get_user("usr_admin_carol")
        assert u3 is not None
        assert u3["profile"]["name"] == "Carol Danvers"
        assert "Admin Operations" in u3["profile"]["assigned_permissions"]
        
        # Test telemetry generation from profile
        event = um.build_telemetry_event("usr_admin_carol")
        assert event["user_id"] == "usr_admin_carol"
        assert event["failed_logins"] == 0
        assert event["device_trust_score"] == 0.98
        
        # Test Effective Permissions mapping
        assigned = ["Read Data", "Write Data", "API Access", "Database Access", "Deploy Service", "Admin Operations"]
        
        # Case 1: ALLOW -> All effective
        eff_allow = um.compute_effective_permissions(assigned, "ALLOW")
        active_count = sum(1 for p in eff_allow if p["effective"])
        assert active_count == len(assigned)
        
        # Case 2: RESTRICT -> Only Read Data effective, others revoked
        eff_restrict = um.compute_effective_permissions(assigned, "RESTRICT")
        eff_map = {p["name"]: p["effective"] for p in eff_restrict}
        assert eff_map["Read Data"] is True
        assert eff_map["Write Data"] is False
        assert eff_map["Admin Operations"] is False
        assert eff_map["Deploy Service"] is False
        
        # Case 3: BLOCK -> None effective
        eff_block = um.compute_effective_permissions(assigned, "BLOCK + RESPONSE")
        assert sum(1 for p in eff_block if p["effective"]) == 0

if __name__ == "__main__":
    pytest.main(["-v", __file__])

