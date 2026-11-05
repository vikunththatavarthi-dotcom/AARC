from modules.cloudtrail_pipeline import enrich_cloudtrail_event
from modules.risk_engine import DynamicRiskEngine
from modules.zero_trust import ZeroTrustController
from modules.response_engine import AutonomousResponseEngine
from modules.safety_controller import SafetyController


def components():
    safety = SafetyController()
    return (
        DynamicRiskEngine(),
        ZeroTrustController(),
        AutonomousResponseEngine(safety_controller=safety),
        safety,
    )


def test_high_risk_event_requires_approval():
    risk, zero, response, safety = components()
    event = {
        "event_id": "test-high",
        "event_name": "StopLogging",
        "username": "test-user",
        "triage_risk": "HIGH",
    }
    result = enrich_cloudtrail_event(event, risk, zero, response, safety)
    decision = result["response_recommendation"]

    assert decision["safety_decision"] == "REQUIRE_HUMAN_APPROVAL"
    assert decision["runtime_execution_allowed"] is False
    assert response.action_history == []


def test_medium_risk_event_is_constrained():
    risk, zero, response, safety = components()
    event = {
        "event_id": "test-medium",
        "event_name": "DescribeInstances",
        "username": "test-user",
        "triage_risk": "MEDIUM",
    }
    result = enrich_cloudtrail_event(event, risk, zero, response, safety)
    decision = result["response_recommendation"]

    assert decision["safety_decision"] == "CONSTRAIN"
    assert decision["recommended_action"] == "RATE_LIMIT"
    assert decision["runtime_execution_allowed"] is False
    assert response.action_history == []


def test_low_risk_event_recommends_no_action():
    risk, zero, response, safety = components()
    event = {
        "event_id": "test-low",
        "event_name": "DescribeInstances",
        "triage_risk": "LOW",
    }
    result = enrich_cloudtrail_event(event, risk, zero, response, safety)

    assert result["response_recommendation"]["recommended_action"] == "NO_ACTION"
    assert response.action_history == []
