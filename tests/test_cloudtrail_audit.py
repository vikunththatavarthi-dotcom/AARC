import json
from modules.cloudtrail_audit import save_analysis


def test_repeated_analysis_does_not_duplicate_event(tmp_path):
    path = tmp_path / "audit.json"
    event = {
        "event_id": "evt-1",
        "event_name": "StopLogging",
        "time": "2026-10-24T10:00:00+00:00",
        "triage_risk": "HIGH",
        "contextual_risk_assessment": {
            "overall_risk": 0.7, "risk_level": "HIGH"
        },
        "zero_trust_assessment": {"access_decision": "RESTRICT"},
        "response_recommendation": {
            "recommended_action": "ISOLATE_SERVICE",
            "safety_decision": "REQUIRE_HUMAN_APPROVAL",
        },
    }

    save_analysis(event, path)
    save_analysis(event, path)
    data = json.loads(path.read_text())

    assert len(data["records"]) == 1
    assert data["records"][0]["analysis_count"] == 2
    assert len(data["records"][0]["decision_history"]) == 1


def test_decision_change_is_recorded(tmp_path):
    path = tmp_path / "audit.json"
    event = {"event_id": "evt-2", "triage_risk": "LOW"}

    save_analysis(event, path)
    event["triage_risk"] = "HIGH"
    save_analysis(event, path)

    record = json.loads(path.read_text())["records"][0]
    assert len(record["decision_history"]) == 2
    assert record["triage_risk"] == "HIGH"
