import json
from modules.response_audit import record_response, get_response_history


def test_no_action_is_persisted(tmp_path, monkeypatch):
    import modules.response_audit as audit
    monkeypatch.setattr(audit, "_PATH", tmp_path / "history.json")

    record = audit.record_response(
        {"action": "NO_ACTION", "execution_status": "SKIPPED"},
        {"event_id": "evt-1", "target_service": "Nominal Traffic"},
        {"overall_risk": 0.1},
    )
    records = json.loads(audit._PATH.read_text())["records"]

    assert len(records) == 1
    assert records[0]["final_action"] == "NO_ACTION"
    assert records[0]["status"] == "NO_ACTION"
    assert records[0]["execution_mode"] == "SIMULATION_ONLY"
    assert record["risk_score"] == 0.1


def test_same_action_is_updated_not_duplicated(tmp_path, monkeypatch):
    import modules.response_audit as audit
    monkeypatch.setattr(audit, "_PATH", tmp_path / "history.json")

    audit.record_response(
        {"action_id": "act-1", "final_action": "ISOLATE_SERVICE",
         "status": "PENDING_APPROVAL"},
        {"event_id": "evt-2"},
    )
    audit.record_response(
        {"action_id": "act-1", "final_action": "ISOLATE_SERVICE",
         "status": "REJECTED_BY_OPERATOR"},
        {"event_id": "evt-2"},
    )

    records = audit.get_response_history()
    assert len(records) == 1
    assert records[0]["status"] == "REJECTED_BY_OPERATOR"
