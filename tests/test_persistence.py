import json
from modules.monitoring import CloudTelemetryMonitor
from modules.user_manager import UserManager


def test_user_profile_and_latest_evaluation_survive_restart(tmp_path):
    state_path = tmp_path / "user_state.json"
    first = UserManager(persist_path=str(state_path))
    first.update_user_profile("usr_dev_alice", {"failed_logins": 7})
    first.record_simulation_result(
        user_id="usr_dev_alice", event={"event_id": "evt_persist_test"},
        threat_data={"predicted_class": "Suspicious", "threat_score": 0.7},
        adaptive_policy_data={}, risk_data={"overall_risk": 0.7},
        zt_decision={"access_decision": "RESTRICT"}, effective_permissions=[],
        response_data={}, explanation={},
    )
    restarted = UserManager(persist_path=str(state_path))
    assert restarted.users["usr_dev_alice"]["failed_logins"] == 7
    assert restarted.user_states["usr_dev_alice"]["event"]["event_id"] == "evt_persist_test"
    assert restarted.user_states["usr_dev_alice"]["risk_assessment"]["overall_risk"] == 0.7


def test_telemetry_history_survives_restart_and_stays_bounded(tmp_path):
    event_path = tmp_path / "telemetry_events.json"
    monitor = CloudTelemetryMonitor(buffer_size=2, persist_path=str(event_path))
    monitor.record_event({"event_id": "one"})
    monitor.record_event({"event_id": "two"})
    monitor.record_event({"event_id": "three"})
    restarted = CloudTelemetryMonitor(buffer_size=2, persist_path=str(event_path))
    assert [event["event_id"] for event in restarted.get_recent_events(10)] == ["two", "three"]
    assert json.loads(event_path.read_text(encoding="utf-8"))[-1]["event_id"] == "three"
