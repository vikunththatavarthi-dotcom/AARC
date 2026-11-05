"""Persistent audit trail for AARC response decisions."""

import json
import threading
import uuid
from datetime import datetime, timezone

import config

_PATH = config.DATA_DIR / "response_decision_history.json"
_LOCK = threading.Lock()
_MAX_RECORDS = 500


def record_response(response, event=None, risk_data=None):
    """Persist or update one response decision without executing actions."""
    response = dict(response or {})
    event = dict(event or {})
    risk_data = dict(risk_data or {})

    event_id = response.get("event_id") or event.get("event_id")
    action = response.get("final_action") or response.get("action") or "UNKNOWN"
    action_id = response.get("action_id")
    if not action_id:
        action_id = (
            f"decision_{event_id}" if event_id
            else f"decision_{uuid.uuid4().hex[:12]}"
        )

    status = response.get("status")
    if not status:
        if action == "NO_ACTION":
            status = "NO_ACTION"
        elif response.get("execution_status") == "PENDING_APPROVAL":
            status = "PENDING_APPROVAL"
        elif response.get("safety_decision") == "REQUIRE_HUMAN_APPROVAL":
            status = "PENDING_APPROVAL"
        else:
            status = response.get("execution_status", "RECORDED")

    record = {
        "action_id": action_id,
        "event_id": event_id or "unknown",
        "timestamp": response.get("timestamp")
            or datetime.now(timezone.utc).isoformat(),
        "proposed_action": response.get("proposed_action")
            or response.get("action") or action,
        "final_action": action,
        "target": response.get("target")
            or event.get("target_service")
            or event.get("src_ip") or "Unknown",
        "safety_decision": response.get("safety_decision")
            or response.get("safety_status") or "NOT_REQUIRED",
        "safety_rationale": response.get("safety_rationale")
            or response.get("message") or "Decision recorded.",
        "response_time_ms": response.get("response_time_ms"),
        "status": status,
        "risk_score": risk_data.get("overall_risk",
                                    response.get("risk_score")),
        "execution_mode": "SIMULATION_ONLY",
    }

    with _LOCK:
        _PATH.parent.mkdir(parents=True, exist_ok=True)
        if _PATH.exists():
            try:
                data = json.loads(_PATH.read_text())
            except (OSError, json.JSONDecodeError):
                data = {"records": []}
        else:
            data = {"records": []}

        records = data.get("records", [])
        existing = next(
            (i for i, item in enumerate(records)
             if item.get("action_id") == action_id), None
        )
        if existing is None:
            records.append(record)
        else:
            records[existing] = {**records[existing], **record}

        data = {"schema_version": 1, "records": records[-_MAX_RECORDS:]}
        temp = _PATH.with_suffix(".tmp")
        temp.write_text(json.dumps(data, indent=2))
        temp.replace(_PATH)

    return record


def get_response_history(limit=20):
    """Return the most recent decisions in chronological order."""
    with _LOCK:
        if not _PATH.exists():
            return []
        try:
            data = json.loads(_PATH.read_text())
            records = data.get("records", [])
            return records[-max(1, min(int(limit), _MAX_RECORDS)):]
        except (OSError, ValueError, json.JSONDecodeError):
            return []
