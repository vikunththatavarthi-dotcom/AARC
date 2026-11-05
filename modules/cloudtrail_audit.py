"""Deduplicated persistent audit records for CloudTrail analysis."""

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_PATH = (
    Path(__file__).resolve().parent.parent
    / "data" / "cloudtrail_analysis_audit.json"
)
_LOCK = threading.Lock()
MAX_RECORDS = 1000


def save_analysis(event, audit_path=None):
    """Upsert an event; retain history only when its decision changes."""
    path = Path(audit_path) if audit_path else DEFAULT_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc).isoformat()
    identity = {
        "event_name": event.get("event_name"),
        "time": event.get("time"),
        "username": event.get("username"),
        "event_source": event.get("event_source"),
        "source_ip": event.get("source_ip"),
    }
    event_id = event.get("event_id")
    key = str(event_id) if event_id else hashlib.sha256(
        json.dumps(identity, sort_keys=True).encode()
    ).hexdigest()

    risk = event.get("contextual_risk_assessment") or {}
    access = event.get("zero_trust_assessment") or {}
    response = event.get("response_recommendation") or {}

    decision = {
        "triage_risk": event.get("triage_risk", "LOW"),
        "overall_risk": risk.get("overall_risk"),
        "risk_level": risk.get("risk_level"),
        "access_decision": access.get("access_decision"),
        "recommended_action": response.get("recommended_action"),
        "safety_decision": response.get("safety_decision"),
    }
    signature = hashlib.sha256(
        json.dumps(decision, sort_keys=True).encode()
    ).hexdigest()

    fields = {
        **identity,
        "event_id": key,
        "triage_risk": event.get("triage_risk", "LOW"),
        "error_code": event.get("error_code"),
        "triage_reasons": event.get("triage_reasons", []),
        "contextual_risk_assessment": risk,
        "zero_trust_assessment": access,
        "response_recommendation": response,
    }

    with _LOCK:
        if path.exists():
            document = json.loads(path.read_text())
            records = document.get("records", [])
        else:
            records = []

        record = next(
            (r for r in records if r.get("event_id") == key), None
        )

        snapshot = {"analyzed_at": now, **decision}
        if record is None:
            record = {
                **fields,
                "first_analyzed_at": now,
                "last_analyzed_at": now,
                "analysis_count": 1,
                "decision_history": [{**snapshot, "signature": signature}],
                "_signature": signature,
            }
            records.append(record)
        else:
            record.update(fields)
            record["last_analyzed_at"] = now
            record["analysis_count"] += 1
            if record.get("_signature") != signature:
                record["decision_history"].append(
                    {**snapshot, "signature": signature}
                )
                record["decision_history"] = record["decision_history"][-20:]
                record["_signature"] = signature

        records = records[-MAX_RECORDS:]
        path.write_text(json.dumps(
            {"schema_version": 1, "records": records}, indent=2
        ))

    return record
