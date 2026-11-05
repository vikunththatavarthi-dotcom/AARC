"""Contextual risk analysis for CloudTrail. Simulation only."""

TRIAGE_SCORE = {"LOW": 0.10, "MEDIUM": 0.50, "HIGH": 0.70}
TRIAGE_ATTACK = {
    "LOW": "BENIGN",
    "MEDIUM": "Auth",
    "HIGH": "Compromise",
}


def enrich_cloudtrail_event(
    event, risk_engine, zero_trust, response_engine, safety_controller
):
    """Assess risk and produce a non-executing response recommendation."""
    item = dict(event)
    level = str(item.get("triage_risk", "LOW")).upper()

    if level not in TRIAGE_SCORE:
        raise ValueError(f"Unsupported triage risk: {level}")

    score = TRIAGE_SCORE[level]
    weights = {
        "user_risk": 0.0,
        "device_risk": 0.0,
        "network_risk": 0.0,
        "behaviour_risk": 0.0,
        "threat_score": 1.0,
    }

    risk = risk_engine.assess_risk(
        item, threat_score=score, custom_weights=weights
    )
    risk_profile = {
        "overall_risk": risk["overall_risk"],
        "risk_level": risk["risk_level"],
        "components": {"CloudTrail rule-based triage": score},
    }

    identity = item.get("username") or "unknown"
    access = zero_trust.evaluate_access(
        risk_profile,
        {"user_id": identity, "role": item.get("identity_type", "unknown")},
    )

    # This is rule-based triage, not an ML prediction.
    threat = {
        "predicted_class": "Benign" if level == "LOW" else "Suspicious",
        "confidence": 0.0,
        "threat_score": score,
    }
    response_event = dict(item)
    response_event["attack_type"] = TRIAGE_ATTACK[level]
    response_event["target_service"] = (
        f"cloudtrail-event:{item.get('event_id') or item.get('event_name', 'unknown')}"
    )

    candidate = response_engine.propose_action(
        threat, risk_profile, response_event
    )

    if candidate == "NO_ACTION":
        safety = {
            "proposed_action": "NO_ACTION",
            "safety_decision": "NOT_REQUIRED",
            "safety_rationale": "Low-risk triage; no response recommended.",
        }
    else:
        safety = safety_controller.validate_action(
            proposed_action=candidate,
            risk_score=risk["overall_risk"],
            threat_severity=threat["predicted_class"],
            model_confidence=0.0,
            target_entity=response_event["target_service"],
        )

    return {
        **item,
        "contextual_risk_assessment": {
            "overall_risk": risk["overall_risk"],
            "risk_level": risk["risk_level"],
            "risk_basis": "CloudTrail rule-based triage only",
            "triage_score": score,
            "score_is_calibrated_probability": False,
            "unavailable_signals": [
                "user risk telemetry",
                "device trust telemetry",
                "network risk telemetry",
                "behaviour telemetry",
                "ML confidence for this CloudTrail event",
            ],
        },
        "zero_trust_assessment": {
            "access_decision": access["access_decision"],
            "policy_action": access["policy_action"],
            "explanation": access["explanation"],
        },
        "response_recommendation": {
            "candidate_action": candidate,
            "recommended_action": safety["proposed_action"],
            "safety_decision": safety["safety_decision"],
            "safety_rationale": safety["safety_rationale"],
            "requires_human_approval": (
                safety["safety_decision"] == "REQUIRE_HUMAN_APPROVAL"
            ),
            "runtime_execution_allowed": False,
            "execution_status": "NOT_EXECUTED_SIMULATION_ONLY",
        },
    }
