"""
AARC: Adaptive Autonomous Resilient Cloud Security Model - Research Prototype Backend.
Flask web server hosting REST APIs for real-time cloud monitoring, AI threat detection,
deterministic adaptive policy engine, dynamic risk assessment, zero-trust control,
autonomous response, self-healing, and experimental results visualization.
"""
import os
import json
import time
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_from_directory, send_file

import config
from modules.monitoring import CloudTelemetryMonitor
from modules.aws_monitoring import get_ec2_instances,get_cloudtrail_events
from modules.preprocessing import DataPreprocessor
from modules.threat_detection import ThreatDetector
from modules.adaptive_policy import AdaptivePolicyEngine
from modules.risk_engine import DynamicRiskEngine
from modules.zero_trust import ZeroTrustController
from modules.safety_controller import SafetyController
from modules.response_engine import AutonomousResponseEngine
from modules.self_healing import SelfHealingEngine
from modules.explainability import ExplainabilityEngine
from modules.feedback import FeedbackLoop
from modules.user_manager import UserManager, SYSTEM_PERMISSIONS
from experiments.run_all import execute_complete_experimental_suite
from modules.cloudtrail_triage import classify_cloudtrail_event
from modules.response_audit import record_response, get_response_history

app = Flask(
    __name__,
    template_folder="frontend/templates",
    static_folder="frontend/static"
)

# Initialize Core System Modules
monitor = CloudTelemetryMonitor(persist_path=config.DATA_DIR / "telemetry_events.json")
preprocessor = None
detector = None
adaptive_policy = AdaptivePolicyEngine()
risk_engine = DynamicRiskEngine()
zero_trust = ZeroTrustController()
safety_controller = SafetyController()
response_engine = AutonomousResponseEngine(safety_controller=safety_controller)
self_healing = SelfHealingEngine()
explainability = ExplainabilityEngine()
feedback_loop = FeedbackLoop()
user_manager = UserManager(persist_path=config.DATA_DIR / "user_state.json")

def load_or_init_models():
    """Ensures preprocessor and threat detector models are loaded in memory."""
    global preprocessor, detector
    try:
        if (config.MODELS_DIR / "preprocessor.joblib").exists():
            preprocessor = DataPreprocessor.load()
        if (config.MODELS_DIR / "threat_detector.joblib").exists():
            detector = ThreatDetector.load()
    except Exception as e:
        print(f"[App] Note: Model load deferred: {e}")

load_or_init_models()

def run_aarc_pipeline_for_user(user_id: str, overrides: dict = None) -> dict:
    """
    Executes the complete end-to-end AARC closed-loop pipeline for a specified user:
    User Context -> Telemetry -> AI Threat Detection -> Adaptive Policy ->
    Dynamic Risk Calculation -> Zero-Trust Access Decision -> Effective Permissions ->
    Autonomous Response & Safety Gate -> Explainability -> State Update.
    """
    global preprocessor, detector
    load_or_init_models()

    if preprocessor is None or detector is None:
        raise ValueError("ML Models (Preprocessor / ThreatDetector) are not trained or loaded.")

    # 1. Synthesize Telemetry Event from User Security Context
    raw_event = user_manager.build_telemetry_event(user_id, overrides=overrides)
    
    # 2. Module 1: Preprocessing
    X_sample = preprocessor.transform_single_event(raw_event)

    # 3. Module 2: AI Threat Detection (Random Forest + Isolation Forest)
    threat_data = detector.predict_single(X_sample)

    # 4. Module 3 Extension: Deterministic Adaptive Policy Engine
    context_payload = {
        "event": raw_event,
        "threat_data": threat_data
    }
    policy_data = adaptive_policy.adapt_policy(context_payload)
    adapted_weights = policy_data["adaptive_weights"]

    # 5. Module 3: Dynamic Risk Assessment with Adapted Weights (Algorithm 1)
    risk_data = risk_engine.assess_risk(raw_event, threat_data["threat_score"], custom_weights=adapted_weights)

    # 6. Module 3: Adaptive Zero-Trust Decision
    zt_decision = zero_trust.evaluate_access(risk_data, raw_event)

    # 7. Dynamic Effective Permissions Matrix
    user_profile = user_manager.users[user_id]
    effective_permissions = user_manager.compute_effective_permissions(
        user_profile["assigned_permissions"],
        zt_decision["access_decision"]
    )

    # 8. Module 4: Autonomous Response & Safety Guardrails
    response_data = response_engine.handle_threat(raw_event, threat_data, risk_data)
    record_response(response_data, raw_event, risk_data)

    # 9. Module 5: Explainability Engine
    explanation = explainability.explain_decision(raw_event, threat_data, risk_data)

    # 10. Module 5: Self-Healing Trigger (if service isolation occurred and was executed)
    healing_data = None
    if response_data.get("final_action") in ["ISOLATE_SERVICE", "ROLLBACK_DEPLOYMENT", "RESTORE_HEALTHY_INSTANCE"]:
        if response_data.get("executable_now"):
            svc_id = raw_event.get("service_id", "svc-api")
            monitor.update_service_status(svc_id, "QUARANTINED")
            healing_data = self_healing.execute_recovery_pipeline(
                service_id=svc_id,
                service_name=raw_event.get("target_service", "Target Microservice"),
                attack_type=raw_event.get("attack_type", "ANOMALY"),
                initial_action=response_data.get("final_action")
            )
            monitor.update_service_status(svc_id, "HEALTHY")

    # Record event in live stream buffer
    monitor.record_event(raw_event)

    # Persist state into UserManager
    user_manager.record_simulation_result(
        user_id=user_id,
        event=raw_event,
        threat_data=threat_data,
        adaptive_policy_data=policy_data,
        risk_data=risk_data,
        zt_decision=zt_decision,
        effective_permissions=effective_permissions,
        response_data=response_data,
        explanation=explanation
    )

    return {
        "user_id": user_id,
        "user_profile": user_profile,
        "event": raw_event,
        "threat_detection": threat_data,
        "adaptive_policy": policy_data,
        "risk_assessment": risk_data,
        "zero_trust_decision": zt_decision,
        "effective_permissions": effective_permissions,
        "response_action": response_data,
        "self_healing": healing_data,
        "explanation": explanation
    }

# -------------------------------------------------------------
# Frontend Routes
# -------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/analytics/chart/<chart_type>.png")
def analytics_chart(chart_type):
    """Render live AARC analytics as a Matplotlib PNG."""
    from modules.analytics_charts import make_chart

    try:
        chart = make_chart(chart_type)
    except ValueError:
        return jsonify({"error": "Unknown chart type"}), 404

    return send_file(chart, mimetype="image/png", max_age=0)


# Static route for generated result figures
@app.route("/results/figures/<path:filename>")
def serve_figure(filename):
    return send_from_directory(config.FIGURES_DIR, filename)

# -------------------------------------------------------------
# User Profile & Security Context Endpoints
# -------------------------------------------------------------
@app.route("/api/aws/instances", methods=["GET"])
def get_aws_instances():
    """Returns real EC2 instances from the connected AWS account."""
    try:
        instances = get_ec2_instances()
        return jsonify({
            "status": "SUCCESS",
            "source": "AWS EC2 API",
            "region": "ap-south-1",
            "count": len(instances),
            "instances": instances
        })
    except Exception:
        app.logger.exception("Failed to retrieve AWS EC2 instances")
        return jsonify({
            "status": "ERROR",
            "message": "Unable to retrieve AWS EC2 instances. Check AWS permissions and server logs."
        }), 500
@app.route("/api/users", methods=["GET"])
def get_users():
    """Returns list of all 5 demo users with their security summary."""
    return jsonify({
        "status": "SUCCESS",
        "system_permissions": SYSTEM_PERMISSIONS,
        "users": user_manager.get_all_users()
    })

@app.route("/api/users/<user_id>", methods=["GET"])
def get_user_details(user_id):
    """Returns detailed profile and latest state of a user."""
    data = user_manager.get_user(user_id)
    if not data:
        return jsonify({"error": f"User '{user_id}' not found"}), 404
    return jsonify({
        "status": "SUCCESS",
        "system_permissions": SYSTEM_PERMISSIONS,
        "user": data["profile"],
        "state": data["state"]
    })

@app.route("/api/users/<user_id>/update", methods=["POST"])
def update_user(user_id):
    """Updates editable security attributes and assigned permissions."""
    updates = request.get_json() or {}
    updated_user = user_manager.update_user_profile(user_id, updates)
    if not updated_user:
        return jsonify({"error": f"User '{user_id}' not found"}), 404
    return jsonify({
        "status": "SUCCESS",
        "message": f"User {updated_user['name']} profile updated successfully.",
        "user": updated_user
    })

@app.route("/api/users/<user_id>/simulate", methods=["POST"])
def simulate_user_activity(user_id):
    """
    Simulates activity for the user using their current security context,
    runs through the full AARC pipeline, and returns calculated results.
    """
    body = request.get_json() or {}
    overrides = body.get("overrides")
    try:
        result = run_aarc_pipeline_for_user(user_id, overrides=overrides)
        return jsonify({
            "status": "SUCCESS",
            "message": f"Telemetry processed for {result['user_profile']['name']}. All AARC modules evaluated.",
            "data": result
        })
    except Exception as e:        return jsonify({
            "status": "ERROR",
            "message": str(e)
        }), 500



@app.route("/api/aws/analyze", methods=["GET"])
def analyze_aws_events():
    """Read-only rule-based triage of recent CloudTrail events."""
    try:
        events = get_cloudtrail_events()
        analyzed = []

        for event in events:
            item = dict(event)
            result = classify_cloudtrail_event(item)
            item.update(result)
            analyzed.append(item)

        from modules.cloudtrail_triage import flag_repeated_failures
        from modules.cloudtrail_pipeline import enrich_cloudtrail_event
        from modules.cloudtrail_audit import save_analysis
        analyzed = flag_repeated_failures(analyzed)

        # Assess each event and persist its deduplicated audit record.
        for index, item in enumerate(analyzed):
            analyzed[index] = enrich_cloudtrail_event(
                item,
                risk_engine=risk_engine,
                zero_trust=zero_trust,
                response_engine=response_engine,
                safety_controller=safety_controller,
            )
            save_analysis(analyzed[index])

        counts = {
            level: sum(
                event["triage_risk"] == level
                for event in analyzed
            )
            for level in ("HIGH", "MEDIUM", "LOW")
        }

        return jsonify({
            "status": "SUCCESS",
            "source": "AWS CloudTrail",
            "region": "ap-south-1",
            "analysis_type": "READ_ONLY_RULE_BASED",
            "count": len(analyzed),
            "risk_counts": counts,
            "limitations": [
                "Only recent events returned by the existing CloudTrail reader are analyzed.",
                "A flagged action is not proof of malicious intent.",
                "Unmatched events are not confirmed safe.",
                "Failed API calls require investigation and are not proof of an attack.",
                "No AWS resources are modified."
            ],
            "events": analyzed
        })
    except Exception:
        app.logger.exception("CloudTrail analysis failed")
        return jsonify({
            "status": "ERROR",
            "message": "CloudTrail analysis failed. Check server logs and AWS permissions."
        }), 500


@app.route("/api/aws/events", methods=["GET"])
def get_aws_events():
    """Returns recent real AWS CloudTrail management events."""
    try:
        events = get_cloudtrail_events()
        return jsonify({
            "status": "SUCCESS",
            "source": "AWS CloudTrail",
            "region": "ap-south-1",
            "count": len(events),
            "events": events
        })
    except Exception:
        app.logger.exception("Failed to retrieve AWS CloudTrail events")
        return jsonify({
            "status": "ERROR",
            "message": "Unable to retrieve AWS CloudTrail events. Check AWS permissions and server logs."
        }), 500



@app.route("/api/users/<user_id>/reset", methods=["POST"])
def reset_single_user(user_id):
    """Resets user to baseline default profile."""
    res = user_manager.reset_user(user_id)
    if not res:
        return jsonify({"error": f"User '{user_id}' not found"}), 404
    return jsonify({
        "status": "SUCCESS",
        "message": f"User '{user_id}' reset to baseline profile.",
        "user": res
    })

@app.route("/api/users/reset-all", methods=["POST"])
def reset_all_users():
    """Resets all 5 users to baseline profiles."""
    user_manager.reset_all_users()
    return jsonify({
        "status": "SUCCESS",
        "message": "All 5 demo users reset to baseline profiles.",
        "users": user_manager.get_all_users()
    })

# -------------------------------------------------------------
# Adaptive Policy Endpoint
# -------------------------------------------------------------
@app.route("/api/adaptive-policy", methods=["GET"])
def get_adaptive_policy():
    """Returns current adaptive policy configuration and last adaptation."""
    return jsonify({
        "status": "SUCCESS",
        "baseline_weights": adaptive_policy.baseline_weights,
        "current_weights": adaptive_policy.current_weights,
        "last_adaptation": adaptive_policy.last_adaptation
    })

# -------------------------------------------------------------
# System Status & Topology Endpoints
# -------------------------------------------------------------
@app.route("/api/status", methods=["GET"])
def get_system_status():
    """Returns top-level cloud health metrics."""
    recent_events = monitor.get_recent_events(50)
    threats_count = sum(1 for e in recent_events if e.get("behavior_label") in ["Suspicious", "Malicious"] or e.get("predicted_class") in ["Suspicious", "Malicious"])
    
    users = user_manager.get_all_users()
    high_risk_users = sum(1 for u in users if u.get("current_risk_score", 0) >= 0.60)
    
    return jsonify({
        "system_status": "ONLINE",
        "model_name": "AARC (Adaptive Autonomous Resilient Cloud Security Model)",
        "monitored_services_count": len(monitor.cloud_services),
        "active_users_monitored": len(users),
        "high_risk_users_count": high_risk_users,
        "total_events_ingested": len(monitor.event_buffer),
        "detected_threats_count": threats_count,
        "mitigations_executed": response_engine.mitigation_stats["auto_executed"],
        "pending_human_approvals": len(response_engine.pending_approvals),
        "recovered_services": self_healing.healing_stats["successful_recoveries"],
        "avg_recovery_time_sec": self_healing.healing_stats["avg_recovery_time_sec"],
        "current_risk_weights": adaptive_policy.current_weights
    })

@app.route("/api/services", methods=["GET"])
def get_services():
    """Returns current state of all cloud services."""
    return jsonify({
        "services": monitor.get_cloud_services()
    })

@app.route("/api/events", methods=["GET"])
def get_recent_events():
    """Returns recent telemetry stream."""
    return jsonify({
        "events": monitor.get_recent_events(30)
    })

@app.route("/api/generate-event", methods=["POST"])
def generate_and_process_event():
    """
    Generic event generator for live continuous telemetry streaming.
    """
    load_or_init_models()
    data = request.get_json() or {}
    behavior_type = data.get("behavior_type", "normal")
    overrides = data.get("overrides", None)
    
    raw_event = monitor.generate_event(behavior_type=behavior_type, custom_overrides=overrides)
    if preprocessor is None or detector is None:
        return jsonify({
            "status": "MODELS_NOT_TRAINED",
            "message": "ML models have not been trained yet. Please run experiments first.",
            "event": raw_event
        }), 200

    X_sample = preprocessor.transform_single_event(raw_event)
    threat_data = detector.predict_single(X_sample)
    
    policy_data = adaptive_policy.adapt_policy({"event": raw_event, "threat_data": threat_data})
    risk_data = risk_engine.assess_risk(raw_event, threat_data["threat_score"], custom_weights=policy_data["adaptive_weights"])
    zt_decision = zero_trust.evaluate_access(risk_data, raw_event)
    response_data = response_engine.handle_threat(raw_event, threat_data, risk_data)
    record_response(response_data, raw_event, risk_data)
    explanation = explainability.explain_decision(raw_event, threat_data, risk_data)

    healing_data = None
    if response_data.get("final_action") in ["ISOLATE_SERVICE", "ROLLBACK_DEPLOYMENT", "RESTORE_HEALTHY_INSTANCE"]:
        if response_data.get("executable_now"):
            svc_id = raw_event.get("service_id", "svc-auth")
            monitor.update_service_status(svc_id, "QUARANTINED")
            healing_data = self_healing.execute_recovery_pipeline(
                service_id=svc_id,
                service_name=raw_event.get("target_service", "Cloud Service"),
                attack_type=raw_event.get("attack_type", "ANOMALY"),
                initial_action=response_data.get("final_action")
            )
            monitor.update_service_status(svc_id, "HEALTHY")

    return jsonify({
        "event": raw_event,
        "threat_detection": threat_data,
        "adaptive_policy": policy_data,
        "risk_assessment": risk_data,
        "zero_trust_decision": zt_decision,
        "response_action": response_data,
        "self_healing": healing_data,
        "explanation": explanation
    })

# -------------------------------------------------------------
# Research Demonstration Scenarios
# -------------------------------------------------------------
@app.route("/api/scenarios/<scenario_id>", methods=["POST"])
def execute_scenario(scenario_id):
    """
    Executes one of the 5 predefined research demonstration scenarios
    by updating the corresponding demo user and running through the pipeline.
    """
    if scenario_id == "1":
        # SCENARIO 1: Normal Enterprise User (Alice)
        user_id = "usr_dev_alice"
        overrides = {
            "device_trust_score": 0.96,
            "failed_logins": 0,
            "login_attempts": 1,
            "request_frequency": 1.2,
            "api_requests_count": 8,
            "data_transferred_mb": 2.0,
            "syn_flag_count": 0,
            "flow_packets_per_sec": 4.0,
            "cpu_usage_pct": 18.0,
            "memory_usage_pct": 28.0
        }
        title = "Scenario 1: Normal Enterprise User"
        expected = "Low Threat (T < 0.15) -> Baseline Weights -> Low Risk (R < 0.30) -> Access: ALLOW -> Full Effective Permissions"

    elif scenario_id == "2":
        # SCENARIO 2: Suspicious Activity & Auth Probes (Carol or Dan)
        user_id = "usr_admin_carol"
        overrides = {
            "device_trust_score": 0.48,
            "failed_logins": 8,
            "login_attempts": 9,
            "request_frequency": 22.0,
            "api_requests_count": 55,
            "data_transferred_mb": 12.0,
            "syn_flag_count": 5,
            "flow_packets_per_sec": 30.0,
            "cpu_usage_pct": 65.0,
            "memory_usage_pct": 60.0
        }
        title = "Scenario 2: Suspicious Authentication & Credential Probing"
        expected = "Elevated Threat -> Adaptive Policy shifts User Risk to 30% -> Risk: RESTRICT -> Admin/Write Permissions Revoked"

    elif scenario_id == "3":
        # SCENARIO 3: Aggressive Distributed Denial of Service (DDoS)
        user_id = "usr_guest_eve"
        overrides = {
            "device_trust_score": 0.05,
            "failed_logins": 15,
            "login_attempts": 20,
            "request_frequency": 220.0,
            "api_requests_count": 350,
            "data_transferred_mb": 180.0,
            "syn_flag_count": 650,
            "flow_packets_per_sec": 420.0,
            "cpu_usage_pct": 96.0,
            "memory_usage_pct": 92.0
        }
        title = "Scenario 3: Volumetric DDoS SYN Flood Attack"
        expected = "Critical Threat -> Adaptive Policy shifts Network Risk to 40% & Threat to 35% -> Risk: BLOCK -> Action: BLOCK_IP"

    elif scenario_id == "4":
        # SCENARIO 4: SQL Injection & Data Exfiltration
        user_id = "usr_analyst_bob"
        overrides = {
            "device_trust_score": 0.25,
            "failed_logins": 4,
            "login_attempts": 6,
            "request_frequency": 45.0,
            "api_requests_count": 180,
            "data_transferred_mb": 750.0,
            "syn_flag_count": 8,
            "flow_packets_per_sec": 85.0,
            "cpu_usage_pct": 92.0,
            "memory_usage_pct": 88.0
        }
        title = "Scenario 4: SQL Injection & Mass Data Exfiltration"
        expected = "Critical Threat -> Adaptive Policy shifts Behaviour Risk to 40% -> Access: BLOCK/ISOLATE -> Database Access Revoked"

    elif scenario_id == "5":
        # SCENARIO 5: Compromised Cloud Microservice & Safety Gate Interposition
        user_id = "usr_contractor_dan"
        overrides = {
            "device_trust_score": 0.05,
            "failed_logins": 5,
            "login_attempts": 6,
            "request_frequency": 38.0,
            "api_requests_count": 220,
            "data_transferred_mb": 150.0,
            "syn_flag_count": 2,
            "flow_packets_per_sec": 35.0,
            "cpu_usage_pct": 98.0,
            "memory_usage_pct": 95.0,
            "attack_type": "Infiltration_Compromise",
            "target_service": "Authentication Microservice",
            "service_id": "svc-auth"
        }
        title = "Scenario 5: High-Impact Infrastructure Action with Safety Gate"
        expected = "AI Proposes ISOLATE_SERVICE -> Safety Controller: High Blast Radius -> Intercepted -> Queued in Operator Approval Plane"

    else:
        return jsonify({"error": "Unknown scenario ID"}), 400

    result = run_aarc_pipeline_for_user(user_id, overrides=overrides)
    result["scenario_id"] = scenario_id
    result["scenario_title"] = title
    result["expected_behavior"] = expected

    return jsonify({
        "status": "SUCCESS",
        "scenario": result
    })

# -------------------------------------------------------------
# Human-in-the-Loop Safety Approvals Endpoints
# -------------------------------------------------------------
@app.route("/api/pending-approvals", methods=["GET"])
def get_pending_approvals():
    """Returns all pending high-impact action approvals and action history."""
    return jsonify({
        "pending_approvals": response_engine.pending_approvals,
        "action_history": get_response_history(20)
    })

@app.route("/api/approve-action", methods=["POST"])
def resolve_approval():
    """Approves or rejects a queued response action."""
    data = request.get_json() or {}
    action_id = data.get("action_id")
    approved = data.get("approved", True)
    operator = data.get("operator", "Cloud_Security_Officer")
    
    result = response_engine.resolve_pending_approval(action_id, approved, operator)
    if result:
        record_response(result)
        # If approved an isolation/recovery action, trigger self-healing
        if approved and result.get("final_action") in ["ISOLATE_SERVICE", "ROLLBACK_DEPLOYMENT", "RESTORE_HEALTHY_INSTANCE"]:
            svc_id = result.get("service_id", "svc-auth")
            healing_record = self_healing.execute_recovery_pipeline(
                service_id=svc_id,
                service_name=result.get("target", "Target Service"),
                attack_type="Post-Approval Remediation",
                initial_action=result.get("final_action")
            )
            result["self_healing_execution"] = healing_record

        return jsonify({"status": "RESOLVED", "record": result})
    else:
        return jsonify({"error": "Action ID not found or already resolved"}), 404

# -------------------------------------------------------------
# Self-Healing Interactive Endpoint
# -------------------------------------------------------------
@app.route("/api/self-healing/simulate", methods=["POST"])
def simulate_self_healing():
    """Manually simulates self-healing recovery workflow on a microservice."""
    data = request.get_json() or {}
    svc_id = data.get("service_id", "svc-auth")
    svc_name = data.get("service_name", "Authentication Microservice")
    attack = data.get("attack_type", "Compromised_Container_Quarantine")
    
    monitor.update_service_status(svc_id, "QUARANTINED")
    record = self_healing.execute_recovery_pipeline(
        service_id=svc_id,
        service_name=svc_name,
        attack_type=attack,
        initial_action="ISOLATE_SERVICE"
    )
    monitor.update_service_status(svc_id, "HEALTHY")
    
    return jsonify({
        "status": "SUCCESS",
        "record": record,
        "stats": self_healing.healing_stats
    })

# -------------------------------------------------------------
# Research Results & Experiment Pipeline Endpoints
# -------------------------------------------------------------
@app.route("/api/results/metrics", methods=["GET"])
def get_experimental_metrics():
    """Returns stored experimental metrics JSON."""
    try:
        with open(config.METRICS_DIR / "proposed_metrics.json") as f:
            prop = json.load(f)
        with open(config.METRICS_DIR / "baseline_metrics.json") as f:
            base = json.load(f)
        with open(config.METRICS_DIR / "ablation_metrics.json") as f:
            abl = json.load(f)
        with open(config.METRICS_DIR / "tuning_metrics.json") as f:
            tun = json.load(f)
        return jsonify({
            "status": "SUCCESS",
            "proposed": prop,
            "baselines": base,
            "ablation": abl,
            "tuning": tun
        })
    except Exception as e:
        return jsonify({"status": "NOT_FOUND", "message": f"Metrics not yet generated: {e}"}), 404

@app.route("/api/results/tables", methods=["GET"])
def get_tables():
    """Returns HTML versions of generated tables."""
    tables_html = {}
    for table_file in config.TABLES_DIR.glob("*.html"):
        with open(table_file, "r") as f:
            tables_html[table_file.stem] = f.read()
    return jsonify({
        "status": "SUCCESS",
        "tables": tables_html
    })

@app.route("/api/results/figures", methods=["GET"])
def get_figures_list():
    """Returns list of figure image filenames."""
    figs = [f.name for f in config.FIGURES_DIR.glob("*.png")]
    return jsonify({
        "status": "SUCCESS",
        "figures": sorted(figs)
    })

@app.route("/api/run-experiments", methods=["POST"])
def trigger_experiments():
    """Triggers the complete experimental execution pipeline."""
    try:
        execute_complete_experimental_suite()
        load_or_init_models()
        return jsonify({
            "status": "COMPLETED",
            "message": "Complete experimental pipeline executed successfully. All models, metrics, figures, and tables regenerated."
        })
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500



# Authenticated telemetry ingestion for external AARC clients.
@app.route("/api/v1/client/telemetry", methods=["POST"])
def ingest_client_telemetry():
    import hashlib
    import hmac
    import math
    import os
    import uuid
    from datetime import datetime, timezone

    from flask import current_app

    # Configure AARC_CLIENT_KEYS as JSON:
    # {"client-a":"long-random-secret-a","client-b":"long-random-secret-b"}
    configured = os.environ.get("AARC_CLIENT_KEYS", "")
    if not configured:
        return jsonify({"error": "Client ingestion is not configured"}), 503

    try:
        client_keys = json.loads(configured)
    except (TypeError, ValueError):
        current_app.logger.error("AARC_CLIENT_KEYS is not valid JSON")
        return jsonify({"error": "Client authentication is misconfigured"}), 503

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Bearer token required"}), 401

    token = auth[7:].strip()
    if not token:
        return jsonify({"error": "Bearer token required"}), 401

    matched_client = None
    for client_id, secret in client_keys.items():
        if isinstance(client_id, str) and isinstance(secret, str):
            if hmac.compare_digest(token, secret):
                matched_client = client_id
                break

    if matched_client is None:
        return jsonify({"error": "Invalid client credentials"}), 401

    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    if len(request.get_data(cache=True)) > 16384:
        return jsonify({"error": "Payload exceeds 16 KB"}), 413

    features = list(config.FEATURE_COLUMNS)
    missing = [name for name in features if name not in payload]
    if missing:
        return jsonify({
            "error": "Missing required telemetry features",
            "missing_features": missing
        }), 400

    event = {}
    for name in features:
        value = payload[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return jsonify({"error": f"Feature '{name}' must be numeric"}), 400
        value = float(value)
        if not math.isfinite(value):
            return jsonify({"error": f"Feature '{name}' must be finite"}), 400
        event[name] = value

    # The authenticated identity is authoritative; never trust a client-supplied ID.
    event.update({
        "event_id": str(uuid.uuid4()),
        "client_id": matched_client,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "authenticated_client",
    })

    if preprocessor is None or detector is None:
        return jsonify({"error": "Detection model is not available"}), 503

    try:
        transformed = preprocessor.transform_single_event(event)
        prediction = detector.predict_single(transformed)
    except Exception:
        current_app.logger.exception("Client telemetry inference failed")
        return jsonify({"error": "Telemetry inference failed"}), 500

    # Persist the original event plus its prediction; do not trigger live
    # infrastructure changes from an unverified client event.
    event["prediction"] = prediction
    monitor.record_event(event)

    return jsonify({
        "status": "accepted",
        "event_id": event["event_id"],
        "client_id": matched_client,
        "prediction": prediction,
        "response_actions_executed": False
    }), 200


if __name__ == "__main__":
    print(f"[Server] Starting AARC Research Prototype on http://{config.SERVER_HOST}:{config.SERVER_PORT}")
    app.run(host=config.SERVER_HOST, port=config.SERVER_PORT, debug=config.DEBUG)
