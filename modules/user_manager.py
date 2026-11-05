"""
User Management and Security Profile Controller for AARC.
Maintains state for the 5 interactive demo users, exposes editable security context attributes,
synthesizes telemetry vectors for AI pipeline ingestion, and maps Zero-Trust decisions
to granular effective permissions.
"""
import uuid
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import numpy as np

# Standard Permission Catalog in Cloud Environment
SYSTEM_PERMISSIONS = [
    {"id": "read_data", "name": "Read Data", "description": "Read-only access to authorized cloud data resources", "risk_tier": "LOW"},
    {"id": "write_data", "name": "Write Data", "description": "Mutation and creation privileges on cloud databases", "risk_tier": "MEDIUM"},
    {"id": "api_access", "name": "API Access", "description": "Execution access to cloud REST/gRPC API endpoints", "risk_tier": "MEDIUM"},
    {"id": "database_access", "name": "Database Access", "description": "Direct relational query & SQL cluster access", "risk_tier": "HIGH"},
    {"id": "deploy_service", "name": "Deploy Service", "description": "Container deployment and CI/CD release triggers", "risk_tier": "HIGH"},
    {"id": "admin_operations", "name": "Admin Operations", "description": "IAM role modification and cluster policy controls", "risk_tier": "CRITICAL"}
]

DEFAULT_USERS: List[Dict[str, Any]] = [
    {
        "id": "usr_dev_alice",
        "name": "Alice Chen",
        "role": "Developer",
        "department": "Core Platform Engineering",
        "ip": "10.0.4.12",
        "target_service": "API Gateway",
        "service_id": "svc-api",
        "device_trust_score": 0.95,
        "failed_logins": 0,
        "login_attempts": 1,
        "request_frequency": 1.2,
        "api_requests_count": 10,
        "data_transferred_mb": 2.5,
        "session_duration_min": 45,
        "syn_flag_count": 0,
        "flow_packets_per_sec": 4.5,
        "cpu_usage_pct": 18.0,
        "memory_usage_pct": 28.0,
        "assigned_permissions": ["Read Data", "Write Data", "API Access", "Deploy Service"],
        "notes": "Standard developer profile with nominal activity patterns."
    },
    {
        "id": "usr_analyst_bob",
        "name": "Bob Vance",
        "role": "Data Analyst",
        "department": "Business Intelligence & Analytics",
        "ip": "10.0.6.45",
        "target_service": "Cloud SQL Database Cluster",
        "service_id": "svc-db",
        "device_trust_score": 0.90,
        "failed_logins": 0,
        "login_attempts": 1,
        "request_frequency": 2.0,
        "api_requests_count": 25,
        "data_transferred_mb": 18.0,
        "session_duration_min": 60,
        "syn_flag_count": 0,
        "flow_packets_per_sec": 6.0,
        "cpu_usage_pct": 22.0,
        "memory_usage_pct": 35.0,
        "assigned_permissions": ["Read Data", "API Access", "Database Access"],
        "notes": "Analytics workstation querying warehouse clusters."
    },
    {
        "id": "usr_admin_carol",
        "name": "Carol Danvers",
        "role": "Cloud Admin",
        "department": "Infrastructure & SecOps",
        "ip": "10.0.1.2",
        "target_service": "Authentication Microservice",
        "service_id": "svc-auth",
        "device_trust_score": 0.98,
        "failed_logins": 0,
        "login_attempts": 1,
        "request_frequency": 1.5,
        "api_requests_count": 15,
        "data_transferred_mb": 5.0,
        "session_duration_min": 30,
        "syn_flag_count": 0,
        "flow_packets_per_sec": 5.0,
        "cpu_usage_pct": 15.0,
        "memory_usage_pct": 25.0,
        "assigned_permissions": ["Read Data", "Write Data", "API Access", "Database Access", "Deploy Service", "Admin Operations"],
        "notes": "Full administrative privileged account."
    },
    {
        "id": "usr_contractor_dan",
        "name": "Dan Miller",
        "role": "External Contractor",
        "department": "Third-Party QA Auditing",
        "ip": "192.168.10.88",
        "target_service": "Object Storage Service",
        "service_id": "svc-storage",
        "device_trust_score": 0.70,
        "failed_logins": 1,
        "login_attempts": 2,
        "request_frequency": 3.5,
        "api_requests_count": 8,
        "data_transferred_mb": 1.2,
        "session_duration_min": 20,
        "syn_flag_count": 1,
        "flow_packets_per_sec": 8.0,
        "cpu_usage_pct": 30.0,
        "memory_usage_pct": 40.0,
        "assigned_permissions": ["Read Data", "API Access"],
        "notes": "Scoped external access on managed contractor device."
    },
    {
        "id": "usr_guest_eve",
        "name": "Eve Adams",
        "role": "Guest / Anonymous",
        "department": "Public Ingress Gateway",
        "ip": "198.51.100.24",
        "target_service": "API Gateway",
        "service_id": "svc-api",
        "device_trust_score": 0.40,
        "failed_logins": 2,
        "login_attempts": 4,
        "request_frequency": 5.0,
        "api_requests_count": 4,
        "data_transferred_mb": 0.5,
        "session_duration_min": 10,
        "syn_flag_count": 2,
        "flow_packets_per_sec": 12.0,
        "cpu_usage_pct": 35.0,
        "memory_usage_pct": 45.0,
        "assigned_permissions": ["Read Data"],
        "notes": "Unverified untrusted endpoint session."
    }
]

class UserManager:
    """
    Manages the 5 demo users, their editable security context profiles,
    and their latest live AARC evaluation states.
    """
    def __init__(self, persist_path: Optional[str] = None):
        self.persist_path = Path(persist_path) if persist_path else None
        self.users: Dict[str, Dict[str, Any]] = {}
        self.user_states: Dict[str, Dict[str, Any]] = {}
        self.reset_all_users(persist=False)
        self._load_persisted_state()

    def _load_persisted_state(self) -> None:
        """Restore editable profiles and last evaluation results after a restart."""
        if not self.persist_path or not self.persist_path.exists():
            return
        try:
            saved = json.loads(self.persist_path.read_text(encoding="utf-8"))
            saved_users = saved.get("users", {})
            saved_states = saved.get("user_states", {})
            # Only accept known demo user IDs and preserve the current schema defaults.
            for uid in self.users:
                profile = saved_users.get(uid)
                if isinstance(profile, dict):
                    self.users[uid].update(profile)
                    self.users[uid]["assigned_permissions"] = list(
                        profile.get("assigned_permissions", self.users[uid]["assigned_permissions"])
                    )
                state = saved_states.get(uid)
                if isinstance(state, dict):
                    self.user_states[uid].update(state)
        except (OSError, ValueError, TypeError) as exc:
            # Keep safe defaults rather than preventing the dashboard from starting.
            print(f"[UserManager] Could not load persisted state: {exc}")

    def _save_persisted_state(self) -> None:
        """Atomically save user profiles and current security results to disk."""
        if not self.persist_path:
            return
        try:
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self.persist_path.with_suffix(self.persist_path.suffix + ".tmp")
            tmp_path.write_text(json.dumps({
                "users": self.users,
                "user_states": self.user_states,
            }, ensure_ascii=False, allow_nan=False), encoding="utf-8")
            tmp_path.replace(self.persist_path)
        except (OSError, TypeError, ValueError) as exc:
            print(f"[UserManager] Could not save persisted state: {exc}")

    def reset_all_users(self, persist: bool = True) -> None:
        """Resets all 5 users to baseline default profiles."""
        self.users = {}
        self.user_states = {}
        for u in DEFAULT_USERS:
            u_copy = u.copy()
            u_copy["assigned_permissions"] = list(u["assigned_permissions"])
            self.users[u["id"]] = u_copy
            # Initialize state with placeholder
            self.user_states[u["id"]] = {
                "last_simulated": None,
                "event": None,
                "threat_detection": {
                    "predicted_class": "Benign",
                    "threat_score": 0.05,
                    "confidence": 0.98,
                    "anomaly_score": 0.12,
                    "probabilities": {"Benign": 0.98, "Suspicious": 0.02, "Malicious": 0.00}
                },
                "adaptive_policy": {
                    "context_name": "Normal Enterprise Activity",
                    "context_key": "NORMAL_BASELINE",
                    "is_adapted": False,
                    "adaptation_reason": "Operational baseline with standard weight distribution."
                },
                "risk_assessment": {
                    "overall_risk": 0.05,
                    "risk_level": "LOW",
                    "components": {
                        "user_risk (U)": 0.05,
                        "device_risk (D)": 0.05,
                        "network_risk (N)": 0.02,
                        "behaviour_risk (B)": 0.04,
                        "threat_score (T)": 0.05
                    }
                },
                "zero_trust_decision": {
                    "access_decision": "ALLOW",
                    "policy_action": "FULL_ACCESS",
                    "restrictions": []
                },
                "effective_permissions": self.compute_effective_permissions(u_copy["assigned_permissions"], "ALLOW"),
                "response_action": {
                    "action": "NO_ACTION",
                    "safety_decision": "NOT_REQUIRED",
                    "status": "NORMAL"
                },
                "explainability": {
                    "narrative_explanation": "User baseline operating within normal bounds. Full authorized access granted."
                }
            }
        if persist:
            self._save_persisted_state()

    def get_all_users(self) -> List[Dict[str, Any]]:
        """Returns list of all users merged with their latest security summary."""
        result = []
        for uid, user in self.users.items():
            state = self.user_states.get(uid, {})
            merged = user.copy()
            merged["last_simulated"] = state.get("last_simulated")
            merged["current_threat_score"] = state.get("threat_detection", {}).get("threat_score", 0.05)
            merged["current_risk_score"] = state.get("risk_assessment", {}).get("overall_risk", 0.05)
            merged["current_risk_level"] = state.get("risk_assessment", {}).get("risk_level", "LOW")
            merged["current_access_decision"] = state.get("zero_trust_decision", {}).get("access_decision", "ALLOW")
            merged["current_policy_context"] = state.get("adaptive_policy", {}).get("context_name", "Normal")
            merged["effective_permissions_count"] = sum(
                1 for p in state.get("effective_permissions", []) if p.get("effective")
            )
            result.append(merged)
        return result

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Returns specific user details and full state."""
        if user_id not in self.users:
            return None
        return {
            "profile": self.users[user_id],
            "state": self.user_states.get(user_id, {})
        }

    def update_user_profile(self, user_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Updates editable attributes of a user profile."""
        if user_id not in self.users:
            return None
        user = self.users[user_id]
        
        # Whitelisted editable fields
        editable_fields = [
            "name", "role", "device_trust_score", "failed_logins", "login_attempts",
            "request_frequency", "api_requests_count", "data_transferred_mb",
            "session_duration_min", "syn_flag_count", "flow_packets_per_sec",
            "cpu_usage_pct", "memory_usage_pct", "target_service", "service_id",
            "assigned_permissions", "notes"
        ]
        
        for k in editable_fields:
            if k in updates:
                val = updates[k]
                if k in ["device_trust_score", "request_frequency", "data_transferred_mb",
                         "flow_packets_per_sec", "cpu_usage_pct", "memory_usage_pct"]:
                    user[k] = float(val)
                elif k in ["failed_logins", "login_attempts", "api_requests_count",
                           "session_duration_min", "syn_flag_count"]:
                    user[k] = int(val)
                elif k == "assigned_permissions":
                    if isinstance(val, list):
                        user[k] = [str(p) for p in val]
                else:
                    user[k] = str(val)

        self._save_persisted_state()
        return user

    def reset_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Resets a single user to initial baseline."""
        for u in DEFAULT_USERS:
            if u["id"] == user_id:
                u_copy = u.copy()
                u_copy["assigned_permissions"] = list(u["assigned_permissions"])
                self.users[user_id] = u_copy
                self.user_states[user_id]["effective_permissions"] = self.compute_effective_permissions(
                    u_copy["assigned_permissions"], "ALLOW"
                )
                self._save_persisted_state()
                return u_copy
        return None

    def build_telemetry_event(self, user_id: str, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Synthesizes a realistic telemetry event matching CICIDS-2017 schema
        directly from the user's current security context attributes.
        """
        user = self.users.get(user_id)
        if not user:
            raise ValueError(f"User {user_id} not found.")

        if overrides:
            self.update_user_profile(user_id, overrides)
            user = self.users[user_id]

        timestamp = datetime.now(timezone.utc).isoformat()
        event_id = f"evt_{uuid.uuid4().hex[:8]}"

        dev_trust = float(user["device_trust_score"])
        failed_logins = int(user["failed_logins"])
        login_attempts = max(1, int(user["login_attempts"]), failed_logins)
        req_freq = float(user["request_frequency"])
        api_count = int(user["api_requests_count"])
        data_mb = float(user["data_transferred_mb"])
        sess_dur_sec = float(user["session_duration_min"] * 60)
        syn_flags = int(user["syn_flag_count"])
        pkts_per_sec = float(user.get("flow_packets_per_sec", req_freq * 2.5))
        cpu_pct = float(user["cpu_usage_pct"])
        mem_pct = float(user["memory_usage_pct"])

        # Realistic derived flow properties
        flow_duration = max(1.0, 100.0 / (req_freq + 0.1))
        fwd_pkts = max(1, int(pkts_per_sec * flow_duration * 0.6))
        bwd_pkts = max(1, int(pkts_per_sec * flow_duration * 0.4))
        bytes_per_sec = (data_mb * 1024 * 1024) / max(flow_duration, 1.0)
        pkt_len_mean = max(40.0, min(1400.0, (bytes_per_sec / max(pkts_per_sec, 1.0))))
        pkt_len_std = max(5.0, pkt_len_mean * 0.25)
        ack_flags = max(0, fwd_pkts + bwd_pkts - syn_flags)
        rst_flags = max(0, int(syn_flags * 0.15))

        # Infer behavior label & attack type hint from context
        if "attack_type" in user and user["attack_type"] != "BENIGN":
            attack_type = user["attack_type"]
            behavior_label = "Malicious"
        elif syn_flags >= 50 or pkts_per_sec >= 150.0:
            behavior_label = "Malicious"
            attack_type = "DDoS_SYN_Flood"
        elif cpu_pct >= 90.0 and (api_count >= 150 or req_freq >= 30.0):
            behavior_label = "Malicious"
            attack_type = "Infiltration_Compromise"
        elif data_mb >= 50.0 or (api_count >= 80 and cpu_pct >= 80):
            behavior_label = "Malicious"
            attack_type = "SQLi_Exfiltration"
        elif failed_logins >= 3:
            behavior_label = "Malicious" if failed_logins >= 6 else "Suspicious"
            attack_type = "SSH_BruteForce" if failed_logins >= 6 else "Auth_Probe_Anomaly"
        elif dev_trust < 0.45 or req_freq >= 10.0 or syn_flags >= 4:
            behavior_label = "Suspicious"
            attack_type = "Anomalous_Burst"
        else:
            behavior_label = "Normal"
            attack_type = "BENIGN"

        event = {
            "event_id": event_id,
            "timestamp": timestamp,
            "user_id": user["id"],
            "user_name": user["name"],
            "role": user["role"],
            "department": user["department"],
            "src_ip": user["ip"],
            "dst_ip": "172.16.0.20",
            "target_service": user["target_service"],
            "service_id": user.get("service_id", "svc-api"),
            "flow_duration": float(flow_duration),
            "total_fwd_packets": int(fwd_pkts),
            "total_bwd_packets": int(bwd_pkts),
            "flow_bytes_per_sec": float(bytes_per_sec),
            "flow_packets_per_sec": float(pkts_per_sec),
            "packet_length_mean": float(pkt_len_mean),
            "packet_length_std": float(pkt_len_std),
            "syn_flag_count": int(syn_flags),
            "ack_flag_count": int(ack_flags),
            "rst_flag_count": int(rst_flags),
            "login_attempts": int(login_attempts),
            "failed_logins": int(failed_logins),
            "request_frequency": float(req_freq),
            "api_requests_count": int(api_count),
            "data_transferred_mb": float(data_mb),
            "session_duration_sec": float(sess_dur_sec),
            "device_trust_score": float(dev_trust),
            "cpu_usage_pct": float(cpu_pct),
            "memory_usage_pct": float(mem_pct),
            "behavior_label": behavior_label,
            "attack_type": attack_type
        }
        return event

    def compute_effective_permissions(self, assigned_permissions: List[str], access_decision: str) -> List[Dict[str, Any]]:
        """
        Deterministically evaluates Effective Permissions by applying Zero-Trust
        enforcement policies against baseline Assigned Permissions.
        """
        effective_list = []
        
        for perm in SYSTEM_PERMISSIONS:
            name = perm["name"]
            is_assigned = name in assigned_permissions
            
            effective = False
            status = "NOT_ASSIGNED"
            status_badge = "muted"
            reason = "Not granted in baseline role profile"
            
            if is_assigned:
                if access_decision == "ALLOW":
                    effective = True
                    status = "ACTIVE"
                    status_badge = "success"
                    reason = "Authorized under verified low-risk posture."
                
                elif access_decision == "ALLOW + MONITOR":
                    effective = True
                    if perm["risk_tier"] in ["HIGH", "CRITICAL"]:
                        status = "ACTIVE_MONITORED"
                        status_badge = "warning"
                        reason = "Active with mandatory audit logging and step-up MFA challenge."
                    else:
                        status = "ACTIVE"
                        status_badge = "success"
                        reason = "Active under standard session observation."
                
                elif access_decision == "RESTRICT":
                    if name == "Read Data":
                        effective = True
                        status = "ACTIVE_READ_ONLY"
                        status_badge = "warning"
                        reason = "Restricted to least-privilege read-only access."
                    else:
                        effective = False
                        status = "REVOKED_ZERO_TRUST"
                        status_badge = "danger"
                        reason = "Revoked due to elevated contextual risk (RESTRICT policy)."
                
                elif access_decision == "ISOLATE":
                    effective = False
                    status = "QUARANTINED"
                    status_badge = "danger"
                    reason = "Quarantined in isolated sandbox; production access suspended."
                
                elif access_decision == "BLOCK + RESPONSE":
                    effective = False
                    status = "BLOCKED"
                    status_badge = "danger"
                    reason = "Unconditionally blocked; autonomous containment active."

            effective_list.append({
                "id": perm["id"],
                "name": name,
                "description": perm["description"],
                "risk_tier": perm["risk_tier"],
                "assigned": is_assigned,
                "effective": effective,
                "status": status,
                "status_badge": status_badge,
                "reason": reason
            })
            
        return effective_list

    def record_simulation_result(
        self,
        user_id: str,
        event: Dict[str, Any],
        threat_data: Dict[str, Any],
        adaptive_policy_data: Dict[str, Any],
        risk_data: Dict[str, Any],
        zt_decision: Dict[str, Any],
        effective_permissions: List[Dict[str, Any]],
        response_data: Dict[str, Any],
        explanation: Dict[str, Any]
    ) -> None:
        """Stores the full state of a simulation for a user."""
        self.user_states[user_id] = {
            "last_simulated": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "threat_detection": threat_data,
            "adaptive_policy": adaptive_policy_data,
            "risk_assessment": risk_data,
            "zero_trust_decision": zt_decision,
            "effective_permissions": effective_permissions,
            "response_action": response_data,
            "explainability": explanation
        }
        self._save_persisted_state()
