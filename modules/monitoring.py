"""
Module 1: Cloud Monitoring and Data Acquisition.
Simulates continuous monitoring of a multi-tier cloud infrastructure.
Collects and streams multi-attribute telemetry including user sessions, network flows,
container resources, and service activities.
"""
import time
import json
from pathlib import Path
import uuid
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import config

class CloudTelemetryMonitor:
    """
    Simulates continuous cloud environment monitoring.
    Emits telemetry events across compute instances, microservices, and user sessions.
    """
    def __init__(self, buffer_size: int = 200, persist_path: Optional[str] = None):
        self.buffer_size = buffer_size
        self.persist_path = Path(persist_path) if persist_path else None
        self.event_buffer: List[Dict[str, Any]] = []
        if self.persist_path and self.persist_path.exists():
            try:
                saved_events = json.loads(self.persist_path.read_text(encoding="utf-8"))
                if isinstance(saved_events, list):
                    self.event_buffer = [e for e in saved_events if isinstance(e, dict)][-self.buffer_size:]
            except (OSError, ValueError, TypeError) as exc:
                print(f"[Telemetry] Could not load persisted events: {exc}")
        
        # Simulated Cloud Topology
        self.cloud_services = [
            {"id": "svc-auth", "name": "Authentication Microservice", "status": "HEALTHY", "instances": 3, "ip": "172.16.0.10"},
            {"id": "svc-api", "name": "API Gateway", "status": "HEALTHY", "instances": 4, "ip": "172.16.0.20"},
            {"id": "svc-pay", "name": "Payment Processing Engine", "status": "HEALTHY", "instances": 2, "ip": "172.16.0.30"},
            {"id": "svc-db", "name": "Cloud SQL Database Cluster", "status": "HEALTHY", "instances": 2, "ip": "172.16.0.40"},
            {"id": "svc-storage", "name": "Object Storage Service", "status": "HEALTHY", "instances": 3, "ip": "172.16.0.50"}
        ]
        
        self.demo_users = [
            {"user_id": "usr_dev_alice", "role": "Developer", "base_trust": 0.95, "ip": "10.0.4.12"},
            {"user_id": "usr_analyst_bob", "role": "Data Analyst", "base_trust": 0.90, "ip": "10.0.6.45"},
            {"user_id": "usr_admin_carol", "role": "Cloud Admin", "base_trust": 0.98, "ip": "10.0.1.2"},
            {"user_id": "usr_contractor_dan", "role": "External Contractor", "base_trust": 0.70, "ip": "192.168.10.88"},
            {"user_id": "usr_guest_eve", "role": "Guest / Anonymous", "base_trust": 0.40, "ip": "198.51.100.24"}
        ]

    def generate_event(self, behavior_type: str = "normal", custom_overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generates a synthetic telemetry record representing cloud activity.
        behavior_type can be 'normal', 'suspicious', or 'malicious'.
        """
        user = np.random.choice(self.demo_users)
        service = np.random.choice(self.cloud_services)
        timestamp = datetime.now(timezone.utc).isoformat()
        event_id = f"evt_{uuid.uuid4().hex[:8]}"

        if behavior_type == "normal":
            event = {
                "event_id": event_id,
                "timestamp": timestamp,
                "user_id": user["user_id"],
                "role": user["role"],
                "src_ip": user["ip"],
                "dst_ip": service["ip"],
                "target_service": service["name"],
                "service_id": service["id"],
                "flow_duration": float(np.random.exponential(scale=60.0) + 1.0),
                "total_fwd_packets": int(np.random.poisson(lam=12) + 1),
                "total_bwd_packets": int(np.random.poisson(lam=15) + 1),
                "flow_bytes_per_sec": float(np.random.normal(loc=3500, scale=800)),
                "flow_packets_per_sec": float(np.random.uniform(2.0, 15.0)),
                "packet_length_mean": float(np.random.normal(loc=280, scale=30)),
                "packet_length_std": float(np.random.normal(loc=35, scale=8)),
                "syn_flag_count": 0,
                "ack_flag_count": int(np.random.poisson(lam=14)),
                "rst_flag_count": 0,
                "login_attempts": 1,
                "failed_logins": 0,
                "request_frequency": float(np.random.uniform(0.5, 3.0)),
                "api_requests_count": int(np.random.poisson(lam=8)),
                "data_transferred_mb": float(np.random.exponential(scale=1.5) + 0.1),
                "session_duration_sec": float(np.random.exponential(scale=1200) + 30),
                "device_trust_score": float(np.clip(user["base_trust"] + np.random.normal(0, 0.02), 0.7, 1.0)),
                "cpu_usage_pct": float(np.clip(np.random.normal(loc=20, scale=5), 5.0, 50.0)),
                "memory_usage_pct": float(np.clip(np.random.normal(loc=35, scale=8), 10.0, 60.0)),
                "behavior_label": "Normal",
                "attack_type": "BENIGN"
            }
        elif behavior_type == "suspicious":
            event = {
                "event_id": event_id,
                "timestamp": timestamp,
                "user_id": user["user_id"],
                "role": user["role"],
                "src_ip": f"192.168.{np.random.randint(50, 90)}.{np.random.randint(10, 200)}",
                "dst_ip": service["ip"],
                "target_service": service["name"],
                "service_id": service["id"],
                "flow_duration": float(np.random.exponential(scale=30.0) + 0.5),
                "total_fwd_packets": int(np.random.poisson(lam=45) + 5),
                "total_bwd_packets": int(np.random.poisson(lam=20) + 2),
                "flow_bytes_per_sec": float(np.random.normal(loc=15000, scale=4000)),
                "flow_packets_per_sec": float(np.random.uniform(25.0, 70.0)),
                "packet_length_mean": float(np.random.normal(loc=520, scale=80)),
                "packet_length_std": float(np.random.normal(loc=95, scale=20)),
                "syn_flag_count": int(np.random.randint(3, 8)),
                "ack_flag_count": int(np.random.randint(5, 20)),
                "rst_flag_count": int(np.random.randint(1, 4)),
                "login_attempts": int(np.random.randint(3, 6)),
                "failed_logins": int(np.random.randint(2, 5)),
                "request_frequency": float(np.random.uniform(12.0, 30.0)),
                "api_requests_count": int(np.random.poisson(lam=45)),
                "data_transferred_mb": float(np.random.exponential(scale=15.0) + 2.0),
                "session_duration_sec": float(np.random.exponential(scale=300) + 15),
                "device_trust_score": float(np.clip(np.random.uniform(0.40, 0.65), 0.0, 1.0)),
                "cpu_usage_pct": float(np.clip(np.random.normal(loc=58, scale=10), 30.0, 85.0)),
                "memory_usage_pct": float(np.clip(np.random.normal(loc=65, scale=10), 40.0, 85.0)),
                "behavior_label": "Suspicious",
                "attack_type": "Anomalous_Burst"
            }
        else: # malicious
            attack_sub = np.random.choice(["DDoS_SYN_Flood", "SSH_BruteForce", "SQLi_Exfiltration", "Infiltration_Compromise"])
            event = {
                "event_id": event_id,
                "timestamp": timestamp,
                "user_id": f"anon_attacker_{np.random.randint(10, 99)}",
                "role": "Unauthenticated Attacker",
                "src_ip": f"{np.random.randint(190, 223)}.{np.random.randint(10, 200)}.{np.random.randint(1, 250)}.{np.random.randint(2, 254)}",
                "dst_ip": service["ip"],
                "target_service": service["name"],
                "service_id": service["id"],
                "flow_duration": float(np.random.uniform(0.5, 10.0)),
                "total_fwd_packets": int(np.random.randint(400, 1200)),
                "total_bwd_packets": int(np.random.randint(2, 20)),
                "flow_bytes_per_sec": float(np.random.uniform(50000.0, 250000.0)),
                "flow_packets_per_sec": float(np.random.uniform(150.0, 800.0)),
                "packet_length_mean": float(np.random.normal(loc=850, scale=150)),
                "packet_length_std": float(np.random.normal(loc=190, scale=30)),
                "syn_flag_count": int(np.random.randint(200, 800)),
                "ack_flag_count": int(np.random.randint(2, 20)),
                "rst_flag_count": int(np.random.randint(40, 150)),
                "login_attempts": int(np.random.randint(15, 60)),
                "failed_logins": int(np.random.randint(14, 58)),
                "request_frequency": float(np.random.uniform(80.0, 400.0)),
                "api_requests_count": int(np.random.randint(120, 500)),
                "data_transferred_mb": float(np.random.uniform(80.0, 500.0)),
                "session_duration_sec": float(np.random.uniform(5.0, 60.0)),
                "device_trust_score": float(np.random.uniform(0.02, 0.15)),
                "cpu_usage_pct": float(np.random.uniform(88.0, 99.0)),
                "memory_usage_pct": float(np.random.uniform(85.0, 98.0)),
                "behavior_label": "Malicious",
                "attack_type": attack_sub
            }

        # Apply any explicit overrides
        if custom_overrides:
            event.update(custom_overrides)

        # Store in the bounded live buffer and persist it across process restarts.
        self.record_event(event)

        return event

    def record_event(self, event: Dict[str, Any]) -> None:
        """Record a telemetry event in memory and on disk when persistence is enabled."""
        self.event_buffer.append(event)
        self.event_buffer = self.event_buffer[-self.buffer_size:]
        if self.persist_path:
            try:
                self.persist_path.parent.mkdir(parents=True, exist_ok=True)
                tmp_path = self.persist_path.with_suffix(self.persist_path.suffix + ".tmp")
                tmp_path.write_text(json.dumps(self.event_buffer, ensure_ascii=False, allow_nan=False), encoding="utf-8")
                tmp_path.replace(self.persist_path)
            except (OSError, TypeError, ValueError) as exc:
                print(f"[Telemetry] Could not save events: {exc}")

    def get_recent_events(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Returns the most recent buffered events."""
        return self.event_buffer[-limit:]

    def get_cloud_services(self) -> List[Dict[str, Any]]:
        """Returns current status of all monitored cloud services."""
        return self.cloud_services

    def update_service_status(self, service_id: str, new_status: str) -> bool:
        """Updates operational state of a cloud service (e.g. ISOLATED, RECOVERING, HEALTHY)."""
        for svc in self.cloud_services:
            if svc["id"] == service_id or svc["name"] == service_id:
                svc["status"] = new_status
                return True
        return False
