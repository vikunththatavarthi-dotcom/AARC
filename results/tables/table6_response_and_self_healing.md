### Table 6: Autonomous Response and Self-Healing Resilience Metrics

| Target Cloud Service        | Attack Scenario          | Containment Action         | Self-Healing Action              | MTTR (s)   | Health Verification Score   | Recovery Status   |
|:----------------------------|:-------------------------|:---------------------------|:---------------------------------|:-----------|:----------------------------|:------------------|
| Authentication Microservice | DDoS SYN Flood           | BLOCK_IP & RATE_LIMIT      | Golden Image Replica Spawn       | 1.42s      | 0.99 (Passed)               | SUCCESS           |
| API Gateway                 | Anomalous Burst Probe    | RESTRICT_API (Scoped)      | Routing Table Update             | 1.15s      | 0.98 (Passed)               | SUCCESS           |
| Payment Processing Engine   | SSH BruteForce Intrusion | REVOKE_SESSION & ISOLATE   | Container Rebuild & Key Rotation | 1.88s      | 1.00 (Passed)               | SUCCESS           |
| Cloud SQL Database Cluster  | SQLi Data Exfiltration   | ISOLATE_SERVICE (Approval) | Failover to Read-Replica         | 2.10s      | 0.97 (Passed)               | SUCCESS           |
| Object Storage Service      | Infiltration & API Abuse | REVOKE_ACCESS & ROLLBACK   | Config State Reconciliation      | 1.65s      | 0.99 (Passed)               | SUCCESS           |
