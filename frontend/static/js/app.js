/**
 * AARC - Adaptive Autonomous Resilient Cloud Security Model
 * Enterprise SOC Front-End Controller Script
 */

document.addEventListener("DOMContentLoaded", () => {
    // Global Application State
    const AppState = {
        users: [],
        systemPermissions: [],
        selectedUserId: "usr_admin_carol",
        currentUserData: null,
        currentView: "view-overview",
        systemStatus: null,
        pendingApprovals: [],
        actionHistory: [],
        recoveryHistory: []
    };

    // DOM Element References
    const DOM = {
        sidebarLinks: document.querySelectorAll(".sidebar-link"),
        views: document.querySelectorAll(".app-view"),
        topbarTitle: document.getElementById("topbar-title-text"),
        topbarActiveUserName: document.getElementById("topbar-active-user-name"),
        topbarActiveUserBadge: document.getElementById("topbar-active-user-badge"),
        btnTopbarSimulate: document.getElementById("btn-topbar-simulate"),
        sidebarApprovalsBadge: document.getElementById("sidebar-approvals-badge"),

        // Overview Elements
        kpiThreatsCount: document.getElementById("kpi-threats-count"),
        kpiHighRiskUsers: document.getElementById("kpi-high-risk-users"),
        kpiPendingApprovals: document.getElementById("kpi-pending-approvals"),
        overviewUsersTbody: document.getElementById("overview-users-tbody"),
        overviewServicesTbody: document.getElementById("overview-services-tbody"),
        overviewEventsTbody: document.getElementById("overview-events-tbody"),
        awsInstancesTbody: document.getElementById("aws-instances-tbody"),
        awsConnectionStatus: document.getElementById("aws-connection-status"),
        cloudtrailEventsTbody: document.getElementById("cloudtrail-events-tbody"),
        cloudtrailStatus: document.getElementById("cloudtrail-status"),
        btnOverviewManageUsers: document.getElementById("btn-overview-manage-users"),

        // Users & Access Elements
        userSelectionCards: document.getElementById("user-selection-cards"),
        btnResetAllUsers: document.getElementById("btn-reset-all-users"),
        formSelectedUserId: document.getElementById("form-selected-user-id"),
        inputUserName: document.getElementById("input-user-name"),
        inputUserRole: document.getElementById("input-user-role"),
        rangeDeviceTrust: document.getElementById("range-device-trust"),
        valDeviceTrust: document.getElementById("val-device-trust"),
        inputFailedLogins: document.getElementById("input-failed-logins"),
        rangeReqFreq: document.getElementById("range-req-freq"),
        valReqFreq: document.getElementById("val-req-freq"),
        inputApiRequests: document.getElementById("input-api-requests"),
        inputDataMb: document.getElementById("input-data-mb"),
        inputSynFlags: document.getElementById("input-syn-flags"),
        inputTargetService: document.getElementById("input-target-service"),
        inputSessionMin: document.getElementById("input-session-min"),
        formAssignedPermissionsContainer: document.getElementById("form-assigned-permissions-container"),
        btnSimulateUserActivity: document.getElementById("btn-simulate-user-activity"),
        btnResetSelectedUser: document.getElementById("btn-reset-selected-user"),
        usersAccessDecisionBadge: document.getElementById("users-access-decision-badge"),
        usersThreatScoreVal: document.getElementById("users-threat-score-val"),
        usersRiskScoreVal: document.getElementById("users-risk-score-val"),
        usersTierText: document.getElementById("users-tier-text"),
        usersEvalExplanation: document.getElementById("users-eval-explanation"),
        usersPolicyContextText: document.getElementById("users-policy-context-text"),
        usersEffectivePermissionsTbody: document.getElementById("users-effective-permissions-tbody"),
        btnJumpToAdaptiveRisk: document.getElementById("btn-jump-to-adaptive-risk"),

        // Threat Detection Elements
        threatsViewUserName: document.getElementById("threats-view-user-name"),
        threatsViewSrcIp: document.getElementById("threats-view-src-ip"),
        threatsViewTargetSvc: document.getElementById("threats-view-target-svc"),
        threatsPredictedClass: document.getElementById("threats-predicted-class"),
        threatsScoreVal: document.getElementById("threats-score-val"),
        threatsConfidenceVal: document.getElementById("threats-confidence-val"),
        threatsAnomalyVal: document.getElementById("threats-anomaly-val"),
        probBenignPct: document.getElementById("prob-benign-pct"),
        probBenignBar: document.getElementById("prob-benign-bar"),
        probSuspiciousPct: document.getElementById("prob-suspicious-pct"),
        probSuspiciousBar: document.getElementById("prob-suspicious-bar"),
        probMaliciousPct: document.getElementById("prob-malicious-pct"),
        probMaliciousBar: document.getElementById("prob-malicious-bar"),
        threatsTelemetryTbody: document.getElementById("threats-telemetry-tbody"),

        // Adaptive Risk Elements
        riskFormulaText: document.getElementById("risk-formula-text"),
        riskCompositeBadge: document.getElementById("risk-composite-badge"),
        policyContextBadge: document.getElementById("policy-context-badge"),
        policyTriggerFactorsList: document.getElementById("policy-trigger-factors-list"),
        policyAdaptationReason: document.getElementById("policy-adaptation-reason"),
        policyWeightsComparisonTbody: document.getElementById("policy-weights-comparison-tbody"),
        riskComponentsTbody: document.getElementById("risk-components-tbody"),
        riskTableTotalVal: document.getElementById("risk-table-total-val"),

        // Zero-Trust Elements
        ztDecisionBadge: document.getElementById("zt-decision-badge"),
        ztPolicyActionName: document.getElementById("zt-policy-action-name"),
        ztPrimaryDriver: document.getElementById("zt-primary-driver"),
        ztExplanationText: document.getElementById("zt-explanation-text"),
        ztRestrictionsList: document.getElementById("zt-restrictions-list"),
        ztPermissionsMatrixTbody: document.getElementById("zt-permissions-matrix-tbody"),

        // Response & Safety Elements
        responseStatusBadge: document.getElementById("response-status-badge"),
        responseProposedAction: document.getElementById("response-proposed-action"),
        responseImpactVal: document.getElementById("response-impact-val"),
        responseSafetyDecision: document.getElementById("response-safety-decision"),
        responseTargetEntity: document.getElementById("response-target-entity"),
        responseSafetyRationale: document.getElementById("response-safety-rationale"),
        responsePendingCountBadge: document.getElementById("response-pending-count-badge"),
        responsePendingApprovalsList: document.getElementById("response-pending-approvals-list"),
        responseHistoryTbody: document.getElementById("response-history-tbody"),

        // Self-Healing Elements
        healingSuccessCount: document.getElementById("healing-success-count"),
        healingAvgMttr: document.getElementById("healing-avg-mttr"),
        healingLatestHealth: document.getElementById("healing-latest-health"),
        healingSelectService: document.getElementById("healing-select-service"),
        healingSelectAttack: document.getElementById("healing-select-attack"),
        btnTriggerSelfHealing: document.getElementById("btn-trigger-self-healing"),
        healingHistoryTbody: document.getElementById("healing-history-tbody"),

        // Research Scenarios Elements
        scenarioTracePanel: document.getElementById("scenario-trace-panel"),
        scenarioTraceTitle: document.getElementById("scenario-trace-title"),
        scenarioTraceBadge: document.getElementById("scenario-trace-badge"),
        scenarioTraceContent: document.getElementById("scenario-trace-content"),
        researchFiguresGrid: document.getElementById("research-figures-grid")
    };

    // =========================================================================
    // VIEW ROUTING & NAVIGATION
    // =========================================================================

    function switchView(targetViewId) {
        DOM.views.forEach(v => {
            v.classList.remove("active");
            if (v.id === targetViewId) v.classList.add("active");
        });

        DOM.sidebarLinks.forEach(link => {
            link.classList.remove("active");
            if (link.dataset.view === targetViewId) link.classList.add("active");
        });

        AppState.currentView = targetViewId;
        window.location.hash = targetViewId.replace("view-", "");

        // Update Topbar Title
        const viewTitles = {
            "view-overview": "Operations Overview",
            "view-users": "Users & Access Management",
            "view-threats": "Module 2: AI Threat Detection",
            "view-risk": "Module 3: Dynamic Risk & Adaptive Policy",
            "view-zerotrust": "Module 3: Zero-Trust Access Controller",
            "view-response": "Module 4: Safety-Constrained Response",
            "view-healing": "Module 5: Self-Healing & Cloud Resilience",
            "view-research": "Research Scenarios & Paper Evaluation"
        };
        DOM.topbarTitle.textContent = viewTitles[targetViewId] || "AARC Security Console";

        // Refresh views when switched
        if (targetViewId === "view-overview") loadOverviewData();
        if (targetViewId === "view-response") loadPendingApprovals();
        if (targetViewId === "view-research") loadFiguresGallery();
    }

    DOM.sidebarLinks.forEach(link => {
        link.addEventListener("click", () => {
            const target = link.dataset.view;
            if (target) switchView(target);
        });
    });

    if (DOM.btnOverviewManageUsers) {
        DOM.btnOverviewManageUsers.addEventListener("click", () => switchView("view-users"));
    }
    if (DOM.btnJumpToAdaptiveRisk) {
        DOM.btnJumpToAdaptiveRisk.addEventListener("click", () => switchView("view-risk"));
    }

    // =========================================================================
    // INITIALIZATION & DATA LOADING
    // =========================================================================

    async function initApp() {
        // Set up hash routing
        if (window.location.hash) {
            const hashView = "view-" + window.location.hash.replace("#", "");
            if (document.getElementById(hashView)) {
                switchView(hashView);
            }
        }

        // Attach Form Slider Event Listeners
        DOM.rangeDeviceTrust.addEventListener("input", (e) => {
            DOM.valDeviceTrust.textContent = parseFloat(e.target.value).toFixed(2);
        });
        DOM.rangeReqFreq.addEventListener("input", (e) => {
            DOM.valReqFreq.textContent = parseFloat(e.target.value).toFixed(1);
        });

        // Load Users
        await loadUsers();
        // Load Status
        await loadOverviewData();
	await loadAwsInstances();
        await loadCloudTrailEvents();
        // Load Approvals
        await loadPendingApprovals();
        // Setup Presets
        setupPresetButtons();
                // Automatically refresh real AWS data every 60 seconds
        setInterval(() => {
            loadAwsInstances();
            loadCloudTrailEvents();
        }, 60000);
    }

    async function loadUsers() {
        try {
            const res = await fetch("/api/users");
            const data = await res.json();
            if (data.status === "SUCCESS") {
                AppState.users = data.users;
                AppState.systemPermissions = data.system_permissions;
                renderUserSelectionCards();
                renderAssignedPermissionsCheckboxes();
                await selectUser(AppState.selectedUserId);
            }
        } catch (err) {
            console.error("Failed to load users:", err);
        }
    }

    async function selectUser(userId) {
        AppState.selectedUserId = userId;
        try {
            const res = await fetch(`/api/users/${userId}`);
            const data = await res.json();
            if (data.status === "SUCCESS") {
                AppState.currentUserData = data;
                renderUserProfileInForm(data.user);
                renderUserEvaluationState(data.state);
                updateTopbarActiveUser(data.user, data.state);
                renderUserSelectionCards(); // update active card highlight
            }
        } catch (err) {
            console.error(`Failed to load details for user ${userId}:`, err);
        }
    }

    function updateTopbarActiveUser(user, state) {
        DOM.topbarActiveUserName.textContent = `${user.name} (${user.role})`;
        const decision = state?.zero_trust_decision?.access_decision || "ALLOW";
        DOM.topbarActiveUserBadge.textContent = decision;
        DOM.topbarActiveUserBadge.className = "badge-soc " + getDecisionBadgeClass(decision);
    }

    // =========================================================================
    // RENDERING FUNCTIONS
    // =========================================================================

    function renderUserSelectionCards() {
        if (!DOM.userSelectionCards) return;
        DOM.userSelectionCards.innerHTML = "";

        AppState.users.forEach(u => {
            const isSelected = u.id === AppState.selectedUserId;
            const card = document.createElement("div");
            card.className = `user-card-selectable ${isSelected ? "active" : ""}`;
            card.dataset.userId = u.id;

            const decision = u.current_access_decision || "ALLOW";
            const decisionClass = getDecisionBadgeClass(decision);

            card.innerHTML = `
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <div class="d-flex align-items-center gap-2">
                        <div class="user-avatar-sm">${u.name.charAt(0)}</div>
                        <div>
                            <div class="fw-bold text-light small">${u.name}</div>
                            <div class="extra-small text-muted">${u.role}</div>
                        </div>
                    </div>
                    <span class="badge-soc ${decisionClass} extra-small">${decision}</span>
                </div>
                <div class="d-flex justify-content-between extra-small text-muted font-mono">
                    <span>Trust: <b class="text-light">${parseFloat(u.device_trust_score).toFixed(2)}</b></span>
                    <span>Risk R: <b class="text-warning">${parseFloat(u.current_risk_score || 0.05).toFixed(2)}</b></span>
                </div>
            `;

            card.addEventListener("click", () => selectUser(u.id));
            DOM.userSelectionCards.appendChild(card);
        });
    }

    function renderAssignedPermissionsCheckboxes() {
        if (!DOM.formAssignedPermissionsContainer) return;
        DOM.formAssignedPermissionsContainer.innerHTML = "";

        AppState.systemPermissions.forEach(perm => {
            const col = document.createElement("div");
            col.className = "col-md-6";
            col.innerHTML = `
                <div class="permission-check-item">
                    <label class="form-check-label d-flex align-items-center gap-2 cursor-pointer mb-0">
                        <input class="form-check-input permission-checkbox" type="checkbox" value="${perm.name}" id="chk-perm-${perm.id}">
                        <div>
                            <div class="fw-bold text-light small">${perm.name}</div>
                            <div class="extra-small text-muted">${perm.description}</div>
                        </div>
                    </label>
                    <span class="badge-soc muted extra-small">${perm.risk_tier}</span>
                </div>
            `;
            DOM.formAssignedPermissionsContainer.appendChild(col);
        });
    }

    function renderUserProfileInForm(user) {
        DOM.formSelectedUserId.textContent = user.id;
        DOM.inputUserName.value = user.name;
        DOM.inputUserRole.value = user.role;
        DOM.rangeDeviceTrust.value = user.device_trust_score;
        DOM.valDeviceTrust.textContent = parseFloat(user.device_trust_score).toFixed(2);
        DOM.inputFailedLogins.value = user.failed_logins;
        DOM.rangeReqFreq.value = user.request_frequency;
        DOM.valReqFreq.textContent = parseFloat(user.request_frequency).toFixed(1);
        DOM.inputApiRequests.value = user.api_requests_count;
        DOM.inputDataMb.value = user.data_transferred_mb;
        DOM.inputSynFlags.value = user.syn_flag_count;
        DOM.inputTargetService.value = user.target_service;
        DOM.inputSessionMin.value = user.session_duration_min;

        // Set permissions checkboxes
        const assigned = user.assigned_permissions || [];
        document.querySelectorAll(".permission-checkbox").forEach(chk => {
            chk.checked = assigned.includes(chk.value);
        });
    }

    function renderUserEvaluationState(state) {
        if (!state) return;

        const threat = state.threat_detection || {};
        const policy = state.adaptive_policy || {};
        const risk = state.risk_assessment || {};
        const zt = state.zero_trust_decision || {};
        const effectivePerms = state.effective_permissions || [];
        const resp = state.response_action || {};
        const event = state.event || {};

        // 1. Users & Access View Status Banner & Table
        const decision = zt.access_decision || "ALLOW";
        DOM.usersAccessDecisionBadge.textContent = decision;
        DOM.usersAccessDecisionBadge.className = "badge-soc " + getDecisionBadgeClass(decision);
        DOM.usersThreatScoreVal.textContent = (threat.threat_score !== undefined) ? threat.threat_score.toFixed(3) : "0.050";
        DOM.usersRiskScoreVal.textContent = (risk.overall_risk !== undefined) ? risk.overall_risk.toFixed(3) : "0.050";
        DOM.usersTierText.textContent = decision;
        DOM.usersTierText.className = `fw-bold font-mono fs-6 ${getTextColorClass(decision)}`;
        DOM.usersEvalExplanation.textContent = zt.explanation || "Nominal security baseline.";
        DOM.usersPolicyContextText.textContent = policy.context_name || "Normal Enterprise Activity";

        // Effective Permissions Table in Users View
        if (DOM.usersEffectivePermissionsTbody) {
            DOM.usersEffectivePermissionsTbody.innerHTML = "";
            effectivePerms.forEach(p => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td>
                        <div class="fw-bold text-light">${p.name}</div>
                        <div class="extra-small text-muted">${p.description}</div>
                    </td>
                    <td>
                        ${p.assigned ? '<span class="text-success"><i class="fa-solid fa-check me-1"></i>Assigned</span>' : '<span class="text-muted"><i class="fa-solid fa-minus me-1"></i>Unassigned</span>'}
                    </td>
                    <td>
                        ${renderEffectiveStatusBadge(p.status, p.effective)}
                    </td>
                `;
                DOM.usersEffectivePermissionsTbody.appendChild(tr);
            });
        }

        // 2. Threat Detection Screen Rendering
        if (DOM.threatsPredictedClass) {
            DOM.threatsViewUserName.textContent = `${AppState.currentUserData.user.name} (${AppState.currentUserData.user.role})`;
            DOM.threatsViewSrcIp.textContent = event.src_ip || AppState.currentUserData.user.ip || "10.0.1.2";
            DOM.threatsViewTargetSvc.textContent = event.target_service || AppState.currentUserData.user.target_service;

            const predClass = threat.predicted_class || "Benign";
            DOM.threatsPredictedClass.textContent = predClass.toUpperCase();
            DOM.threatsPredictedClass.className = `stat-widget-value ${getClassColor(predClass)}`;

            DOM.threatsScoreVal.textContent = (threat.threat_score !== undefined) ? threat.threat_score.toFixed(3) : "0.050";
            DOM.threatsConfidenceVal.textContent = (threat.confidence !== undefined) ? `${(threat.confidence * 100).toFixed(1)}%` : "98.5%";
            DOM.threatsAnomalyVal.textContent = (threat.anomaly_score !== undefined) ? threat.anomaly_score.toFixed(3) : "0.120";

            // Class probabilities
            const probas = threat.probabilities || { Benign: 0.98, Suspicious: 0.02, Malicious: 0.00 };
            const pB = (probas.Benign * 100).toFixed(1);
            const pS = (probas.Suspicious * 100).toFixed(1);
            const pM = (probas.Malicious * 100).toFixed(1);

            DOM.probBenignPct.textContent = `${pB}%`;
            DOM.probBenignBar.style.width = `${pB}%`;
            DOM.probSuspiciousPct.textContent = `${pS}%`;
            DOM.probSuspiciousBar.style.width = `${pS}%`;
            DOM.probMaliciousPct.textContent = `${pM}%`;
            DOM.probMaliciousBar.style.width = `${pM}%`;

            // Telemetry Features Table
            if (DOM.threatsTelemetryTbody && event) {
                DOM.threatsTelemetryTbody.innerHTML = "";
                const features = [
                    { name: "Device Trust Posture", val: (event.device_trust_score !== undefined) ? event.device_trust_score.toFixed(2) : "0.95", note: "Normalized Host Trust Score" },
                    { name: "Failed Login Attempts", val: event.failed_logins ?? 0, note: "Authentication Failure Counter" },
                    { name: "Request Frequency", val: `${(event.request_frequency !== undefined) ? event.request_frequency.toFixed(1) : 1.2} req/s`, note: "Ingress Request Rate" },
                    { name: "API Request Volume", val: `${event.api_requests_count ?? 10} reqs`, note: "Application Layer Mutations" },
                    { name: "Data Transferred", val: `${(event.data_transferred_mb !== undefined) ? event.data_transferred_mb.toFixed(1) : 2.5} MB`, note: "Payload Volume" },
                    { name: "SYN Flag Count", val: event.syn_flag_count ?? 0, note: "TCP Handshake Anomalies" },
                    { name: "Flow Packets / sec", val: `${(event.flow_packets_per_sec !== undefined) ? event.flow_packets_per_sec.toFixed(1) : 4.5} pkts/s`, note: "Transport Layer Rate" },
                    { name: "CPU Utilization", val: `${(event.cpu_usage_pct !== undefined) ? event.cpu_usage_pct.toFixed(1) : 18.0}%`, note: "Compute Stress Level" },
                    { name: "Memory Utilization", val: `${(event.memory_usage_pct !== undefined) ? event.memory_usage_pct.toFixed(1) : 28.0}%`, note: "Container Memory Pressure" }
                ];
                features.forEach(f => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td class="text-light fw-bold">${f.name}</td>
                        <td class="font-mono text-info">${f.val}</td>
                        <td class="text-muted extra-small">${f.note}</td>
                    `;
                    DOM.threatsTelemetryTbody.appendChild(tr);
                });
            }
        }

        // 3. Adaptive Risk Screen Rendering
        if (DOM.riskFormulaText) {
            DOM.riskFormulaText.textContent = risk.formula || "R = 0.15*U + 0.15*D + 0.20*N + 0.20*B + 0.30*T";
            const overallRisk = (risk.overall_risk !== undefined) ? risk.overall_risk.toFixed(3) : "0.050";
            const riskLevel = risk.risk_level || "LOW";
            DOM.riskCompositeBadge.textContent = `R = ${overallRisk} (${riskLevel})`;
            DOM.riskCompositeBadge.className = `badge-soc ${getRiskBadgeClass(riskLevel)} fs-6 font-mono`;

            DOM.policyContextBadge.textContent = policy.context_name || "Normal Enterprise Activity";
            DOM.policyContextBadge.className = `badge-soc ${policy.is_adapted ? "warn" : "info"}`;

            // Triggering factors
            DOM.policyTriggerFactorsList.innerHTML = "";
            (policy.triggering_factors || []).forEach(factor => {
                const li = document.createElement("li");
                li.innerHTML = `<i class="fa-solid fa-arrow-right text-info me-2"></i>${factor}`;
                DOM.policyTriggerFactorsList.appendChild(li);
            });

            DOM.policyAdaptationReason.textContent = policy.adaptation_reason || "Standard baseline operational weighting.";

            // Weights comparison table
            if (DOM.policyWeightsComparisonTbody) {
                DOM.policyWeightsComparisonTbody.innerHTML = "";
                const transitions = policy.weight_transitions || {};
                const labels = {
                    user_risk: "User Risk (wU)",
                    device_risk: "Device Risk (wD)",
                    network_risk: "Network Risk (wN)",
                    behaviour_risk: "Behaviour Risk (wB)",
                    threat_score: "Threat Score (wT)"
                };
                for (const [k, v] of Object.entries(transitions)) {
                    const tr = document.createElement("tr");
                    const dirIcon = (v.direction === "INCREASED") ? '<span class="text-warning fw-bold"><i class="fa-solid fa-arrow-up me-1"></i>' + v.percentage_adaptive + '</span>' :
                                    (v.direction === "DECREASED") ? '<span class="text-muted"><i class="fa-solid fa-arrow-down me-1"></i>' + v.percentage_adaptive + '</span>' :
                                    '<span class="text-light">' + v.percentage_adaptive + '</span>';
                    tr.innerHTML = `
                        <td class="text-light fw-bold">${labels[k] || k}</td>
                        <td class="font-mono text-muted">${v.percentage_baseline}</td>
                        <td class="font-mono">${dirIcon}</td>
                        <td class="font-mono extra-small ${v.delta > 0 ? 'text-warning' : (v.delta < 0 ? 'text-muted' : 'text-light')}">
                            ${v.delta > 0 ? '+' : ''}${(v.delta * 100).toFixed(0)}%
                        </td>
                    `;
                    DOM.policyWeightsComparisonTbody.appendChild(tr);
                }
            }

            // Risk Components Breakdown Table
            if (DOM.riskComponentsTbody) {
                DOM.riskComponentsTbody.innerHTML = "";
                (risk.component_table || []).forEach(row => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td class="text-light fw-bold">${row.name}</td>
                        <td class="font-mono text-info">${row.symbol}</td>
                        <td class="font-mono text-light">${row.value.toFixed(3)}</td>
                        <td class="font-mono text-warning">${row.weight_pct} (${row.weight.toFixed(2)})</td>
                        <td class="font-mono text-success fw-bold">${row.contribution.toFixed(4)}</td>
                    `;
                    DOM.riskComponentsTbody.appendChild(tr);
                });
                DOM.riskTableTotalVal.textContent = overallRisk;
            }
        }

        // 4. Zero-Trust Access Screen Rendering
        if (DOM.ztDecisionBadge) {
            DOM.ztDecisionBadge.textContent = decision;
            DOM.ztDecisionBadge.className = `badge-soc ${getDecisionBadgeClass(decision)} fs-6`;
            DOM.ztPolicyActionName.textContent = zt.policy_action || "FULL_ACCESS";
            DOM.ztPrimaryDriver.textContent = zt.primary_driver || "threat_score (T)";
            DOM.ztExplanationText.textContent = zt.explanation || "Nominal baseline.";

            DOM.ztRestrictionsList.innerHTML = "";
            const rests = zt.restrictions || [];
            if (rests.length === 0) {
                DOM.ztRestrictionsList.innerHTML = '<li><i class="fa-solid fa-check text-success me-2"></i>No active restrictions (Standard baseline operations)</li>';
            } else {
                rests.forEach(r => {
                    const li = document.createElement("li");
                    li.innerHTML = `<i class="fa-solid fa-triangle-exclamation text-warning me-2"></i>${r}`;
                    DOM.ztRestrictionsList.appendChild(li);
                });
            }

            // Matrix Table
            if (DOM.ztPermissionsMatrixTbody) {
                DOM.ztPermissionsMatrixTbody.innerHTML = "";
                effectivePerms.forEach(p => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td class="fw-bold text-light">${p.name}</td>
                        <td class="extra-small text-muted">${p.description}</td>
                        <td><span class="badge-soc muted extra-small">${p.risk_tier}</span></td>
                        <td>${p.assigned ? '<span class="text-success"><i class="fa-solid fa-check me-1"></i>YES</span>' : '<span class="text-muted"><i class="fa-solid fa-xmark me-1"></i>NO</span>'}</td>
                        <td>${renderEffectiveStatusBadge(p.status, p.effective)}</td>
                        <td class="extra-small text-light">${p.reason}</td>
                    `;
                    DOM.ztPermissionsMatrixTbody.appendChild(tr);
                });
            }
        }

        // 5. Response & Safety Screen Rendering
        if (DOM.responseProposedAction) {
            const propAction = resp.final_action || resp.proposed_action || "NO_ACTION";
            DOM.responseProposedAction.textContent = propAction;
            DOM.responseImpactVal.textContent = resp.evaluated_impact || (propAction === "NO_ACTION" ? "LOW" : "HIGH");
            DOM.responseSafetyDecision.textContent = resp.safety_decision || "EXECUTE";
            DOM.responseSafetyDecision.className = `fw-bold ${resp.safety_decision === 'REQUIRE_HUMAN_APPROVAL' ? 'text-warning' : 'text-success'}`;
            DOM.responseTargetEntity.textContent = resp.target || event.target_service || "Nominal Traffic";
            DOM.responseSafetyRationale.textContent = resp.safety_rationale || resp.message || "Activity deemed safe; no automated intervention required.";

            if (propAction === "NO_ACTION") {
                DOM.responseStatusBadge.textContent = "NO INTERVENTION NEEDED";
                DOM.responseStatusBadge.className = "badge-soc safe";
            } else if (resp.safety_decision === "REQUIRE_HUMAN_APPROVAL") {
                DOM.responseStatusBadge.textContent = "QUEUED IN SAFETY APPROVAL PLANE";
                DOM.responseStatusBadge.className = "badge-soc warn";
            } else {
                DOM.responseStatusBadge.textContent = "AUTOMATICALLY CONTAINED";
                DOM.responseStatusBadge.className = "badge-soc danger";
            }
        }
    }

    // =========================================================================
    // SIMULATION TRIGGER & EVENT DISPATCH
    // =========================================================================

    async function executeUserSimulation() {
        const userId = AppState.selectedUserId;
        if (!userId) return;

        // Gather assigned permissions from checkboxes
        const selectedPerms = [];
        document.querySelectorAll(".permission-checkbox:checked").forEach(chk => {
            selectedPerms.push(chk.value);
        });

        const overrides = {
            name: DOM.inputUserName.value,
            role: DOM.inputUserRole.value,
            device_trust_score: parseFloat(DOM.rangeDeviceTrust.value),
            failed_logins: parseInt(DOM.inputFailedLogins.value),
            request_frequency: parseFloat(DOM.rangeReqFreq.value),
            api_requests_count: parseInt(DOM.inputApiRequests.value),
            data_transferred_mb: parseFloat(DOM.inputDataMb.value),
            syn_flag_count: parseInt(DOM.inputSynFlags.value),
            target_service: DOM.inputTargetService.value,
            session_duration_min: parseInt(DOM.inputSessionMin.value),
            assigned_permissions: selectedPerms
        };

        try {
            // Visual loading state
            DOM.btnSimulateUserActivity.disabled = true;
            DOM.btnSimulateUserActivity.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-2"></i>EVALUATING AARC PIPELINE...';

            const res = await fetch(`/api/users/${userId}/simulate`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ overrides })
            });

            const result = await res.json();
            if (result.status === "SUCCESS") {
                const data = result.data;
                AppState.currentUserData = {
                    user: data.user_profile,
                    state: {
                        last_simulated: new Date().toISOString(),
                        event: data.event,
                        threat_detection: data.threat_detection,
                        adaptive_policy: data.adaptive_policy,
                        risk_assessment: data.risk_assessment,
                        zero_trust_decision: data.zero_trust_decision,
                        effective_permissions: data.effective_permissions,
                        response_action: data.response_action,
                        self_healing: data.self_healing,
                        explainability: data.explanation
                    }
                };

                // Refresh state across app
                renderUserEvaluationState(AppState.currentUserData.state);
                updateTopbarActiveUser(data.user_profile, AppState.currentUserData.state);
                await loadUsers();
                await loadOverviewData();
                await loadPendingApprovals();
            }
        } catch (err) {
            console.error("Simulation error:", err);
            alert("Error during simulation: " + err);
        } finally {
            DOM.btnSimulateUserActivity.disabled = false;
            DOM.btnSimulateUserActivity.innerHTML = '<i class="fa-solid fa-bolt me-2"></i>SIMULATE ACTIVITY & APPLY SECURITY CONTEXT';
        }
    }

    if (DOM.btnSimulateUserActivity) {
        DOM.btnSimulateUserActivity.addEventListener("click", executeUserSimulation);
    }
    if (DOM.btnTopbarSimulate) {
        DOM.btnTopbarSimulate.addEventListener("click", () => {
            if (AppState.currentView !== "view-users") switchView("view-users");
            executeUserSimulation();
        });
    }

    if (DOM.btnResetSelectedUser) {
        DOM.btnResetSelectedUser.addEventListener("click", async () => {
            if (AppState.selectedUserId) {
                await fetch(`/api/users/${AppState.selectedUserId}/reset`, { method: "POST" });
                await selectUser(AppState.selectedUserId);
                await loadOverviewData();
            }
        });
    }

    if (DOM.btnResetAllUsers) {
        DOM.btnResetAllUsers.addEventListener("click", async () => {
            await fetch("/api/users/reset-all", { method: "POST" });
            await loadUsers();
            await loadOverviewData();
        });
    }

    // =========================================================================
    // PRESET BUTTONS FOR RAPID DEMO
    // =========================================================================

    function setupPresetButtons() {
        document.querySelectorAll(".preset-chip").forEach(chip => {
            chip.addEventListener("click", () => {
                const preset = chip.dataset.preset;
                if (preset === "normal") {
                    DOM.rangeDeviceTrust.value = 0.96;
                    DOM.valDeviceTrust.textContent = "0.96";
                    DOM.inputFailedLogins.value = 0;
                    DOM.rangeReqFreq.value = 1.2;
                    DOM.valReqFreq.textContent = "1.2";
                    DOM.inputApiRequests.value = 8;
                    DOM.inputDataMb.value = 2.0;
                    DOM.inputSynFlags.value = 0;
                } else if (preset === "auth-probes") {
                    DOM.rangeDeviceTrust.value = 0.48;
                    DOM.valDeviceTrust.textContent = "0.48";
                    DOM.inputFailedLogins.value = 8;
                    DOM.rangeReqFreq.value = 22.0;
                    DOM.valReqFreq.textContent = "22.0";
                    DOM.inputApiRequests.value = 55;
                    DOM.inputDataMb.value = 12.0;
                    DOM.inputSynFlags.value = 4;
                } else if (preset === "ddos-flood") {
                    DOM.rangeDeviceTrust.value = 0.05;
                    DOM.valDeviceTrust.textContent = "0.05";
                    DOM.inputFailedLogins.value = 15;
                    DOM.rangeReqFreq.value = 220.0;
                    DOM.valReqFreq.textContent = "220.0";
                    DOM.inputApiRequests.value = 350;
                    DOM.inputDataMb.value = 180.0;
                    DOM.inputSynFlags.value = 650;
                } else if (preset === "data-exfil") {
                    DOM.rangeDeviceTrust.value = 0.25;
                    DOM.valDeviceTrust.textContent = "0.25";
                    DOM.inputFailedLogins.value = 4;
                    DOM.rangeReqFreq.value = 45.0;
                    DOM.valReqFreq.textContent = "45.0";
                    DOM.inputApiRequests.value = 180;
                    DOM.inputDataMb.value = 750.0;
                    DOM.inputSynFlags.value = 8;
                } else if (preset === "compromised-device") {
                    DOM.rangeDeviceTrust.value = 0.25;
                    DOM.valDeviceTrust.textContent = "0.25";
                    DOM.inputFailedLogins.value = 2;
                    DOM.rangeReqFreq.value = 6.0;
                    DOM.valReqFreq.textContent = "6.0";
                    DOM.inputApiRequests.value = 20;
                    DOM.inputDataMb.value = 5.0;
                    DOM.inputSynFlags.value = 2;
                }
            });
        });
    }

    // =========================================================================
    // OVERVIEW DATA LOADING
    // =========================================================================

    async function loadOverviewData() {
        try {
            const res = await fetch("/api/status");
            const status = await res.json();
            AppState.systemStatus = status;

            DOM.kpiThreatsCount.textContent = status.detected_threats_count || 0;
            DOM.kpiHighRiskUsers.textContent = status.high_risk_users_count || 0;
            DOM.kpiPendingApprovals.textContent = status.pending_human_approvals || 0;

            if (status.pending_human_approvals > 0) {
                DOM.sidebarApprovalsBadge.textContent = status.pending_human_approvals;
                DOM.sidebarApprovalsBadge.classList.remove("d-none");
            } else {
                DOM.sidebarApprovalsBadge.classList.add("d-none");
            }

            // Render Overview Users Table
            if (DOM.overviewUsersTbody && AppState.users.length > 0) {
                DOM.overviewUsersTbody.innerHTML = "";
                AppState.users.forEach(u => {
                    const tr = document.createElement("tr");
                    const decision = u.current_access_decision || "ALLOW";
                    const badgeClass = getDecisionBadgeClass(decision);
                    tr.innerHTML = `
                        <td>
                            <div class="fw-bold text-light">${u.name}</div>
                            <div class="extra-small font-mono text-muted">${u.id}</div>
                        </td>
                        <td>
                            <div class="text-light">${u.role}</div>
                            <div class="extra-small text-muted">${u.department || 'Cloud Platform'}</div>
                        </td>
                        <td class="font-mono">${parseFloat(u.device_trust_score).toFixed(2)}</td>
                        <td class="font-mono text-info">${parseFloat(u.current_threat_score || 0.05).toFixed(3)}</td>
                        <td class="font-mono text-warning">${parseFloat(u.current_risk_score || 0.05).toFixed(3)}</td>
                        <td><span class="badge-soc ${badgeClass}">${decision}</span></td>
                        <td><span class="badge-soc info extra-small">${u.effective_permissions_count || 0} Permissions Active</span></td>
                        <td>
                            <button class="soc-btn soc-btn-outline soc-btn-sm btn-inspect-user" data-uid="${u.id}">
                                <i class="fa-solid fa-sliders"></i>
                                <span>Inspect</span>
                            </button>
                        </td>
                    `;
                    tr.querySelector(".btn-inspect-user").addEventListener("click", () => {
                        selectUser(u.id);
                        switchView("view-users");
                    });
                    DOM.overviewUsersTbody.appendChild(tr);
                });
            }

            // Services Table
            const sRes = await fetch("/api/services");
            const sData = await sRes.json();
            if (DOM.overviewServicesTbody && sData.services) {
                DOM.overviewServicesTbody.innerHTML = "";
                sData.services.forEach(s => {
                    const tr = document.createElement("tr");
                    const isHealthy = s.status === "HEALTHY";
                    tr.innerHTML = `
                        <td class="fw-bold text-light">${s.name}</td>
                        <td class="font-mono text-muted">${s.ip}</td>
                        <td>${s.instances}</td>
                        <td><span class="badge-soc ${isHealthy ? 'safe' : 'danger'}">${s.status}</span></td>
                    `;
                    DOM.overviewServicesTbody.appendChild(tr);
                });
            }

            
            // Recent Events Table — live AARC telemetry
            const eRes = await fetch("/api/events");
            if (!eRes.ok) {
                throw new Error(`AARC Events API returned HTTP ${eRes.status}`);
            }

            const eData = await eRes.json();
            if (DOM.overviewEventsTbody) {
                DOM.overviewEventsTbody.innerHTML = "";
                const recent = Array.isArray(eData.events)
                    ? eData.events.slice(-8).reverse()
                    : [];

                if (recent.length === 0) {
                    DOM.overviewEventsTbody.innerHTML =
                        '<tr><td colspan="4" class="text-muted">No AARC telemetry received yet.</td></tr>';
                }

                const fmt = (value, digits = 0) =>
                    value !== null && value !== undefined && value !== "" &&
                    Number.isFinite(Number(value))
                        ? Number(value).toFixed(digits) : "n/a";

                recent.forEach(e => {
                    const tr = document.createElement("tr");
                    const prediction = e.prediction || {};
                    const classification = prediction.predicted_class || "Unclassified";
                    const riskClass = classification === "Malicious" ? "danger"
                        : classification === "Suspicious" ? "warn" : "safe";

                    const parsedTime = e.timestamp ? new Date(e.timestamp) : null;
                    const timestamp = parsedTime && !Number.isNaN(parsedTime.getTime())
                        ? parsedTime.toLocaleString() : "Unknown";
                    const subject = `${e.client_id || e.user_id || "Host telemetry"} · ${e.source || "AARC"}`;
                    const activity = `Packets ${fmt(e.total_fwd_packets)} F / ${fmt(e.total_bwd_packets)} B · CPU ${fmt(e.cpu_usage_pct, 1)}% · Memory ${fmt(e.memory_usage_pct, 1)}% · Threat ${fmt(prediction.threat_score, 3)}`;

                    [timestamp, subject, classification, activity].forEach((value, index) => {
                        const td = document.createElement("td");

                        if (index === 2 && classification !== "Unclassified") {
                            const badge = document.createElement("span");
                            badge.className = `badge-soc ${riskClass} extra-small`;
                            badge.textContent = classification;
                            td.appendChild(badge);
                        } else {
                            td.textContent = value;
                        }

                        if (index === 0) td.className = "extra-small text-muted font-mono";
                        if (index === 1) td.className = "font-mono text-light";
                        if (index === 2 && classification === "Unclassified") td.className = "text-muted";
                        if (index === 3) td.className = "extra-small font-mono text-muted";

                        tr.appendChild(td);
                    });

                    DOM.overviewEventsTbody.appendChild(tr);
                });
            }
        } catch (err) {
            console.error("Failed to load overview data:", err);
        }
    }

    // =========================================================================
    // SAFETY APPROVALS & RESPONSE HANDLING
    // =========================================================================
    
    async function loadAwsInstances() {
        if (!DOM.awsInstancesTbody || !DOM.awsConnectionStatus) return;

        try {
            const res = await fetch("/api/aws/instances");

            if (!res.ok) {
                throw new Error(`AWS API returned HTTP ${res.status}`);
            }

            const data = await res.json();

            if (data.status !== "SUCCESS") {
                throw new Error("AWS instance retrieval failed");
            }

            DOM.awsConnectionStatus.textContent = "CONNECTED";
            DOM.awsConnectionStatus.className = "badge-soc safe";
            DOM.awsInstancesTbody.innerHTML = "";

            if (!data.instances || data.instances.length === 0) {
                DOM.awsInstancesTbody.innerHTML =
                    '<tr><td colspan="5" class="text-muted">No EC2 instances found.</td></tr>';
                return;
            }

            data.instances.forEach(instance => {
                const tr = document.createElement("tr");
                const state = instance.state || "unknown";
                const stateClass = state === "running" ? "safe" : "warn";

                tr.innerHTML = `
                    <td class="fw-bold text-light">${instance.name}</td>
                    <td class="font-mono text-muted">${instance.instance_id}</td>
                    <td>${instance.instance_type || "—"}</td>
                    <td><span class="badge-soc ${stateClass}">${state.toUpperCase()}</span></td>
                    <td class="font-mono">${instance.availability_zone || "—"}</td>
                `;

                DOM.awsInstancesTbody.appendChild(tr);
            });
        } catch (err) {
            console.error("Failed to load AWS instances:", err);
            DOM.awsConnectionStatus.textContent = "UNAVAILABLE";
            DOM.awsConnectionStatus.className = "badge-soc danger";
            DOM.awsInstancesTbody.innerHTML =
                '<tr><td colspan="5" class="text-muted">Unable to load AWS resources. Check the API and server logs.</td></tr>';
        }
    }
    
    async function loadCloudTrailEvents() {
        if (!DOM.cloudtrailEventsTbody || !DOM.cloudtrailStatus) return;

        try {
            const res = await fetch("/api/aws/analyze");

            if (!res.ok) {
                throw new Error(`CloudTrail analysis API returned HTTP ${res.status}`);
            }

            const data = await res.json();

            if (data.status !== "SUCCESS") {
                throw new Error("CloudTrail analysis failed");
            }

            DOM.cloudtrailStatus.textContent = "CONNECTED · RULE ANALYSIS";
            DOM.cloudtrailStatus.className = "badge-soc safe";
            DOM.cloudtrailEventsTbody.innerHTML = "";

            if (!data.events || data.events.length === 0) {
                DOM.cloudtrailEventsTbody.innerHTML =
                    '<tr><td colspan="6" class="text-muted">No recent AWS events found.</td></tr>';
                return;
            }

            data.events.forEach(event => {
                const tr = document.createElement("tr");
                const timestamp = event.time
                    ? event.time.replace("T", " ").replace("+00:00", "")
                    : "Unknown";

    
            const risk = event.triage_risk || "LOW";
            const contextual = event.contextual_risk_assessment || {};
            const zt = event.zero_trust_assessment || {};
            const response = event.response_recommendation || {};

            const riskClass = risk === "HIGH"
                ? "danger"
                : risk === "MEDIUM" ? "warning" : "safe";

            const score = Number(contextual.overall_risk);
            const riskDisplay = contextual.risk_level &&
                Number.isFinite(score)
                ? `${risk} / ${contextual.risk_level} (${score.toFixed(2)})`
                : risk;

            const reasons = Array.isArray(event.triage_reasons)
                ? event.triage_reasons.join(" ")
                : "No reason supplied.";

            const details = [
                reasons,
                zt.access_decision
                    ? `Zero Trust: ${zt.access_decision}.` : "",
                response.recommended_action
                    ? `Recommended response: ${response.recommended_action}; simulation only, not executed.`
                    : ""
            ].filter(Boolean);

            const cells = [
                timestamp,
                event.event_name || "Unknown",
                event.event_source || "Unknown",
                event.username || "Unknown",
                riskDisplay,
                details.join(" ")
            ];

            cells.forEach((value, index) => {
                    const td = document.createElement("td");
                    td.textContent = value;
                    if (index === 0) td.className = "extra-small font-mono text-muted";
                    if (index === 1) td.className = "fw-bold text-light";
                    if (index === 2) td.className = "font-mono text-info";
                    if (index === 3) td.className = "font-mono text-muted";
                    if (index === 4) {
                        td.className = `badge-soc ${riskClass}`;
                    }
                    if (index === 5) td.className = "text-muted small";
                    tr.appendChild(td);
                });

                DOM.cloudtrailEventsTbody.appendChild(tr);
            });
        } catch (err) {
            console.error("Failed to load CloudTrail analysis:", err);
            DOM.cloudtrailStatus.textContent = "UNAVAILABLE";
            DOM.cloudtrailStatus.className = "badge-soc danger";
            DOM.cloudtrailEventsTbody.innerHTML =
                '<tr><td colspan="6" class="text-muted">Unable to load AWS analysis. Check the API and server logs.</td></tr>';
        }
    }

    async function loadPendingApprovals() {
        try {
            const res = await fetch("/api/pending-approvals");
            const data = await res.json();
            AppState.pendingApprovals = data.pending_approvals || [];
            AppState.actionHistory = data.action_history || [];

            DOM.responsePendingCountBadge.textContent = `${AppState.pendingApprovals.length} PENDING`;

            if (DOM.responsePendingApprovalsList) {
                DOM.responsePendingApprovalsList.innerHTML = "";
                if (AppState.pendingApprovals.length === 0) {
                    DOM.responsePendingApprovalsList.innerHTML = `
                        <div class="text-muted small py-3 text-center">
                            <i class="fa-solid fa-circle-check text-success me-2"></i>No high-impact actions currently pending operator authorization.
                        </div>
                    `;
                } else {
                    AppState.pendingApprovals.forEach(item => {
                        const card = document.createElement("div");
                        card.className = "approval-card-item";
                        card.innerHTML = `
                            <div class="d-flex justify-content-between align-items-center mb-2">
                                <div class="fw-bold text-light"><i class="fa-solid fa-triangle-exclamation text-warning me-2"></i>Action Intercepted: <span class="font-mono text-warning">${item.final_action}</span></div>
                                <span class="badge-soc danger">REQUIRE HUMAN APPROVAL</span>
                            </div>
                            <div class="extra-small text-light mb-2">${item.safety_rationale}</div>
                            <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 pt-2 border-top border-secondary border-opacity-25">
                                <div class="extra-small font-mono text-muted">Target: ${item.target} | Action ID: ${item.action_id}</div>
                                <div class="d-flex gap-2">
                                    <button class="soc-btn soc-btn-success soc-btn-sm btn-approve" data-id="${item.action_id}">
                                        <i class="fa-solid fa-check"></i> Authorize & Dispatch
                                    </button>
                                    <button class="soc-btn soc-btn-danger soc-btn-sm btn-reject" data-id="${item.action_id}">
                                        <i class="fa-solid fa-xmark"></i> Reject
                                    </button>
                                </div>
                            </div>
                        `;
                        card.querySelector(".btn-approve").addEventListener("click", () => resolveApproval(item.action_id, true));
                        card.querySelector(".btn-reject").addEventListener("click", () => resolveApproval(item.action_id, false));
                        DOM.responsePendingApprovalsList.appendChild(card);
                    });
                }
            }

            // History Table
            if (DOM.responseHistoryTbody) {
                DOM.responseHistoryTbody.innerHTML = "";
                AppState.actionHistory.slice(-10).reverse().forEach(act => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td class="extra-small font-mono text-muted">${(act.timestamp || "").split("T")[1]?.slice(0, 8) || 'Now'}</td>
                        <td class="font-mono text-info extra-small">${act.action_id}</td>
                        <td class="font-mono text-light fw-bold">${act.final_action}</td>
                        <td class="text-light">${act.target}</td>
                        <td><span class="badge-soc ${['EXECUTE', 'NOT_REQUIRED'].includes(act.safety_decision) ? 'safe' : (act.safety_decision === 'REQUIRE_HUMAN_APPROVAL' ? 'warn' : 'danger')} extra-small">${act.safety_decision}</span></td>
                        <td class="font-mono text-muted">${act.response_time_ms != null && Number.isFinite(Number(act.response_time_ms)) ? Number(act.response_time_ms).toFixed(2) + ' ms' : '—'}</td>
                        <td><span class="badge-soc ${['NO_ACTION', 'COMPLETED', 'APPROVED_AND_EXECUTED'].includes(act.status) ? 'safe' : (act.status === 'PENDING_APPROVAL' ? 'warn' : 'muted')} extra-small">${act.status}</span></td>
                    `;
                    DOM.responseHistoryTbody.appendChild(tr);
                });
            }
        } catch (err) {
            console.error("Failed to load approvals:", err);
        }
    }

    async function resolveApproval(actionId, approved) {
        try {
            const res = await fetch("/api/approve-action", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ action_id: actionId, approved: approved })
            });
            const result = await res.json();
            if (result.status === "RESOLVED") {
                await loadPendingApprovals();
                await loadOverviewData();
            }
        } catch (err) {
            console.error("Failed to resolve approval:", err);
        }
    }

    // =========================================================================
    // SELF-HEALING SIMULATION
    // =========================================================================

    if (DOM.btnTriggerSelfHealing) {
        DOM.btnTriggerSelfHealing.addEventListener("click", async () => {
            const svcId = DOM.healingSelectService.value;
            const svcName = DOM.healingSelectService.options[DOM.healingSelectService.selectedIndex].text;
            const attackType = DOM.healingSelectAttack.value;

            try {
                DOM.btnTriggerSelfHealing.disabled = true;
                DOM.btnTriggerSelfHealing.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-2"></i>EXECUTING 5-PHASE RECOVERY...';

                const res = await fetch("/api/self-healing/simulate", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ service_id: svcId, service_name: svcName, attack_type: attackType })
                });

                const result = await res.json();
                if (result.status === "SUCCESS") {
                    const record = result.record;
                    const stats = result.stats;

                    DOM.healingSuccessCount.textContent = stats.successful_recoveries;
                    DOM.healingAvgMttr.textContent = `${stats.avg_recovery_time_sec}s`;
                    DOM.healingLatestHealth.textContent = record.health_score;

                    // Prepend to history table
                    if (DOM.healingHistoryTbody) {
                        const tr = document.createElement("tr");
                        tr.innerHTML = `
                            <td class="extra-small font-mono text-muted">${(record.timestamp || "").split("T")[1]?.slice(0, 8) || 'Now'}</td>
                            <td class="font-mono text-info extra-small">${record.recovery_id}</td>
                            <td class="fw-bold text-light">${record.service_name}</td>
                            <td class="extra-small text-warning font-mono">${record.attack_type}</td>
                            <td class="font-mono text-light extra-small">${record.restored_instance_id}</td>
                            <td class="font-mono text-success fw-bold">${record.recovery_time_sec}s</td>
                            <td class="font-mono text-info">${record.health_score}</td>
                            <td><span class="badge-soc safe extra-small">SUCCESS</span></td>
                        `;
                        DOM.healingHistoryTbody.prepend(tr);
                    }
                }
            } catch (err) {
                console.error("Self healing simulation error:", err);
            } finally {
                DOM.btnTriggerSelfHealing.disabled = false;
                DOM.btnTriggerSelfHealing.innerHTML = '<i class="fa-solid fa-play me-2"></i>TRIGGER RECOVERY SIMULATION';
            }
        });
    }

    // =========================================================================
    // RESEARCH SCENARIOS
    // =========================================================================

    document.querySelectorAll(".scenario-card-btn").forEach(btn => {
        btn.addEventListener("click", async () => {
            const scenarioId = btn.dataset.scenario;
            try {
                const res = await fetch(`/api/scenarios/${scenarioId}`, { method: "POST" });
                const data = await res.json();
                if (data.status === "SUCCESS") {
                    const s = data.scenario;
                    DOM.scenarioTracePanel.classList.remove("d-none");
                    DOM.scenarioTraceTitle.textContent = s.scenario_title;
                    DOM.scenarioTraceContent.innerHTML = `
                        <div><b>Subject:</b> ${s.user_profile.name} (${s.user_profile.role})</div>
                        <div><b>Expected Outcome:</b> ${s.expected_behavior}</div>
                        <div class="mt-2 text-warning"><b>Threat Score (T):</b> ${s.threat_detection.threat_score.toFixed(3)} | <b>Class:</b> ${s.threat_detection.predicted_class}</div>
                        <div class="text-info"><b>Adaptive Policy Context:</b> ${s.adaptive_policy.context_name}</div>
                        <div class="text-success"><b>Dynamic Risk (R):</b> ${s.risk_assessment.overall_risk.toFixed(3)} &rarr; <b>Zero-Trust Decision:</b> ${s.zero_trust_decision.access_decision}</div>
                        <div class="text-light"><b>Autonomous Response:</b> ${s.response_action.final_action || s.response_action.proposed_action} (${s.response_action.safety_decision})</div>
                    `;

                    // Select and load this user across console
                    await selectUser(s.user_id);
                    await loadOverviewData();
                    await loadPendingApprovals();
                }
            } catch (err) {
                console.error(`Failed to execute scenario ${scenarioId}:`, err);
            }
        });
    });

    async function loadFiguresGallery() {
        if (!DOM.researchFiguresGrid) return;
        try {
            const res = await fetch("/api/results/figures");
            const data = await res.json();
            if (data.status === "SUCCESS" && data.figures) {
                DOM.researchFiguresGrid.innerHTML = "";
                const orderedFigures = data.figures.slice().sort((a, b) => {
                    const numberFor = name => {
                        if (/^figure1_architecture\.png$/i.test(name)) return 0;
                        const match = name.match(/^fig(\d+)/i);
                        return match ? Number(match[1]) : 999;
                    };
                    return numberFor(a) - numberFor(b) ||
                           a.localeCompare(b);
                });
                orderedFigures.forEach(fig => {
                    const col = document.createElement("div");
                    col.className = "col-12 col-md-6 col-xxl-4";
                    const cleanTitle = fig.replace(".png", "").replace(/_/g, " ").toUpperCase();
                    col.innerHTML = `
                        <div class="soc-card h-100 mb-0">
                            <div class="soc-card-header py-2">
                                <span class="extra-small fw-bold text-light">${cleanTitle}</span>
                            </div>
                            <div class="soc-card-body p-2 text-center"
                                 style="background:#ffffff; min-height:220px; display:flex; align-items:center; justify-content:center;">
                                <img src="/results/figures/${fig}?v=20261025c" alt="${cleanTitle}" class="img-fluid rounded"
                                     style="width:100%; max-height:210px; object-fit:contain; background:#ffffff;">
                            </div>
                        </div>
                    `;
                    DOM.researchFiguresGrid.appendChild(col);
                });
            }
        } catch (err) {
            console.error("Failed to load figures gallery:", err);
        }
    }

    // =========================================================================
    // HELPER STYLING UTILITIES
    // =========================================================================

    function getDecisionBadgeClass(decision) {
        if (decision === "ALLOW") return "safe";
        if (decision === "ALLOW + MONITOR") return "warn";
        if (decision === "RESTRICT") return "danger";
        if (decision === "ISOLATE") return "danger";
        if (decision === "BLOCK + RESPONSE") return "danger";
        return "muted";
    }

    function getRiskBadgeClass(level) {
        if (level === "LOW") return "safe";
        if (level === "MEDIUM") return "warn";
        if (level === "HIGH") return "danger";
        if (level === "CRITICAL") return "danger";
        return "muted";
    }

    function getTextColorClass(decision) {
        if (decision === "ALLOW") return "text-success";
        if (decision === "ALLOW + MONITOR") return "text-warning";
        return "text-danger";
    }

    function getClassColor(predClass) {
        if (predClass === "Benign") return "text-success";
        if (predClass === "Suspicious") return "text-warning";
        return "text-danger";
    }

    function renderEffectiveStatusBadge(status, effective) {
        if (status === "ACTIVE") {
            return '<span class="badge-soc safe extra-small"><i class="fa-solid fa-check me-1"></i>ACTIVE</span>';
        }
        if (status === "ACTIVE_MONITORED") {
            return '<span class="badge-soc warn extra-small"><i class="fa-solid fa-eye me-1"></i>MONITORED</span>';
        }
        if (status === "ACTIVE_READ_ONLY") {
            return '<span class="badge-soc warn extra-small"><i class="fa-solid fa-lock me-1"></i>READ ONLY</span>';
        }
        if (status === "REVOKED_ZERO_TRUST") {
            return '<span class="badge-soc danger extra-small"><i class="fa-solid fa-ban me-1"></i>REVOKED</span>';
        }
        if (status === "QUARANTINED" || status === "BLOCKED") {
            return '<span class="badge-soc danger extra-small"><i class="fa-solid fa-xmark me-1"></i>BLOCKED</span>';
        }
        return '<span class="badge-soc muted extra-small">NOT ASSIGNED</span>';
    }

    // Refresh Matplotlib analytics without reloading the dashboard.
    const refreshAnalyticsButton =
        document.getElementById("refresh-analytics-charts");

    if (refreshAnalyticsButton) {
        refreshAnalyticsButton.addEventListener("click", () => {
            document.querySelectorAll("img.analytics-chart").forEach(img => {
                const url = new URL(img.src, window.location.origin);
                url.searchParams.set("refresh", Date.now().toString());
                img.src = url.toString();
            });
        });
    }

    // Start App
    initApp();
});
