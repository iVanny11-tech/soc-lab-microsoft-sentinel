# Project ATLAS — Tier 1→2 Escalation Guide & SOAR Playbook

**Document ID:** ATLAS-SOAR-001  
**Version:** 1.0  
**Author:** Ivan Yamoah Baoakye  
**Date:** July 5, 2026  
**Scope:** Microsoft Sentinel + Entra ID Protection + Microsoft Defender XDR  
**Incident Reference:** Incident ID 2 — Initial access involving one user (Compromised account)

---

## Purpose

This document serves two functions:

1. **Escalation Guide** — A structured Tier 1 decision framework for triaging cloud identity incidents in the Microsoft security stack, defining exactly when and how to escalate to Tier 2
2. **SOAR Playbook** — A Logic App–based automated response design for anonymous IP / Tor sign-in detections in Microsoft Sentinel, reducing mean time to respond (MTTR) through automation

Both sections are grounded in the actual Project ATLAS incident: a Tor-based anonymous IP sign-in that generated 8 correlated alerts, was not auto-contained, and required 35 hours from detection to analyst triage due to absence of automation.

---

## Part 1 — Tier 1 Escalation Framework

### 1.1 Alert Triage Decision Tree

```
ALERT ARRIVES IN INCIDENT QUEUE (Defender XDR / Sentinel)
│
├─► Is severity INFORMATIONAL or LOW?
│       └─► Tier 1: Review, document, close as False Positive or Expected behavior
│
├─► Is severity MEDIUM?
│       └─► Tier 1: Full triage (steps 1.2 below)
│               └─► Does entity have active risk score or prior incidents? → ESCALATE TO TIER 2
│
└─► Is severity HIGH or CRITICAL?
        └─► Tier 1: Immediate triage + containment attempt (steps 1.2 + 1.3)
                └─► Cannot contain within 15 min? → ESCALATE TO TIER 2
                └─► Involves admin account, data exfiltration, or persistence? → ESCALATE TO TIER 2 immediately
```

---

### 1.2 Tier 1 Triage Checklist (Standard)

Apply to every Medium/High incident before touching any remediation action:

**Step 1 — Review the incident graph**
- Open incident in security.microsoft.com → Incidents & Alerts
- Confirm entities: which user, which device, which IP, which cloud app
- Check alert timeline for sequence — single event vs. sustained activity
- Note AI-generated technique profile (if present)

**Step 2 — Confirm entity context**
- User: Is this a service account, admin account, or standard user? Check Entra ID admin roles
- Device: Is it enrolled in Defender for Endpoint? Is it a managed or unmanaged device?
- IP: Is it known? Run against threat intel (if available). Check Entra Named Locations
- Cloud app: Is this a sanctioned app? Was this user expected to access it at this time?

**Step 3 — Check for prior activity**
- Search Entra ID Sign-in logs for the user over the prior 30 days — is this behaviorally anomalous?
- Check Risky users panel — was this user already flagged before the incident?
- Query SigninLogs for the same IP across all users — is this IP hitting other accounts?

**Step 4 — Classify**
- True positive (TP): Alert maps to real attacker activity matching the described technique
- False positive (FP): Alert fired on benign activity — document why and update detection logic
- True positive — Benign (TP-B): Alert fired correctly, but activity was authorized (e.g., red team, pen test)

**Step 5 — Add incident comment**
Minimum comment format:
```
[DATE] [ANALYST] — Triage complete.
Classification: [TP/FP/TP-B]
Entities confirmed: [USER] / [DEVICE] / [IP]
Evidence: [1-2 sentence summary of what you observed]
Action taken: [describe what you did or why you escalated]
```

---

### 1.3 Tier 1 Containment Actions (Before Escalation)

These are actions Tier 1 can take immediately without Tier 2 approval for a confirmed TP cloud identity incident:

| Action | How | When to use |
|---|---|---|
| Confirm user compromised | Entra ID Protection → Risky users → Confirm compromised | TP sign-in from anonymous IP, confirmed not authorized |
| Reset user password | Entra admin center → Users → [user] → Reset password | After Confirm compromised |
| Revoke all active sessions | Entra admin center → Users → [user] → Revoke sessions | Immediately on TP compromise |
| Isolate endpoint (EDR) | Defender for Endpoint → Devices → [device] → Isolate | If MDE is enrolled and TP malware/intrusion confirmed |
| Manual host firewall isolation | Windows Firewall → netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound | If no MDE — last resort, severs telemetry too |
| Disable Conditional Access sign-in | Entra admin center → Users → [user] → Block sign-in | For admin accounts pending investigation |

**Do NOT do before Tier 2 review:**
- Delete accounts or mailboxes
- Revoke OAuth application tokens tenant-wide
- Modify Conditional Access policies from Report-only to On without approval
- Wipe or factory-reset devices

---

### 1.4 Escalation Criteria (Mandatory Tier 2 Handoff)

Escalate to Tier 2 immediately if any of the following is true:

| Condition | Why it requires Tier 2 |
|---|---|
| Compromised account has Global Administrator or Privileged Role Administrator role | Blast radius is entire tenant |
| Evidence of lateral movement to additional accounts or devices | Scope unknown — T2 needed for full investigation |
| Persistence artifacts found (new OAuth apps, new service principals, scheduled tasks, registry run keys) | Eradication requires deep knowledge of the environment |
| Data access or exfiltration suspected (SharePoint, OneDrive, Exchange) | Legal, compliance, and forensic considerations |
| Incident involves more than 5 entities or spans cloud + on-prem | Complexity exceeds Tier 1 scope |
| Custom detection rule appears to have misfired or missed the full scope | Rule tuning and detection engineering is T2 |
| Attack technique is in the top 10 current threat intel TTPs (e.g. ransomware precursor) | Elevated urgency, may require CISO notification |

---

### 1.5 Escalation Handoff Template

When handing off to Tier 2, populate this template in the incident comment thread:

```
TIER 2 ESCALATION — [INCIDENT ID] — [DATE TIME]

Escalating analyst: [NAME]
Escalation reason: [one of the criteria from 1.4]

Summary:
- Affected user: [UPN] — Admin/Standard/Service account
- Affected device: [hostname] — Managed/Unmanaged — MDE enrolled: Y/N
- Attack timeline: [first event datetime] → [most recent event datetime]
- Technique(s): [MITRE IDs]
- Containment actions already taken: [list from 1.3]

Outstanding risks:
- [What hasn't been contained yet]
- [What is still unknown]

Priority: [P1 CRITICAL / P2 HIGH / P3 MEDIUM]
```

---

## Part 2 — SOAR Playbook Design

### 2.1 Playbook Overview

**Playbook name:** ATLAS-PB-001 — Auto-Respond: High Risk Sign-in from Anonymous IP  
**Trigger:** Microsoft Sentinel incident created — when alert rule "Entra ID Protection: Anonymous IP address sign-in" fires  
**Automation type:** Microsoft Sentinel Playbook (Azure Logic App)  
**Authentication:** Managed Identity (preferred) or API Connection with OAuth  
**Estimated MTTR reduction:** From 35 hours (human triage) → ~3 minutes (automated response + notification)

---

### 2.2 Playbook Logic — Step by Step

```
TRIGGER: Sentinel Incident Created
│
│  Input: Incident.Entities → extract UserPrincipalName, IPAddress
│
├─► STEP 1: Enrich the incident
│   Action: HTTP GET → Microsoft Graph API
│   Endpoint: GET /users/{UPN}/authentication/methods
│   Purpose: Confirm whether user has MFA registered (informs urgency)
│   Output: MFA registered: True/False → store as variable
│
├─► STEP 2: Check user risk level
│   Action: HTTP GET → Microsoft Graph API
│   Endpoint: GET /identityProtection/riskyUsers?$filter=userPrincipalName eq '{UPN}'
│   Purpose: Get current riskLevel (none/low/medium/high)
│   Output: CurrentRiskLevel → store as variable
│
├─► CONDITION: Is riskLevel "high" OR incident severity "High"?
│   ├─► YES → BRANCH A (High-risk auto-response)
│   └─► NO  → BRANCH B (Medium-risk notification)
│
│  BRANCH A — High Risk
│  ├─► STEP 3A: Confirm user compromised
│  │   Action: HTTP POST → Microsoft Graph API
│  │   Endpoint: POST /identityProtection/riskyUsers/confirmCompromised
│  │   Body: { "userIds": ["{userId}"] }
│  │   Purpose: Sets user risk state to "confirmed compromised" — triggers remediation policies
│  │
│  ├─► STEP 4A: Revoke all active sessions
│  │   Action: HTTP POST → Microsoft Graph API
│  │   Endpoint: POST /users/{userId}/revokeSignInSessions
│  │   Purpose: Immediately terminates all active access tokens
│  │
│  ├─► STEP 5A: Add incident comment documenting automated actions
│  │   Action: Sentinel — Add Comment to Incident
│  │   Comment: "ATLAS-PB-001 AUTO RESPONSE: User [UPN] confirmed compromised, sessions revoked.
│  │             MFA registered: [True/False]. Requires analyst review for password reset
│  │             and persistence check. Automated at [timestamp]."
│  │
│  └─► STEP 6A: Notify on-call via Teams/Email
│      Action: Send Teams message + Email
│      Target: SOC-oncall channel / on-call distribution list
│      Message: "🔴 HIGH RISK SIGN-IN AUTO-CONTAINED | Incident [ID] | User: [UPN]
│                IP: [IP] (Tor exit node) | Actions taken: Confirmed compromised,
│                sessions revoked | REVIEW REQUIRED: password reset + persistence check"
│
│  BRANCH B — Medium Risk
│  ├─► STEP 3B: Add informational incident comment
│  │   Comment: "ATLAS-PB-001 NOTIFICATION: Medium-risk sign-in detected for [UPN]
│  │             from anonymous IP [IP]. No automated containment taken at Medium risk.
│  │             Analyst review required within SLA."
│  │
│  └─► STEP 4B: Notify SOC analyst queue via Teams
│      Message: "🟡 MEDIUM RISK SIGN-IN | Incident [ID] | User: [UPN] | IP: [IP]
│                Requires analyst triage within [SLA]. No auto-action taken."
│
└─► STEP FINAL: Update Sentinel incident status
    Action: Sentinel — Update Incident
    Status: In Progress (from New)
    Owner: Assigned to "ATLAS-PB-001 automated triage"
    Purpose: Prevents incident from being missed in queue
```

---

### 2.3 Logic App ARM Template (Simplified)

The following is a representative excerpt of what the Logic App resource definition looks like in ARM/Bicep. This is for documentation and architecture reference — full deployment requires an Azure subscription with Sentinel and Logic Apps enabled.

```json
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "triggers": {
      "Microsoft_Sentinel_incident": {
        "type": "ApiConnectionWebhook",
        "inputs": {
          "host": { "connection": { "name": "@parameters('$connections')['azuresentinel']['connectionId']" } },
          "body": { "callback_url": "@{listCallbackUrl()}" },
          "path": "/incident-creation"
        }
      }
    },
    "actions": {
      "Get_Incident_Entities": {
        "type": "ApiConnection",
        "inputs": {
          "host": { "connection": { "name": "@parameters('$connections')['azuresentinel']['connectionId']" } },
          "method": "post",
          "path": "/Incidents/entities"
        }
      },
      "Confirm_User_Compromised": {
        "type": "Http",
        "inputs": {
          "method": "POST",
          "uri": "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/confirmCompromised",
          "authentication": { "type": "ManagedServiceIdentity" },
          "body": { "userIds": ["@{variables('userId')}"] }
        },
        "runAfter": { "Check_Risk_Level": ["Succeeded"] }
      },
      "Revoke_Sessions": {
        "type": "Http",
        "inputs": {
          "method": "POST",
          "uri": "https://graph.microsoft.com/v1.0/users/@{variables('userId')}/revokeSignInSessions",
          "authentication": { "type": "ManagedServiceIdentity" }
        },
        "runAfter": { "Confirm_User_Compromised": ["Succeeded"] }
      }
    }
  }
}
```

---

### 2.4 Required Permissions (Logic App Managed Identity)

The Logic App's managed identity must be granted the following Microsoft Graph API permissions:

| Permission | Type | Purpose |
|---|---|---|
| IdentityRiskyUser.ReadWrite.All | Application | Read risk level, confirm compromised |
| User.ReadWrite.All | Application | Revoke sessions, read user properties |
| SecurityIncident.ReadWrite.All | Application | Update Sentinel incidents, add comments |
| Directory.Read.All | Application | Read group memberships and admin roles |

**Also required:** The managed identity must be assigned the **Microsoft Sentinel Responder** role in the Sentinel workspace.

---

### 2.5 KQL Rule That Triggers This Playbook

```kql
// Analytics Rule: Entra ID Protection — Anonymous IP Sign-in (High Priority)
// Schedule: Run every 5 minutes, lookback 10 minutes
// Alert threshold: 1 or more

SigninLogs
| where TimeGenerated >= ago(10m)
| where RiskEventTypes has "anonymizedIPAddress"
| where RiskLevelDuringSignIn in ("medium", "high")
| where ResultType == "0"   // Successful sign-in only
| extend
    City     = tostring(LocationDetails.city),
    Country  = tostring(LocationDetails.countryOrRegion)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    City,
    Country,
    RiskLevelDuringSignIn,
    RiskEventTypes,
    AppDisplayName,
    CorrelationId
| order by TimeGenerated desc
```

**Alert mapping:**
- Entity: Account → UserPrincipalName
- Entity: IP → IPAddress
- Playbook trigger: On incident creation → ATLAS-PB-001

---

### 2.6 Playbook Test Plan

Before enabling in production, validate the playbook with these test cases:

| Test | Expected behaviour |
|---|---|
| Simulate sign-in from anonymous IP with Medium risk | Branch B fires: Teams notification sent, incident updated to In Progress, no auto-containment |
| Simulate sign-in from anonymous IP with High risk | Branch A fires: Confirm compromised API called, sessions revoked, Teams alert sent |
| Simulate High risk — user not found in Graph | Playbook exits gracefully (catch block), adds comment "User lookup failed — manual action required" |
| Simulate API failure on revokeSignInSessions | Retry 2x, then notify analyst: "Session revocation failed — manual intervention required" |
| Confirm Sentinel incident status updated | Incident status changes from New → In Progress with owner set to playbook name |

---

## Part 3 — Lessons Learned (SOAR Angle)

### From Incident ID 2 specifically

The 35-hour gap between Entra ID Protection's first anonymous IP alert (23:14 Jul 3) and analyst triage (10:56 Jul 5) is unacceptable in any real SOC with a production SLA. In this case it was a simulated environment with no 24/7 coverage — but the gap illustrates why SOAR exists.

Had ATLAS-PB-001 been operational:
- At T+0 (23:14): Incident created
- At T+~1 min: Playbook fires, confirms compromise, revokes sessions
- At T+~2 min: On-call notified with full context
- At T+~3 min: Analyst receives enriched incident, ready to review

The brute-force entry point (T1110.001) into the endpoint would still be unaddressed — because the endpoint telemetry gap (AMA failure) means the playbook has no data to act on there. This is the correct architecture insight: **SOAR makes your existing detection faster; it cannot compensate for missing detections.** Fix the telemetry gap first (R1 in PIR), then build the automation.

### Interview talking points derived from this playbook

1. "I designed a Logic App playbook that auto-confirms compromised users and revokes sessions on High-risk Entra ID Protection detections — reducing the manual response window from 35 hours to under 3 minutes"
2. "I explicitly kept Medium-risk detections in notification-only mode, because auto-blocking on Medium would cause false-positive lockouts — this mirrors the Report-only CA policy decision"
3. "I documented the playbook test plan before deployment — including failure paths — which is what you'd do before any production automation touches identity infrastructure"

---

*Document prepared by: Ivan Yamoah Baoakye | July 5, 2026*  
*Reference: Project ATLAS | law-soc-atlas | VANPASSSC200*
