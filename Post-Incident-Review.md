# Project ATLAS — Post-Incident Review (PIR) & Root Cause Analysis

**Incident ID:** 2  
**Title:** Initial access incident involving one user — Anonymous IP / Token Anomaly  
**Severity:** High  
**Classification:** True Positive — Compromised Account  
**Date of Incident:** 3–4 July 2026  
**Date of PIR:** 5 July 2026  
**Author:** Ivan Yamoah Baoakye  
**Status:** Closed

---

## 1. Incident Summary

On 3 July 2026 at 23:14 local time, Microsoft Entra ID Protection detected the first of five anonymous IP address sign-in events originating from Tor exit nodes in Germany (Karlsruhe, 2a03:4000:46:197:b434:d3ff:fe68:d9e1) and Sweden (2a0f:df00:0:255::194). The affected account was the tenant administrator (ivanyamoahbaoakye@VANPASSSC200.onmicrosoft.com) and a test account (soc-tor-test@VANPASSSC200.onmicrosoft.com).

Concurrently, Microsoft Defender XDR auto-correlated 8 identity risk alerts into Incident ID 2, generating a High-severity "Initial access incident involving one user." The AI-generated technique profile identified the attack pattern as "token theft and token replay for unauthorized access" with a threat overview of "Cloud identity abuse."

All sign-ins succeeded — no MFA or Conditional Access policy was in place to block or challenge sign-ins from anonymous IP addresses.

---

## 2. Timeline of Events

| Time (Local) | Event | Source |
|---|---|---|
| 3 Jul 23:14:11 | First Anonymous IP address detection fires | Entra ID Protection |
| 3 Jul 23:15:16 | Anomalous Token detection fires | Entra ID Protection |
| 3 Jul 23:17:22 | Incident ID 2 created in Defender XDR | Microsoft Defender |
| 3 Jul 23:17–23:18 | Three additional Anonymous IP + Anomalous Token alerts generated | Entra ID Protection |
| 4 Jul 00:07:04–00:07:08 | Two final Anonymous IP alerts (same Tor exit IP, Germany) | Entra ID Protection |
| 5 Jul 10:56 | Analyst opened incident, reviewed alert timeline and entity graph | SOC analyst |
| 5 Jul 10:56 | Incident classified: True positive — Compromised account | SOC analyst |
| 5 Jul 10:57 | Endpoint DESKTOP-TRF9U79 isolated via host-based firewall | SOC analyst |
| 5 Jul 11:00 | SOC Tor Test user confirmed compromised in Entra ID Protection | SOC analyst |
| 5 Jul 11:37 | Conditional Access policy created in Report-only mode | SOC analyst |

**Total time from first detection to analyst triage:** ~35 hours (simulated environment, no on-call coverage)  
**Total time from analyst engagement to containment:** ~4 minutes

---

## 3. Root Cause Analysis

### 3.1 Immediate Cause
A valid account (soc-tor-test@VANPASSSC200.onmicrosoft.com) was authenticated successfully via the Microsoft identity platform from Tor exit-node IP addresses. The authentication succeeded because:

1. The account was protected only by a username/password — no MFA was enforced
2. No Conditional Access policy existed to block or challenge sign-ins from high-risk IPs or anonymous proxies
3. Security Defaults had been disabled on the tenant (required for Conditional Access testing), removing the baseline MFA requirement

### 3.2 Contributing Factors

**CF-1: No risk-based Conditional Access policy**  
The tenant had no Conditional Access policy configured to act on Entra ID Protection's sign-in risk signals. Entra ID Protection detected the anonymous IP correctly, but had no enforcement mechanism to act on that detection. Detection without enforcement is visibility without defence.

**CF-2: Endpoint telemetry pipeline failure**  
Both the SecurityEvent (Windows Security Events via AMA) and Sysmon (Event table via AMA) pipelines were found to contain 0 records during threat hunting. As a result, the T1110.001 (brute force) and T1059.001/T1027 (encoded PowerShell) attacks generated no Sentinel alerts, leaving endpoint-layer detection completely blind. Root cause of the pipeline failure: AMA agent health issue on DESKTOP-TRF9U79 — exact trigger undetermined (likely agent restart after VM snapshot restore without re-registration).

**CF-3: No phishing-resistant MFA**  
The phishing simulation (T1566.002) achieved 100% compromise (1/1 click, 1/1 credential submission), confirming that users have no phishing-resistant authentication factor. FIDO2 keys or Microsoft Authenticator with number matching would have prevented credential theft even on a successful phishing click.

**CF-4: Absence of Named Locations / Trusted IP configuration**  
No Named Locations were configured in Conditional Access. Configuring known safe IP ranges (e.g., home network, office ranges) would have reduced false-positive risk for sign-in risk policies and allowed a tighter block scope.

### 3.3 Why It Was Not Detected Earlier
The incident was not detected in real time for two reasons:
1. No on-call analyst was monitoring the incident queue (simulated environment with no 24/7 coverage)
2. The endpoint-layer custom KQL detection rules (Sentinel analytics rules 4.1 and 4.2) were non-functional due to empty telemetry tables — meaning no alerts fired for the brute force or PowerShell attacks

Detection occurred through cloud identity telemetry (Entra ID Protection) which operates independently of the endpoint AMA pipeline.

---

## 4. Impact Assessment

| Impact Area | Assessment |
|---|---|
| Data exfiltration | None — test tenant, no sensitive data |
| Lateral movement | None confirmed — limited to cloud identity layer |
| Persistence | None — no OAuth tokens or app registrations created by attacker |
| Availability | None — no service disruption |
| Detection coverage | High impact — endpoint telemetry gap leaves T1110.001 and T1059.001 blind |
| Identity risk | Medium — successful Tor sign-in to test account; admin account also flagged |

---

## 5. Containment & Remediation Actions

### Immediate (completed)
- [x] Incident classified True positive — Compromised account
- [x] DESKTOP-TRF9U79 isolated via host-based Windows Firewall (BlockInbound,BlockOutbound)
- [x] SOC Tor Test confirmed compromised in Entra ID Protection (automated remediation initiated)
- [x] Conditional Access policy created: ATLAS - Block sign-in risk (anonymous IP) — Report-only mode

### Short-term (recommended)
- [ ] Diagnose AMA agent health on DESKTOP-TRF9U79 (check Heartbeat table, re-register agent if needed)
- [ ] Validate SecurityEvent and Sysmon Event DCRs are receiving data after remediation
- [ ] Flip Conditional Access policy from Report-only to On after confirming no false-positive lockout risk
- [ ] Enable phishing-resistant MFA (Microsoft Authenticator number matching or FIDO2) for all accounts
- [ ] Configure Named Locations for known safe IP ranges

### Long-term (recommended)
- [ ] Deploy Microsoft Defender for Endpoint on DESKTOP-TRF9U79 for richer endpoint telemetry (replaces Sysmon/AMA for process, file, and network telemetry)
- [ ] Implement SOAR automation: Sentinel Logic App playbook to auto-block risky user sign-ins and notify on-call analyst
- [ ] Build ATT&CK Navigator coverage heatmap and schedule quarterly review
- [ ] Run Attack Simulation Training on a monthly cadence with mandatory awareness training for failed users

---

## 6. Detection Effectiveness Review

| Detection Rule | Expected to Fire | Actually Fired | Reason |
|---|---|---|---|
| ATLAS - Brute force failed logon spike (4.1) | Yes | No | SecurityEvent table = 0 records (AMA issue) |
| ATLAS - Encoded PowerShell execution (4.2) | Yes | No | Sysmon Event table = 0 records (AMA issue) |
| OOB: SecurityEvent - Multiple auth failures + success | Yes | No | SecurityEvent table = 0 records |
| Entra ID Protection: Anonymous IP address | Yes | **Yes** ✅ | Cloud identity telemetry independent of AMA |
| Entra ID Protection: Anomalous Token | Possible | **Yes** ✅ | Cloud identity telemetry independent of AMA |

**Detection coverage score: 2/5 rules fired (40%) — endpoint layer completely blind**

---

## 7. Lessons Learned

### What went well
1. **Cloud identity detection was fast and accurate** — Entra ID Protection fired within seconds of the Tor sign-in, with no configuration required beyond enabling the P2 licence
2. **Incident auto-correlation saved triage time** — 8 individual alerts were grouped into 1 actionable incident automatically
3. **Proactive threat hunting surfaced the telemetry gap** — without the hunting step, the AMA pipeline failure would have remained invisible
4. **Manual containment was effective** — endpoint isolation without EDR tooling demonstrates process depth

### What to improve
1. **Never rely on a single telemetry pipeline** — the endpoint AMA failure left 3 of 5 attack techniques undetected. Defence in depth applies to telemetry architecture too
2. **Validate detection rules before attack simulation** — run `SecurityEvent | take 10` and `Event | where Source == "Microsoft-Windows-Sysmon" | take 10` at the start of every session to confirm pipelines are live
3. **Report-only Conditional Access is not containment** — a policy in Report-only mode takes no action. The correct production sequence is: deploy Report-only → review sign-in logs for 2–4 weeks → flip to On

---

## 8. Recommendations (Priority Order)

**P1 — Critical:** Remediate AMA agent on DESKTOP-TRF9U79. Re-validate both DCRs. Without this, the two highest-value custom detection rules are non-functional.

**P2 — High:** Enforce Conditional Access risk-based sign-in policy (flip from Report-only to On) after validating P1.

**P3 — High:** Enforce phishing-resistant MFA on all user accounts. The 100% phishing compromise rate confirms this is not optional.

**P4 — Medium:** Deploy Microsoft Defender for Endpoint to replace Sysmon/AMA for endpoint detection. MDE provides pre-parsed, always-on telemetry that does not depend on a manually configured AMA pipeline.

**P5 — Medium:** Implement a SOAR playbook to auto-notify on Entra ID Protection High-risk sign-ins and auto-disable the account pending analyst review.

---

*Document prepared by: Ivan Yamoah Baoakye | July 5, 2026*  
*Next review: 30 days post-remediation of P1*
