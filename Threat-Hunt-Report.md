# Project ATLAS — Threat Hunt Report

**Hunt ID:** TH-2026-001  
**Hunt Name:** Post-Incident Proactive Hunt — Cloud Identity Abuse & Endpoint Telemetry Gap  
**Analyst:** Ivan Yamoah Baoakye  
**Hunt Period:** 4–5 July 2026  
**Environment:** VANPASSSC200 tenant | law-soc-atlas (East US) | DESKTOP-TRF9U79  
**Trigger:** Post-incident hunt following closure of Incident ID 2 (True positive — Compromised account)

---

## 1. Executive Summary

This threat hunt was initiated after the closure of Incident ID 2 to determine: (a) whether attacker activity beyond what Entra ID Protection detected had persisted undetected on the endpoint, and (b) whether the Log Analytics workspace contained sufficient telemetry to support retrospective threat hunting on the endpoint layer.

**Key Finding:** The endpoint telemetry pipeline (AMA → Log Analytics) was confirmed completely non-functional. Both the SecurityEvent table and the Sysmon/Event table contained 0 records. This is not a minor gap — it means four of the five simulated attack techniques (T1110.001, T1059.001, T1027, T1566.002) were completely invisible to Sentinel analytics rules and any retrospective hunt queries. Detection during this incident relied entirely on cloud-identity telemetry (Entra ID Protection), which operates independently of the AMA pipeline.

The cloud identity hunt surfaced no additional attacker activity beyond what Entra ID Protection had already flagged.

---

## 2. Hunt Hypotheses

Threat hunting is hypothesis-driven. Each hypothesis below maps to a specific ATT&CK technique observed during the simulation and asks: *did the attacker leave additional evidence we haven't already seen?*

---

### Hypothesis 1 — Brute force pre-cursor activity before incident window

**Hypothesis:** The Hydra RDP brute force attack (T1110.001) generated failed logon events in Windows Security Log before the first detected successful login. These events should appear in SecurityEvent (EventID 4625) and would reveal the full scope of the brute force — number of attempts, duration, source IP, and targeted account.

**Technique:** T1110.001 — Brute Force: Password Guessing  
**Data source:** SecurityEvent (Windows Security Events via AMA)  
**Expected table:** `SecurityEvent`  
**Hunt query:**

```kql
// Hunt 1.1 — Brute force failed logons (4625) from external IP
SecurityEvent
| where EventID == 4625
| where TimeGenerated >= ago(7d)
| summarize
    FailedAttempts = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Accounts = make_set(TargetUserName),
    SourceIPs = make_set(IpAddress)
  by IpAddress, Computer
| where FailedAttempts > 10
| order by FailedAttempts desc
```

**Expected result:** Multiple 4625 events from 10.0.2.15 (Kali) targeting the `soclab-test` account, spike pattern consistent with automated brute force  
**Actual result:** 0 records returned (SecurityEvent table empty)

```kql
// Hunt 1.2 — Telemetry gap check: confirm SecurityEvent is empty
SecurityEvent
| summarize count()
```

**Actual result:** count_ = 0 — confirmed AMA pipeline failure

---

### Hypothesis 2 — Encoded PowerShell execution (T1059.001 + T1027)

**Hypothesis:** After gaining RDP access via brute force, the attacker executed a base64-encoded PowerShell command (T1059.001 + T1027). Process creation events (Sysmon EventID 1 or Windows EventID 4688 with command-line logging) should capture the full command line, parent process, and user context.

**Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell + T1027 — Obfuscated Files or Information  
**Data source:** Sysmon Event (EventID 1 — Process Create) via AMA  
**Expected table:** `Event` (Sysmon XML events)  
**Hunt query:**

```kql
// Hunt 2.1 — Encoded PowerShell execution via Sysmon EventID 1
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where TimeGenerated >= ago(7d)
| extend EventData = parse_xml(EventData)
| mv-expand CommandLine = EventData.DataItem.EventData.Data
| where CommandLine has "-enc" or CommandLine has "-EncodedCommand"
| project
    TimeGenerated,
    Computer,
    CommandLine,
    EventID
| order by TimeGenerated desc
```

**Expected result:** Process create event with `powershell.exe -enc <base64 blob>` in command line  
**Actual result:** 0 records returned (Event/Sysmon table empty)

```kql
// Hunt 2.2 — Telemetry gap check: confirm Sysmon Event table is empty
Event
| where Source == "Microsoft-Windows-Sysmon"
| summarize count()
```

**Actual result:** count_ = 0 — confirmed Sysmon not forwarding via AMA

```kql
// Hunt 2.3 — Alternative: Windows 4688 process creation with command line
SecurityEvent
| where EventID == 4688
| where TimeGenerated >= ago(7d)
| where CommandLine has "-enc" or CommandLine has "powershell" or CommandLine has "cmd"
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine
| order by TimeGenerated desc
```

**Actual result:** 0 records (SecurityEvent table empty)

---

### Hypothesis 3 — Tor / anonymous proxy sign-in beyond what Entra ID Protection flagged

**Hypothesis:** The Entra ID Protection anonymous IP alerts covered 5 sign-in events. Were there additional sign-ins from anonymous proxies or Tor exit nodes that Entra ID Protection may have missed, or that occurred to different accounts?

**Technique:** T1090.003 — Proxy: Multi-hop Proxy + T1078.004 — Valid Accounts: Cloud Accounts  
**Data source:** SigninLogs (Entra ID sign-in logs)  
**Expected table:** `SigninLogs`  
**Hunt query:**

```kql
// Hunt 3.1 — All sign-ins from IPs with risk detections
SigninLogs
| where TimeGenerated >= ago(7d)
| where RiskLevelDuringSignIn in ("medium", "high")
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    RiskDetail,
    RiskLevelDuringSignIn,
    RiskEventTypes,
    ResultType,
    AppDisplayName
| order by TimeGenerated desc
```

**Expected result:** 5 sign-in events from Tor exit IPs for soc-tor-test account  
**Actual result:** Query confirmed the same 5 events already captured by Entra ID Protection — no additional risky sign-ins discovered

```kql
// Hunt 3.2 — Anonymous IP sign-ins by any user (broader scope)
SigninLogs
| where TimeGenerated >= ago(7d)
| where RiskEventTypes has "anonymizedIPAddress"
| summarize
    SignInCount = count(),
    SuccessCount = countif(ResultType == "0"),
    FailureCount = countif(ResultType != "0"),
    Locations = make_set(Location)
  by UserPrincipalName, IPAddress
| order by SignInCount desc
```

**Actual result:** 2 users flagged (ivanyamoahbaoakye, soc-tor-test), all events already in incident scope — no lateral spread to other accounts

```kql
// Hunt 3.3 — Sign-ins from new or unfamiliar countries
SigninLogs
| where TimeGenerated >= ago(7d)
| where isnotempty(Location)
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize
    SignInCount = count(),
    Countries = make_set(Country)
  by UserPrincipalName
| where array_length(Countries) > 1
| order by SignInCount desc
```

**Actual result:** Both flagged accounts showed sign-ins from Germany and Sweden (Tor exit nodes) in addition to Canada (normal location) — matches known simulation activity, no unexpected countries

---

### Hypothesis 4 — Persistence mechanisms post-compromise

**Hypothesis:** After a successful RDP brute force + credential theft, a real attacker would establish persistence — registry run keys, scheduled tasks, new local user accounts. Did any such activity occur during the simulation window?

**Technique:** T1053 — Scheduled Task/Job + T1136 — Create Account  
**Data source:** SecurityEvent (EventIDs 4720 new account, 4698 scheduled task), Sysmon EventID 12/13 (registry)  
**Hunt query:**

```kql
// Hunt 4.1 — New local account creation
SecurityEvent
| where EventID == 4720
| where TimeGenerated >= ago(7d)
| project TimeGenerated, Computer, TargetUserName, SubjectUserName

// Hunt 4.2 — Scheduled task creation
SecurityEvent
| where EventID == 4698
| where TimeGenerated >= ago(7d)
| project TimeGenerated, Computer, SubjectUserName, TaskName

// Hunt 4.3 — Registry persistence via Sysmon
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID in (12, 13)
| where TimeGenerated >= ago(7d)
| extend EventData = parse_xml(EventData)
| where tostring(EventData) has "\\Run\\" or tostring(EventData) has "\\RunOnce\\"
| project TimeGenerated, Computer, EventData
```

**Actual result:** All queries returned 0 records — endpoint telemetry gap confirms no visibility. Persistence activity cannot be confirmed or denied from SIEM data alone.

---

## 3. Hunt Results Summary

| Hypothesis | Technique | Table Queried | Records Returned | Finding |
|---|---|---|---|---|
| H1: Brute force pre-cursor | T1110.001 | SecurityEvent (4625) | 0 | Telemetry gap — AMA pipeline failed |
| H2: Encoded PowerShell | T1059.001 + T1027 | Event/Sysmon (EID 1) | 0 | Telemetry gap — Sysmon not forwarding |
| H2b: Process creation (4688) | T1059.001 | SecurityEvent (4688) | 0 | Telemetry gap — AMA pipeline failed |
| H3: Anonymous proxy sign-ins | T1090.003 | SigninLogs | 5 (known) | No additional scope — matches incident |
| H3b: Lateral account spread | T1078.004 | SigninLogs | 0 new | No lateral movement to other accounts |
| H4: Persistence mechanisms | T1053 / T1136 | SecurityEvent + Sysmon | 0 | Cannot confirm or deny — no telemetry |

**Cloud identity layer: fully visible. Endpoint layer: completely blind.**

---

## 4. Gap Analysis

### Gap 1 — AMA Endpoint Telemetry Pipeline (Critical)

**Scope of impact:** 4 of 5 simulated ATT&CK techniques were invisible to Sentinel and to retrospective hunting:
- T1110.001 — Brute Force (RDP failed logons, 4625)
- T1059.001 — PowerShell (process creation, 4688 / Sysmon EID 1)
- T1027 — Obfuscated commands (Sysmon EID 1 command-line)
- T1566.002 — Phishing (click telemetry, no security log event generated)

**Affected detection rules:** ATLAS 4.1 (Brute force spike), ATLAS 4.2 (Encoded PowerShell) — both non-functional during the simulation period

**Diagnosis steps (not yet completed):**
1. Query `Heartbeat` table for agent health: `Heartbeat | where Computer == "DESKTOP-TRF9U79" | summarize max(TimeGenerated)`
2. Review DCR association in Azure Monitor → Data Collection Rules → confirm DESKTOP-TRF9U79 appears in Resources tab
3. Review AMA extension health in Azure → Virtual Machines → DESKTOP-TRF9U79 → Extensions and Applications

**Remediation path:** Re-register AMA agent on DESKTOP-TRF9U79 or migrate to Microsoft Defender for Endpoint (preferred — provides richer telemetry without manual AMA configuration)

### Gap 2 — No Phishing Click Telemetry in SIEM (Medium)

The M365 Attack Simulation Training captured the phishing simulation result (1 click, 1 credential submission) in the Microsoft 365 Defender portal under Attack simulation training → Reports. However, this event did not generate a SecurityEvent or Sysmon event, and phishing simulation results are not automatically forwarded to Log Analytics via a standard connector. A real phishing campaign via email would generate alerts in Microsoft Defender for Office 365 (EmailEvents table in Advanced Hunting), but the simulation is intentionally marked safe and excluded.

**Remediation path:** For real phishing detection, ensure the Microsoft Defender for Office 365 connector is enabled in Sentinel's content hub. For simulation tracking, document the gap explicitly in reports.

### Gap 3 — No SOAR Automation on Entra ID Protection Alerts (Medium)

When Entra ID Protection fired the anonymous IP alert at 23:14, the only automated action was the creation of Incident ID 2. No playbook triggered to: notify on-call, disable the account, or block sign-in. A Sentinel Logic App playbook with a "When an incident is created" trigger could have automated immediate response — reducing the 35-hour gap between detection and analyst triage.

---

## 5. MITRE ATT&CK Coverage Assessment

| Technique | Description | Detection Status | Hunt Coverage |
|---|---|---|---|
| T1110.001 | Brute Force: Password Guessing | ❌ Not detected (AMA gap) | ❌ Cannot hunt (no data) |
| T1059.001 | PowerShell execution | ❌ Not detected (AMA gap) | ❌ Cannot hunt (no data) |
| T1027 | Obfuscated command | ❌ Not detected (AMA gap) | ❌ Cannot hunt (no data) |
| T1566.002 | Spearphishing Link | ℹ️ Tracked in M365 Defender (simulation) | ❌ Not huntable in SIEM |
| T1078.004 | Valid Accounts: Cloud | ✅ Detected by Entra ID Protection | ✅ Hunted — no additional scope |
| T1090.003 | Proxy: Multi-hop | ✅ Detected (Anonymous IP alert) | ✅ Hunted — no additional scope |

**Detection coverage: 2/6 techniques (33%) — entirely reliant on cloud identity layer**

---

## 6. Recommendations

**R1 (Critical):** Remediate AMA agent on DESKTOP-TRF9U79 and validate both DCRs deliver data to SecurityEvent and Event tables. Do not close the hunt formally until `SecurityEvent | summarize count()` returns > 0.

**R2 (High):** Migrate from Sysmon/AMA to Microsoft Defender for Endpoint. MDE provides always-on process, file, network, and registry telemetry via the pre-built MDE connector — eliminating the DCR/AMA configuration dependency that caused this gap.

**R3 (High):** Re-run all four ATT&CK simulations after R1 or R2 is complete and validate that analytics rules 4.1 and 4.2 produce alerts. Document confirmed detection in Day 5 Final Report addendum.

**R4 (Medium):** Enable scheduled threat hunt runs — at minimum weekly KQL queries on SigninLogs for anomalous sign-in geography and velocity. This can be automated via a Sentinel scheduled analytics rule with low-priority action (e.g., create an informational incident for analyst review).

---

## 7. Hunt Closure

**Hunt status:** Closed — telemetry gap confirmed, cloud identity scope exhausted  
**Open actions:** R1 (AMA remediation) — assigned to platform team  
**Next hunt trigger:** After AMA remediation — repeat H1–H4 to validate detection coverage  
**Hunt log retained in:** law-soc-atlas → Log Analytics → Saved Queries

---

*Analyst: Ivan Yamoah Baoakye | July 5, 2026*  
*Reference: Incident ID 2, Project ATLAS*
