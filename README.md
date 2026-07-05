# Project ATLAS — SOC Tier 1/2 Simulation

> A self-directed, end-to-end Security Operations Centre simulation built on Microsoft Sentinel, Entra ID Protection, and a custom attacker/victim lab. Designed to demonstrate senior SOC analyst competencies across the full incident lifecycle: detection engineering, adversary simulation, investigation, containment, identity remediation, and proactive threat hunting.

**Tenant:** VANPASSSC200.onmicrosoft.com  
**Duration:** June 27 – July 5, 2026  
**Platform:** Microsoft Sentinel · Entra ID P2 · Microsoft Defender XDR · Azure Arc · Sysmon · Kali Linux  
**Exam alignment:** SC-200 (Microsoft Security Operations Analyst)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  MacBook Air M4 (Host)                                      │
│                                                             │
│  ┌──────────────────┐    NAT     ┌──────────────────────┐  │
│  │  Kali Linux      │◄──────────►│  Windows 11 ARM64    │  │
│  │  ARM64 (Attacker)│  10.0.2.2  │  DESKTOP-TRF9U79     │  │
│  │  10.0.2.15       │  :33389    │  (Victim)            │  │
│  └──────────────────┘            │  Sysmon v15 + AMA    │  │
│                                  │  Azure Arc connected │  │
│                                  └──────────┬───────────┘  │
└─────────────────────────────────────────────┼───────────────┘
                                              │ AMA → DCR
                                              ▼
                              ┌───────────────────────────┐
                              │  Microsoft Azure           │
                              │  law-soc-atlas (Sentinel)  │
                              │  rg-soc-atlas              │
                              │  East US                   │
                              └───────────────────────────┘
                                              │
                              ┌───────────────▼───────────┐
                              │  Microsoft Entra ID P2     │
                              │  VANPASSSC200 Tenant       │
                              │  Identity Protection        │
                              │  Conditional Access         │
                              └───────────────────────────┘
```

---

## Project Structure

```
SOC PROJECTS/
├── README.md                              ← You are here
├── Day-2-Session-Log-2026-06-27.pdf       ← Detection Engineering
├── Day-3-Session-Log-2026-07-04.pdf       ← Attack Simulation
├── Day-4-Session-Log-2026-07-05.pdf       ← Investigation & Containment
├── Day-5-Final-Report-2026-07-05.pdf      ← Final Incident Report
├── Post-Incident-Review.pdf               ← PIR + Root Cause Analysis
├── Threat-Hunt-Report.pdf                 ← Proactive Hunting Findings
├── Escalation-and-SOAR-Playbook.pdf       ← Tier 1→2 Escalation + Automation
├── Post-Incident-Review.md
├── Threat-Hunt-Report.md
├── Escalation-and-SOAR-Playbook.md
├── kql/
│   ├── hunt-brute-force-4625.kql
│   ├── hunt-encoded-powershell.kql
│   ├── hunt-tor-anonymous-ip.kql
│   └── telemetry-gap-check.kql
└── attack-navigator/
    └── atlas-attack-layer.json            ← ATT&CK Navigator heatmap
```

---

## Attack Chain Simulated

| # | Technique | ID | Tool | Detection Source |
|---|-----------|-----|------|-----------------|
| 1 | Brute Force: Password Guessing | T1110.001 | Hydra (rdp://) | SecurityEvent EID 4625 |
| 2 | PowerShell Execution + Obfuscation | T1059.001 + T1027 | powershell -enc | Sysmon EID 1 (Event table) |
| 3 | Spearphishing Link | T1566.002 | M365 Attack Simulation Training | Attack Sim report |
| 4 | Valid Accounts: Cloud | T1078.004 | soc-tor-test credentials | Entra ID Protection |
| 5 | Multi-hop Proxy (Tor) | T1090.003 | Tor Browser | Anonymous IP address (ML) |

---

## Detection Rules Built (Microsoft Sentinel KQL)

### Rule 4.1 — Brute Force Failed Logon Spike (T1110.001)
```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4625
| summarize FailedAttempts = count(), Accounts = make_set(Account) by Computer, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
| order by FailedAttempts desc
```
Severity: **Medium** | MITRE: Credential Access → T1110.001

### Rule 4.2 — Encoded PowerShell Execution (T1059.001 + T1027)
```kql
Event
| where TimeGenerated > ago(1d)
| where Source == "Microsoft-Windows-Sysmon" and EventID == 1
| extend Image = extract(@"Image:\s*(.*?)\r?\n", 1, RenderedDescription)
| extend CommandLine = extract(@"CommandLine:\s*(.*?)\r?\n", 1, RenderedDescription)
| extend User = extract(@"User:\s*(.*?)\r?\n", 1, RenderedDescription)
| where Image has_any ("powershell.exe", "powershell_ise.exe")
| where CommandLine has_any ("-enc", "-EncodedCommand", "-e ")
| project TimeGenerated, Computer, User, Image, CommandLine
```
Severity: **High** | MITRE: Execution + Defense Evasion → T1059.001 + T1027

---

## Threat Hunting Queries

### Hunt: Telemetry Gap Check
```kql
// Validate both endpoint telemetry pipelines are functional
SecurityEvent | summarize SecurityEvent_count = count()
// Expected: > 0. Result in this lab: 0 (AMA pipeline issue confirmed)

Event
| where Source == "Microsoft-Windows-Sysmon"
| summarize Sysmon_count = count()
// Expected: > 0. Result in this lab: 0 (AMA pipeline issue confirmed)
```

### Hunt: Anonymous IP Sign-ins (Tor / VPN)
```kql
AADSignInEventsBeta
| where TimeGenerated > ago(7d)
| where RiskLevelDuringSignIn >= 50
| where IsAnonymousProxy == 1
| project TimeGenerated, AccountUpn, IPAddress, City, CountryCode, RiskLevelDuringSignIn
| order by TimeGenerated desc
```

---

## Key Findings

### ✅ What Worked
- **Entra ID Protection** detected Tor-based anonymous sign-in within minutes — no custom rule required
- **Microsoft Defender XDR** auto-correlated 8 alerts into 1 High-severity incident with AI-generated technique profiling
- **Manual endpoint containment** (netsh advfirewall) successfully isolated DESKTOP-TRF9U79 without EDR tooling
- **Phishing simulation** confirmed 100% user susceptibility — drives real security awareness program recommendations

### ⚠️ Gaps Discovered
- **Endpoint telemetry gap**: Both SecurityEvent (AMA) and Sysmon (AMA) tables contain 0 records — AMA agent health issue on DESKTOP-TRF9U79. Custom KQL detection rules cannot fire without data.
- **No MFA enforced** on test accounts — Tor sign-in succeeded with only password authentication
- **Hydra RDP module** blocked by Windows 11 NLA at transport layer — tool limitation, not a detection success

---

## Response Actions Taken

| Action | Method | Outcome |
|--------|--------|---------|
| Incident triage | Defender XDR Incidents | Classified True positive — Compromised account |
| Endpoint containment | netsh advfirewall blockinbound,blockoutbound | All traffic blocked, state confirmed |
| Risky user remediation | Entra ID Protection — Confirm compromised | Automated remediation flow initiated |
| Conditional Access policy | Report-only: block Medium/High sign-in risk | Created — awaiting validation before enforcement |

---

## Skills Demonstrated

| Domain | Evidence |
|--------|----------|
| SIEM / Detection Engineering | Custom KQL analytics rules with entity mapping, DCR configuration, telemetry gap diagnosis |
| Incident Response | Triage → classification → containment → remediation → PIR |
| Cloud Security (Entra / Azure) | Identity Protection risk detections, Conditional Access policy design |
| Threat Hunting | Hypothesis-driven KQL hunting, telemetry coverage validation |
| Adversary Simulation | MITRE ATT&CK-mapped attack chain across 5 techniques |
| Cost Governance | Proactive Defender for Cloud plan audit, prevented unintended billing |
| Documentation | Session logs, RCA, PIR, threat hunt report, escalation playbook |

---

## Certifications & Study Context

This project was built as part of preparation for the **SC-200: Microsoft Security Operations Analyst** certification. All techniques, tools, and detection logic align with SC-200 exam domains.

---

*Built by Ivan Yamoah Baoakye · July 2026*
