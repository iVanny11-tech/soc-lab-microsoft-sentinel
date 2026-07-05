# Project ATLAS — Multi-Vector SOC Tier 1 Incident Response Simulation

**Role simulated:** SOC Analyst Tier 1 (modeled on the Starling Group SOC Analyst job description)
**Stack:** Microsoft Defender XDR · Microsoft Sentinel · Defender for Cloud · Defender for Office 365 · Entra ID Protection · Sysmon + Azure Arc + Azure Monitor Agent (custom endpoint telemetry pipeline — see note below) (Defender for Identity optional, see Section 2)
**Attacker tooling:** Kali Linux (VirtualBox) + Tor Browser
**Framework:** MITRE ATT&CK
**Duration:** 5 days (fits comfortably inside your 1-month Azure free trial)

---

## 1. Why this project maps to the job description

| Starling Group JD bullet | How this project demonstrates it |
|---|---|
| Incident triage/response/investigation from Cloud Infrastructure, EDR, and Perimeter detection sources | Defender for Cloud (cloud), Sysmon + Azure Arc + AMA → Sentinel (EDR-equivalent endpoint telemetry), Kali-driven network attacks against the lab "perimeter" |
| Investigating and responding to user-reported alerts | Phishing simulation via Defender for Office 365 Attack Simulator, triaged as a user-reported message |
| Enhancing/creating analytic triggers to improve alert efficacy | Two custom KQL analytics rules built and tuned in Sentinel |
| Continuous development of incident handling/readiness processes | Written incident-handling notes and a reusable triage runbook produced as you go |
| Proactive threat hunting based on threat intelligence | Advanced Hunting KQL hunts for the attacker's IP, encoded PowerShell, and risky sign-ins |
| Documentation of incidents and investigations | Post-incident report + MITRE ATT&CK Navigator heatmap |

Two honest notes for your README. First: a real SOC also ingests firewall/IDS "perimeter" telemetry. Your home lab doesn't have a physical firewall, so Sysmon's network-connection events (Event ID 3, forwarded into the `Event` table) stand in for that data source. Second, and more interesting to talk about in an interview: this project originally planned to use Microsoft Defender for Endpoint as the EDR layer, but Microsoft retired the standalone free trial for it partway through building this lab, and the tenant's billing region blocked a workaround payment method. Rather than stall on a licensing gap, the EDR layer was rebuilt as a custom pipeline — Sysmon for endpoint telemetry, Azure Arc to bring the non-Azure VM under Azure management, and the Azure Monitor Agent to forward logs into the same Sentinel workspace. Naming both substitutions explicitly reads as more credible than implying enterprise tooling you didn't have — and the Arc-based pipeline is arguably a stronger demonstration of hybrid environment monitoring than just enabling a vendor agent would have been.

---

## 2. Environment-to-tool mapping

| You have | Used for |
|---|---|
| Microsoft 365 E5 (no Teams) | Defender for Office 365 (Attack Simulator, Threat Explorer), Entra ID P2 (Identity Protection, Conditional Access) |
| Azure free trial (1 month) | Microsoft Sentinel workspace, Defender for Cloud (Foundational CSPM plan, free tier) |
| MacBook Air M4 (host) + VirtualBox + Kali Linux ARM64 (Debian) | Attacker VM: recon, brute force, encoded PowerShell delivery, reverse-shell listener |
| Tor Browser | Triggers a genuine Entra ID Protection "anonymous IP" / "atypical travel" risk detection |
| **Missing — add this** | A Windows 11 **ARM64** VM as your "victim" endpoint, on the same VirtualBox NAT Network as Kali, running Sysmon and Arc-onboarded to Azure so its logs reach Sentinel. |

**Hardware note — this matters for your setup specifically:** because your host is Apple Silicon (M4), both VMs must be ARM64 builds — VirtualBox on an ARM Mac cannot run x86_64 guests at usable speed. Your Kali VM is already correctly ARM64. For the Windows victim VM, you cannot use the normal x86_64 Windows evaluation ISO — you need the **Windows 11 ARM64 ISO**. Good news: Microsoft now publishes this as a direct, stable download — no Windows Insider Program registration needed. Get it at **https://www.microsoft.com/en-us/software-download/windows11arm64** (select the multi-edition Arm64 ISO, pick your language, Download Now — no sign-in required). Sysmon, the Azure Connected Machine agent (Arc), and the Azure Monitor Agent all officially support Windows on ARM64, so this pipeline works the same way it would on an x86_64 device.

Also confirm you're on **VirtualBox 7.2 or later** — Windows-on-Arm guest support on Apple Silicon hosts only landed in that release and is still flagged by Oracle as early-access/experimental (Guest Additions, graphics, and USB passthrough are known to be flaky). None of that affects this project — you only need network connectivity and the ability to run PowerShell, not 3D acceleration. Two practical safeguards: give the Windows VM as much RAM/vCPU as you can spare, and take a VirtualBox snapshot right after a clean install, before you start the Arc/Sysmon onboarding, so a bad VM state is one click to undo instead of a reinstall. Note also: VirtualBox's Unattended Installation wizard doesn't support Arm guests, so you'll click through Windows Setup manually — a few extra clicks, nothing difficult.

Network setup — corrected from the original draft: a fully air-gapped **Internal Network** would block Sentinel, Azure Arc, and the Azure Monitor Agent from ever reporting telemetry, since all three need outbound internet access to reach Microsoft's cloud. Instead, create a VirtualBox **NAT Network** (VirtualBox Manager → Tools → Network → NAT Networks → Create, name it e.g. `SOC-Lab`), and attach both the Kali VM's and the Windows VM's network adapter to that same NAT Network. This gives you both things at once: Kali and the Windows VM can reach each other directly (so Nmap/Hydra/the reverse shell all work), and both still get outbound internet (so MDE onboarding, Sentinel telemetry, and Tor Browser on Kali all work) — while staying isolated from your home Wi-Fi/LAN (no bridged adapter, nothing reachable from your router's other devices).

Defender for Identity is dropped from the core path to keep this simple — it requires promoting a VM to an AD DS domain controller and installing a sensor, which is its own multi-day side project. If you finish early and want the extra badge on your stack, it's a clean bonus add-on, not a blocker here.

---

## 3. MITRE ATT&CK technique map

| Stage | Simulated action | Tactic | Technique |
|---|---|---|---|
| 1 | Kali runs Nmap against the victim subnet | Reconnaissance | T1595 – Active Scanning |
| 2 | Phishing email via Defender for Office 365 Attack Simulator | Initial Access | T1566.002 – Phishing: Spearphishing Link |
| 3 | Sign-in to test Entra account over Tor | Initial Access / Defense Evasion | T1078.004 – Valid Accounts: Cloud Accounts, T1090.003 – Proxy: Multi-hop Proxy |
| 4 | Hydra brute force against victim RDP/SMB | Credential Access | T1110.001 – Brute Force: Password Guessing |
| 5 | Base64-encoded PowerShell executed on victim | Execution / Defense Evasion | T1059.001 – Command and Scripting Interpreter: PowerShell, T1027 – Obfuscated Files or Information |
| 6 | Reverse shell from victim to Kali listener | Command and Control | T1071 – Application Layer Protocol |
| 7 (optional stretch) | Create a local account for persistence | Persistence | T1136 – Create Account |

Keep stage 7 optional — the brief asked for something achievable, not maximal. Six stages already give you a full kill-chain narrative.

---

## 4. Detection & hunting queries (verified against current Microsoft schema, June 2026)

A note on accuracy: `AADSignInEventsBeta` was retired in favor of `EntraIdSignInEvents` on **December 9, 2025**. The query below uses the current table and its real column name, `RiskLevelAggregated` (there is no `RiskLevelDuringSignIn` column in the new table — that was a guess worth flagging and correcting).

A second note, specific to this build: 4.1–4.3 originally targeted Defender for Endpoint's Advanced Hunting tables (`DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`). Those tables only populate if an MDE sensor is onboarded — see Section 2's note on the licensing pivot. With Sysmon + Azure Monitor Agent forwarding into the Sentinel workspace instead, the same three detections are rebuilt against `SecurityEvent` and `Event` — the native Log Analytics tables those logs actually land in.

**4.1 Brute-force failed-logon spike** (custom Sentinel analytics rule, `SecurityEvent`, Windows Security log EventID 4625)
```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4625
| summarize FailedAttempts = count(), Accounts = make_set(Account) by Computer, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
| order by FailedAttempts desc
```

**4.2 Encoded PowerShell execution** (custom Sentinel analytics rule, `Event`, Sysmon EventID 1 — Process Create)
```kql
Event
| where TimeGenerated > ago(1d)
| where Source == "Microsoft-Windows-Sysmon" and EventID == 1
| extend Image = extract(@"Image:\s*(.*?)\r?\n", 1, RenderedDescription)
| extend CommandLine = extract(@"CommandLine:\s*(.*?)\r?\n", 1, RenderedDescription)
| where Image has_any ("powershell.exe", "powershell_ise.exe")
| where CommandLine has_any ("-enc", "-EncodedCommand", "-e ")
| project TimeGenerated, Computer, Image, CommandLine
```
Sysmon's `Event` rows don't come pre-parsed into columns the way MDE's Advanced Hunting schema does — `RenderedDescription` holds the full rendered text block (Image, CommandLine, ParentImage, etc. each on their own line), so `extract()` with a regex pulls the two fields this rule actually needs. Worth a line in the README: this is closer to how detection engineering works against raw Windows Event Log data in environments that don't have Microsoft's pre-parsed EDR schema.

**4.3 Proactive hunt — traffic to the attacker IP** (`Event`, Sysmon EventID 3 — Network Connection)
```kql
let AttackerIP = "10.0.2.2"; // NOT Kali's own address — under plain NAT (see Day 1, Part B) every outbound connection from the Windows VM shows the host gateway as the remote endpoint, since Kali's real 10.0.2.x address is on a separate, isolated NAT instance. The reverse shell actually lands on Kali via the host's port-forward (44444 -> Kali 4444).
Event
| where TimeGenerated > ago(7d)
| where Source == "Microsoft-Windows-Sysmon" and EventID == 3
| extend Image = extract(@"Image:\s*(.*?)\r?\n", 1, RenderedDescription)
| extend SourceIp = extract(@"SourceIp:\s*(.*?)\r?\n", 1, RenderedDescription)
| extend DestinationIp = extract(@"DestinationIp:\s*(.*?)\r?\n", 1, RenderedDescription)
| extend DestinationPort = extract(@"DestinationPort:\s*(.*?)\r?\n", 1, RenderedDescription)
| where SourceIp == AttackerIP or DestinationIp == AttackerIP
| project TimeGenerated, Computer, Image, SourceIp, DestinationIp, DestinationPort
```

**4.4 Proactive hunt — risky sign-ins** (`EntraIdSignInEvents`)
```kql
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where RiskLevelAggregated >= 10   // 10 = low, 50 = medium, 100 = high
| project Timestamp, AccountUpn, IPAddress, Country, City, RiskLevelAggregated, RiskState, ConditionalAccessStatus
```
This one is untouched by the pivot — Entra ID sign-in telemetry comes from Entra ID Protection (Entra ID P2), not the endpoint, so it was never dependent on Defender for Endpoint.

Before relying on 4.1's exact column names, confirm them against the live schema reference pane inside the Sentinel Logs blade (`SecurityEvent` and `Event` tables) — table contents are stable but it's good practice to verify in-product rather than from memory.

---

## 5. Day-by-day timeline (5 days, ~2–3 hours/day)

| Day | Phase | Tasks |
|---|---|---|
| 1 | Setup | Build Windows victim VM in VirtualBox; put it on a shared NAT Network with Kali; register Azure resource providers, create a Log Analytics workspace, onboard the VM to Azure Arc, install Sysmon, build a Data Collection Rule forwarding Sysmon + Security log events into the workspace; enable Defender for Cloud (Foundational CSPM), connect Sentinel to the workspace, deploy the "Microsoft Defender XDR" solution from Content Hub |
| 2 | Detection engineering | Enable 1 out-of-box Sentinel analytics rule template; write and test the two custom KQL rules (4.1, 4.2); schedule them; jot down why each was built |
| 3 | Attack simulation | From Kali: Nmap scan → Hydra brute force against RDP/SMB → base64-encoded PowerShell on the victim → reverse shell to a Kali listener; launch a Credential Harvest campaign via Defender for Office 365 Attack Simulator; sign in to the test Entra account via Tor Browser |
| 4 | Investigation & containment | Triage every incident that landed in the Defender XDR unified queue; write a short root-cause narrative tying the stages together; contain the victim device with a manual host-based firewall block (the no-MDE equivalent of a one-click EDR isolation); remediate/dismiss the risky user in Entra ID; draft a Conditional Access policy blocking anonymous/Tor sign-ins |
| 5 | Hunting, docs & GitHub | Run hunts 4.3 and 4.4; write the post-incident report; build the MITRE ATT&CK Navigator heatmap (https://mitre-attack.github.io/attack-navigator/, export layer JSON + screenshot); push the repo (README, `/screenshots`, `/kql-queries`, `/reports`, `/attack-navigator-layer.json`) |

This leaves roughly 25 days of slack inside your 30-day Azure trial — plenty of room if any day runs long. Disable the Defender for Cloud trial plans (or cancel the subscription) once you're done, well before day 30, to avoid charges.

---

## 6. Lab safety note (include this in your GitHub README)

All offensive activity (scanning, brute force, encoded PowerShell, reverse shell) was performed entirely inside an isolated VirtualBox NAT Network against VMs you own and control — no exposure to your home LAN, no real-world targets. Tor was used only to sign into a disposable test account you created for this purpose. Stating this plainly heads off any "did you actually hack something" confusion from a recruiter skimming the repo.

---

## 7. What comes after you execute this

Once you've actually run through the 5 days, the next step is the four standard deliverables for this project: a polished GitHub documentation pass, a LinkedIn posting strategy, a Loom video walkthrough script, and a recruiter outreach angle. Come back for those once you have real screenshots and incident data to work from — they're much stronger when built from your actual results rather than drafted in advance.
