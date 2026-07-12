# SOC1 Alert Triage Playbook — Project BEACON

Written before triaging any alert in the queue (Part D), applied mechanically during triage (Part E) rather than ad-hoc judgment per alert. Based on the actual alert batch generated in this session: two port scans, an RDP auth-failure burst, one benign PowerShell command, and one encoded PowerShell command.

---

## 1. Port Scan (Fast / Service Detection)

**Trigger condition:** `nmap -sV` style scan — full TCP connect attempts with service/version probing, hits multiple ports in quick succession.

**Initial checks:**
- Is the source IP/entity internal (expected admin/scanning tool) or unrecognized?
- Does the timing match a known scheduled vulnerability scan or maintenance window?
- Which ports were probed — standard service ports, or an unusual/targeted set?

**False-positive indicators:**
- Source matches an approved vulnerability-scanning tool or internal IP with a documented scanning schedule.
- Only a handful of standard, expected-open ports probed (e.g., a monitoring tool checking service health).

**True-positive / escalation criteria:**
- Source is external or an unrecognized internal host.
- Broad port range probed with no known business justification.
- Scan is immediately followed by connection attempts to the discovered open ports (recon → exploitation pattern).

**Required evidence before escalating:** Sentinel incident screenshot, source/destination IPs and timestamp, list of ports found open, KQL query result showing the underlying Sysmon/firewall events.

---

## 2. Port Scan (Slow / Stealthy)

**Trigger condition:** `nmap -sS -T2` style scan — half-open SYN scan at slow timing, designed to look less like an obvious burst.

**Initial checks:** Same as above, plus: compare timing/pattern against the fast scan — is this the same source trying to evade detection after a faster scan already got noticed?

**False-positive indicators:** Same as fast scan — approved source/tool.

**True-positive / escalation criteria:** Same as fast scan, but treat a *stealthy* scan as a slightly higher-confidence indicator of deliberate reconnaissance — a legitimate admin tool has no reason to scan slowly and quietly.

**Required evidence:** Same as fast scan, plus a note comparing it against any other scan incidents from the same source/timeframe.

---

## 3. RDP Authentication Failure Burst

**Trigger condition:** Multiple failed logon attempts (Event ID 4625) against the same account in a short window, followed by either a successful logon (4624) or continued failures.

**Initial checks:**
- Which account was targeted — a real user, a test/service account, or a high-privilege account?
- Source: interactive console logon or remote (network/RDP)? Check the Logon Type field.
- Did a successful logon eventually follow the failures?

**False-positive indicators:**
- Known user who mistyped their own password a few times (matches their normal working hours/pattern).
- Source matches a known, expected admin workstation.

**True-positive / escalation criteria:**
- Failed attempts followed by a successful logon on an account that doesn't normally authenticate from that source/pattern.
- Target account is a test/service account with no legitimate reason to be logging in at that time.
- Volume/speed of attempts is inconsistent with a human mistyping a password (rapid, scripted-looking bursts).

**Required evidence:** Screenshot of the 4625/4624 event sequence, account name, timestamps, KQL query showing the full sequence, note on Logon Type.

**Note from this session:** the original plan was to generate this pattern remotely via RDP from the attack-simulation host, but a persistent VirtualBox NAT issue prevented sustained RDP sessions after the initial TCP handshake (confirmed via port scan showing the port open, but the RDP application-layer negotiation repeatedly reset after ~77 seconds). Pivoted to generating the same failed/successful logon events locally via the Windows lock screen instead — same Event IDs, same triage logic applies, just a different Logon Type (Interactive rather than RemoteInteractive/Network). Worth a line in the Challenges & Lessons section.

---

## 4. Benign PowerShell Execution

**Trigger condition:** A plain-text, non-obfuscated PowerShell command that might superficially resemble "PowerShell activity" in a broad hunting query, but isn't inherently suspicious.

**Initial checks:**
- Is the command itself something a normal admin/user would run (e.g., process listing, file operations)?
- Any obfuscation, encoding, or unusual flags involved?
- Does it match a documented admin task?

**False-positive indicators:** Plain-text, readable command; no encoding; no download/network activity; matches routine administrative behavior (e.g., `Get-Process`, `Get-Service`).

**True-positive / escalation criteria:** Would only escalate if the plain-text command itself does something inherently risky (e.g., disabling security tooling, dumping credentials) even without obfuscation.

**Required evidence:** Not usually needed to escalate — but document the verdict and reasoning in the ticket regardless, since "correctly identifying non-suspicious activity" is itself a demonstrable Tier 1 skill.

---

## 5. Encoded / Obfuscated PowerShell Execution

**Trigger condition:** `powershell -EncodedCommand <base64>` or similar obfuscation technique.

**Initial checks:**
- Decode the base64 command (CyberChef, or `[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("<value>"))` in PowerShell) to see the actual command that ran.
- What does the decoded command actually do? Is it benign once decoded, or genuinely malicious?
- Who/what process launched it, and from where?

**False-positive indicators:** Decoded command turns out to be genuinely harmless (e.g., a test string), AND there's a documented reason for using encoding (some legitimate deployment/automation tools do encode commands to avoid shell-escaping issues).

**True-positive / escalation criteria:** Decoded command does anything suspicious (downloads a file, contacts an external IP, modifies security settings, dumps credentials) — or even a benign decoded payload with no legitimate business reason for the encoding should be treated cautiously, since encoding itself is a common evasion technique regardless of payload content.

**Required evidence:** Screenshot of the raw encoded command as it appeared in the alert, the decoded plain-text command, and your verdict reasoning.

---

## Note on Evidence Source (this session)

Sentinel ingestion broke sometime after ATLAS wrapped (last Heartbeat: 3 Jul 2026, a week before this session). Diagnosed in stages: confirmed `azcmagent`/Arc connectivity was healthy (a red herring — that's a separate system from telemetry shipping), found the `AzureMonitorWindowsAgent` extension showing "Succeeded" in Azure's control plane while the actual Windows service didn't exist on the VM, restarted the Arc extension-handling services, and redeployed the extension twice — neither fully resolved it. Pivoted to using **Windows Event Viewer directly on the VM** (Sysmon Operational + Security logs) as the evidence source for triage instead of Sentinel incidents, since the underlying events are genuinely being generated and logged locally; only the shipping pipeline into the workspace is broken. Triage logic and verdicts below apply identically regardless of evidence source — only the screenshot/reference changes from "Sentinel incident" to "Event Viewer entry." This is a real, documentable lesson: an Arc-connected machine reporting "Connected" does not guarantee its monitoring agent is actually shipping telemetry — they're independently-failing components.

## Decision Tree (quick reference)

1. **Is this expected/scheduled activity** (known admin task, approved tool, documented schedule)? → If yes, likely **False Positive** — document why and close.
2. **Does it match a known false-positive pattern** from this playbook? → If yes, **False Positive**, cite the specific indicator.
3. **Does the entity/account criticality or the specific technique (encoding, targeted scanning, credential-related) warrant escalation regardless of surface-level ambiguity?** → If yes, **Escalate**, even if some individual indicators look borderline.
4. When in doubt between False Positive and Escalate, default to **Escalate** with a note — a missed true positive is worse than an over-cautious escalation that Tier 2 closes quickly.
