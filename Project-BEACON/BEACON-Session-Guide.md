# Project BEACON — Single-Session Guide (~6 hours)

One sitting, not a multi-day plan. Work top to bottom. Telemetry ingestion in Part C is the only real wait — let it run in the background while you write the playbook (Part D). Take breaks between blocks; the times below are focused work, not wall-clock including rest.

| Block | Focus | Time |
|---|---|---|
| A | Confirm the lab is alive | 15 min |
| B | Stand up Jira Service Management | 15 min |
| C | Generate a larger, varied alert batch | 30 min (+ ~15-20 min ingest, runs in background) |
| D | Write the full Alert Triage Playbook | 30 min |
| E | Triage pass, all alerts | 60 min |
| F | Deep investigation on escalated alerts | 60 min |
| G | Phishing simulation & investigation (2 scenarios) | 45 min |
| H | Escalation write-ups | 30 min |
| I | Shift log & metrics | 20 min |
| J | Challenges & Lessons Learned | 15 min |
| K | README + screenshot pass + Loom prep | 45 min |
| **Total** | | **~6 hours** |

## Part A — Confirm the lab is alive (15 min)

1. VirtualBox Manager → confirm both VMs (`KALI ` — trailing space in the name, and the Windows VM) are present.
2. `VBoxManage list vms` → get UUIDs → `VBoxManage startvm <UUID> --type headless` for both.
3. SSH into Kali from Terminal: `ssh <kali-user>@10.0.2.15`. RDP into Windows via Microsoft Remote Desktop (`localhost:33389`).
4. In Windows, elevated PowerShell: `azcmagent show` → confirm `Agent Status: Connected`.
5. Azure Portal → **Subscriptions** → confirm trial days remaining (started ~06/18-19, expires ~07/18-19 — check you're still inside the window).

## Part B — Stand up Jira Service Management (15 min)

1. atlassian.com/software/jira/service-management → free tier → **IT Service Management** project → name `SOC1 Queue`, key `SOC1`.
2. Use the default **Task** issue type. Ticket title convention: `[ALERT] <Sentinel alert name> — <entity>`.
3. Set up a simple board view filtered by status (Open / In Progress / Escalated / Resolved) — this is what you'll screenshot for the Shift Log later.
4. Screenshot the empty board (before shot for the README).

## Part C — Generate a larger, varied alert batch (30 min active + 15-20 min background ingest)

Bigger and more varied than a quick smoke test — aim for **10-12 alerts** across at least four distinct patterns, all distinct from ATLAS's incidents:

1. **Port scan variant 1 (fast/noisy):** `nmap -sV -p 33389,33445,35985 10.0.2.2 -oN beacon_scan1.txt --reason` — target the actual forwarded ports directly (33389→RDP, 33445→SMB, 35985→WinRM), not a broad range like 1-1000. This lab's plain-NAT setup only routes traffic to Windows on these three specific ports; anything else gets dropped at the Mac's NAT layer before it ever reaches the VM, so it won't generate any telemetry to alert on.
2. **Port scan variant 2 (slow/stealthy):** `nmap -sS -T2 -p 33389,33445,35985 10.0.2.2 -oN beacon_scan2.txt --reason` (may need `sudo` for the raw SYN scan) — same real ports, but a stealthy half-open SYN scan at slow timing instead of a full connect+version probe. Generates a distinguishable Sentinel signature, giving you a genuine "same category, different confidence level" triage decision later.
3. **Failed/successful RDP mix:** three wrong-password attempts + one correct one, done manually via the Remote Desktop client (not Hydra — keep this pattern distinct from ATLAS's brute-force rule).
4. **A second RDP burst from a different simulated "user"** a few minutes later, to produce two separate incidents you have to tell apart rather than merge.
5. **One benign interactive PowerShell command** (e.g. `Get-Process | Sort-Object CPU -Descending`) — should NOT fire the encoded-PowerShell rule; a deliberate "is this actually suspicious?" judgment call.
6. **One encoded/obfuscated PowerShell command** (base64-encoded, harmless payload) — should fire the encoded-PowerShell rule, giving you a genuine true positive to escalate.
7. Let it ingest 15-20 min — move on to Part D while you wait.
8. Azure Portal → search `Microsoft Sentinel` → `law-soc-atlas` → **Incidents** → confirm 10-12 new incidents distinct from ATLAS's, spanning all the patterns above.

## Part D — Write the full Alert Triage Playbook (30 min)

`Alert-Triage-Playbook.md`: one section per alert type generated above (fast port scan, slow port scan, RDP auth-failure burst, benign PowerShell, encoded PowerShell) plus the built-in auth-failure template. For each, document: trigger condition, initial checks, false-positive indicators, true-positive/escalation criteria, required evidence. Add a short **triage decision tree** (even a simple nested list) covering: is this expected/scheduled activity → does it match a known FP pattern → does severity/entity criticality warrant escalation regardless. This playbook is what you mechanically apply next, not ad-hoc judgment — call this out later in the Loom video.

## Part E — Triage pass, all alerts (60 min)

For each of the 10-12 incidents: open in Sentinel → note severity/entities/timestamp → create matching Jira ticket (Open) → run the relevant KQL, e.g.:

```kql
Event
| where TimeGenerated > ago(1d)
| where Computer == "DESKTOP-TRF9U79"
| where EventID == 3
| order by TimeGenerated desc
```

Write a one-line verdict in the ticket: **False Positive** (reason) or **Escalate** (reason). With 10-12 alerts across multiple patterns you should land at least 3-4 genuine escalations plus several deliberate false positives — the mix is the point, since a Tier 1 shift is mostly noise with a handful of real signals.

## Part F — Deep investigation on escalated alerts (60 min)

For each **Escalate** ticket: check the IP/hash/domain against AbuseIPDB and VirusTotal (free accounts), screenshot the reputation result. Go one level deeper than a single lookup:

1. Correlate across tables — check whether the same host/entity shows other unusual activity in a wider time window.
2. Build a simple **event timeline** for at least one escalated incident (timestamp → event → why it matters) — this is a concrete artifact hiring managers ask for in interviews ("walk me through how you'd investigate this").
3. Attach KQL output + IOC screenshots to each ticket, move to **In Progress**.

## Part G — Phishing simulation & investigation, two scenarios (45 min)

1. Defender portal (security.microsoft.com) → **Email & collaboration** → **Attack simulation training** → **Launch a simulation** → **Credential Harvest**, your own test mailbox, a template different from ATLAS's.
2. Investigate the landed email without clicking: Outlook → message → **File** → **Properties** → **Internet headers** (check Return-Path, SPF, DKIM, DMARC); hover the link to see the real URL.
3. Launch a **second simulation** with a different technique (e.g. **Link in Attachment** or a different lure template) — gives you a genuine "which one looks more convincing and why" comparison instead of a single one-off.
4. Write `Phishing-Investigation-Report.md` covering both: what looked suspicious, header findings, verdict, playbook next steps (report/quarantine/block/notify) for each.
5. Log each as its own Jira ticket through to Resolved.

## Part H — Escalation write-ups (30 min)

For each escalated ticket, a short formal handoff: Severity / Affected entity / Summary / Evidence link / Recommended action / Escalated by + time. Attach to the ticket, move to Escalated, then resolve with a closing note.

## Part I — Shift log & metrics (20 min)

`Shift-Log.md` pulled straight from the Jira board: alerts reviewed, false positives closed, true positives escalated, false-positive rate, mean time to triage, mean time to escalate, breakdown by alert type. With 10-12 alerts across multiple categories this gives you a more credible metrics table than a 5-alert sample would — this is the concrete number you drop in an interview.

## Part J — Challenges & Lessons Learned (15 min)

Populate from whatever actually went sideways during Parts A-H (Jira config decisions, KQL troubleshooting, a threat-intel lookup that flipped your verdict, telling apart the two RDP bursts, comparing the two phishing templates). Filter: does it demonstrate a SOC-relevant skill, or is it lab housekeeping? Only the former belongs here.

## Part K — README + screenshot pass + Loom prep (45 min)

Title/pitch, role context (from the Blueprint's JD summary), architecture note (reuses ATLAS's pipeline), what you did, 2-3 sample screenshots (one triage decision, one escalation writeup, one phishing header comparison), metrics from Part I, challenges from Part J, skills-demonstrated table. Redact subscription IDs/account identifiers before publishing. Do a final pass against `Loom-Recording-Guide.md` to confirm you have everything on screen you'll need for the recording.

## Final checklist

- [ ] Lab confirmed healthy, trial days remaining checked
- [ ] Jira `SOC1 Queue` live with one ticket per alert (10-12 alerts), all resolved/escalated
- [ ] Playbook written and applied, including the decision tree
- [ ] Both phishing scenarios investigated and reported
- [ ] Shift log with real metrics, broken down by alert type
- [ ] README + screenshots ready
- [ ] VMs saved state (`VBoxManage controlvm <uuid> savestate`)
