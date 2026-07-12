> **Superseded:** the whole project fits in one ~6-hour session. Use `BEACON-Session-Guide.md` instead — this file is kept only as a more granular reference.

# Day 1 — Queue Setup & Triage Playbook

Goal: stand up the Tier 1 workflow (ticketing + fresh alerts) and write the playbook you'll apply on Day 2.

## Part A — Confirm the lab is still alive

1. Open VirtualBox Manager. Confirm both VMs (`KALI ` — note the trailing space in its registered name, and the Windows VM) show as **Saved**, not powered off.
2. Get each VM's UUID (needed because of the trailing-space bug):
   ```
   VBoxManage list vms
   ```
3. Start both by UUID:
   ```
   VBoxManage startvm <KALI-UUID> --type headless
   VBoxManage startvm <WINDOWS-UUID> --type headless
   ```
4. SSH into Kali from Mac Terminal (not the VirtualBox GUI console — clipboard doesn't work there):
   ```
   ssh <kali-user>@10.0.2.15
   ```
5. RDP into the Windows VM via Microsoft Remote Desktop, saved tile pointing at `localhost:33389`.
6. In the Windows VM, open an elevated PowerShell and run:
   ```
   azcmagent show
   ```
   Confirm `Agent Status: Connected`. If not connected, this is a blocker — stop and reconnect before continuing (don't build new alerts on top of a broken telemetry pipeline).
7. In the Azure Portal (portal.azure.com), go to **Subscriptions** (search bar, top center) → click your subscription → confirm the trial hasn't expired and note the days remaining. If under 3 days remain, flag it — the timeline is tight.

## Part B — Stand up Jira Service Management (new tool for this project)

1. Go to https://www.atlassian.com/software/jira/service-management → **Get it free**.
2. Sign up with your email, choose **Service Management** product, free tier.
3. Create a new project: type **IT Service Management** (closest fit to a SOC queue), name it `SOC1 Queue`, key `SOC1`.
4. In project settings → **Issue Types**, keep it simple: use the default **Task** type for each alert ticket (don't over-engineer the Jira config — the point is documentation discipline, not Jira administration).
5. Create one custom field-free convention instead of custom fields: every ticket title follows the pattern:
   `[ALERT] <Sentinel alert name> — <entity, e.g. hostname or IP>`
6. Screenshot the empty board for your GitHub writeup (day 3) — this is the "before" shot showing the queue starting clean.

## Part C — Generate a fresh alert batch (different from ATLAS's incidents)

You want 5–8 alerts in the Sentinel incident queue that you have NOT already investigated under ATLAS. Run a short, varied batch from Kali against the Windows VM (via the forwarded ports, `10.0.2.2:<port>`):

1. **Port scan (new angle vs. ATLAS's recon):** from Kali,
   ```
   nmap -sV -p 1-1000 10.0.2.2 -oN beacon_scan1.txt --reason
   ```
2. **A handful of legitimate-looking failed logons mixed with real ones** (to force a real false-positive judgment call) — RDP into the Windows VM three times with an intentionally wrong password, then once with the correct one, from a *different* source than ATLAS's brute-force pattern (e.g., manually via Remote Desktop client rather than Hydra) — this should look different enough in the logs that it's a genuinely new triage decision, not a repeat of ATLAS's Rule 4.1.
3. **One deliberately benign trigger** — e.g., a legitimate admin-looking PowerShell command (`Get-Process | Sort-Object CPU -Descending`) run interactively on the Windows VM. This should NOT fire your encoded-PowerShell rule from ATLAS, but may surface in a broader "PowerShell execution" hunting query if you add one — useful for practicing "is this actually suspicious?" judgment.
4. Let telemetry ingest for 10–15 minutes (same ingestion-lag pattern as ATLAS — don't panic if `SecurityEvent`/`Event` look empty immediately).
5. In the Azure Portal, navigate: left-hand nav → **All services** (if Sentinel isn't pinned) → search `Microsoft Sentinel` → select your workspace `law-soc-atlas` → left nav under **Threat management** → **Incidents**. Confirm new incidents appear separate from ATLAS's earlier ones (check timestamps).

## Part D — Write the SOC1 Alert Triage Playbook

Create `Alert-Triage-Playbook.md` in the BEACON folder. For each alert type you might see, document:

- **Trigger condition** (what generates it)
- **Initial checks** (what to look at first: entity, time, source IP reputation, is it expected/scheduled activity)
- **False-positive indicators** (what makes you close it without escalating)
- **True-positive indicators / escalation criteria**
- **Required evidence to attach before escalating** (screenshots, raw log excerpt, IOC lookups)

Base it on the three Sentinel rules already live from ATLAS (brute-force spike, encoded PowerShell, built-in auth-failure template) plus the port scan you just generated. This playbook is what you'll mechanically follow on Day 2 — the discipline of following a written playbook rather than ad-hoc judgment is itself a Tier 1 competency worth calling out in your Loom recording.

## End of Day 1 checklist

- [ ] Both VMs confirmed healthy, telemetry pipeline connected
- [ ] Jira `SOC1 Queue` project live, empty-board screenshot taken
- [ ] 5–8 fresh alerts confirmed in Sentinel Incidents blade, distinct from ATLAS's incidents
- [ ] `Alert-Triage-Playbook.md` written
- [ ] VMs saved state before ending session (`VBoxManage controlvm <uuid> savestate`)
