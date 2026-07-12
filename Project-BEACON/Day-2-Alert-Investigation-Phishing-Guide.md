> **Superseded:** the whole project fits in one ~6-hour session. Use `BEACON-Session-Guide.md` instead — this file is kept only as a more granular reference.

# Day 2 — Work the Queue: Triage, Investigation, Phishing, Escalation

Goal: mechanically apply the Day 1 playbook to every alert, run a phishing investigation, and escalate the genuine incidents.

## Part A — Triage pass (fast, per-alert)

For each Sentinel incident from Day 1:

1. Azure Portal → `law-soc-atlas` → **Incidents** → open the incident.
2. Note severity, entities involved, and timestamp.
3. Create the matching Jira ticket (title convention from Day 1 Part B). Status: **Open**.
4. Apply the playbook's "initial checks" step: pull the raw KQL for the underlying events. Example for the port scan:
   ```kql
   Event
   | where TimeGenerated > ago(1d)
   | where Computer == "DESKTOP-TRF9U79"
   | where EventID == 3
   | order by TimeGenerated desc
   ```
5. Write a one-line triage verdict in the Jira ticket comment: **False Positive** (with reason) or **Escalate** (with reason). This one-line-verdict habit is exactly what real Tier 1 metrics dashboards are built from — call this out in your Loom video.

## Part B — Deep investigation on anything you escalate

For each alert marked **Escalate**:

1. Pull full entity context: for an IP, check both **AbuseIPDB** (abuseipdb.com, free account, paste IP) and **VirusTotal** (virustotal.com, free account, IP/domain/hash search tab). Screenshot the reputation result.
2. Correlate across tables — e.g., if a suspicious process fired, check whether the same host also shows unusual sign-in activity:
   ```kql
   Event
   | where Computer == "DESKTOP-TRF9U79"
   | where TimeGenerated between (datetime(<start>) .. datetime(<end>))
   | project TimeGenerated, EventID, RenderedDescription
   | order by TimeGenerated asc
   ```
3. Attach the KQL output screenshot + IOC lookup screenshot to the Jira ticket.
4. Move the Jira ticket to **In Progress**.

## Part C — Phishing simulation & investigation (new to BEACON, not in ATLAS)

1. In the Microsoft 365 Defender portal (security.microsoft.com) → left nav → **Email & collaboration** → **Attack simulation training** → **Launch a simulation**.
2. Choose a **Credential Harvest** technique, target your own test mailbox, use a different template than any used in ATLAS (ATLAS used this feature to trigger a real sign-in risk event — BEACON's angle is investigating the *email itself*, not the downstream sign-in).
3. Once the simulated email lands in your inbox, open it (don't click the link) and investigate like a real Tier 1 analyst would:
   - View the message headers: Outlook → open message → **File** → **Properties** → **Internet headers**. Check `Return-Path`, `Received-SPF`, `DKIM`, `DMARC` results.
   - Hover the link (don't click) to see the real destination URL vs. the display text.
   - Check the sender domain against a WHOIS lookup or AbuseIPDB if it resolves to an IP you can check.
4. Write `Phishing-Investigation-Report.md`: what looked suspicious, header analysis results, verdict, and what the standard response playbook says to do next (report to Microsoft, quarantine, block sender, notify affected user) — even though this is a simulation, write the report as if it were real, since this is what a hiring manager wants to see you can produce.
5. Log this as its own Jira ticket, worked through to **Resolved**.

## Part D — Escalation write-ups

For every ticket marked **Escalate**, write a short formal handoff (this is the artifact of "escalating to Tier 2 with documented findings" from the JD):

```
## Escalation: <alert name>
**Severity:** 
**Affected entity:** 
**Summary:** 
**Evidence:** (link to attached screenshots/KQL)
**Recommended action:** 
**Escalated by:** Ivan | **Time:** 
```

Attach these to the Jira ticket, move to **Escalated**, then (since you're also playing Tier 2 in this simulation) resolve them with a closing note — same pattern ATLAS used for its incident report, but framed here as a handoff rather than a self-contained investigation.

## End of Day 2 checklist

- [ ] Every Day 1 alert has a Jira ticket with a triage verdict
- [ ] Escalated tickets have KQL + threat intel evidence attached
- [ ] Phishing simulation run, headers analyzed, `Phishing-Investigation-Report.md` written
- [ ] All tickets moved to a terminal status (Resolved/Escalated-Closed)
