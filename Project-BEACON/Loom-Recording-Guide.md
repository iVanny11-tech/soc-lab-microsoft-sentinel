# Loom Recording Guide — Project BEACON

Purpose: a 6–9 minute walkthrough you can send directly to a recruiter or hiring manager as a follow-up after applying, or attach to your application/LinkedIn post. Keep it tighter than a full ATLAS-style deep-dive — Tier 1 hiring managers want to see triage discipline and communication clarity, not architecture depth.

## Structure

**0:00–0:45 — Who you are and what this is**
"Hi, I'm Ivan. I built this project to simulate the actual day-to-day of an entry-level SOC Analyst I — alert triage, investigation, and escalation — using Microsoft Sentinel and Jira Service Management, based on real Tier 1 job postings I researched."

**0:45–2:00 — Show the queue and the playbook**
Screen: Sentinel Incidents blade with the alert batch, then the `Alert-Triage-Playbook.md`. "Here's the queue I worked from, and here's the playbook I wrote first — every triage decision below follows this, not gut feel."

**2:00–4:30 — Walk one alert end to end**
Pick your best example (ideally one false positive and one true positive, if time allows two short ones instead of one long one). Show: Sentinel incident → KQL investigation query → threat intel lookup (VirusTotal/AbuseIPDB) → Jira ticket with verdict and evidence attached → (if true positive) escalation writeup.

**4:30–6:00 — Phishing investigation**
Show the simulated phishing email, the header analysis (SPF/DKIM/DMARC), and your investigation report. This is a high-signal segment — phishing triage is one of the most common real Tier 1 tasks.

**6:00–7:30 — Metrics and wrap-up**
Show `Shift-Log.md`. "Across this shift I reviewed X alerts, escalated Y, with a Z% false-positive rate and an average triage time of N minutes." Close with: "This is the workflow I'd bring on day one to a SOC1 role" — direct, confident, no hedging.

## Delivery notes

- Record at 1080p, cursor visible, zoom in on KQL/Jira text so it's readable at Loom's default embed size.
- Close Slack/notifications/anything with PII before recording.
- Do one full unscripted practice run first — this keeps the real take conversational instead of read-off-a-script.
- Trim dead air in Loom's editor before sending; keep total runtime under 9 minutes — recruiters will not watch longer than that for an unsolicited video.
- End with your name, the GitHub link on screen (as text overlay or spoken), and a one-line CTA: "Happy to walk through the full repo or take questions."

## Where to send it

- Attach the Loom link directly in a LinkedIn message to the recruiter/hiring manager after applying, not as a cold-open — reference the job posting explicitly.
- Include it in the "additional info" field on the application if one exists.
- Pin it to the GitHub README's top (badge/link) so anyone browsing the repo sees it first.
