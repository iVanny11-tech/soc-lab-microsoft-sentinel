> **Superseded:** the whole project fits in one ~6-hour session. Use `BEACON-Session-Guide.md` instead — this file is kept only as a more granular reference.

# Day 3 — Shift Log, Documentation & GitHub Packaging

Goal: close the loop with the artifact that separates a real SOC1 operator from someone who just ran a lab — shift metrics — then package for GitHub and Loom.

## Part A — End-of-shift log

Create `Shift-Log.md`. Pull the numbers straight from your Jira board (Jira → your project → filter by status):

- **Alerts reviewed:** (total tickets created)
- **False positives closed:** 
- **True positives escalated:** 
- **False-positive rate:** (false positives ÷ total)
- **Mean time to triage (MTTA):** for each ticket, ticket-created timestamp → first-verdict-comment timestamp; average it
- **Mean time to escalate:** for escalated tickets, verdict timestamp → escalation-writeup timestamp

This mirrors exactly what a real SOC shift handoff report looks like and is a strong, concrete metric to drop in an interview ("I processed X alerts with a Y% false-positive rate and an average triage time of Z minutes").

## Part B — Challenges, Overcomings & Lessons Learned

Don't pre-write this — populate it as you actually hit real snags during Days 1–2 execution (same standard as Project ATLAS). Before adding anything, ask: does this demonstrate a SOC-job-relevant skill (SIEM investigation, ticketing discipline, threat-intel lookup, phishing analysis), or is it lab/VM housekeeping? Only the former belongs here.

Likely candidates based on what Day 1–2 involve: Jira project configuration decisions, KQL query troubleshooting for the new alert batch, phishing header analysis findings, threat-intel lookup results that changed your triage verdict.

## Part C — GitHub README for the BEACON section

Structure (keep it separate from the ATLAS README — either a subfolder `Project-BEACON/README.md` in the same repo, or its own repo entirely, your call):

1. **Title & one-line pitch:** "SOC1 Tier 1 Analyst Workflow Simulation — alert triage, investigation, and escalation using Microsoft Sentinel and Jira Service Management"
2. **Role context:** 2–3 sentences framing this as simulating an entry-level SOC Analyst I day-to-day (cite the JD summary from the Blueprint)
3. **Architecture:** reuse the ATLAS architecture diagram with a note that this project layers a Tier 1 workflow (Jira + playbook + threat intel) on top of the existing pipeline
4. **What I did:** Day 1–3 summary, linking each guide
5. **Sample artifacts:** 1–2 screenshots of a worked Jira ticket, the triage playbook excerpt, a phishing header analysis screenshot
6. **Metrics:** pull straight from `Shift-Log.md`
7. **Challenges & Lessons Learned:** from Part B
8. **Skills demonstrated:** map directly to the JD table in the Blueprint

## Part D — Screenshot flagging

As you assemble the README, flag which screenshots are genuinely doc-worthy (clear triage decisions, a clean escalation writeup, the phishing header comparison) vs. incidental (a terminal window mid-command). Redact any subscription IDs or account identifiers before publishing, same as ATLAS.

## End of Day 3 / project checklist

- [ ] `Shift-Log.md` written with real metrics
- [ ] Challenges section populated from real Day 1–2 friction, filtered to job-relevant items
- [ ] README.md written and placed in repo
- [ ] Screenshots selected, redacted, and referenced
- [ ] VMs saved state; Jira project left live (or exported) for future reference
