# Project BEACON — SOC1 Tier 1 Analyst Workflow Simulation

**A separate project from Project ATLAS.** ATLAS simulated a senior escalation/detection-engineering role. BEACON simulates the day-to-day grind of an **entry-level SOC Analyst I (Tier 1)** — the first line of defense in a SOC. Keep the two portfolio pieces distinct: different repo folder, different narrative, different resume bullet ("Tier 1 triage & response" vs. "Senior detection engineering & cloud architecture").

---

## 1. Target Job Description (representative — grounded in current 2026 postings)

**Title:** SOC Analyst I (Tier 1) — Security Operations Center
**Level:** Entry-level, 0–2 years experience
**Typical salary (US market, July 2026):** $72,000–$126,500/yr, average ~$99,000 ([Dropzone.ai SOC salary guide 2026](https://www.dropzone.ai/resource-guide/soc-analyst-career-path-salary-guide-2026-ai-powered-edition); [ZipRecruiter](https://www.ziprecruiter.com/Jobs/Soc-Analyst-Tier-1))

**Responsibilities:**
- Monitor SIEM dashboards and triage incoming alerts continuously during shift (dozens to hundreds of alerts/shift)
- Filter false positives from genuine threats using documented runbooks/playbooks
- Perform initial investigation: pull relevant logs, correlate events across tools, check threat intelligence feeds (IP/domain/hash reputation)
- Escalate confirmed incidents to Tier 2 with clear documented findings and evidence
- Take initial containment actions per playbook when authorized
- Log every alert reviewed, action taken, and finding in the ticketing system — clean documentation is a core competency, not an afterthought
- Investigate and respond to phishing reports from end users
- Maintain awareness of basic networking (TCP/IP, DNS, HTTP/S) and OS internals (Windows Event Logs, Linux syslog)

**Tools commonly listed:** SIEM (Splunk / Microsoft Sentinel / IBM QRadar), ticketing (Jira / ServiceNow), threat intel lookups (VirusTotal, AbuseIPDB), Windows/Linux/macOS basics

**Certifications that pair with this level:** CompTIA Security+, CompTIA CySA+, Microsoft SC-200, Splunk Core Certified User

Sources: [Wiz — Tier 1 SOC Analyst](https://www.wiz.io/academy/cloud-careers/soc-analyst-tier-1), [Exabeam — SOC Analyst Job Description](https://www.exabeam.com/blog/security-operations-center/soc-analyst-job-description-skills-and-5-key-responsibilities/), [3University — SOC Analyst Certifications Guide](https://www.3university.io/soc-analyst-skills-certifications-qualifications-guide/)

---

## 2. What BEACON Demonstrates (mapped to the JD above)

| JD line | BEACON deliverable |
|---|---|
| Monitor SIEM, triage alerts | Live-worked Sentinel incident queue, screenshots of triage decisions |
| Filter false positives via playbook | Written SOC1 Alert Triage Playbook, applied to each queue item |
| Investigate: logs, correlation, threat intel | KQL investigation queries + VirusTotal/AbuseIPDB lookups per incident |
| Escalate with documented findings | Formal Tier 2 escalation write-ups for true positives |
| Ticketing/documentation | Real Jira Service Management project, one ticket per alert |
| Phishing investigation | Simulated phishing email, header/URL analysis, response playbook executed |
| Shift metrics awareness | End-of-project shift log with MTTA, escalation rate, false-positive rate |

---

## 3. Environment (reuses Project ATLAS infrastructure — practical decision, see note below)

- **SIEM:** Same Microsoft Sentinel workspace (`law-soc-atlas`) and Log Analytics tables (`SecurityEvent`, `Event`) from ATLAS. Already ingesting from `DESKTOP-TRF9U79` (Windows victim VM) via Sysmon + AMA.
- **Attack source:** Same Kali VM, used only to generate a *fresh* batch of alerts for BEACON (not the same incidents ATLAS already investigated).
- **Ticketing (new):** Jira Service Management free tier (free forever, up to 3 agents) — sign up at atlassian.com, create project `SOC1-QUEUE`. This is a genuine, resume-worthy tool addition ATLAS didn't use.
- **Threat intel (new):** VirusTotal (free account, 4 lookups/min) and AbuseIPDB (free tier, 1,000 checks/day) for IOC enrichment during investigation.
- **Phishing simulation:** Microsoft Defender for Office 365 Attack Simulator (already licensed under the same M365 E5 trial from ATLAS) — new campaign, different template than ATLAS used.

**Why reuse the lab instead of building fresh:** the Sentinel/Sysmon/AMA pipeline already works end-to-end (confirmed in ATLAS) — rebuilding it would just repeat plumbing work with no new SOC1 skill demonstrated. The *narrative, incidents, and documentation* are 100% new and BEACON-specific, so the two projects read as clearly separate portfolio pieces despite sharing a backend.

**Timing note:** the Azure free trial began ~2026-06-18/19 (per ATLAS setup). A 30-day trial puts expiry around **2026-07-18/19** — roughly 9–10 days out from today. BEACON's 3-day timeline fits comfortably, but don't let it slip; confirm trial/subscription status in the Azure portal (Subscriptions blade) before Day 1.

**Alternative if you'd rather have a fully separate environment:** stand up Wazuh (free, open-source SIEM) on a small Linux VM instead. Say the word and I'll redraft around that — flagging it here since I defaulted to lab reuse for speed.

---

## 4. Timeline — single session, ~6 hours

Corrected 2026-07-09, then corrected again same day: this is Tier 1 scope, not a multi-day build like ATLAS, but Ivan wants the full ~6-hour depth in one sitting rather than a compressed 2.5-hour pass. See `BEACON-Session-Guide.md` (Parts A–K, with time estimates) for the full walkthrough. Rough breakdown:

| Block | Focus | Time |
|---|---|---|
| Setup (A–C) | Confirm lab, stand up Jira, generate a larger 10-12 alert batch | ~60 min |
| Playbook + triage (D–F) | Write full playbook w/ decision tree, triage queue, deep-investigate escalations | ~150 min |
| Phishing + escalation (G–H) | Two phishing scenarios investigated, escalation handoffs | ~75 min |
| Wrap-up (I–K) | Shift log metrics, challenges section, README/screenshots/Loom prep | ~80 min |

(The `Day-1/2/3` guides in this folder are superseded by `BEACON-Session-Guide.md` — kept only as more granular reference if you want to spread it out.)

---

## 5. Deliverables checklist

- [ ] SOC1 Alert Triage Playbook (Day 1)
- [ ] Jira `SOC1-QUEUE` project with one ticket per alert, worked to closure (Day 1–2)
- [ ] KQL investigation queries per incident (Day 2)
- [ ] Phishing investigation report (Day 2)
- [ ] Tier 2 escalation write-ups for true positives (Day 2)
- [ ] End-of-shift log with triage metrics (Day 3)
- [ ] GitHub README for the BEACON section (Day 3)
- [ ] Loom recording script (Day 3)

Next: Day 1 guide.
