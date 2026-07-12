# Shift Log — Project BEACON

Single-session Tier 1 SOC shift, 10-11 July 2026. Pulled from the `SOC1 Queue` Jira board (project key `SOC1`).

## Summary

| Metric | Value |
|---|---|
| Total alerts/incidents reviewed | 7 |
| False positives closed | 3 |
| True positives escalated | 4 |
| False-positive rate | 43% (3/7) |
| Escalation rate | 57% (4/7) |

## Breakdown by type

| Ticket | Alert type | Verdict | Reasoning (short) |
|---|---|---|---|
| SOC1-1 | Fast port scan (`nmap -sV`) | False Positive | Internal lab-simulated source, matched known scanning pattern, no follow-on exploitation attempt |
| SOC1-6 | Stealthy port scan (`nmap -sS -T2`) | False Positive | Same source as above; slower/quieter timing noted but no escalation criteria met |
| SOC1-2 | RDP auth-failure burst (`soclab-test`) | **Escalate** | 3 failed + 1 successful logon in 42s on a test account with no legitimate reason to authenticate; timing consistent with manual credential guessing |
| SOC1-3 | Benign PowerShell (`Get-Process`) | False Positive | Plain-text, non-obfuscated, routine admin-style command; correctly identifying non-suspicious activity documented as its own Tier 1 skill |
| SOC1-4 | Encoded PowerShell (`-EncodedCommand`) | **Escalate** | Decoded to benign `whoami`, but obfuscation technique itself is inherently suspicious regardless of payload; binary hash-verified clean via VirusTotal |
| SOC1-7 | Phishing — Credential Harvest ("Black Friday" lure) | **Escalate** | Sender domain flagged malicious by 7/91 VT vendors; SCL -1; automated risk score 75/100 |
| SOC1-8 | Phishing — Link in Attachment ("Invoice" lure) | **Escalate** | Sender domain flagged malicious by 3/91 VT vendors; malicious link hidden in attachment, evading body-text URL scanning; automated risk score 40/100 |

## Timing notes

Mean-time-to-triage (MTTA) and mean-time-to-escalate (MTTE) weren't tracked as precise per-ticket stopwatch deltas in this single compressed lab session — alerts were generated and triaged in a continuous working block rather than arriving organically over a shift, so a fabricated MTTA/MTTE number wouldn't be honest. In a live SOC rotation, these would be pulled directly from Jira's "time in status" reporting.

## Notable pattern

Both true-positive alert-type escalations (RDP burst, encoded PowerShell) were escalated on **technique/context rather than confirmed malicious payload** — neither instance actually contained a malicious action once fully investigated, but both matched playbook criteria that treat certain techniques (encoding, test-account authentication) as escalation-worthy regardless of surface-level outcome. This mirrors real Tier 1 practice: a missed true positive is worse than an over-cautious escalation that Tier 2 closes quickly.
