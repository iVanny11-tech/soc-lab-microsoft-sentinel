# Project ATLAS — Day 4 Walkthrough: Investigation & Containment

Goal for today: switch from attacker to analyst. Triage everything Day 3 generated, isolate the compromised device, remediate the risky user, and draft a Conditional Access policy. ~2–2.5 hours.

---

## Part A — Triage the incident queue (30–40 min)

1. **security.microsoft.com → Incidents & alerts → Incidents.**
2. You should see several incidents now — expect roughly:
   - One covering the failed-logon spike (your custom rule 4.1, fed by Sysmon/Security-log telemetry via Azure Arc + AMA)
   - One covering the encoded PowerShell execution (your custom rule 4.2, same telemetry pipeline)
   - Possibly one tied to the Tor sign-in risk, since Entra ID Protection risk detections surface into the same unified queue
3. **The phishing simulation usually won't appear here as a real incident** — it's intentionally benign/simulated, so Defender for Office 365 tracks it under Attack simulation training reporting rather than raising a security incident. That's expected, not a gap.
4. Note in your documentation that, unlike a tenant with Defender for Endpoint, these two incidents are surfaced entirely by your own custom analytics rules rather than a blend of custom + native vendor detections — a direct consequence of the Sysmon/Arc pivot (see Day 1, Part F). Worth a sentence in the report: the detection logic here is fully yours, which is arguably a stronger demonstration of the "creating analytic triggers" JD bullet than relying on a vendor's built-in alert.
5. For each real incident: open it, walk the **incident graph/timeline**, check the **Alerts** and **Assets** tabs to confirm the device (`DESKTOP-TRF9U79`) and account (`soclab-test`) involved, classify it as a **true positive**, and add a comment to the incident summarizing your triage reasoning (one or two sentences — e.g. "Confirmed brute force against soclab-test from Kali test VM, Project ATLAS Day 3 simulation. Proceeding to containment.").
6. Leave status as **Active** for now — you'll set incidents to **Resolved** once containment (Parts C–E) is done.

---

## Part B — Root-cause narrative (10 min)

Draft (don't formalize yet — that's Day 5) a short paragraph tying the stages together chronologically. Something like:

> Reconnaissance via Nmap identified an exposed RDP service on the victim host. A phishing simulation independently tested the user-reported-email vector. A sign-in over Tor flagged an anonymous-IP risk on a test Entra account. Hydra then brute-forced the RDP service's local test account, after which a base64-encoded PowerShell command established a reverse shell back to the attacker host, completing the kill chain from initial recon to command-and-control.

Keep your own version short — 3–5 sentences. This becomes the executive summary in Day 5's report, so write it now while the sequence is fresh.

---

## Part C — Contain the victim device (15 min)

Without Defender for Endpoint, there's no one-click "Isolate device" action — so this builds the manual equivalent: a host-based Windows Firewall rule blocking all inbound and outbound traffic, applied directly on the VM. This is the real action a Tier 1 analyst takes when EDR-based isolation isn't available (e.g. an unmanaged or unenrolled host), so it's a legitimate — arguably more hands-on — way to demonstrate the same containment skill.

1. On the Windows VM, open an elevated PowerShell (right-click Start → **Terminal (Admin)**).
2. Block all inbound traffic:
   ```powershell
   New-NetFirewallRule -DisplayName "ATLAS-Isolation-Block-Inbound" -Direction Inbound -Action Block -Enabled True -Profile Any
   ```
3. Block all outbound traffic:
   ```powershell
   New-NetFirewallRule -DisplayName "ATLAS-Isolation-Block-Outbound" -Direction Outbound -Action Block -Enabled True -Profile Any
   ```
4. Confirm containment: from Kali, try to reach the Windows VM (`ping <Windows-VM-IP>` or re-run the earlier Nmap scan) — it should now be unreachable.
   - 📸 **Screenshot (must-have):** the two firewall rules listed in `Get-NetFirewallRule -DisplayName "ATLAS-Isolation-*"`, plus the failed ping/Nmap attempt from Kali — together this is your containment evidence.
5. In the incident in security.microsoft.com, add a comment documenting the action taken: `Contained victim device via host-based Windows Firewall block-all rule (manual equivalent of EDR isolation — no MDE sensor present, see Day 1 Part F) — Project ATLAS Day 4 containment.`
6. Heads up: this cuts all network traffic on the VM, including the Sysmon/AMA telemetry pipeline's outbound connection to Azure — expected, same tradeoff as MDE's full isolation cutting everything except its own management channel. Once you've screenshotted the contained state, release it so the VM is usable again for Day 5:
   ```powershell
   Remove-NetFirewallRule -DisplayName "ATLAS-Isolation-Block-Inbound"
   Remove-NetFirewallRule -DisplayName "ATLAS-Isolation-Block-Outbound"
   ```

This is your evidence for the "containment" half of the JD's incident response bullet.

---

## Part D — Remediate the risky user in Entra ID (10 min)

1. **Entra admin center (entra.microsoft.com) → Protection → Identity Protection → Risky users.**
2. Select the test account flagged from Tuesday's Tor sign-in. Review its **Risk state**, **Risk level**, and the **Risk detections** list.
3. Click **Confirm compromised** — this is the realistic SOC action for a true-positive compromise (as opposed to "Dismiss user risk," which is for false positives).
4. Separately, reset the test account's password to fully remediate (Confirm compromised flags the account; it doesn't change the password for you).
5. Note your reasoning in the incident comment from Part A, or in your running notes for Day 5.

---

## Part E — Draft a Conditional Access policy (20 min)

A real practical safety note first: scope this to your **test user only**, not "All users." You don't want your own admin account locked out if your home network's IP reputation ever gets flagged.

1. **Entra admin center → Protection → Conditional Access → "+ New policy."**
2. Name: `ATLAS - Block sign-in risk (anonymous IP / Tor)`
3. **Assignments → Users → Include**: select your specific test user (or a small test group if you've created one). **Exclude**: your real admin/break-glass account, regardless.
4. **Target resources → Cloud apps**: All cloud apps.
5. **Conditions → Sign-in risk → Configure: Yes** → select **Medium and high.**
6. **Grant**: choose **Block access** (matches the project's stated goal of blocking anonymous/Tor sign-ins). **Require multifactor authentication** is the lighter-touch alternative many real orgs use instead of an outright block — worth mentioning you considered it.
7. **Enable policy: set to "Report-only"** rather than "On." This is the real-world best practice — you see what the policy *would* have done without risking a lockout, which matters even more in a single-admin lab than in a large org.
8. Save.
9. To verify: check **Entra admin center → Monitoring → Sign-in logs → filter by "Report-only (preview)"** — if the test user signs in again over Tor, you should see the event flagged as "would have been blocked." Screenshot that.
10. Document why you left it in Report-only rather than flipping to "On" (single-user lab, no production traffic at risk, but the correct rollout procedure either way) — that's a good line for your README and for interview conversation.

---

## End-of-day checklist

- All real incidents (brute force, encoded PowerShell, Tor risk) triaged, classified true positive, commented
- Root-cause narrative drafted (3–5 sentences)
- Victim device contained via manual host-based firewall block, screenshot taken, then released
- Risky test user confirmed compromised, password reset
- Conditional Access policy created in Report-only mode, sign-in log evidence captured

Tomorrow (Day 5) is hunting, the formal report, the ATT&CK Navigator heatmap, and pushing the repo. If an incident won't classify, isolation gets stuck on "Pending," or the Conditional Access policy doesn't show up in Report-only sign-in logs, tell me exactly what you're seeing.
