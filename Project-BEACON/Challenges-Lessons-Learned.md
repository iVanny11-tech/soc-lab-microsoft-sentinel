# Challenges & Lessons Learned — Project BEACON

Real trial-and-error from this session, filtered to what's actually SOC-relevant (not lab/VM housekeeping).

## 1. Azure Monitor Agent telemetry pipeline silently failed while Arc connectivity showed healthy

The Log Analytics workspace stopped receiving fresh Heartbeat data a week before this session, with no obvious error anywhere in the Portal. Diagnosis:

- `azcmagent show` reported `Agent Status: Connected` — looked healthy, and was a red herring.
- The `AzureMonitorWindowsAgent` extension showed **"Succeeded"** in the Azure Portal's Extensions blade.
- On the actual Windows VM, `Get-Service` showed **no Azure Monitor Agent service at all** — not stopped, not misnamed, genuinely never installed.

**Lesson:** Azure Arc connectivity (`himds`/Arc heartbeat) and the Azure Monitor Agent (telemetry shipping to Log Analytics) are independently-failing systems, even though they look related in the Portal. A "Connected" Arc status is not proof that monitoring data is actually flowing — the extension's control-plane status ("Succeeded") can also be wrong relative to what's actually running on the guest OS. Two restart/redeploy attempts didn't fully resolve it within the session; pivoted to using Windows Event Viewer (Sysmon Operational + Security logs) directly on the VM as the evidence source instead of waiting on the pipeline, since the underlying events were still being generated and logged locally regardless of the shipping failure.

## 2. RDP-based attack simulation hit a persistent network wall — pivoted rather than lost the alert type

The original plan was to generate the RDP auth-failure burst remotely via `xfreerdp` from the Kali attack-simulation host. The TCP handshake succeeded (confirmed via port scan) but the RDP application-layer negotiation reset after ~77 seconds every time, across several fix attempts (NLA already disabled, forcing legacy RDP security layer, restarting `TermService`).

**Lesson:** Rather than burning further time chasing an infrastructure-specific networking issue, generated the same failed/successful logon event sequence locally via the Windows lock screen instead — same Event IDs (4625/4624), same triage logic, just a different Logon Type (Interactive vs. RemoteInteractive). The alert type and investigation value were preserved even though the delivery mechanism had to change. Knowing when to pivot instead of continuing to debug a side issue is itself a practical skill.

## 3. Automated phishing IOC enrichment has a blind spot for attachment-based lures

Built a custom Python pipeline that parses a `.eml`, extracts sender domain/URLs/IPs, and enriches via VirusTotal + AbuseIPDB into a weighted risk score. Running it against two phishing simulations with comparable sender-domain reputation produced very different scores: 75/100 (Credential Harvest, link directly in the email body) vs. 40/100 (Link in Attachment, malicious link hidden inside a fake document preview).

**Lesson:** The lower score wasn't a lower actual risk — it was a tooling blind spot. The script only parses the visible email body/headers, so an attachment-hidden link produces zero extractable URLs and the automated score under-represents it. This is exactly why attachment-based delivery is a real evasion technique against automated scanners, and why a Tier 1/2 analyst can't rely on an automated score alone — attachments need to be separately extracted and hashed (a noted next-iteration improvement for the script).

## 4. Windows Event Viewer's built-in "User" filter doesn't match on the field that actually matters for logon events

Tried filtering the Security log by the "User:" field in the GUI's Filter Current Log dialog to isolate a specific test account's logon events — returned zero results despite the events genuinely being present.

**Lesson:** That GUI filter matches against the event's internal metadata "UserID" property, not the `TargetUserName` field where the actual authenticating account appears in logon events. Switched to a direct PowerShell query instead:
```
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624 or EventID=4625)]] and *[EventData[Data[@Name='TargetUserName']='soclab-test']]"
```
This is a small but genuinely useful thing to know when a Tier 1/2 analyst is hunting through a large Security log for a specific account under time pressure — the GUI isn't always the right or fastest tool.
