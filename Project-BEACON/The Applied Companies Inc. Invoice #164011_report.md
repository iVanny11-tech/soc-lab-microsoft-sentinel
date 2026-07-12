# Phishing IOC Enrichment Report

**Source file:** `The Applied Companies Inc. Invoice #164011.eml`  
**Generated:** 2026-07-10 23:27:33

## Email Metadata

- **From:** Bafa Mefroum <bafamefroum@securembly.org>
- **Return-Path:** 
- **Subject:** The Applied Companies Inc. Invoice #164011
- **Date:** Sat, 11 Jul 2026 02:55:27 +0000
- **SCL:** -1
- **Authentication-Results:** N/A

## Extracted IOCs

- **Sender domain:** securembly.org
- **IPs (from Received headers):** none found
- **URLs in body:** 0 found

## Enrichment Results

### Sender domain: securembly.org
```
{'malicious': 3, 'suspicious': 2, 'undetected': 31, 'harmless': 55, 'timeout': 0}
```

## Risk Score

**Score: 40/100 — MEDIUM — Escalate for review**

### Contributing factors:
- SCL=-1 (spam filtering bypassed — typical of simulation platforms AND of attacker-controlled trusted relays; not conclusive alone)
- Sender domain: 3 VT vendors flagged malicious
- Sender domain: 2 VT vendors flagged suspicious

## Analyst Notes

_(Add manual observations here — lure theme, plausibility, why a real user might click, recommended action: block sender/domain, notify affected users, submit for takedown, etc.)_
