#!/usr/bin/env python3
"""
Phishing IOC Enrichment Pipeline — Project BEACON

Parses a .eml phishing email, extracts IOCs (sender domain, embedded URLs,
IPs from the Received chain), enriches each against VirusTotal + AbuseIPDB,
computes a weighted risk score, and writes a markdown investigation report.

Usage:
    python3 phishing_enrichment.py <path-to-email.eml> [--vt-key KEY] [--abuseipdb-key KEY]

API keys can also be set via environment variables instead of flags:
    export VT_API_KEY=...
    export ABUSEIPDB_API_KEY=...

Free-tier notes:
    VirusTotal free API: ~4 requests/min, 500/day — script sleeps 1s between calls.
    AbuseIPDB free API: 1000 checks/day.
"""

import argparse
import base64
import email
import os
import re
import time
from email import policy

import requests

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"


def parse_eml(path):
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    headers = {
        "From": msg.get("From", ""),
        "Return-Path": msg.get("Return-Path", ""),
        "Subject": msg.get("Subject", ""),
        "Date": msg.get("Date", ""),
        "SCL": msg.get("X-MS-Exchange-Organization-SCL", "N/A"),
        "Authentication-Results": msg.get("Authentication-Results", "N/A"),
    }

    from_addr = headers["From"]
    domain_match = re.search(r"@([\w.-]+)", from_addr)
    sender_domain = domain_match.group(1) if domain_match else None

    received_headers = msg.get_all("Received", [])
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    ips = set()
    for r in received_headers:
        ips.update(ip_pattern.findall(r))

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                try:
                    body += part.get_content()
                except Exception:
                    pass
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = ""

    url_pattern = re.compile(r'href=["\'](http[s]?://[^"\']+)["\']|(\bhttp[s]?://[^\s"<>]+)')
    urls = set()
    for m in url_pattern.findall(body):
        url = m[0] or m[1]
        if url:
            urls.add(url.strip().rstrip(")].,"))

    return {
        "headers": headers,
        "sender_domain": sender_domain,
        "ips": sorted(ips),
        "urls": sorted(urls),
    }


def vt_lookup_domain(domain, api_key):
    if not api_key or not domain:
        return None
    try:
        r = requests.get(f"{VT_BASE}/domains/{domain}", headers={"x-apikey": api_key}, timeout=15)
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}: {r.text[:200]}"}
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return stats
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {e}"}


def vt_lookup_ip(ip, api_key):
    if not api_key:
        return None
    try:
        r = requests.get(f"{VT_BASE}/ip_addresses/{ip}", headers={"x-apikey": api_key}, timeout=15)
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}: {r.text[:200]}"}
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return stats
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {e}"}


def vt_lookup_url(target_url, api_key):
    if not api_key:
        return None
    try:
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        r = requests.get(f"{VT_BASE}/urls/{url_id}", headers={"x-apikey": api_key}, timeout=15)
        if r.status_code == 404:
            requests.post(
                f"{VT_BASE}/urls",
                headers={"x-apikey": api_key},
                data={"url": target_url},
                timeout=15,
            )
            return {"note": "URL submitted for first-time analysis — re-run script in ~60s for results"}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}: {r.text[:200]}"}
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return stats
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {e}"}


def abuseipdb_lookup(ip, api_key):
    if not api_key:
        return None
    try:
        r = requests.get(
            f"{ABUSEIPDB_BASE}/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=15,
        )
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}: {r.text[:200]}"}
        return r.json().get("data", {})
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {e}"}


def compute_risk_score(headers, domain_result, ip_results, url_results):
    score = 0
    reasons = []

    scl = str(headers.get("SCL", "N/A")).strip()
    if scl == "-1":
        reasons.append("SCL=-1 (spam filtering bypassed — typical of simulation platforms AND of attacker-controlled trusted relays; not conclusive alone)")
    elif scl not in ("N/A", ""):
        try:
            if int(scl) >= 5:
                score += 15
                reasons.append(f"SCL={scl} (moderate-high spam confidence)")
        except ValueError:
            pass

    auth = str(headers.get("Authentication-Results", "N/A"))
    if auth and auth != "N/A":
        low = auth.lower()
        if "spf=fail" in low:
            score += 20
            reasons.append("SPF fail")
        if "dkim=fail" in low:
            score += 20
            reasons.append("DKIM fail")
        if "dmarc=fail" in low:
            score += 25
            reasons.append("DMARC fail")

    if isinstance(domain_result, dict) and "error" not in domain_result:
        malicious = domain_result.get("malicious", 0)
        suspicious = domain_result.get("suspicious", 0)
        if malicious:
            score += malicious * 10
            reasons.append(f"Sender domain: {malicious} VT vendors flagged malicious")
        if suspicious:
            score += suspicious * 5
            reasons.append(f"Sender domain: {suspicious} VT vendors flagged suspicious")

    for ip, res in ip_results.items():
        vt = res.get("vt") or {}
        abuse = res.get("abuseipdb") or {}
        if isinstance(vt, dict) and "error" not in vt:
            m = vt.get("malicious", 0)
            if m:
                score += m * 8
                reasons.append(f"IP {ip}: {m} VT vendors flagged malicious")
        if isinstance(abuse, dict) and "error" not in abuse:
            conf = abuse.get("abuseConfidenceScore", 0)
            if conf:
                score += conf // 2
                reasons.append(f"IP {ip}: AbuseIPDB confidence score {conf}%")

    for u, res in url_results.items():
        if isinstance(res, dict) and "error" not in res and "note" not in res:
            m = res.get("malicious", 0)
            if m:
                score += m * 10
                reasons.append(f"URL flagged malicious by {m} VT vendors: {u}")

    score = min(score, 100)
    if score >= 60:
        verdict = "HIGH — Escalate immediately"
    elif score >= 30:
        verdict = "MEDIUM — Escalate for review"
    else:
        verdict = "LOW — Likely benign / expected (e.g. known simulation) — document and close"

    return score, verdict, reasons


def build_report(eml_path, parsed, domain_result, ip_results, url_results, score, verdict, reasons):
    lines = []
    lines.append("# Phishing IOC Enrichment Report\n")
    lines.append(f"**Source file:** `{os.path.basename(eml_path)}`  ")
    lines.append(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    lines.append("## Email Metadata\n")
    for k, v in parsed["headers"].items():
        lines.append(f"- **{k}:** {v}")
    lines.append("")

    lines.append("## Extracted IOCs\n")
    lines.append(f"- **Sender domain:** {parsed['sender_domain']}")
    lines.append(f"- **IPs (from Received headers):** {', '.join(parsed['ips']) or 'none found'}")
    lines.append(f"- **URLs in body:** {len(parsed['urls'])} found")
    for u in parsed["urls"]:
        lines.append(f"  - {u}")
    lines.append("")

    lines.append("## Enrichment Results\n")
    lines.append(f"### Sender domain: {parsed['sender_domain']}")
    lines.append(f"```\n{domain_result}\n```\n")

    for ip, res in ip_results.items():
        lines.append(f"### IP: {ip}")
        lines.append(f"```\n{res}\n```\n")

    for u, res in url_results.items():
        lines.append(f"### URL: {u}")
        lines.append(f"```\n{res}\n```\n")

    lines.append("## Risk Score\n")
    lines.append(f"**Score: {score}/100 — {verdict}**\n")
    lines.append("### Contributing factors:")
    if reasons:
        for r in reasons:
            lines.append(f"- {r}")
    else:
        lines.append("- No significant risk indicators found in automated checks.")
    lines.append("")

    lines.append("## Analyst Notes\n")
    lines.append("_(Add manual observations here — lure theme, plausibility, why a real user might click, recommended action: block sender/domain, notify affected users, submit for takedown, etc.)_\n")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Phishing email IOC enrichment pipeline")
    parser.add_argument("eml_path", help="Path to the .eml file")
    parser.add_argument("--vt-key", default=os.environ.get("VT_API_KEY"))
    parser.add_argument("--abuseipdb-key", default=os.environ.get("ABUSEIPDB_API_KEY"))
    parser.add_argument("-o", "--output", default=None, help="Output markdown report path")
    args = parser.parse_args()

    print(f"[*] Parsing {args.eml_path} ...")
    parsed = parse_eml(args.eml_path)
    print(f"    Sender domain: {parsed['sender_domain']}")
    print(f"    IPs found: {parsed['ips']}")
    print(f"    URLs found: {len(parsed['urls'])}")

    if not args.vt_key:
        print("[!] No VirusTotal API key provided — domain/IP/URL enrichment will be skipped.")
    if not args.abuseipdb_key:
        print("[!] No AbuseIPDB API key provided — IP reputation enrichment will be skipped.")

    print("[*] Enriching sender domain ...")
    domain_result = vt_lookup_domain(parsed["sender_domain"], args.vt_key)
    time.sleep(1)

    ip_results = {}
    for ip in parsed["ips"]:
        print(f"[*] Enriching IP {ip} ...")
        vt_res = vt_lookup_ip(ip, args.vt_key)
        time.sleep(1)
        abuse_res = abuseipdb_lookup(ip, args.abuseipdb_key)
        time.sleep(1)
        ip_results[ip] = {"vt": vt_res, "abuseipdb": abuse_res}

    url_results = {}
    for u in parsed["urls"]:
        print(f"[*] Enriching URL {u} ...")
        url_results[u] = vt_lookup_url(u, args.vt_key)
        time.sleep(1)

    score, verdict, reasons = compute_risk_score(parsed["headers"], domain_result, ip_results, url_results)
    print(f"[*] Risk score: {score}/100 — {verdict}")

    report = build_report(args.eml_path, parsed, domain_result, ip_results, url_results, score, verdict, reasons)
    out_path = args.output or (os.path.splitext(args.eml_path)[0] + "_report.md")
    with open(out_path, "w") as f:
        f.write(report)
    print(f"[*] Report written to {out_path}")


if __name__ == "__main__":
    main()
