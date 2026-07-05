<div align="center">

# IVAN YAMOAH BOAKYE
### Security Operations Analyst &nbsp;|&nbsp; IT Support Specialist

*Building real enterprise SOC workflows — detection engineering, incident response, threat hunting, and cloud security across Microsoft and Fortinet platforms.*

<br>

<a href="https://www.linkedin.com/in/ivanboakye121"><img src="https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white"/></a>
<a href="mailto:yivan56@gmail.com"><img src="https://img.shields.io/badge/Gmail-D14836?style=for-the-badge&logo=gmail&logoColor=white"/></a>
<a href="https://github.com/iVanny11-tech"><img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white"/></a>

</div>

---

## Quick Stats

- 6+ hands-on security labs documented end-to-end with screenshots
- Built a full Microsoft SOC simulation — Sentinel · Defender XDR · Entra ID Protection · Azure Arc
- Fortinet NSE 4 certified | Pursuing NSE 5 and SC-200
- Hands-on with FortiGate, FortiAnalyzer, Microsoft Sentinel, Defender XDR, and Azure
- Based in Toronto — open to remote, hybrid, and onsite roles across the GTA

---

## Project Portfolio

---

### Phase 1 — Microsoft SOC & Azure Security

---

<h3><a href="https://github.com/iVanny11-tech/soc-lab-microsoft-sentinel">01 — Project ATLAS: Microsoft SOC Tier 1/2 Simulation</a></h3>

**Incident Response & Detection Engineering | Microsoft Sentinel + Defender XDR + Entra ID Protection**

Built a hybrid SOC lab using VirtualBox (Kali + Windows 11 ARM64), Azure Arc, Sysmon, and the Azure Monitor Agent. Simulated a full MITRE ATT&CK attack chain and performed end-to-end incident response.

- Simulated 5 ATT&CK techniques: RDP brute force, encoded PowerShell, spearphishing, Tor sign-in, and valid cloud account abuse
- Built custom KQL analytics rules in Sentinel — brute force (EID 4625) and encoded PowerShell via Sysmon EID 1
- Triaged Defender XDR Incident ID 2 — High severity, 8 correlated alerts — classified as True Positive: Compromised Account
- Performed hypothesis-driven threat hunt and discovered a full AMA telemetry pipeline failure
- Contained endpoint with `netsh advfirewall`; remediated via Entra ID Protection confirmCompromised
- Created Conditional Access policy blocking anonymous IP sign-in risk (Tor exit nodes)

**Tools:** Microsoft Sentinel | Defender XDR | Entra ID P2 | Azure Arc | Sysmon | KQL | Hydra | Kali Linux

---

### Phase 2 — Fortinet Network Security

---

<h3><a href="https://github.com/iVanny11-tech/fortinet-security-labs">02 — FortiGate IPS Lab</a></h3>

**Threat Detection & Prevention | FortiGate + FortiAnalyzer**

- Built a custom IPS sensor targeting CVE-based HTTP exploit signatures
- Configured Virtual IPs (VIPs) for inbound NAT and policy enforcement
- Simulated real attacks using Nikto web scanner against a live target
- Analysed triggered alerts in FortiAnalyzer with CLI diagnostics
- Documented full topology with inline screenshots per step

**Tools:** FortiGate | FortiAnalyzer | Nikto | CLI Diagnostics

---

<h3><a href="https://github.com/iVanny11-tech/fortianalyzer-log-management-fortiview">03 — FortiAnalyzer Log Management & FortiView</a></h3>

**Log Analysis & Threat Investigation | FortiAnalyzer + FortiView**

- Imported historical FortiGate log files and generated live traffic for analysis
- Drilled into raw log records — decoding srcip, dstip, policyid, action, and sessionid fields
- Built a custom saved view for Application Control logs (P2P and cloud storage activity)
- Configured a server-scoped IPS sensor; simulated a real Nikto web attack
- Traced the attack in FortiView Top Threats — source IP, threat score, and technique
- Validated FortiAnalyzer health via CLI: log insertion rate, per-device storage, and lag time

**Tools:** FortiAnalyzer | FortiView | FortiGate | Nikto | PuTTY | CLI Diagnostics

---

### Phase 3 — Cloud & DevOps Security

---

<h3><a href="https://github.com/iVanny11-tech/aws-ec2-nginx-dns-project">04 — AWS EC2 Nginx + DNS</a></h3>

**Web Server Deployment | AWS EC2 + Route 53**

- Deployed NGINX web server on AWS EC2 connected to a custom domain via Route 53
- Configured security groups and IAM access controls

**Tools:** AWS EC2 | NGINX | Route 53 | IAM

---

<h3><a href="https://github.com/iVanny11-tech/AWS-TIER-2-WEB-APP">05 — AWS Web Tier 2 Application</a></h3>

**Multi-Tier Architecture | AWS**

- Designed and deployed a multi-tier web application on AWS
- Implemented network segmentation across public and private subnets

**Tools:** AWS VPC | EC2 | Security Groups | Subnetting

---

### Phase 4 — SOC Analyst & SIEM (In Progress)

---

### 06 — Splunk SIEM Home Lab *(Coming Soon)*

**Security Monitoring | Splunk + SPL**

- Ingesting Linux auth logs and building SPL detection queries
- Detecting brute force SSH, privilege escalation, and suspicious login patterns
- Building dashboards and custom alerts

**Tools:** Splunk | SPL | Ubuntu | Linux Auth Logs

---

### 07 — Wazuh SIEM & EDR Lab *(Coming Soon)*

**SIEM + EDR | Wazuh + VirtualBox**

- Deploying Wazuh manager and agent on Ubuntu VM
- Configuring custom detection rules and alert thresholds
- Simulating phishing and endpoint compromise scenarios

**Tools:** Wazuh | VirtualBox | Ubuntu | Gophish

---

## Technical Skills

| Category | Tools & Technologies |
|---|---|
| **SIEM & Detection Engineering** | Microsoft Sentinel, Defender XDR, Wazuh, Splunk, FortiAnalyzer |
| **Firewall & Network Security** | FortiGate, FortiAnalyzer, FortiManager, VIPs, IPS, SD-WAN |
| **Cloud Security** | Microsoft Azure, Entra ID P2, Azure Arc, AWS EC2, IAM, KQL |
| **Identity & Access** | Entra ID Protection, Conditional Access, Azure AD, IAM, RBAC |
| **EDR & Endpoint** | CrowdStrike Falcon, Darktrace, Microsoft Purview |
| **Threat Simulation** | Hydra, Nmap, Nikto, M365 Attack Simulation Training, Tor |
| **Scripting & Automation** | Python, Bash, KQL, CLI |
| **Operating Systems** | Windows, Ubuntu Linux, Kali Linux, macOS |

---

## Certifications & Training

| Certification | Status |
|---|---|
| CompTIA Security+ | Completed |
| Fortinet NSE 1, 2, 3 | Completed |
| Fortinet NSE 4 — FortiOS 7.6 Administrator | Completed |
| Microsoft AI Skills Fest 2026 | Completed |
| Fortinet NSE 5 — FortiAnalyzer SOC Analyst | In Progress |
| Microsoft SC-200 — Security Operations Analyst | In Progress |

---

<div align="center">

**Targeting:** SOC Analyst &nbsp;·&nbsp; Cloud Security Engineer &nbsp;·&nbsp; SecOps Roles

Toronto, Ontario — Remote & Hybrid Welcome

</div>
