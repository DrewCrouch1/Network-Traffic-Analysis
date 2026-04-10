# Network-Traffic-Analysis

**Author:** Andrew Crouch  
**Classification:** Confidential  

---

## Indicators and Technical Details

| Datetime | Indicator | MITRE Technique | Analyst Comment |
|----------|----------|----------------|----------------|
| 2015-03-31 11:32:18 | 10.200.2.252 | T1082 – System Information Discovery | Host identified as Windows XP via HTTP User-Agent string (`Windows NT 5.1`) |
| 2015-03-31 11:32:18 | 185.91.175.64 | T1105 – Ingress Tool Transfer | Host served malicious executable `g39b2cx.exe` via HTTP GET request |
| 2015-03-31 11:32:18 | /jsaxo8u/g39b2cx.exe | T1204 – User Execution | Executable downloaded directly from IP (no DNS resolution) |
| 2015-03-31 11:32:23+ | Multiple IPs (C2 Infrastructure) | T1071.001 – Web Protocols | Periodic GET/POST beaconing behavior to multiple suspicious IPs |
| 2015-03-31 | Port 8080 (HTTP) | T1571 – Non-Standard Port | HTTP POST traffic observed over non-standard port 8080 |
| 2015-03-31 | Randomized Domains (.it, .me, .net) | T1568 – Dynamic Resolution | Algorithmically generated domains (DGA-like behavior) |

**Known Malicious Indicators:**
- Initial download source: `185.91.175.64`
- C2 IPs:
  - `188.120.225.17`
  - `107.191.46.222`
  - `199.201.121.169`
  - `45.55.154.235`
  - `5.135.28.104`
  - `188.226.129.49`

**Malware Identification:**
- File: `g39b2cx.exe`
- SHA-256: 7C9D5724064693DFEEF76FD4DA8D6F159EF0E6707E67C4A692A03E94F4A6E27A

- Original filename: `twext.dll`
- Malware family: Dridex Trojan

---

## Executive Summary

Network traffic analysis identified that host `10.200.2.252` was compromised following the download of a malicious executable from an external IP address.

Post-infection behavior shows clear indicators of command-and-control (C2) communication, including:
- Regular beaconing to multiple external IPs
- Use of randomized domain names
- HTTP communication over non-standard ports
- Manipulation of User-Agent strings to evade detection

This activity is consistent with infection by the Dridex banking trojan, which is commonly used for credential theft, financial fraud, and as a delivery mechanism for additional malware.

**Risk Impact:**
- Credential harvesting and financial data theft
- Establishment of persistent attacker access
- Potential lateral movement within the network
- Increased risk of secondary payloads (e.g., ransomware)

**Business Impact Considerations:**
- Exposure of sensitive financial or authentication data
- Regulatory and compliance implications
- Need for immediate containment and investigation
- Gaps in endpoint visibility and network monitoring

---

## Technical Summary

Analysis of packet capture (PCAP) data revealed that host `10.200.2.252` initiated an HTTP GET request to `185.91.175.64` to download the file `g39b2cx.exe`.

Wireshark filtering used:
http.request.method == "GET" && ip.addr == 10.200.2.252


The file was downloaded directly via IP address without DNS resolution, which is a strong indicator of malicious activity.

Following execution, the host exhibited:
- Repeated HTTP GET and POST requests to multiple external IP addresses
- Communication at regular intervals (beaconing)
- Use of randomized domain names resembling DGA activity
- HTTP POST traffic over port 8080 instead of standard port 80
- Frequent changes in User-Agent strings (multiple OS/browser combinations)

Wireshark filter used for OS identification:
http.user_agent && ip.addr == 10.200.2.252


User-Agent string revealed:
- `Windows NT 5.1` → Windows XP

This sequence aligns with a typical infection chain:
1. Initial payload delivery via HTTP
2. Execution on endpoint
3. Establishment of C2 communication
4. Persistence and data exchange

---

## Findings and Analysis

### Initial Infection

The infected host downloaded a malicious executable over HTTP from `185.91.175.64`.

<img width="1760" height="251" alt="Figure 1" src="https://github.com/user-attachments/assets/5bf82e62-8b9b-4207-8c4d-f13e1a2542cc" />

Key observations:
- Direct IP-based download (no domain resolution)
- Executable file transfer over unencrypted HTTP
- No prior suspicious activity before download

---

### Post-Infection Command and Control Behavior

Following infection, the host began communicating with multiple external IPs at regular intervals (Screenshot above).

Indicators of compromise:
- Periodic beaconing behavior
- Multiple destination IPs
- Combination of HTTP GET and POST requests

This behavior strongly indicates active C2 communication.

---

### User-Agent Manipulation

The infected host exhibited rapidly changing User-Agent strings.

<img width="1768" height="292" alt="Figure 2" src="https://github.com/user-attachments/assets/842b74b7-2db8-4a47-8ce1-969ee51bd594" />

Examples included:
- Different browsers (Chrome, Firefox)
- Multiple operating systems (Windows XP, 7, 8)

This is anomalous and indicative of malware attempting to:
- Evade detection
- Blend into normal traffic patterns

---

### Non-Standard Port Usage

HTTP POST traffic was observed over port 8080.

<img width="1761" height="182" alt="Figure 3" src="https://github.com/user-attachments/assets/76dca9cb-906a-47e1-bba6-df6babc4137b" />

This is significant because:
- Standard HTTP operates over port 80
- Use of alternate ports is a common evasion technique
- Indicates deliberate C2 channel configuration

---

### Domain and Infrastructure Analysis

Suspicious domains observed:
- `Ji4UgXwN6EcLIO9x.it`
- `xPzo1fZVOgTaZwGrv.it`
- `A2fHjlAkEOVi3OHpH.it`
- `mW9ZsIhPN9HNCuzDB.me`
- `FbJCM.net`
- `x6dqcsgDuitOZ3TA2ok.in`

Characteristics:
- Randomized, non-human-readable strings
- Likely generated via Domain Generation Algorithm (DGA)
- Difficult to block via static lists

---

### Malware Confirmation

VirusTotal analysis confirms:
- File classified as Dridex trojan
- Original filename: `twext.dll`
- High detection confidence across vendors 

<img width="1678" height="510" alt="Figure 4" src="https://github.com/user-attachments/assets/3f534b93-1747-4a87-baff-c824de9dbc2e" />

---

## Remediation and Recommendations

### Immediate Containment Actions
- Isolate host `10.200.2.252` from the network immediately
- Block all identified malicious IPs at firewall and DNS layers
- Terminate active network sessions from the infected host
- Remove or quarantine the malicious executable

---

### Threat Hunting & Environment Validation
- Search across all endpoints for:
  - File hash: `7C9D5724064693DFEEF76FD4DA8D6F159EF0E6707E67C4A692A03E94F4A6E27A`
- Identify:
  - Similar HTTP GET requests to external IPs
  - Beaconing patterns (regular intervals)
  - Connections to port 8080
- Investigate additional hosts communicating with listed C2 infrastructure

---

### Endpoint Security Improvements
- Deploy or validate EDR coverage across all endpoints
- Enable:
  - Process execution logging
  - Network connection telemetry
- Block execution of:
  - Unknown binaries
  - Files downloaded via HTTP
- Implement application control (e.g., allowlisting)

---

### Network Security Enhancements
- Enforce egress filtering:
  - Restrict outbound traffic to approved destinations
- Block:
  - Known malicious IPs and domains
  - Non-standard HTTP ports unless required
- Implement network intrusion detection/prevention (IDS/IPS)

---

### Detection Engineering (High-Value Addition)
Create detections for:
- HTTP downloads from IP addresses (no DNS resolution)
- Frequent User-Agent changes from a single host
- HTTP POST traffic over non-standard ports
- Repeated connections to multiple external IPs at regular intervals

---

### Identity & Credential Protection
- Reset credentials for affected users
- Monitor for:
  - Suspicious authentication attempts
  - Lateral movement indicators
- Enforce MFA across all critical systems

---

### User Awareness & Training
- Educate users on:
  - Risks of downloading unknown files
  - Identifying suspicious downloads
- Reinforce safe browsing and email practices

---

### Long-Term Security Strategy
- Integrate PCAP analysis workflows into incident response
- Leverage SIEM (e.g., Microsoft Sentinel) for:
  - Automated IOC correlation
  - Behavioral analytics
- Continuously ingest threat intelligence feeds
- Build playbooks for:
  - Malware infection
  - C2 detection and response

---
 

---
