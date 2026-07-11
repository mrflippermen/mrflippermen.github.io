---
title: "Uber Hack Simulation: Lapsus$ Emulation"
date: 2026-02-02
description: "Emulación de TTPs de Lapsus$ contra infraestructura corporativa (MFA Fatigue & PAM Abuse)."
tags: ["Red Team", "Active Directory", "MFA Fatigue", "Lapsus$", "Samba", "Infrastructure"]
image: "/images/blog/uber-hack.png"
---

# Tactical Writeup: Uber Infrastructure Breach (Lapsus$ Emulation)
**Document ID:** SEC-CORP-RED-2026-001  
**Classification:** ELITE RED TEAM REPORT  
**Operation Name:** Project Lapsus-Uber  
**Objective:** End-to-end compromise of corporate vault infrastructure.

---

## 1. Executive Summary
This engagement successfully emulated the Tactics, Techniques, and Procedures (TTPs) of the **Lapsus$** threat group against a segmented corporate environment. The attack chain leveraged human-factor vulnerabilities (MFA Fatigue), identified technical misconfigurations in internal services (Samba), and ultimately achieved full privilege escalation via the corporate Privileged Access Management (PAM) solution, resulting in the compromise of the **Uber-Vault** and extraction of high-value data.

---

## 2. Attack Vectors & MITRE ATT&CK Mapping

### Chain of Compromise Logic
```mermaid
graph TD
    A["Initial Recon (T1589)"] -->|vpn_key.js| B["VPN Entry (T1133)"]
    B -->|MFA Fatigue (T1621)| C["Internal Tunnel"]
    C -->|Network Service Scanning (T1046)| D["SMB Null Session (T1039)"]
    D -->|Credentials in Files (T1552.001)| E["Admin Identity"]
    E -->|Identity Provider Access (T1550)| F["PAM Portal Control"]
    F -->|Internal Proxy Abuse| G["Uber-Vault Compromise"]
    G -->|Data from Local System (T1005)| H["FLAG EXTRACTION"]
```

| Tactic | Technique ID | Description |
| :--- | :--- | :--- |
| **Initial Access** | T1133 | External Remote Services (VPN) |
| **Credential Access** | T1621 | Multi-Factor Authentication Request Generation |
| **Discovery** | T1046 | Network Service Scanning |
| **Lateral Movement** | T1550 | Use Alternate Authentication Material |
| **Exfiltration** | T1041 | Exfiltration Over C2 Channel |

---

## 3. Technical Phase Analysis

### Phase I: External Presence & Secret Discovery
The breach began with a reconnaissance of the external authentication portal. 
*   **Artifact Analysis:** A hidden module, `vpn_key.js`, was identified. It contained the raw cryptographic keys for the corporate OpenVPN gateway.
*   **Result:** Transport layer established.

### Phase II: Psychological Social Engineering (MFA Fatigue)
The VPN required a hardware-backed OTP. We leveraged the "Push Bombing" technique to overwhelm the administrator.
*   **Strategy:** Automated delivery of 10+ push notifications.
*   **Human Vulnerability:** The administrator approved the 11th request to stop the recurring alerts.
*   **Compromised Session:** Account `pam@ubercorp.com` and its time-sensitive OTP were harvested.

### Phase III: The Pivot (Internal Pillage)
Inside the `10.0.10.0/24` subnet, we pivoted to the internal `192.168.5.0/24` range.
*   **Vulnerability identified:** Host `192.168.5.10` allowed unauthenticated SMB Null Sessions.
*   **Data found:** `automate.ps1` contained hardcoded Base64-encoded administrative credentials for the PAM solution.
*   **Extraction:** Decoded `Username: pam@ubercorp.com` and `Password: qBMT2sTNA23}A23}`.

### Phase IV: PAM Abuse & Infrastructure Takeover
The corporate **PAM (Privileged Access Management)** solution at `192.168.5.12` was accessed using the stolen credentials.
*   **Escalation:** The PAM portal provided authorized "Action" menus to manage backend servers.
*   **Actionable Intelligence:** We utilized the PAM web terminal to initiate a session directly into the **Uber-Vault** machine.
*   **Bypassing Security:** This method requires no secondary login for the vault itself, as the PAM provider injects the managed credentials.

---

## 4. Investigative Findings (Final Resolution)

| Finding Category | Data Point |
| :--- | :--- |
| **Critical Host (OS Vulnerabilities)** | `192.168.5.100` (Ubuntu/OpenSSH) |
| **SMB Misconfiguration** | Anonymous Access (3 shares identified) |
| **Leaked Infrastructure Domain** | `ubercorp.com` |
| **Reconstructed Admin Password** | `qBMT2sTNA23}A23}` |
| **Central Management IP (PAM)** | `192.168.5.12` |
| **Final Target Hostname** | `Uber-Vault` |
| **The Flag (ROOT Access)** | `UB3rH@ck!S!mulat!on` |

---

## 5. Tactical Risk Assessment & Impact

| Threat Vector | Likelihood | Impact | Severity | Mitigation Priority |
| :--- | :--- | :--- | :--- | :--- |
| **MFA Fatigue** | High | High | **CRITICAL** | P1 (Immediate) |
| **Hardcoded Secrets** | Medium | Critical | **CRITICAL** | P1 (Immediate) |
| **SMB Null Sessions** | High | Low | **MEDIUM** | P2 (High) |

**Operational Impact:** Successful exploitation allows for complete data exfiltration and persistent administrative access without triggering traditional perimeter defenses.

## 6. Strategic Hardening Recommendations
*   **Technical Control:** Transition from push notifications to **Match-Number MFA** or **FIDO2/WebAuthn** keys.
*   **Architectural Control:** Implement **EAP-TLS** for VPN access, relying on client certificates rather than shared keys.
*   **Policy Control:** Enforce a "Redline" secrets policy: prohibit any credentials (even obfuscated) in automation scripts.

---
*Generated by Secure Corp Red Team Documentation Engine.*
