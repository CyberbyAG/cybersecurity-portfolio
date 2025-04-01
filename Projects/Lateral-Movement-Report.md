
# Project Report – Lateral Movement Detection via Windows Event Logs

**Analyst:** CyberbyAG  
**Date:** 31/03/2025  
**Tool(s) Used:** Windows Event Viewer, Sysmon  
**Log Source:** Collected from a Windows host during a simulated lateral movement attack.  
**Event IDs Analyzed:** 4624 (Successful Logon), 4648 (Logon with Explicit Credentials), 3 (Network Connection - Sysmon)

---

## Objective

To investigate potential lateral movement within a Windows environment by analysing logon activity and network connections, and identifying signs of impersonation or remote access behaviour.

---

## Methodology

1. Uploaded and extracted the file from simulated attack logs.    
2. **Filtered for Event ID 4624** to identify successful logons, focusing on:
   - Logon Type (3 = Network)
   - Target User
   - IP Address and Port
3. **Reviewed Event ID 4648** (Logon using explicit credentials) to identify potential token stealing or impersonation — *not found in this dataset*.  
4. **Parsed Sysmon Event ID 3**, which logs network connections initiated by a process:
   - Reviewed source and destination IPs and ports.
   - Noted protocol used and whether the connection was initiated or received.
5. Correlated 4624 and 3 using Logon IDs, ports, and timestamps.
6. Cross-referenced PowerShell or cmd processes interacting with local services (port 445 - SMB).
7. Mapped activity to MITRE ATT&CK Technique [T1021 – Remote Services](https://attack.mitre.org/techniques/T1021/).
8. Documented findings and proposed actionable recommendations.

---

## Findings

- **Event ID 4624** shows a successful **Network Logon (Type 3)** for user `user03` from IP `127.0.0.1` on port `49925`.  
  - This loopback IP suggests credential use within the same machine, possibly via token impersonation.  
  - Logon used **NTLM v2** authentication through `NtLmSsp`, which is often used in Pass-the-Hash attacks.

- **Event ID 3 (Sysmon)** reveals:
  - A suspicious connection initiated by `powershell.exe` (PID 2532) on **port 445 (microsoft-ds)**, indicating possible access to remote SMB services.  
  - The PowerShell connection targeted `127.0.0.1`, and used the same source port `49925` as seen in the logon event.  
  - Rule name flagged the event as `Suspicious NetCon`.

- Additional command execution via `cmd.exe` was observed (PID 2740), spawned by the same PowerShell instance, indicating possible lateral payload execution.

- **Event ID 4648** (Explicit credential use) was not found in this dataset, but the use of NTLM and internal service calls implies credential theft or reuse may still be occurring.

---

## MITRE ATT&CK Mapping

- **Tactic:** Lateral Movement  
- **Technique:** Remote Services – [T1021](https://attack.mitre.org/techniques/T1021/)  
- **Reason:**  
  - Use of NTLMv2 to access local services.  
  - PowerShell initiated connections to port 445 (SMB), correlating with an active network logon.  
  - Activity mimics Pass-the-Hash and lateral movement behaviours.

---

## Recommendations

- Disable or restrict NTLM authentication where possible.  
- Monitor PowerShell activity with command-line logging and alert on SMB connections.  
- Apply SMB signing and block inbound SMB connections from untrusted sources.  
- Enforce credential guard and Windows Defender LSA protection.  
- Audit privileged accounts for unusual logon patterns or excessive network logon activity.  
- Investigate `user03` for any signs of token impersonation or credential abuse.
