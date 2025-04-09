
# Project Report – Lateral Movement Detection via Windows Event Logs

**Analyst:** CyberbyAG  
**Date:** 31/03/2025  
**Tool(s) Used:** Windows Event Viewer, Sysmon  
**Log Source:** Collected from a Windows host during a simulated lateral movement attack (`logs.xml`)  
**Event IDs Analyzed:** 4624 (Successful Logon), 4648 (Logon with Explicit Credentials), 3 (Network Connection - Sysmon), 5145 (File Share Access), 1 & 18 (Process Creation & Pipe Access)

---

## Objective

To investigate potential lateral movement within a Windows environment by analysing logon activity and network connections, and identifying signs of impersonation or remote access behaviour.

---

## Methodology

1. Uploaded and extracted logs from the simulated attack.
2. Filtered logs using the following Event IDs:
   - `4624`: Successful Logon
   - `4648`: Logon Using Explicit Credentials
   - `3`: Sysmon Network Connections
   - `5145`: File Share Access
   - `1`: Process Creation
   - `18`: Pipe Access
3. Mapped these events by:
   - Time correlation
   - Logon IDs
   - Process hierarchy (parent-child)
   - Network behavior and protocol usage
4. Focused on internal connections to `127.0.0.1`, which are a typical and suggest credential abuse.
5. Linked suspicious behavior to MITRE ATT&CK Technique T1021 (Remote Services).
6. Included specific EventRecordIDs to support forensic traceability.

---

## Findings

![image](https://github.com/user-attachments/assets/c5603491-b9fa-4d97-af2e-e8072f869110)


### 1. **Event ID 4624** (Logon Success)

- **EventRecordID:** 321446
- **User:** `user03`
- **Logon Type:** 3 (Network)
- **IP Address:** 127.0.0.1
- **Port:** 49925
- **Authentication Method:** NTLMv2 via `NtLmSsp`

> Indicates a network-style login originating from the same machine. This is suspicious and may signal credential abuse or token impersonation.

---

### 2. **Event ID 3** (Network Connection via Sysmon)

- **EventRecordID:** 578500
- **Process:** `powershell.exe`
- **User:** `IEUser`
- **Protocol:** TCP
- **Destination Port:** 445 (microsoft-ds)
- **Destination IP:** 127.0.0.1
- **Rule Name:** Suspicious NetCon

> PowerShell initiated an internal SMB connection over loopback. The source port (49925) matches the logon event, strongly correlating activity.

---

### 3. **Event ID 5145** (File Share Access)

- **EventRecordID:** 321447
- **User:** `user03`
- **Share Accessed:** `\*\IPC$`
- **Target Resource:** `samir`
- **IP Address:** 127.0.0.1
- **Access:** Read and Write

> Access to administrative shares like IPC$ is commonly seen during lateral movement or enumeration.

---

### 4. **Event ID 1** (Process Creation via Sysmon)

- **EventRecordID:** 578499
- **Process Created:** `cmd.exe`
- **Parent Process:** `powershell.exe`
- **User:** `user03`

> Indicates command execution under impersonated credentials, likely following access via token or hash.

---

### 5. **Event ID 18** (Pipe Connection)

- **EventRecordID:** 578498
- **Process:** `System`
- **Pipe Accessed:** `\samir`

> Named pipe communication to `\samir` aligns with the IPC$ share access and may represent lateral staging.

---

## MITRE ATT&CK Mapping

- **Tactic:** Lateral Movement  
- **Technique:** Remote Services – [T1021](https://attack.mitre.org/techniques/T1021/)  
- **Justification:**
  - NTLMv2 logon over loopback
  - PowerShell initiated SMB connection
  - IPC$ share accessed
  - New cmd.exe spawned by PowerShell under a second user's identity

---

## Recommendations

- Disable or restrict NTLM authentication where possible.  
- Enforce SMB signing and block local loopback access to administrative shares.  
- Alert on loopback (127.0.0.1) network logons using NTLM.  
- Harden PowerShell with constrained language mode and logging (ScriptBlock, Module, Transcription).  
- Audit any access to IPC$ shares and named pipes from non-system accounts.  
- Investigate `user03` and `IEUser` for misuse or compromise.
