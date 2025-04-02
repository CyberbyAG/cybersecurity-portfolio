# Project 07 – Remote File Copy Detection

**Analyst:** CyberbyAG  
**Date:** 02/04/2025  
**Tool(s) Used:** Windows Event Viewer  
**Log Source:** LM_5145_Remote_FileCopy.evtx  
**Event IDs Analyzed:** 5145 (Detailed File Share Access)

---

## Objective

To detect and analyze potential lateral movement involving remote file copy operations over SMB using administrative shares, which may indicate the staging of tools like BloodHound for further exploitation.

---

## Methodology

1. Loaded and reviewed the EVTX file `LM_5145_Remote_FileCopy.evtx`.
2. Focused on **Event ID 5145** – "A network share object was checked to see whether the client can be granted the desired access."
3. Extracted and examined fields such as:
   - **Share Name**
   - **Relative Target Name**
   - **Accesses**
   - **Source IP Address**
   - **User Account Details**
4. Filtered events where the accessed share was `C$` and the files were suspicious (e.g. containing keywords like `BloodHound`).
5. Mapped the behavior to MITRE ATT&CK T1105 – Ingress Tool Transfer.

---

## Findings

![image](https://github.com/user-attachments/assets/adcafd32-dc86-41ea-aab6-cc23adfc986f)

### Event ID 5145 – Detailed File Share Access

> **Total Events:** 869  
> Numerous accesses from a remote host to a hidden administrative share `\\*\C$` on a system named `PC01.example.corp`.

#### Example Log Extract:

- **User:** `Administrator`  
- **Domain:** `EXAMPLE`  
- **SID:** `S-1-5-21-1587066498-1489273250-1035260531-500`  
- **Source IP:** `10.0.2.15`  
- **Logon ID:** `0xFC635`  
- **Share Accessed:** `\\*\C$`  
- **Target File:** `\Users\user01\Desktop\BloodHound-win32-x64\BloodHound-win32-x64`
- **Access Type:**  
- `ReadData` (or `ListDirectory`)  
- `ReadAttributes`  
- `SYNCHRONIZE`

This demonstrates a remote host accessing a well-known offensive tool (`BloodHound`) stored on a user desktop through an administrative share, likely for staging or execution.
![image](https://github.com/user-attachments/assets/1a1a7080-2573-4980-9d55-aba961a9f50f)

---

## MITRE ATT&CK Mapping

- **Tactic:** Command and Control  
- **Technique:** [T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

**Justification:**

- Administrative share `C$` was accessed remotely.
- The accessed file directory contains tooling associated with post-exploitation (BloodHound).
- Access occurred under a privileged context (`Administrator` account).

---

## Outcome

The logs confirm that a remote file transfer occurred using SMB, targeting BloodHound executables over the administrative `C$` share. This type of behavior strongly suggests tool staging for domain enumeration and lateral movement activities.

---

## Recommendations

- Restrict access to administrative shares (`C$`) over the network.
- Implement Local Administrator Password Solution(LAPS) to manage local administrator passwords securely.
- Alert on file share access involving known offensive tools (`BloodHound`, `mimikatz`, etc.).
- Harden SMB protocol configurations:
- Disable SMBv1
- Enforce SMB signing
- Restrict NTLM usage
- Monitor and alert on **Event ID 5145** for high-value share access or abnormal source IP activity.

---


