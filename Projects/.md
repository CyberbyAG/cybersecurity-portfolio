# Privilege Escalation Detection Report

**Analyst:** CyberbyAG 
**Date:** 01/04/2025  
**Tool(s) Used:** Windows Event Viewer  
**Log Source:** Security.evtx 
**Event IDs Analyzed:**  
- 4624 (Successful Logon)  
- 4672 (Special Privileges Assigned)  
- 4688 (Process Creation)  
- 4662 (Object Access via WMI)  
- 4627 (Group Membership)  

------------------------------------------------
## Objective

To investigate a potential instance of privilege escalation in a Windows system by analyzing related Event Log entries that indicate elevation of privileges, process creation, and access to sensitive system areas.

------------------------------------------------

## Methodology

1. Opened the `Security.evtx` log in Windows Event Viewer.
2. Filtered for key Event IDs related to privilege escalation.
3. Correlated events by Logon ID (`4624`) to follow the activity of the User account.
4. Analyzed special privileges assigned (Event ID 4672) and the creation of new system-level processes (Event ID 4688).
5. Reviewed object access attempts (Event ID 4662) to identify sensitive system component access.
6. Mapped the behaviour to MITRE ATT&CK privilege escalation techniques.

------------------------------------------------

## Findings

- A logon session was created under the account `SYSTEM` with **Elevated Token = Yes** (Event ID 4624).
- The SYSTEM account was granted high-impact privileges including:(Event ID 4672)
  - `SeDebugPrivilege`
  - `SeTcbPrivilege`
  - `SeLoadDriverPrivilege`
  - `SeTakeOwnershipPrivilege`  
- Immediately after privilege assignment, a system-level process was created:  (Event ID 4688)
  - **New Process:** `C:\Windows\System32\svchost.exe`  
  - **Parent Process:** `services.exe`  
  - **Token Type:** Full (Type 1)  
- The process accessed a sensitive WMI namespace:    (Event ID 4662)
  - `root\CIMV2\Security\MicrosoftVolumeEncryption`  
- Group membership confirmed the user belonged to `BUILTIN\Administrators` (Event ID 4627).

![image](https://github.com/user-attachments/assets/6866521e-a7a5-4fc6-b645-f7321ffb16c6)


------------------------------------------------


## MITRE ATT&CK Mapping

- **Tactic:** Privilege Escalation  
- **Technique:** [T1068 – Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)  

### Mapping Justification

The SYSTEM account was granted special privileges and then created a new process (`svchost.exe`) from a parent service process. This chain of events, combined with access to a sensitive WMI namespace, is consistent with behaviour observed during local privilege escalation. The use of a full elevation token and the timing of event correlation support the mapping to MITRE T1068.

------------------------------------------------


## Recommendations

- Audit all service accounts and SYSTEM-level activity.
- Enable alerts for Event ID 4672 followed by 4688 on sensitive hosts.
- Review WMI access logs for abnormal object access.
- Apply least privilege principle to all accounts.
- Monitor for the use of powerful privileges like `SeDebugPrivilege` and `SeTcbPrivilege`.

------------------------------------------------
