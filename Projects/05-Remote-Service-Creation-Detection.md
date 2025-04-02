# Investigation Report – Project 05: Remote Service Creation Detection

**Project Name:** Detection of Remote Service Creation for Lateral Movement  
**Analyst:** CyberbyAG  
**Date:** 02/04/2025  
**Tools Used:** Event Viewer  
**Log Source:** LM_Remote_Service02_7045.evtx  
**Event IDs Analyzed:** 7045 (System)

---

## Objective

To detect and analyze remote service creation events, which are commonly used by attackers to establish persistence or execute commands remotely as part of lateral movement within a compromised environment.

---

## Methodology

1. Loaded the `LM_Remote_Service02_7045.evtx` file in Event Viewer.
2. Focused on **Event ID 7045**, which logs when a new service is installed on a system.
3. Analysed key fields within each event:
   - `Service Name`
   - `Image Path` (i.e., executable path)
   - `Start Type` and `Service Account`
   - `User SID`
4. Flagged service installs where binaries like `cmd.exe` or `calc.exe` were used, especially under `LocalSystem` accounts.
5. Validated the legitimacy of service names, looking for spoofing or unusual naming.
6. Mapped findings to the MITRE ATT&CK technique **T1021.002**.

---

## Findings

### 1. Service: `remotesvc`

- **Image Path:** `calc.exe`  
- **Service Account:** `LocalSystem`  
- **Start Type:** Auto Start  
- **User SID:** `S-1-5-21-1587066498-1489273250-1035260531-500`

> The service was configured to auto-start and ran `calc.exe`. While `calc.exe` is benign, its usage here is indicative of remote code execution simulation.
![image](https://github.com/user-attachments/assets/66981439-8dcb-4831-a5cd-d5824a49e60a)

---

### 2. Service: `spoolsv`

- **Image Path:** `cmd.exe`  
- **Service Account:** `LocalSystem`  
- **Start Type:** Auto Start  
- **User SID:** `S-1-5-21-1587066498-1489273250-1035260531-1108`

> This service mimics a legitimate system service name `spoolsv`, but the binary path points to `cmd.exe`, indicating a likely abuse for executing system commands.
![image](https://github.com/user-attachments/assets/63848bfe-419e-4855-8031-b41d09f678df)

---

### 3. Service: `spoolfool`

- **Image Path:** `cmd.exe`  
- **Service Account:** `LocalSystem`  
- **Start Type:** Auto Start  
- **User SID:** `S-1-5-21-1587066498-1489273250-1035260531-1108`

> Similar to the above, this is a spoofed variant to evade detection. The repetition suggests multiple attempts to gain or maintain access.
![image](https://github.com/user-attachments/assets/00e5b653-37cf-48ee-8f3b-78f13be4f7f1)

---

## MITRE ATT&CK Mapping

- **Tactic:** Lateral Movement  
- **Technique:** Remote Services – SMB/Windows Admin Shares (T1021.002)

---

## Outcome

This scenario demonstrated how attackers can create new services remotely using legitimate system tools. The services ran under `LocalSystem` with auto-start, giving high privilege access to any attacker or red team operator.

These were simulated events, but this technique is widely used for lateral movement in real-world attacks.

---

## Recommendations

- Monitor for **Event ID 7045** across endpoints, especially with:
  - Executables like `cmd.exe`, `powershell.exe`, `wscript.exe`, etc.
  - Service names mimicking legitimate system processes.
- Implement alerts when a new service is installed by a non-standard user account.
- Cross-reference 7045 events with recent **4624 (Logon)** events to detect remote installations.
- Restrict remote service creation to authorised personnel only.
- Enable Sysmon or EDR rules to flag suspicious service installs.

---
