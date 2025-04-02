# Project 05 – Lateral Movement Detection  
**Technique:** Remote WMI Execution(Windows Management Instrumentation)
**Log Source:** Windows Security Logs (Event IDs 4624, 4688)  
**EVTX File:** LM_WMI_4624_4688_TargetHost.evtx

---

## Summary

This project demonstrates detection of lateral movement using Windows Management Instrumentation (WMI). The attacker uses valid credentials to authenticate remotely and executes a process (`calc.exe`) via WMI. This method is stealthy as it doesn't require writing files to disk.

---

## MITRE ATT&CK Technique

- **T1021.003 – Remote Services: WMI**

---

## Log Analysis

### Event ID 4624 – Successful Logon

Multiple successful network logons (Logon Type 3) were detected from the remote IP `10.0.2.17`.

- **Usernames involved:** `user01`, `Administrator`, `SYSTEM`
- **Domains:** `EXAMPLE`
- **Authentication Packages:** `Kerberos`, `NTLM`
- **Logon Type:** 3 (Network)
- **Impersonation Level:** Impersonation / Delegation

This indicates remote access using valid credentials.

---

### Event ID 4688 – Process Creation

Two relevant process creation events were found:

1. **Process:** `WmiPrvSE.exe`
   - **Path:** `C:\Windows\System32\wbem\WmiPrvSE.exe`
   - **Run As:** SYSTEM
   - **Creator PID:** 0x248

2. **Process:** `calc.exe`
   - **Path:** `C:\Windows\System32\calc.exe`
   - **Parent:** `WmiPrvSE.exe`
   - **Creator PID:** 0xae8

This confirms remote execution of `calc.exe` via WMI on the target system.

---

## Detection Logic

To detect similar WMI-based lateral movement:

1. Look for `Event ID 4624` with:
   - Logon Type = 3
   - Source IP ≠ Localhost
![Screenshot 2025-04-01 161432](https://github.com/user-attachments/assets/31d784d7-b5ab-4d4e-9e46-740d09fe1316)
![Screenshot 2025-04-01 161442](https://github.com/user-attachments/assets/ab76b6d7-8c0c-430d-aa45-384a24bac983)
![image](https://github.com/user-attachments/assets/50f9db2f-ec90-4df1-9365-039eff246cde)


2. Correlate with `Event ID 4688` where:
   - Parent process is `WmiPrvSE.exe`
   - Child process is something suspicious (e.g. `cmd.exe`, `powershell.exe`, `calc.exe`)
![image](https://github.com/user-attachments/assets/2fe968ba-4bf9-4d31-8128-55b7ebd859c2)
![Screenshot 2025-04-01 161518](https://github.com/user-attachments/assets/88f14681-2cff-4b68-b3ce-e9ba5eb20ee1)


3. Sequence:
   - Logon (4624)
   - WMI spawn (`WmiPrvSE.exe` runs)
   - Payload executed (`calc.exe`)
![Screenshot 2025-04-01 161536](https://github.com/user-attachments/assets/12632b03-b18a-4269-9a30-bcf222c36aa7)

---

## Conclusion

The attacker used valid credentials to access the system over the network (Event ID 4624) and performed remote code execution via WMI (Event ID 4688). This technique is commonly used for stealthy lateral movement and requires correlation between network logons and process execution to detect effectively.
