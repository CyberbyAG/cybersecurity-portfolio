# Project Report – Brute Force Detection via Windows Event Logs

**Analyst:** CyberbyAG
**Date:** 31/03/2025
**Tool(s) Used:** Windows Event Viewer  
**Log Source:** Collected from a Windows host during a simulated attack `Security.evtx`
**Event IDs Analyzed:** 4625 (Failed Logon), 4740 (Account Lockout), 4624 (Successful Logon)

-----------------------------------------

## Objective

To investigate a suspected brute force attack using Windows Event Logs and identify signs of repeated failed login attempts that could indicate credential stuffing or automated attack tools.

-----------------------------------------

## Methodology

1. Downloaded and extracted `windows-event-logs.zip`.
2. Opened `Security.evtx` file in Windows Event Viewer.  
3. Applied a filter for Event ID **4625** to identify failed logon attempts.  
4. Reviewed the following fields in each 4625 entry:
   - Target Account Name  
   - Workstation Name / Source Network Address  
   - Failure Reason  
5. Identified multiple failed login attempts against the same user account in a short timeframe.  
6. Checked for Event ID **4740** to confirm if the account was locked out.  
7. Reviewed Event ID **4624** to determine whether a successful logon occurred.  
8. Correlated findings with MITRE ATT&CK Technique [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/).  
9. Documented the analysis and provided security recommendations.

-----------------------------------------

## Findings

- Approximately [25] failed logon attempts against the user account `admin`.  
- All failed attempts originated from the IP address `XX(.)XX(.)XX(.)XX`.  
- The attempts occurred within a time frame of 1 min, indicating automation.  
- Event ID 4740 confirmed that the `admin` account was locked out due to repeated failures.  
- No successful logon (Event ID 4624) was observed from this source during the same time window.

-----------------------------------------

## MITRE ATT&CK Mapping

- **Tactic:** Credential Access  
- **Technique:** Brute Force – [T1110](https://attack.mitre.org/techniques/T1110/)
- **Reason: Repeated failed login attempts from the same IP targeting the same user over a short time. Account was eventually locked out.
-----------------------------------------

## Recommendations

- Block IP address `192.168.1.104` at the network perimeter.  
- Enforce multi-factor authentication for privileged accounts.  
- Review account lockout threshold and time window settings.  
- Monitor for further suspicious login activity from similar sources.  
- Educate users on secure password practices.

-----------------------------------------
