# Playbook: Execution from Non-Standard Paths Detection

**Analyst:** CyberbyAG 

**Date:** 14/04/2025  

**Use Case:** Detect execution of processes from suspicious or non-standard directories such as `Temp`, `AppData`, or `Recycle Bin`, which are often abused by attackers for payload staging and evasion.

**MITRE ATT&CK Mapping:**
- **T1036.005** – Masquerading: Match Legitimate Name or Location
- **T1204.002** – User Execution: Malicious File

---

## Objective

Identify and respond to processes executed from non-standard directories typically used by malware or threat actors to bypass traditional monitoring and detection.

---

## Step-by-Step Detection & Response Guide

### Step 1 – Detection via SIEM

**Relevant Log Sources:**
- Sysmon (Event ID 1: Process Creation)
- Windows Security Logs (Event ID 4688)

**Targeted Paths (partial list):**
- `%TEMP%`
- `%APPDATA%`
- `%LOCALAPPDATA%`
- `%ProgramData%`
- `%PUBLIC%`
- `C:\Recycle.Bin\`

---

### Example Queries by Platform

#### LogPoint
```logpoint
norm_id=WindowsSysmon event_id=1 CommandLine="*\\Temp\\*" OR CommandLine="*\\AppData\\*"
```

#### Splunk
```splunk
index=sysmon EventCode=1 (CommandLine="*\\Temp\\*" OR CommandLine="*\\AppData\\*")
```

#### Elastic (ES|KQL)
```kql
event.code:"1" and process.command_line:*\Temp\* or process.command_line:*\AppData\*
```

#### IBM QRadar (AQL)
```aql
SELECT * FROM events WHERE "CommandLine" LIKE '%\Temp\%' OR "CommandLine" LIKE '%\AppData\%'
```

#### Microsoft Sentinel (KQL)
```kql
SecurityEvent
| where EventID == 4688
| where CommandLine contains "\Temp\" or CommandLine contains "\AppData\"
```

---

## Step 2 – Alerting Criteria

Trigger alert when:
- Non-standard execution path is detected
- Parent process is suspicious (e.g., Office apps, browsers)
- The process spawns other tools (e.g., `cmd.exe`, `powershell.exe`, `rundll32.exe`)

---

## Step 3 – Automation (Optional)

Upon detection:
- Retrieve parent and child process relationship
- Cross-check with known clean/approved paths
- Query AV/EDR telemetry for additional indicators
- Tag endpoint/user for investigation
- Optionally, isolate host or terminate suspicious process

---

## Outcome

This detection playbook helps identify suspicious execution behavior that bypasses traditional execution monitoring. This is useful in early-stage compromise or phishing payload deployment scenarios.

---

## Recommendations

- Block execution from temp directories via AppLocker or Windows Defender policies
- Enable full command-line auditing (Sysmon + Event ID 4688)
- Monitor known directories used by malware
- Investigate signed binaries executing from user-writable directories
