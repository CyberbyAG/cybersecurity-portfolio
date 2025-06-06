
# Playbook: New Scheduled Task Creation Detection and Automation

**Use Case:** Detect creation of new scheduled tasks on Windows systems, which can indicate persistence techniques by adversaries.

**Analyst:** CyberbyAG  

**MITRE ATT&CK Mapping:**
- **T1053.005** – Scheduled Task/Job: Scheduled Task

---

## Objective

Identify when a new scheduled task is created via logs and automate alerting and response. Scheduled tasks are commonly abused to maintain persistence or launch malicious payloads at system startup or on a schedule.

---

## Detection Methodology

### Log Source:
- **Windows Security Logs**
- **Sysmon (if available)**

### Key Event ID:
- **Security Event ID 4698** – A scheduled task was created
- (Alternate: **Microsoft-Windows-TaskScheduler/Operational ID 106**)

---

## Detection Logic

- Monitor for Event ID 4698
- Alert when:
  - `Task Name` contains suspicious terms (e.g. `backdoor`, `update`, random strings)
  - `Author` is SYSTEM or unexpected user
  - `Task Content` includes execution of PowerShell, cmd, or uncommon executables

---

## Sample Queries (SIEMs)

### LogPoint
```logpoint
norm_id=WinServerSecurity event_id=4698 Message="*powershell.exe*" OR Message="*cmd.exe*"
```

### Splunk
```spl
index=wineventlog EventCode=4698 Message="*powershell.exe*" OR Message="*cmd.exe*"
```

### Elastic (ES|KQL)
```kql
event.code: "4698" and winlog.event_data.TaskName: "*"
```

### IBM QRadar (AQL)
```aql
SELECT * FROM events WHERE "EventID" = '4698' AND ("CommandLine" ILIKE '%powershell%' OR "CommandLine" ILIKE '%cmd%')
```

### Microsoft Sentinel (KQL)
```kql
SecurityEvent
| where EventID == 4698
| where CommandLine has_any ("powershell", "cmd", "wscript", "mshta")
```

---

## Automation Plan

### Step-by-Step Automation

1. **Trigger**: When a scheduled task is created (Event ID 4698)
2. **Enrichment**:
   - Capture task name, user, and command
   - Cross-check with threat intel for known indicators
3. **Validation**:
   - Confirm if task is on startup or repeated execution
   - Check parent process and task trigger settings
4. **Response**:
   - Alert SOC team
   - Kill or disable the task via PowerShell/EDR
   - Isolate host if confirmed malicious
5. **Post-Incident**:
   - Store details in case record
   - Add rule for similar task names to detection watchlist

---

## Outcome

Using this detection, defenders can monitor and alert when adversaries attempt to persist via scheduled tasks. It provides a reliable indication of adversary behavior aligned with MITRE ATT&CK T1053.005.

---

## Recommendations

- Enable detailed Task Scheduler logging
- Use allowlisting to alert only on unknown task names
- Restrict task creation permissions to trusted accounts
- Regularly audit scheduled tasks in enterprise systems
