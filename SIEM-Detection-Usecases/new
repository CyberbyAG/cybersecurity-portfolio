# Playbook: Event Log Clearing Detection and Automation

**Use Case:** Detect and respond to attempts to clear Windows Event Logs, which attackers may use to cover their tracks after unauthorized access.



**MITRE ATT&CK Mapping:**
- **T1070.001** – Indicator Removal on Host: Clear Windows Event Logs

---

## Objective

Detect and respond to the clearing of event logs using Windows native logging and SIEM tools. Automate response actions where feasible to minimize impact and alert relevant teams for investigation.

---

## Step-by-Step Detection and Response Plan

### Step 1 – Detection Rule in SIEM

**Log Source:** Windows Security Logs  
**Event ID:**  
- `1102` – "The audit log was cleared"

> This event indicates that the Security log was cleared by a user.

---

### Step 2 – Detection Logic in SIEM

#### LogPoint
```logpoint
norm_id=WindowsSecurity event_id=1102
```

#### Splunk
```spl
index=wineventlog EventCode=1102
```

#### Elastic
```elastic
event.code: "1102" AND log.source: "Security"
```

#### IBM QRadar
```qradar
SELECT * FROM events WHERE "EventID" = '1102' AND "LogSourceType" = 'WinCollect'
```

#### Microsoft Sentinel (KQL)
```kql
SecurityEvent | where EventID == 1102
```

---

### Step 3 – Alert Configuration

Configure the SIEM to trigger an alert when Event ID 1102 is logged, especially on:
- Domain Controllers
- File Servers
- Workstations with sensitive access

Raise alert priority if:
- User clearing logs is not a known admin
- Action follows suspicious login activity

---

### Step 4 – Automated Response Options

Trigger the following based on confidence and severity:

- **Isolate host** (via EDR/SOAR)
- **Alert SOC** with hostname, username, and timestamp
- **Check preceding logon events (4624/4648)** for context
- **Initiate memory or disk image collection**
- **Suspend user account** if insider threat is suspected

---

### Step 5 – Logging and Notification

- Log incident in centralized system (TheHive, JIRA, etc.)
- Notify:
  - SOC Team
  - On-call Engineer
  - Endpoint Detection team

---

## Outcome

Helps detect attempts to erase forensic evidence from systems. A strong indicator of compromise when performed outside change windows or by unknown users.

---

## Recommendations

- Alert on all Event ID 1102 logs.
- Correlate with previous logons (4624) and process creation events (4688).
- Restrict "Clear Log" permission to limited admin accounts.
- Regularly export event logs to secure, remote storage.

---

