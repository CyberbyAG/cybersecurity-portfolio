# Playbook: Multiple Account Lockouts in a Short Time

**Analyst:** CyberbyAG  

**Date:** 03/04/2025  

**Use Case:** Detect and respond to potential brute-force attacks or credential stuffing based on multiple account lockouts within a short period.

**MITRE ATT&CK Mapping:**
- **T1110.001** – Brute Force: Password Guessing
- **T1110.003** – Brute Force: Password Spraying

---

## Objective

To identify brute-force attempts or misuse of credentials that result in multiple account lockouts across the environment within a specific time window. Automate detection and escalation.

---

## Detection Strategy

**Log Sources:**
- Windows Security Event Logs
- Domain Controller Logs

**Relevant Event ID:**
- `4740` – A user account was locked out

---

## Detection Logic

Monitor for multiple `4740` events across one or more user accounts within a short period (e.g., 5-10 minutes).

### Sample Queries

#### LogPoint
```logpoint
norm_id=WinServer event_id=4740
| chart count() as lockouts by user, host
| search count > 5
```

#### Splunk
```spl
index=wineventlog EventCode=4740
| stats count by TargetUserName, host, _time
| where count > 5
```

#### Elastic (KQL)
```kql
event.code:"4740"
| stats count by winlog.event_data.TargetUserName
| where count > 5
```

#### QRadar AQL
```aql
SELECT COUNT(*) FROM events
WHERE "EventID" = '4740'
GROUP BY "Username"
HAVING COUNT(*) > 5
```

#### Microsoft Sentinel (KQL)
```kql
SecurityEvent
| where EventID == 4740
| summarize Count = count() by TargetUserName, bin(TimeGenerated, 5m)
| where Count > 5
```

---

## Response Plan

1. **Immediate Response**
   - Notify security team.
   - Correlate with logon attempts and source IPs.
   - Check user login locations and times.
   - Identify lockout source (workstation name or IP).

2. **Containment**
   - Temporarily disable affected accounts if compromise is suspected.
   - Isolate suspicious hosts if internal.

3. **User Verification**
   - Reach out to affected users to verify any recent password issues.
   - Reset passwords if needed.

---

## Automation Suggestions

- Set a SIEM rule to detect >5 `4740` events in 5 minutes.
- Trigger an automated SOAR playbook to:
  - Notify SOC team.
  - Create a case/ticket.
  - Enrich event with source IP and user details.
  - (Optional) Disable accounts via API.

---

## Outcome

By detecting multiple account lockouts quickly, defenders can identify brute-force attempts, password sprays, or internal misuse before account compromise or service disruption occurs.

