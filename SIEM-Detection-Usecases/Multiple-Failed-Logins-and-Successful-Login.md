# Playbook: Multiple Failed Logins Followed by a Successful Login

**Use Case:** Detect and respond to scenarios where a user experiences multiple failed login attempts followed by a successful one, which may indicate brute-force or credential stuffing attempts.

**Analyst:** CyberbyAG  

**Date:** 03/04/2025  

**MITRE ATT&CK Mapping:**
- **Tactic:** Credential Access, Initial Access
- **Technique:** Valid Accounts – [T1078](https://attack.mitre.org/techniques/T1078/)

---

## Objective

To detect brute-force style attacks or credential stuffing by monitoring patterns of multiple consecutive failed login events followed by a successful login.

---

## Step-by-Step Guide

### Step 1 – Log Source and Events

**Log Source:** Windows Security Logs, Authentication Logs from Identity Providers, VPN, or Cloud Services

**Relevant Event IDs:**
- `4625` – Failed Logon (Windows)
- `4624` – Successful Logon (Windows)
- `529`, `530`, `531`, `532` (Older Windows versions)
- Authentication logs in Cloud environments (e.g., Azure AD, Okta)

---

## Step 2 – SIEM Detection Queries

### LogPoint
```logpoint
norm_id=WinServer event_id=4625 OR event_id=4624 
| chart count() as login_count by user, event_id, log_ts
| search login_count > 5 and event_id=4625
| join [search event_id=4624] on user
```

### Splunk
```splunk
(index=wineventlog EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failed, count(eval(EventCode=4624)) as success by Account_Name, ComputerName, src_ip
| where failed > 5 AND success >= 1
```

### Elastic (EQL)
```eql
sequence by user.name
  [authentication where event.action == "logon-failed"]
  [authentication where event.action == "logon-success"]
```

### IBM QRadar (AQL)
```aql
SELECT "Username", COUNT(*) as failed_count 
FROM events 
WHERE "EventID" = '4625' GROUP BY "Username"
HAVING failed_count > 5
```
*(Join this with 4624 for success using flow rules or correlation rules.)*

### Microsoft Sentinel (KQL)
```kql
SecurityEvent
| where EventID == 4625 or EventID == 4624
| summarize FailedLogons=countif(EventID == 4625), SuccessLogons=countif(EventID == 4624) by Account, IPAddress, bin(TimeGenerated, 30m)
| where FailedLogons > 5 and SuccessLogons >= 1
```

---

## Step 3 – Response Actions

- Alert SOC team with correlated details (user, IP, timestamps)
- Check geolocation and device info for the login source
- Review user activity post-login for lateral movement
- Consider temporary lockout or MFA enforcement

---

## Step 4 – Automation Suggestions

- Auto-tag user account for review
- Integrate with SOAR to isolate device or alert helpdesk
- Cross-reference with known IP blacklists or abnormal login hours
- Generate timeline of failed → success events for rapid triage

---

## Outcome

Detects successful logins that immediately follow multiple failures – a strong indicator of brute-force attack success or compromised credentials.

---

## Recommendations

- Enforce MFA to mitigate credential misuse
- Monitor login behavior over time to spot patterns
- Educate users about phishing and credential hygiene
- Alert on any such login sequences outside business hours or from risky IPs
