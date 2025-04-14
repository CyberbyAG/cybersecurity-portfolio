# SIEM Playbook – Brute Force Attack Detection

**Analyst:** CyberbyAG  
 
**Category:** Authentication Abuse  
**MITRE ATT&CK Technique:** [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)  

---

## Objective

Detect brute-force login attempts targeting Windows systems by identifying excessive failed login events from a single IP or user account within a short timeframe, followed by a successful login if compromise occurs.

---

## Detection Logic

This section includes simple, SIEM-specific queries with inline comments for clarity.

---

### LogPoint

```sql
// Detect multiple failed login attempts from same IP or user in 5 minutes
norm_id=WinServer event_id=4625
| chart count() as failed_attempts by source_address, user, bin(5m)
| search failed_attempts > 10
```

---

### Splunk

```spl
// Brute-force detection: failed logins grouped by source and user in 5m window
index=wineventlog EventCode=4625
| stats count as failed_attempts by src_ip, Account_Name, span=5m
| where failed_attempts > 10
```

---

### Elastic (ELK)

```kql
// Detect brute-force via excessive 4625 logs in 5m interval
event.code: "4625"
| stats count() by source.ip, user.name, date_histogram(field="@timestamp", interval="5m")
| where count > 10
```

---

### IBM QRadar (AQL)

```aql
-- Find sources with more than 10 failed logins in last 5 mins
SELECT sourceIP, username, COUNT(*) AS failed_attempts
FROM events
WHERE eventID = 4625
GROUP BY sourceIP, username, START 'NOW - 5 MINUTES', STOP 'NOW'
HAVING failed_attempts > 10
```

---

### Microsoft Sentinel (KQL)

```kql
// Monitor failed logins over 5-minute interval
SecurityEvent
| where EventID == 4625
| summarize FailedLogons = count() by IPAddress, Account, bin(TimeGenerated, 5m)
| where FailedLogons > 10
```

---

## Investigation

Step-by-step investigation workflow:

1. **Identify Source IP:**
   - Check if it is internal or external.
   - Perform WHOIS/Geo-IP lookup for external IPs.

2. **Review User Account Activity:**
   - Was a successful login (Event ID 4624) observed after the failed attempts?
   - Investigate timing and sequence of events.

3. **Correlate with Endpoint Logs:**
   - Review process execution, privilege escalation, or unusual activity post-login.

4. **Evaluate Login Patterns:**
   - Is the activity coming from multiple IPs to one user (password spray)?
   - Or one IP to many users (brute force)?

5. **Check for Known Attack Tools:**
   - Indicators of Hydra, RDP brute tools, or scripting artifacts.

---

## Response

Actions to take during incident response:

- **Block source IP address** at firewall or proxy.
- **Temporarily disable the user account** to prevent further compromise.
- **Force password reset** and require MFA (if available).
- **Notify affected users and security team**.
- **Search for lateral movement** or privilege escalation attempts from the compromised account.

---

## Prevention

- **Enable MFA** for all user accounts.
- **Set account lockout policies**, especially for critical systems.
- **Limit RDP and other remote access** to necessary personnel only.
- **Monitor login patterns continuously** using alert thresholds.
- **Deploy decoy accounts** to lure and detect brute-force attempts.

---

## MITRE ATT&CK Mapping

- **Tactic:** Credential Access  
- **Technique:** [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)  
- **Sub-techniques:**  
  - **T1110.001 – Password Guessing**  
  - **T1110.003 – Password Spraying**  

---

## Automation Ideas

- Create alert rules that trigger if:
  - >5 failed logins from one IP within 5 minutes
  - Success follows shortly after
- Auto-isolate host or block IP if anomaly is confirmed
- Send enriched alert to SOC channel (Teams/Slack)

---

## Notes

- You can increase or decrease the threshold based on user behavior baseline.
- Combine with successful login detection (Event ID 4624) to track post-compromise activity.
- Consider mapping detections to known threat actor TTPs in threat intelligence platforms.
