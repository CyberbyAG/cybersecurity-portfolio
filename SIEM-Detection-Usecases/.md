# Playbook: Logins Outside Business Hours Detection

**Use Case:** Identify and investigate user login attempts that occur outside standard working hours, which could indicate unauthorized access or compromised credentials.

**MITRE ATT&CK Mapping:**
- **T1078** – Valid Accounts

---

## Objective

Detect anomalous login activity occurring outside of defined business hours (e.g., before 8:00 AM or after 6:00 PM), including weekends and holidays.

---

## Detection Strategy

### Data Sources
- Windows Security Logs
- Azure AD Sign-in Logs
- VPN Logs
- Identity Provider (e.g., Okta, Duo)

### Relevant Event IDs
- **4624** (Successful Logon - Windows)
- **4768** (Kerberos TGT request)
- **Azure AD Sign-in Logs** (Interactive logins)

### SIEM Detection Queries

#### LogPoint
```logpoint
norm_id=WindowsSecurity event_id=4624
| time_of_day(log_ts) NOT BETWEEN "08:00:00" AND "18:00:00"
| weekday(log_ts) IN ("Saturday", "Sunday") OR TRUE
```

#### Splunk
```spl
index=wineventlog EventCode=4624
| eval hour=strftime(_time, "%H")
| where hour < 8 OR hour > 18 OR date_wday IN ("Saturday", "Sunday")
```

#### Elastic (EQL)
```eql
process where event.code == "4624" and 
  (hour(timestamp) < 8 or hour(timestamp) > 18 or day_of_week(timestamp) in ("Saturday", "Sunday"))
```

#### IBM QRadar (AQL)
```aql
SELECT * FROM events
WHERE "EventID" = '4624' AND 
  (HOUR("startTime") < 8 OR HOUR("startTime") > 18 OR DAYOFWEEK("startTime") IN (1, 7))
```

#### Microsoft Sentinel (KQL)
```kql
SecurityEvent
| where EventID == 4624
| where datetime_part("hour", TimeGenerated) < 8 or datetime_part("hour", TimeGenerated) > 18
      or dayofweek(TimeGenerated) in ("Saturday", "Sunday")
```

---

## Fine-Tuning Tips

- Define business hours per region or department.
- Exclude known service accounts and scheduled tasks.
- Consider legitimate off-hour shifts (e.g., 24/7 support teams).

---

## Automation Steps

1. **Detection Alert:** Trigger SIEM alert for off-hour login events.
2. **Enrichment:** Add user details, location/IP address, device info, and past behavior history.
3. **Contextual Checks:**
   - Was this login from a new or unusual IP?
   - Is it a known user with off-hours access?
4. **Response Options:**
   - Notify SOC via Slack/Teams
   - Create case/ticket in incident platform (e.g., TheHive, JIRA)
   - Block user or isolate host if risk is high
5. **Audit Trail:** Record detection and response details for future reference.

---

## Outcome

Helps detect early signs of account compromise by monitoring for login activity that deviates from normal user behavior patterns. Common during lateral movement or data exfiltration attempts.

---

## Recommendations

- Implement behavioral baselines for user logins.
- Enable MFA to reduce account misuse risk.
- Review and alert on changes to login behavior trends.

