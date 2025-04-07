# Playbook: Impossible Travel Login Detection and Response

**Use Case:** Detect and respond to login activity that occurs from geographically distant locations within an unreasonably short time—indicating potential account compromise.
Analyst: CyberbyAG
Date: 03/04/2025

**MITRE ATT&CK Mapping:**
- **T1078** – Valid Accounts
- **T1530** – Data from Cloud Storage Object

---

## Objective

Detect suspicious login patterns where a user logs in from two distant locations in a time frame that defies physical travel, then respond with automated enrichment, containment, and alerting.

---

## Step-by-Step Guide

### Step 1 – Detection Logic

**Log Source:** Identity Provider or Cloud Authentication Logs  
Examples: Azure AD Sign-in logs, Okta, Google Workspace

**Detection Conditions:**
- Same user logs in from:
  - Location A (e.g., India)
  - Location B (e.g., UK)
- Within an impossible time window (e.g., < 2 hours apart)
- Both authentications marked as successful
- Calculate velocity based on timestamp and geolocation

**Additional Flags:**
- New location never seen before for that user
- First login from a Tor/VPN IP or high-risk ASN

---

## Step 2 – SIEM Queries (Simplified with Comments)

### LogPoint
```logpoint
norm_id=AzureADSigninLogs
user="*" status="Success"
| chart earliest(timestamp) as first_login, latest(timestamp) as last_login by user, location
| search geo_distance(location[0], location[1]) > 5000 AND time_diff(first_login, last_login) < 2h
```

### Splunk
```spl
index=o365 sourcetype="azure:signinlogs"
| stats earliest(_time) as first_time, latest(_time) as last_time by user, location
| eval distance=geo_distance(location[0], location[1])
| where distance > 5000 AND (last_time - first_time) < 7200
```

### Elastic
```lucene
event.dataset: "azure.signinlogs" AND event.outcome: "success"
| aggregate by user, location
| filter geo_distance(locationA, locationB) > 5000 AND time_difference < 2h
```

### IBM QRadar (pseudo)
```
SELECT user, sourceIP, destinationGeo, START, END
FROM SigninEvents
WHERE Success = true
GROUP BY user
HAVING distance(location1, location2) > 5000 AND time_diff < 2 hours
```

### Microsoft Sentinel (KQL)
```kql
SigninLogs
| where ResultType == 0
| summarize by UserPrincipalName, IPAddress, Location, TimeGenerated
| join kind=inner (
    SigninLogs
    | where ResultType == 0
    | summarize by UserPrincipalName, IPAddress, Location, TimeGenerated
) on UserPrincipalName
| where abs(datetime_diff("minute", TimeGenerated1, TimeGenerated2)) < 120
| where geo_distance(Location1, Location2) > 5000
```

---

## Step 3 – Alert Enrichment

- Lookup user details (AD, HRDB)
- List all recent successful/failed logins
- Tag account if high privilege
- Determine IP reputation or ASN

---

## Step 4 – Response Actions (Manual or Automated)

- Send alert to SOC team with full timeline
- Block user account temporarily
- Force password reset or MFA challenge
- Notify user for verification
- Disable risky IPs in conditional access policies

---

## Step 5 – Notification

Send to:
- SOC Dashboard
- Security Analyst email
- On-call channel (Slack / Teams)

Include:
- User
- Timestamps and IPs
- Geo distance + velocity
- Risk level and decision path

---

## Step 6 – Prevention

- Enforce conditional access policies:
  - Require MFA on new geo-locations
  - Block high-risk IPs or anonymizers
- Educate users about travel behavior triggers
- Enable location-based login analytics

---
