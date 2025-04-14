# Playbook: Large File Transfer to External IP Detection

**Use Case:** Detect and respond to large data transfers from internal systems to external IP addresses, which may indicate data exfiltration or unauthorised activity.
**Analyst:** CyberbyAG  
**MITRE ATT&CK Mapping:**
- **T1048** – Exfiltration Over Alternative Protocol
- **T1041** – Exfiltration Over Command and Control Channel

---

## Objective

Identify suspiciously large file transfers from internal hosts to external IP addresses and respond with containment, investigation, and remediation steps.

---

## Step-by-Step Detection and Response Plan

### Step 1 – Detection Rule in SIEM

**Log Sources:**
- Network flow logs (NetFlow, Zeek, Suricata, etc.)
- Proxy logs
- Firewall logs
- EDR/Agent logs

**Detection Conditions:**
- Outbound transfer of files >50MB (adjust as per baseline) (50,000,000 bytes = ~47.6 MB)
- Destination is a public IP not on the allow list
- Protocol: FTP, HTTP, HTTPS, SCP, SMB (non-corporate)
- Time of transfer during non-business hours

### Step 2 – Enrichment

- Identify user and hostname initiating the transfer
- Gather full URL/IP, domain, and port
- Correlate with known threat intelligence feeds
- Lookup ASN, GeoIP of destination IP
- Cross-check process that initiated the transfer

### Step 3 – Automated Response (If Confidence is High)

- Isolate host from network (via EDR)
- Block IP/Domain in firewall/proxy
- Notify SOC and relevant teams
- Capture full PCAP or file hash if possible
- Start case ticket automatically

### Step 4 – Notification

Send alert with:
- Hostname and IP
- User involved
- File name and size (if available)
- Destination IP/domain and port
- Process or application used

### Step 5 – Logging and Audit Trail

- Save alert in case management (TheHive, JIRA, etc.)
- Maintain hash, file path, IP, timestamp for evidence

---

## SIEM Queries (Simplified)

### LogPoint
```logpoint
norm_id=NetworkTraffic destination_ip!=10.0.0.0/8 bytes_out>50000000
```

### Splunk
```spl
index=network sourcetype=netflow bytes_out>50000000 dest_ip!=10.0.0.0/8
```

### Elastic
```elasticsearch
event.dataset: "network" AND network.bytes_out > 50000000 AND NOT destination.ip: "10.0.0.0/8"
```

### QRadar
```qradar
SELECT * FROM flows WHERE bytesOut > 50000000 AND NOT (destinationIP STARTS WITH '10.')
```

### Microsoft Sentinel (KQL)
```kql
CommonSecurityLog
| where DestinationIP !startswith "10."
| where SentBytes > 50000000
```


|comment /destination_ip != 10.0.0.0/8 → exclude normal internal traffic, catch outbound transfers/
---

## Outcome

Proactive alerting and containment of high-volume data transfers can help detect insider threats or compromised accounts involved in data exfiltration.

---

