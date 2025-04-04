# Playbook: USB Device Insertion and File Access Detection

**Use Case:** Detect when a USB storage device is inserted into a host and files are accessed or copied from it.
**Analyst:** CyberbyAG  
**Date:** 04/04/2025  
**MITRE ATT&CK Mapping:**
- **Tactic:** Collection
- **Technique:** T1005 – Data from Local System
- **Technique:** T1200 – Hardware Additions

---

## Objective

Detect and respond to USB drive insertions followed by file access or copying, which may indicate data exfiltration attempts or policy violations.

---

## Step-by-Step Playbook

### Step 1 – Detection: USB Device Insertion

**Log Source:** Windows Security Logs  
**Event ID:** 4663 (Object Access), 6416 (System Audit Policy Change)  
**Additional Source:** Sysmon

**Indicators:**
- Detection of removable storage inserted (look for USBSTOR entries)
- New drive letter assigned
- Device class: `USBSTOR`
- `Event ID 4663`: Access to file system objects with `Accesses` = `ReadData (or ListDirectory)`

### Step 2 – Detection: File Access on USB

**Correlate:**
- File access events with device path containing `USBSTOR`
- `4663` events where `Object Name` contains known file paths on external devices (e.g., `E:\`, `F:\`)
- Volume GUIDs or drive letters for removable devices

---

## Detection Queries

### LogPoint
```logpoint
norm_id=WinSec EventID=4663 Object_Name="*:\*" AND Accesses="*ReadData*"
```

### Splunk
```spl
index=winsec EventCode=4663 Object_Name="*:\*" Accesses="ReadData"
```

### Elastic (ES|KQL)
```kql
event.code: "4663" and winlog.event_data.ObjectName: "*:\*" and winlog.event_data.AccessMask: "*ReadData*"
```

### IBM QRadar (AQL)
```aql
SELECT * FROM events WHERE "EventID" = 4663 AND "Object Name" LIKE '%:\%' AND "Accesses" LIKE '%ReadData%'
```

### Microsoft Sentinel (KQL)
```kql
SecurityEvent
| where EventID == 4663 and ObjectName contains ":\"
| where Accesses contains "ReadData"
```

---

## Response Steps

1. **Enrich the alert**:
   - Username and logon session
   - Device ID or serial
   - File names accessed
   - Time of access

2. **Contain**:
   - Revoke device permissions
   - Disconnect host (if malicious intent is suspected)

3. **Investigate**:
   - Confirm if the file access is authorized
   - Check for data exfiltration or bulk file transfers

4. **Alert**:
   - Notify SOC team with context
   - Attach forensic timeline

---

## Automation

**Trigger Criteria:**
- USB device inserted
- Followed by file access from external device

**Automated Actions:**
- Tag device for monitoring
- Alert SOC if file access occurs
- Run EDR query for related processes
- Isolate endpoint (if sensitive data accessed)

---

## Outcome

This playbook helps identify when users access or possibly exfiltrate data via USB storage. It correlates removable device activity with file-level access events and provides a clear workflow for detection, investigation, and response.
