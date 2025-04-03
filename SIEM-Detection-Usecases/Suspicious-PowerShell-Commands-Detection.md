# SIEM Playbook: Suspicious PowerShell Commands Detection

**Use Case:** Detecting potentially malicious or obfuscated PowerShell usage within the environment  
**MITRE ATT&CK Technique:** T1059.001 – Command and Scripting Interpreter: PowerShell  
**Created by:** CyberbyAG  
**Date:** 02/04/2025  

---

##  Objective

Detect suspicious or obfuscated PowerShell command usage that could indicate malicious activity or post-exploitation behavior using SIEM tools.

---

##  Detection Logic

Monitor PowerShell command-line usage, particularly for signs of obfuscation, encoded commands, or use of dangerous flags.

---

##  Sample SIEM Queries

### 1. **LogPoint**
```sql
norm_id=WindowsSysmon event_id=1 "Image"="*\powershell.exe" AND ("CommandLine"="*EncodedCommand*" OR "CommandLine"="*-nop*" OR "CommandLine"="*-w hidden*")
// This detects PowerShell execution with base64 encoding (-EncodedCommand), no profile (-nop), or hidden windows
```

### 2. **Splunk**
```spl
index=sysmon (process_name="powershell.exe") AND (CommandLine="*EncodedCommand*" OR CommandLine="*-nop*" OR CommandLine="*-w hidden*")
// Same logic applied in Splunk index
```

### 3. **Elastic**
```kql
process.name: "powershell.exe" AND process.command_line: ("*EncodedCommand*" OR "*-nop*" OR "*-w hidden*")
// Elastic's Kibana Query Language (KQL) format
```

### 4. **IBM QRadar**
```aql
SELECT * FROM events
WHERE "process_name" = 'powershell.exe' AND ("command_line" LIKE '%EncodedCommand%' OR "command_line" LIKE '%-nop%' OR "command_line" LIKE '%-w hidden%')
// QRadar AQL search
```

### 5. **Microsoft Sentinel (Kusto)**
```kql
SecurityEvent
| where ProcessName has "powershell.exe"
| where CommandLine has_any ("EncodedCommand", "-nop", "-w hidden")
// Sentinel's Kusto Query Language
```

---

##  Investigation Steps

1. **Correlate with Logon Events:**
   - Check who executed the command (Logon ID / Account Name)
   - Review Event ID 4624 (Logon), 4688 (Process Creation)
2. **Check Parent Process:**
   - Investigate whether the parent process is unexpected (e.g., Word or Excel spawning PowerShell)
3. **Review Command Line:**
   - Decode `-EncodedCommand` if present
4. **Pivot on Host/IP:**
   - See if other suspicious activities occurred on the same host or IP

---

##  Response Steps

1. Isolate host from the network (if malicious)
2. Capture memory and volatile artifacts
3. Decode and analyse PowerShell script
4. Revoke potentially compromised accounts
5. Run antivirus or EDR scans on the host

---

##  Prevention & Hardening

- Enable PowerShell logging:
  - Module Logging
  - Script Block Logging
  - Transcription
- Restrict PowerShell usage via Group Policy
- Disable PowerShell v2 if not needed
- Deploy application whitelisting (e.g., AppLocker)

---

## Outcome

This playbook helps detect encoded or obfuscated PowerShell commands that are commonly used by threat actors for lateral movement, data exfiltration, and persistence.

---

##  MITRE ATT&CK Mapping

- **T1059.001 – Command and Scripting Interpreter: PowerShell**
- Tactics: Execution, Defense Evasion
