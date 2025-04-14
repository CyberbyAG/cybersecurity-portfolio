# Playbook: Parent-Child Process Mismatch Detection

**Analyst:** CyberbyAG  

**Use Case:** Detect anomalies in process relationships where legitimate applications (like `winword.exe`, `excel.exe`) spawn suspicious children (e.g., `cmd.exe`, `powershell.exe`, `wscript.exe`).

**MITRE ATT&CK Mapping:**
- **T1059** – Command and Scripting Interpreter
- **T1203** – Exploitation for Client Execution

---

## Objective

Detect suspicious parent-child process relationships that may indicate macro-based or document-embedded code execution, often observed in phishing campaigns.

---

## Log Source & Event IDs

- **Source:** Sysmon / Windows Security Logs
- **Event IDs:**
  - `Sysmon Event ID 1`: Process Creation

---

## Detection Methodology

- Monitor for processes like:
  - `cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`
- Check if parent process is unusual, e.g.:
  - `winword.exe`, `excel.exe`, `outlook.exe`, `teams.exe`

This often indicates the exploitation of office documents to spawn command interpreters or scripts.

---

## Detection Logic (Sample Queries)

### LogPoint
```logpoint
norm_id=WindowsSysmon event_id=1 
Image IN ["*cmd.exe", "*powershell.exe", "*wscript.exe", "*mshta.exe"] 
AND ParentImage IN ["*winword.exe", "*excel.exe", "*outlook.exe"]
```

### Splunk
```splunk
index=sysmon EventCode=1 
(Image="*\cmd.exe" OR Image="*\powershell.exe" OR Image="*\wscript.exe") 
AND (ParentImage="*\winword.exe" OR ParentImage="*\excel.exe" OR ParentImage="*\outlook.exe")
```

### Elastic (EQL)
```eql
process where event.action == "start" and 
process.parent.name in ("WINWORD.EXE", "EXCEL.EXE") and 
process.name in ("cmd.exe", "powershell.exe", "wscript.exe")
```

### IBM QRadar AQL
```aql
SELECT * FROM events 
WHERE "Process Name" IN ('cmd.exe','powershell.exe','wscript.exe') 
AND "Parent Process Name" IN ('winword.exe','excel.exe','outlook.exe')
```

### Microsoft Sentinel (KQL)
```kql
DeviceProcessEvents 
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe")
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "outlook.exe")
```

---

## Outcome

Alerts on suspicious document-based attacks. These alerts help analysts detect macro-based payloads often used in phishing and malware delivery.

---

## Automation Suggestions

- **Auto-isolate** the host via EDR if triggered on high-value users or assets.
- **Send alert to SOC** and auto-enrich with:
  - Process tree
  - File hash lookup (VirusTotal)
  - User session info
- **Run YARA or AV scan** on document and temp files.

---

## Recommendations

- Disable or restrict macros where possible.
- Enable logging of child process creation from Office apps.
- Educate users to avoid opening unknown attachments.
- Monitor outbound connections following suspicious child process execution.

---
