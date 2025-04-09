# Investigation Report – Project 04: Suspicious Script Execution Detection


**Project Name:** Detection of Suspicious Script Execution via LOLBins  

**Analyst:** CyberbyAG  

**Date:** 01/04/2025  

**Tools Used:** Sysmon, Event Viewer  

**Log Source:** Sysmon.evtx  

**Event IDs Analyzed:** 1 (Process Creation), 11 (File Creation)

------------------------------------------------------

## Objective

To detect and analyze suspicious script-based execution using legitimate Windows tools (also known as LOLBins), which are often abused by attackers to bypass traditional defenses.

------------------------------------------------------

## Methodology

1. Reviewed `Sysmon.evtx` logs with a focus on **Event ID 1 (Process Creation)** and **Event ID 11 (File Creation)**.
2. Identified abnormal execution chains involving:
   - `cmd.exe`
   - `rundll32.exe`
   - `mshta.exe`
   - `.hta` file execution (`calc.hta`)
3. Traced process relationships via:
   - `ParentImage`, `ParentCommandLine`, and `Image` fields
   - Process creation timestamps for timeline validation
4. Extracted command-line arguments and binary hashes for further analysis.
5. Verified if process behavior matches known LOLBin abuse techniques.
6. Mapped findings to MITRE ATT&CK technique T1059.005 (Command and Scripting Interpreter: Visual Basic).

------------------------------------------------------

## Findings

- **Initial Process:**  
  `python.exe` running `winpwnage.py` script to simulate LOLBin-based execution.

- **Execution Chain Identified:**
  - `cmd.exe` launched `rundll32.exe`
  - `rundll32.exe` used `url.dll,FileProtocolHandler` to execute:
  - `mshta.exe` with `"C:\ProgramData\calc.hta"`
  - `calc.exe` executed as the final payload

- **Suspicious Artifacts:**
  - HTA file (`calc.hta`) was dropped into `C:\ProgramData\`
  - Multiple `rundll32.exe` executions with variations in parameters
  - File creation events confirming `.hta` deployment (Event ID 11)

![image](https://github.com/user-attachments/assets/a9e50b1c-4276-4f58-98c1-15fa28155a45)
![image](https://github.com/user-attachments/assets/ca4cb3ba-ebe7-4a25-9f5b-d50b51a5fafc)
![image](https://github.com/user-attachments/assets/629e5df2-aaa8-4485-8a53-c9ca54ff7e56)
![image](https://github.com/user-attachments/assets/d6c6553f-98a3-46ba-b8d8-b29b0e4a6c7c)
![image](https://github.com/user-attachments/assets/be2e0096-4eaf-4ebc-8256-e95857dd7edc)
![image](https://github.com/user-attachments/assets/05fb1a4e-99d4-40ed-b555-cabe55922ddf)

------------------------------------------------------

## MITRE ATT&CK Mapping

- Tactic: Execution

- Technique: Command and Scripting Interpreter: Visual Basic - T1059.005

## Outcome

This simulation successfully demonstrates the use of trusted Windows binaries (`rundll32`, `mshta`, `cmd`) to execute an HTA file that launched a benign payload (`calc.exe`). While not inherently malicious, this technique is commonly observed in fileless malware and red team operations.

------------------------------------------------------

## Recommendations

- Monitor command-line usage of `mshta.exe` and `rundll32.exe` with file paths pointing to unusual locations like `ProgramData` or `Temp`.
- Implement Sysmon rules to flag `.hta` file execution.
- Alert on chains where `cmd.exe` → `rundll32.exe` → `mshta.exe` appear within a short time window.
- Educate blue teams to correlate Event IDs 1 (Process Creation) and 11 (File Creation) during threat hunts.

---------------------------------------------------

