# New Zero Day Announced on News PwnCrypt ransomware
![image](https://github.com/user-attachments/assets/c4ac8ee5-ce4b-4e63-93f0-30445f28f1b7)

# Scenario:

A newly discovered ransomware strain, PwnCrypt, has made headlines due to its PowerShell-based payload that encrypts files on infected systems using AES-256 encryption. The ransomware specifically targets user-accessible directories, including C:\Users\Public\Desktop, and renames encrypted files by appending a .pwncrypt extension (e.g., hello.txt → hello.pwncrypt.txt).

The Chief Information Security Officer (CISO) of your organization is deeply concerned about PwnCrypt’s potential impact on the corporate network. The organization relies heavily on Windows-based environments, with employees frequently sharing files across network drives. Given that the ransomware leverages PowerShell, there is a risk of it spreading laterally across Active Directory-linked systems, potentially impacting business-critical data.
🔎 Hypothesis: Could PwnCrypt have spread laterally across the network?

## 🎯 Incident Response Objective:
The Security Operations Center (SOC) is tasked with investigating the threat, assessing potential exposure, and implementing mitigation measures.

## 📌 Platforms and Languages Leveraged
- Microsoft Sentinel
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)


## - The following steps need to be taken:
### 1. Threat Intelligence:
  
   🎯 Goal: Network & Endpoint Detection.

KQL:
```
DeviceProcessEvents
| where ProcessCommandLine has "Invoke-WebRequest" and ProcessCommandLine has "pwncrypt.ps1"
| project Timestamp, DeviceName, InitiatingProcessParentFileName, ProcessCommandLine, AccountName
```
![Screenshot 2025-02-10 at 1 52 52 PM](https://github.com/user-attachments/assets/224d932c-79cf-4c5a-b4b2-e33673b4e219)

### 2. Investigation:
  
   🎯 Goal: Investigate any suspicious findings.

KQL: 

```
DeviceProcessEvents
| where ProcessCommandLine has "C:\\programdata\\pwncrypt.ps1" or FileName == "powershell.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName, InitiatingProcessAccountName
```
![Screenshot 2025-02-10 at 2 02 55 PM](https://github.com/user-attachments/assets/fc78f226-f489-4838-bb60-d4bf8ca02787)

### 3. Analyze data to test the hypothesis

   🎯 Goal: Analyze data to test the hypothesis

- PowerShell Execution: The script pwncrypt.ps1 is executed using the Invoke-WebRequest command.
- Network Activity: Outbound connection established to GitHub to retrieve the ransomware payload.
- File System Changes: .pwncrypt files are generated within user directories, indicating encryption activity.
## 🧠 TTPs Mapped to MITRE ATT&CK Framework

| **MITRE ATT&CK Technique ID** | **Technique Name**                         | **Tactic**          | **Description** |
|------------------------------|--------------------------------|------------------|---------------------------------------------------------------|
| T1059.001                    | Command and Scripting Interpreter (PowerShell) | Execution        | The ransomware executes PowerShell scripts to initiate the attack. |
| T1486                        | Data Encrypted for Impact                    | Impact           | Files are encrypted using AES-256 to disrupt operations. |
| T1105                        | Ingress Tool Transfer                        | Resource Development | The payload is downloaded from a remote GitHub repository. |
| T1547                        | Boot/Logon Autostart Execution               | Persistence       | The ransomware modifies system settings to execute at startup. |


### 4.  Response:
  
   📌 Goal: Contain and mitigate confirmed threats.

#### 🛡️ Containment:
- 🚫 Disconnect affected devices from the network.

- 🧱 Block known malicious IPs and domains.

#### 🧹 Eradication:
- Remove pwncrypt.ps1 and terminate related processes.

- Scan endpoints for persistence mechanisms (e.g., scheduled tasks).

#### 🔄 Recovery:
- Restore data from clean backups.
- Verify integrity of restored systems.

### 5. Documentation:

  📌 Goal: Maintain a detailed log of findings and response actions.

🗒️ Key Documentation Points:

- Incident Timeline: Chronological record of events and actions taken.
- Indicators of Compromise (IoCs): Notable artifacts such as .pwncrypt files and related GitHub URLs.
- Response Measures: Steps implemented for containment, eradication, and recovery efforts.
- Security Gaps & Enhancements: Identified vulnerabilities and recommended improvements to strengthen defenses.

### 6. Improvements:

📌 Goal: Improve your security posture or refine your methods for the next hunt. 
- Enforce Endpoint Protection: Deploy and configure security policies to mitigate ransomware threats.
- Enhance Security Awareness: Train employees to recognize and report phishing attempts.
- Improve Threat Detection: Strengthen logging and monitoring systems to identify suspicious activities earlier.
- Restrict Powershell Usage
- Apply Network Segmentation 
  
