---
title: "AgentTesla"
date: 2024-06-06 16:00:00 +0300
categories: [Malware Analysis]
tags: [Malware Analysis, .NET, Info Stealer, .eml, phishing, ANY.RUN]
---

AgentTesla is spreading through phishing emails. This malware can steal sensitive information like login credentials and keystrokes. In this blog, I'll be analyzing a recently collected sample from ANY.RUN showing a few of its useful features that speed up the analysis.

You can check the report and download the sample from [here](https://app.any.run/tasks/b6c84b9d-d5f7-40a9-abbc-592cc7c91dc6/)

## ANY.RUN Analysis

The phishing email contains an attachment with the payload

![mail](assets/img/posts/2024-06-06-AgentTesla-AnyRun/mail.png)

![payload](assets/img/posts/2024-06-06-AgentTesla-AnyRun/proc.png)

**Execution Graph:**

![graph](assets/img/posts/2024-06-06-AgentTesla-AnyRun/graph.png)

On taking a look at the final payload we get a lot of useful information about the sample behaviour and techniques. And the Chat-GPT plugin can really help to summarize all this information

![info](assets/img/posts/2024-06-06-AgentTesla-AnyRun/info.png)

## Phishing E-Mail Analysis

The `.eml` file can also be opened by any text editor. Scrolling down a bit into its content we find information about where the email originated from. This will always differ for every email as it entirely depends on the email infrastructure and how the email got to the victim.

![mail info](assets/img/posts/2024-06-06-AgentTesla-AnyRun/mail_info.png)

Scrolling down a couple hundred lines passing through the content, the attachment can be found here as a huge Base64 encoded blob.

![attachment](assets/img/posts/2024-06-06-AgentTesla-AnyRun/attachment.png)

This can be dumped into a file and decoded OR just using a Python script to dump the attachment like [this one](https://gist.github.com/urschrei/5258588).

## Droppers Analysis

The first executable loads a DLL named `SimpleLogin.dll`. Which is located in the resources. It'll be fetched, decrypted then loaded into the memory

![first decryption](assets/img/posts/2024-06-06-AgentTesla-AnyRun/first_dec.png)

The same process will be repeated by loading 2 other DLLs from the resources, GZip decompression, and XOR decryption then loading the next stage.

![second decryption](assets/img/posts/2024-06-06-AgentTesla-AnyRun/second_load.png)

Here's a list of loaders' DLL names and their SHA-256 hashes :

| Loader Name | SHA-256 |
| ------ | ----------- |
| 09404copy.exe (pzAh.exe) | 91A58A047D6EA0C7DDB7C89B0A43A5453FD5D7145C78A836EF803D5FB0F65254 |
| SimpleLogin.dll | E8D07DCE1B0EBBF7AC8DFD05B3F3C60BE322F947D96531138610E37F60B0B729 |
| Gamma.dll | CFB9215F0D32C6444C089B65D5334B46C57007373B28F906B0C5FA4AFB66EF0C |
| Tyrone.dll | 8F1ACE685CF6ECE293D8E0BD5CC63D6A31038B797FC97C429632094C0ED733E6 |

## AgentTesla Analysis

| Property | Value |
| ------ | ----------- |
| File Type | 32-bit .NET Executable |
| File Name | 917d4f1f-fa89-464c-b4b2-060ed06bc6cd.exe |
| SHA-256 | E6924926B7D31094065FE908D0C7ED1C2D823F84F8019F01CE27B340D5AA744F |
| SSDEEP | 3072:wNcx4UoTyR6A6M9dBA8bHb+fXu+K+7mR5XSCnIWk:wNcx4UoTyR6pM9dBA8bHbeXu+37mpnL |

The final payload is not really obfuscated so this gives us a clear view of its functionalities.

### System Fingerprinting

AgentTesla collects various data about the infected system including the OS name, UserName and ComputerName, size of RAM, CPU name, public IP and time and date of infection. However, this sample is not configured to fetch the public IP.

It also computes a unique has for every infected device by concatenating and MD5 hashing the motherboard serial number, processor ID and MAC address. However, this is also not utilized in this sample.

### Credentials Grabbers

AgentTesla is set to steal login credentials from various sets of apps and browsers, Here's the struct it uses :

```cs
  public vcYq(string host, string user, string pass, string app)
  {
   this.FhgVGIUuad = host;
   this.EoTZL4GPCok = user;
   this.String_0 = pass;
   this.iZLwcas0C = app;
  }
```

#### Browsers

It steals saved logins and OAuth data from the following browsers :

| Browser | Engine |
| ----- | ----- |
| Flock | Gecko |
| IceCat | Gecko |
| Postbox | Gecko |
| PaleMoon | Gecko |
| CyberFox | Gecko |
| SeaMonkey | Gecko |
| K-Meleon | Gecko |
| BlackHawk | Gecko |
| Thunderbird | Gecko |
| Firefox | Gecko |
| WaterFox | Gecko |
| IceDragon | Gecko |
| Chrome | Chromium |
| QIP Surf | Chromium |
| Uran | Chromium |
| Postbox | Chromium |
| Cool Novo | Chromium |
| Opera Browser | Chromium |
| Coccoc | Chromium |
| Edge Chromium | Chromium |
| Elements Browser | Chromium |
| Iridium Browser | Chromium |
| Orbitum | Chromium |
| Torch Browser | Chromium |
| Yandex Browser | Chromium |
| Comodo Dragon | Chromium |
| CentBrowser | Chromium |
| Sputnik | Chromium |
| Brave | Chromium |
| Kometa | Chromium |
| Liebao Browser | Chromium |
| Epic Privacy | Chromium |
| 7Star | Chromium |
| Citrio | Chromium |
| Chromium | Chromium |
| Chedot | Chromium |
| Sleipnir 6 | Chromium |
| Coowon | Chromium |
| Amigo | Chromium |
| Vivaldi | Chromium |
| 360 Browser | Chromium |
| IE/Edge | Chromium |
| UC Browser | Chromium  |
| QQ Browser | Chromium |
| Safari for Windows | WebKit |
| Falkon | QtWebEngine |

#### E-Mail Clients

Grabbing email, password, and server credentials for the following apps :

```text
Outlook
Windows Mail App
The Bat!
Becky!
IncrediMail
Eudora
ClawsMail
FoxMail
Opera Mail
PocoMail
Mailbird
```

#### File Sharing Apps

```text
FileZilla
WinSCP
CoreFTP
Flash FXP
FTP Navigator
SmartFTP
WS_FTP
FtpCommander
FTPGetter
```

#### VPNs

```text
OpenVPN
NordVPN
Private Internet Access
```

#### Remote Admin Tools

```text
WinVNC/UltraVNC
TigerVNC
RealVNC
TightVNC
```

#### Messaging Apps

```text
eM Client
Discord (Session tokens and MFA tokens)
Trillian
Psi/Psi+ (instant messaging client for the XMPP protocol)
```

#### Other Software Data

```text
Domain Logon
MysqlWorkbench
Internet Downloader Manager (grabs saved Hostname, Username and passwords)
JDownloader 2.0
```

### Data Exfiltration

AgentTesla exfils data via SMTP, it's set to send data back to the C2 every 20 minutes. It is able to provide a screenshot, keylogs and clipboard contents and of course the stolen credentials.

```text
Sender : `sales@protecstronme.com`
Password : `  @iAiRA(0  `
Host: `us2.smtp.mailhostbox.com`
Port : `587`
```

The grabbed data is formatted in HTML and saved to a file: `PW_<UserName/ComputerName>_<yyyy_MM_dd_HH_mm_ss>.html`

And the screenshot is saved in jpeg file : `SC_<UserName/ComputerName>_<yyyy_MM_dd_HH_mm_ss>.jpeg`

The e-mail subject is `PW_<UserName/ComputerName>` and the body contains information about the infected system (UserName, ComputerName, ProcessorName, OS and the public IP if configured)

ANY.RUN did great capturing the traffic for us:

![traffic](assets/img/posts/2024-06-06-AgentTesla-AnyRun/traffic.png)

The `HTML` content should be like so:

![content](assets/img/posts/2024-06-06-AgentTesla-AnyRun/html_info.png)

**NOTE**: This sample is again not configured to enable Keylogging nor take a screenshot of the system. If keylogging was enabled, the keylogs would be stored at `%tmp%/log.tmp`

And it appears to be set for communication over TOR but it's yet to be implemented.

### Persistence

Persistence is not enabled in our case but it generally seems to achieve it via the startup folder and registery key.

App Startup FullPath : `%appdata%\aXfhqD\aXfhqD.exe`

Startup RegName : `aXfhqD`

## IOCs

ANY.RUN provides us with the IOCs ready for some Copy-Pasta and it of course matches with what we got during our analysis

### Files

+ Dropped executable file: `09404copy.exe` | SHA-256: 91a58a047d6ea0c7ddb7c89b0a43a5453fd5d7145c78a836ef803d5fb0f65254
+ email: `7a03424d-5804-f8e2-8c1b-562ce548300c.eml` | SHA-256: 7b2184447031e1e9ebf9509b0dfa4c66744cdf3468299aaad269ad927158d3c8

## YARA Rule

```vim
rule AgentTesla 
{
    meta:
        author = "@3weSxZero"
        date = "2024-06-04"
    strings:
        $str0 = "pzAh.exe"
        $str1 = "words.txt"
        $x1 = "us2.smtp.mailhostbox.com" fullword wide
        $s2 = "org.jdownloader.settings.AccountSettings.accounts.ejs" fullword wide
        $s3 = "\\Trillian\\users\\global\\accounts.dat" fullword wide
        $s4 = "Software\\A.V.M.\\Paltalk NG\\common_settings\\core\\users\\creds\\" fullword wide
        $s5 = "\\\"(hostname|encryptedPassword|encryptedUsername)\":\"(.*?)\"" fullword wide
        $s6 = "SmtpPassword" fullword wide
        $s7 = "SystemProcessorPerformanceInformation" fullword ascii
        $s8 = "aXfhqD.exe" fullword wide
        $s9 = "\\Program Files (x86)\\FTP Commander\\Ftplist.txt" fullword wide
        $s10 = "\\VirtualStore\\Program Files (x86)\\FTP Commander\\Ftplist.txt" fullword wide
        $s11 = "\\Program Files (x86)\\FTP Commander Deluxe\\Ftplist.txt" fullword wide
        $s12 = "\\VirtualStore\\Program Files (x86)\\FTP Commander Deluxe\\Ftplist.txt" fullword wide
        $s13 = "SMTP Password" fullword wide
        $s14 = "privateinternetaccess.com" fullword wide
        $s15 = "paltalk.com" fullword wide
        $s16 = "discord.com" fullword wide
        $s17 = "https://account.dyn.com/" fullword wide
        $s18 = "JDownloader 2.0" fullword wide
        $s19 = "JDownloader 2.0\\cfg" fullword wide
        $s20 = "Internet Downloader Manager" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 700KB and (1 of ($x*) and 4 of ($s*)) or (1 of ($str*))
}
```

Of course, the rule should be tested, I'll use ANY.RUN's ThreatIntel Yara search

![ANY.RUN yara](assets/img/posts/2024-06-06-AgentTesla-AnyRun/yara.png)

## MITRE ATT&CK® TTPs

ANY.RUN is really doing everything for us

![MITRE](assets/img/posts/2024-06-06-AgentTesla-AnyRun/mitre.png)

Providing great insights as well

![MITRE](assets/img/posts/2024-06-06-AgentTesla-AnyRun/ttps.png)

| Tactic | ID | Name |  Use |
| ------ | ------ | ------ | ----------- |
| Execution | T1204 | User Execution | The adversary rely upon an action by the user in order to gain execution. |
| Credential access | T1555 | Credentials from Password Stores | Adversaries search for common password storage locations to obtain user credentials.  |
| Credential access | T1555.003 | Credentials from Web Browsers | Adversaries acquire credentials from web browsers by reading files specific to the target browser. |
| Credential access | T1552.001 | Credentials In Files | Adversaries search local file systems and remote file shares for files containing insecurely stored credentials |
| Discovery | T1012 | Query Registry | Adversaries interact with the Windows Registry to gather information about the system, configuration, and installed software. |
| Discovery | T1082 | System Information Discovery | An adversary attempt to get detailed information about the operating system and hardware, including version and architecture. |
| Collection | T1114.001 | Local Email Collection | Adversaries target user email on local systems to collect sensitive information. |
| C & C | T1071.003 | Mail Protocols | Adversaries communicate using application layer protocols associated with electronic mail delivery to avoid detection/network filtering by blending in with existing traffic. |
