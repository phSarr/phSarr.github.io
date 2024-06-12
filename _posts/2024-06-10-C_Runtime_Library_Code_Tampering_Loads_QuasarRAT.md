---
title: "C/C++ Runtime Library Code Tampering Loads Quasar RAT"
date: 2024-06-10 16:00:00 +0300
categories: [Malware Analysis]
tags: [Malware Analysis, .NET, RAT, Trojan, ANY.RUN]
---

Quasar RAT is a Remote Access Trojan (RAT) that stands out for its [open-source](https://github.com/quasar/Quasar) nature. It supports a wide range of functionalities like keylogging, file transfer, victim screen/webcam monitoring, command execution via CMD and many more. Here it's being distributed utilizing a tampered version of [foobar2000](https://en.wikipedia.org/wiki/Foobar2000) which is an audio player.

You can check the report and download the sample [here](https://app.any.run/tasks/0b4feff1-abab-4f51-9977-3f7ee80309f6/)

## ANYRUN Analysis

The sample is pretty straightforward, the first stage is just a dropper for the payload identified as Quasar RAT.

![flow](assets/img/posts/2024-06-10-C_Runtime_Library_Code_Tampering_Loads_QuasarRAT/flow.png)

And that should be the log file location containing the user keystrokes :

![log file](assets/img/posts/2024-06-10-C_Runtime_Library_Code_Tampering_Loads_QuasarRAT/files.png)

The traffic to Location/IP lookup can also be noticed here:

![lookup](assets/img/posts/2024-06-10-C_Runtime_Library_Code_Tampering_Loads_QuasarRAT/network.png)

## Dropper Analysis

| Property | Value |
| ------ | ----------- |
| File Type | 32-bit C++ Executable |
| SHA-256 | 4a72f3948f014c2ded502832814c6d65feb78bd1caef7df8bcecb78f7a90b6e2 |
| SSDEEP | 49152:rBT0kcpBrQvDFw/Wb/Zy8kIvLSXkbPvEZNLlUHDZQ:rdcf8i/2/Zy8kIO10Q |

On comparing both the tampered `foobar2000` and the original binary we notice extra `BMP` files which look like the encrypted payload that will be dropped into the system

![resources](assets/img/posts/2024-06-10-C_Runtime_Library_Code_Tampering_Loads_QuasarRAT/bmp.png)

A quick BinDiff between the tampered binary and the original executable we notice that it's using C++ Runtime Library Code Tampering executing shellcode at the end of the `___security_init_cookie` that eventually decrypts the payload and runs it in a new process

![bindiff](assets/img/posts/2024-06-10-C_Runtime_Library_Code_Tampering_Loads_QuasarRAT/bind_diff.png)

## Quasar RAT Analysis

| Property | Value |
| ------ | ----------- |
| File Type | 32-bit .NET Executable |
| SHA-256 | D440B5F2E9A6B34CFEC79361172FA287816BCD02D1313B5FFCCE93892B3DB27F |
| SSDEEP | 12288:Vd50NjWAmnDdS7n8APw/cZ4aLI0dB9BfNVkbbePqqJ0rgUQ:Vr0NiAmDevccumIcBfNSX6qqJQQ |

![main](assets/img/posts/2024-06-10-C_Runtime_Library_Code_Tampering_Loads_QuasarRAT/main.png)

The settings initialization function decrypts the configuration. It uses AES mixed with `PBKDF2` key.

![key and iv](assets/img/posts/2024-06-10-C_Runtime_Library_Code_Tampering_Loads_QuasarRAT/keyiv.png)

![aes](assets/img/posts/2024-06-10-C_Runtime_Library_Code_Tampering_Loads_QuasarRAT/aes.png)

We can use a [config extractor](https://github.com/nccgroup/Cyber-Defence/blob/master/Scripts/quasar/quasar_decrypter.py) but ANY.RUN provides the configuration for us in JSON format:

```json
{
  "Version": "1.3.0.0",
  "C2": [
    "roblox.airdns.org:62604",
    ""
  ],
  "Sub_Dir": "SubDir",
  "Install_Name": "Runtime Broker.exe",
  "Mutex": "QSR_MUTEX_DT5aFgoH5h6bbtKq7Q",
  "Startup": "Runtime Broker",
  "Tag": "new",
  "LogDir": "Logs",
  "Signature": "",
  "Certificate": ""
}
```

The other initialization takes care of the RAT functionalities like its location (currently set to be in `%AppData%/SubDir/RuntimeBroker.exe`), persistence, mutex and C2 communication.

![init](assets/img/posts/2024-06-10-C_Runtime_Library_Code_Tampering_Loads_QuasarRAT/init.png)

### Persistence

It sets up persistence by adding a value to the registry key `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run` and if the user is admin it sets up a scheduled task to run every time on user logon

![persist](assets/img/posts/2024-06-10-C_Runtime_Library_Code_Tampering_Loads_QuasarRAT/persist.png)

It also hides the installation directory and the logs folder.

### Victim GeoInfo

It tries to get the location and public IP of the victim by connecting to `http://ip-api.com` or `http://api.ipify.org`, or this one:

![GeoLocation and IP](assets/img/posts/2024-06-10-C_Runtime_Library_Code_Tampering_Loads_QuasarRAT/geoip.png)

### Keylogger

Mouse and Keyboard logging functionality:

![logger](assets/img/posts/2024-06-10-C_Runtime_Library_Code_Tampering_Loads_QuasarRAT/keylog.png)

### Commands

Quasar RAT supports a wide range of functionalities available on their GitHub so I will just go over some highlights

#### Commands Execution

It allows executing commands via CMD

![exec](assets/img/posts/2024-06-10-C_Runtime_Library_Code_Tampering_Loads_QuasarRAT/exec.png)

![create session](assets/img/posts/2024-06-10-C_Runtime_Library_Code_Tampering_Loads_QuasarRAT/cmd.png)

#### Other Functionalities

+ Edit Registry Values
+ Download And Execute additional files
+ Mimic keyboard/mouse
+ Delete/Rename Files
+ Kill/Start Processes
+ Files exfiltration
+ Add/Remove Startup Items
+ Getting System Information

## IOCs

### Files

+ Dropper: `foobar2000.exe` | SHA-256: 4a72f3948f014c2ded502832814c6d65feb78bd1caef7df8bcecb78f7a90b6e2
+ Quasar RAT: `csc.exe` | SHA-256: D440B5F2E9A6B34CFEC79361172FA287816BCD02D1313B5FFCCE93892B3DB27F
+ Logs Folder: `%AppData%/Logs`
+ Installation Folder: `%AppData%/SubDir`

### URLs

+ `roblox.airdns[.]org:62604`

### Mutex

+ `QSR_MUTEX_DT5aFgoH5h6bbtKq7Q`

## YARA Rule

### Quasar Rule

```vim
rule QuasarRAT {
  meta:
      author = "@3weSxZero"
      date = "2024-06-10"
  strings:
       $str0 = ":Zone.Identifier" wide
       $str1 = "&quot;" wide
       $str2 = "<p class=\"h\">[Enter]</p><br>" wide
       $str3 = "Process already elevated." fullword wide
       $str4 = "DoDownloadAndExecute" fullword ascii
       $str5 = "Client.exe" fullword ascii
       $str6 = "GetKeyloggerLogs" fullword ascii
       $str7 = "ping -n 10 localhost > nul" fullword wide
       $str8 = "GetProcessesResponse" fullword ascii
       $str9 = "get_Processname" fullword ascii
 condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and 8 of them
}
```

### Dropper Rule

```vim
rule QuasarRAT_Dropper {
    meta:
      author = "@3weSxZero"
      date = "2024-06-10"
    strings:
      $opcode_1 = {
        F0 02 0F
        AF
        85 10
        FD
      }
      $opcode_2 = {
        81 EA ?? ?? ?? ??
        81 CA ?? ?? ?? ??
        81 CA ?? ?? ?? ??
        5A
        51
        81 E9 ?? ?? ?? ??
        81 E9 ?? ?? ?? ??
        81 F1 ?? ?? ?? ??
        59
        51
      }
      $opcode_3 = {
        38 01
        00 00
        E8 ?? ?? ?? ??
        00 37
        49
        34 ??
        4F
        39 3C 43
        83 C4 ??
        81 C1 ?? ?? ?? ??
        E8 ?? ?? ?? ??
        00 45 ??
        34 ??
        50
      }
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and all of them
}
```

## MITRE ATT&CK® TTPs

| Tactic | ID | Name |  Use |
| ------ | ------ | ------ | ----------- |
| Defense evasion | T1027.004 | Compile After Delivery | Adversaries attempt to make payloads difficult to discover and analyze by delivering files to victims encrypted and embedded within other files |
| Defense evasion | T1562.002 | Disable Windows Event Logging | Adversaries disable Windows event logging to limit data that can be leveraged for detections and audits |
| Discovery | T1016 | System Network Configuration Discovery | Adversaries look for details about the network configuration and settings, such as IP and/or MAC addresses, of systems they access or through information discovery of remote systems |
| Discovery | T1012 | Query Registry | Adversaries interact with the Windows Registry to gather information about the system |
| Discovery | T1082 | System Information Discovery | An adversary attempt to get detailed information about the operating system and hardware |
| C & C | T1571 | Non-Standard Port | Adversaries communicate using a protocol and port paring that are typically not associated. |
| Persistence | T1547.001 | Registry Run Keys / Startup Folder | Adversaries achieve persistence by adding a program to a startup folder or referencing it with a Registry run key |
| Persistence | T1037.005 | Startup Items | Adversaries use startup items automatically executed at boot initialization to establish persistence.  |
| Persistence | T1053.005 | Scheduled Task | Adversaries abuse the Windows Task Scheduler to perform task scheduling for recurring execution of malicious code |

## References

[Link to trend macro article](https://www.trendmicro.com/en_us/research/19/d/analyzing-c-c-runtime-library-code-tampering-in-software-supply-chain-attacks.html)
