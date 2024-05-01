---
title: "WhiteSnake"
date: 2023-06-07 18:34:00 +0000
categories: [Malware Analysis]
tags: [Malware Analysis, Info Stealer, .NET]
---

# Overview

WhiteSnake is an information-stealer/RAT that extracts a range of sensitive information from infected computers.
It's considered to be MaaS as it's being sold on underground forums with a monthly fee of $120, an annual fee of $900, and a lifetime fee of $1,500.

It was first observed in early February of 2023. It has been developed in .NET language and can run on Windows and Linux as a cross-platform.

This sample I have is version `"1.5.9.9"` of `WhiteSnake` and it's capable of extracting credentials from various Browsers and Apps, CryptoCurrency wallets, Syetem files as well as dropping (and executing) additional payloads in addition to Keylogging functionality.

What is pretty cool about this sample is that it uploads stolen data to `Telegram` and uses `Tor` (Onion Routing) as a channel to communicate with C&C Servers.

## Sample Info

| Property | Value |
| ------ | ----------- |
| File Type   | 32-bit executable |
| SHA-256 | C219BEAECC91DF9265574EEA6E9D866C224549B7F41CDDA7E85015F4AE99B7C7 |
| SSDEEP    | 6144:H6Vo3IhHN5ya1R64TxT8jWHgf8YJkVHC++VeQPBZnq0LZYSwFxQx9tkD9bMLtttB:afhtHxpmWHgf8Y6/Qp1nLiDKyOLt |

And a funny compiler-stamp of `Oct 20, 2071` :)

### Anti-Analysis

`WhiteSnake` uses an Anti-VM technique, it queries the machine manufacturer and compares it with a list of blacklisted values :

```text
virtual, vmbox, vmware, thinapp, VMXh, innotek gmbh, tpvcgateway, tpautoconnsvc, vbox, kvm, red hat, qemu
```

So those include `VirtualBox, VMware, RHEV, Linux KVM, QEMU` products.

You can change the manufacturer by editing the RegKey in `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation`

In general if you want to test your VM aganist similar checks you can use [PaFish](https://github.com/a0rtega/pafish) and [VBox Cloak](https://github.com/d4rksystem/VBoxCloak) to "hide" your vbox machine.

Or alternatively you can just use the results from a Sandbox if the sample was already scanned.

It's worth noting that it makes plenty of junk network traffic to Kz domains and other sites

![network](assets/lib/img/posts/2024-05-01-WhiteSnake/network.png)

Needless to say the sample is obfuscated with a simple XOR routine and ofcourse classes, methods and variable names are "scrambled". As well as it has a fair amount of junk code including the code responsible for uploading random data to legitimte domains as we saw earlier.

![code obfuscation](assets/lib/img/posts/2024-05-01-WhiteSnake/code.png)

It's implementing a custom obfusctor yet we can use `de4dot` to try cleaning up a bit.

We notice the method `Izdaenrvjoeqtlyorjlrbo` that is responsible for string decryption, it takes in the encrypted string and the key as parameters and returns the decrypted string. Just a simple XOR.

![str_decryption](assets/lib/img/posts/2024-05-01-WhiteSnake/str_decryption.png)

There are two ways we can use to bypass that :

* Using `de4dot` or a powershell script to invoke the method by name/token, yet I don't prefer this way as the method name could change and there could be more than one method responsible for string decryption.
* We can use a more generic powershell script to invoke the decryption routine(s) by searching by its signature (the method takes in 2 string parameters and returns a string value). Good chance to practice powershell scripting.

Here's the script I used, I commented it explining what it does.

```powershell
# Load dnlib by Reflection
[System.Reflection.Assembly]::LoadFile("C:\Users\REM\Desktop\WhiteSnake\dnlib.dll") | Out-Null   

# Load the .NET assembly
$dot2Patch = "C:\Users\REM\Desktop\WhiteSnake\WhiteSnake_Stealer.bin"
$patchedDot = $dot2Patch + "_mod.bin"

# Looks for a method with 2 params (both string) and return value string - finds decryption method by signature
function FindStringDecryptionMethod($methods)
{
    foreach($method in $methods)
    {
        if(-not $method.HasBody){continue}
        if($method.Parameters.Count -eq 2 -and $method.Parameters[0].Type.FullName -eq "System.String" -and $method.Parameters[1].Type.FullName -eq "System.String" -and $method.ReturnType.FullName -eq "System.String")
        {
            return $method
        }
    }
    return $null   
}


$moduleRefl = [System.Reflection.Assembly]::LoadFile($dot2Patch).modules
$moduleDefMD = [dnlib.DotNet.ModuleDefMD]::Load($dot2Patch)

# Iterate all methods
$methods = $moduleDefMD.GetTypes().ForEach{$_.Methods}
$decryptionMethod = FindStringDecryptionMethod -methods $methods

$global:methodsToRemove = @($decryptionMethod)

foreach($method in $methods)
{
    if(-not $method.HasBody){continue}

    # Saves IL to array for easier parsing of method calls and finding its arguments
    foreach($instr in $method.MethodBody.Instructions.ToArray()) 
    {
        # Looks for call instruction
        if($instr.OpCode.Name -like "call" -and $instr.Operand -eq $decryptionMethod)
        {
            $indexDecryptionMethodInstr = $method.MethodBody.Instructions.IndexOf($instr) # index of the call
            $stateStr1 = $method.MethodBody.Instructions[$indexDecryptionMethodInstr-2].Operand # 1st argument - data
            $stateStr2 = $method.MethodBody.Instructions[$indexDecryptionMethodInstr-1].Operand # 2nd argument - key
            
            # Invoke method to decrypt
            $decryptedString = ($moduleRefl.ResolveMethod($instr.Operand.MDToken.ToInt32())).Invoke($null, @($stateStr1, $stateStr2))

            # Workaround to avoid patching of branch target (this way will refresh the branch target)
            $method.MethodBody.Instructions[$indexDecryptionMethodInstr-2].Opcode = [dnlib.DotNet.Emit.OpCodes]::Ldstr
            $method.MethodBody.Instructions[$indexDecryptionMethodInstr-2].Operand = $decryptedString

            # NOP out call instruction and 2nd argument 
            $method.MethodBody.Instructions.RemoveRange($indexDecryptionMethodInstr-1, 2)
        }
    }
    # corrects the instruction offsets
    $method.MethodBody.UpdateInstructionOffsets() | Out-Null
}

# Removes decryption methods
foreach($method in ($global:methodsToRemove | Sort-Object -Property MDToken -Unique))
{
    $method.DeclaringType.Remove($method)
}

# Writes modified file
$moduleWriterOptions = [dnlib.DotNet.Writer.ModuleWriterOptions]::new($moduleDefMD)
$moduleWriterOptions.MetadataOptions.Flags = $moduleWriterOptions.MetadataOptions.Flags -bor [dnlib.DotNet.Writer.MetadataFlags]::KeepOldMaxStack
$moduleDefMD.Write($patchedDot, $moduleWriterOptions)

```

 I highly recommend taking a look at [Dump-GUY](https://github.com/Dump-GUY) <3

 And voila :

![decrypted](assets/lib/img/posts/2024-05-01-WhiteSnake/decrypted_presist.png)

We got a persistance mechanism using the Startup folder.

## Persistance and Spreading

### persistance

Here's the cleaned method for the startup persistance

![persistance in startup](assets/lib/img/posts/2024-05-01-WhiteSnake/persist_cleaned.png)

It also uses scheduled tasks, it will launch a hidden cmd window and run this command

 `schtasks /create /tn "WhiteSnake_Stealer" /sc MINUTE /tr "C:\Users\REM\AppData\Local\EsetSecurity\WhiteSnake_Stealer.exe" /rl HIGHEST /f && DEL /F /S /Q /A "C:\Users\REM\Desktop\WhiteSnake\WhiteSnake_Stealer.exe" &&START "" "C:\Users\REM\AppData\Local\EsetSecurity\WhiteSnake_Stealer.exe"` 

This runs a scheduled task called "WhiteSnake_Stealer" that runs the malware every minute. The command also deletes the malware from its originl running direcory.
Note that it will check the priority it's running on and chaange that accordingly additionally it will create a folder called `EsetSecurity` in the `C:\...\AppData\Local` directory and copies itself there beforehand.

It will also create a mutex name `mefr3hjdol`

### Spreading

WhiteSnake will check if there's a removable device with a free space larger than 5GBs and copies itself there.

![USB Spreading](assets/lib/img/posts/2024-05-01-WhiteSnake/usb_spread.png)

## Communication with C&C Servers

`WhiteSnake` uses Onion Routing (Tor) to communicate with C2, which is pretty cool and not so common I belive.

It would download and initialize `Tor` if it's not present on the system and launches the "Beacon" process with the follwing config :

```text
SOCKSPort Port
ControlPort Port+1
DataDirectory appdataLocal/76spawx7mu/data
HiddenServiceDir appdataLocal/76spawx7mu/host
HiddenServicePort 80 127.0.0.1:Port
HiddenServiceVersion 3
```

The port is read from the `port.dat` file or assigned a random value between `2000` and `7000`.

You can read more about it [here](https://www.jamieweb.net/blog/onionv3-hidden-service/) if you want.

After it finishes it will save the Onion Address to upload it with the report to Telegram but we will get to that later.

Next, it starts listening to `hxxp://127.0.0.1:Port/` waiting for commands coming from the C2. Here's a list of commands and what it does :

| Command | Functionality/Response |
| ------ | ----------- |
| REFRESH | Generates and sends the report (base64 encoded) containing the stolen creditentials with additional system information (I'll get through the details later). |
| COMPRESS <FilePath\>| Compress the file using `tar` indicating its compressed size |
| PING | Replies with `">> PONG <Currently active window title> <Key-logged Window Names>"` |
| UNINSTALL | Kills the Tor Beacon process and deletes itself using cmd with command `/C chcp 65001 && ping 127.0.0.1 && DEL /F /S /Q /A <Executable_Path>` then exits|
| WEBCAM | Checks for Camera/Image device using Object searcher ```SELECT * FROM Win32_PnPEntity WHERE (PNPClass = 'Image' OR PNPClass = 'Camera')``` , capture an image via webcam, bse64 encode it then sends it|
| KEYLOGGER START | Start keylogging by setting a hook to the current active Window using `SetWindowsHookExA` and recording Keystrokes (I'll get into how its using native/unmanaged code later) |
| KEYLOGGER STOP | Stops keylogging, removes the hook using `UnhookWindowsHookEx` |
| KEYLOGGER VIEW <Window\>| Views the keylogged keys for a Window |
| LIST_PROCESSES | Lists current processes names and IDs |
| GET_FILE <File_Path\> | Reads the file, base64 encode it and sends it as a response |
| SCREENSHOT | Captures a Screenshot, base64 encode it and sends it as a response |
| DECOMPRESS <Compressed_File\> | Unzips a tar archive. Returns decompressed file path (in current directory) |
| LOADER <File\> | Downloads a file into `LocalAppData` folder (Without executing it) |
| LIST_FILES | Lists all files and directory files in current directory aand their size in KBs |
| TRANSFER <File_Name\> | Uploads the specified file and returns its download URL. It uploads the file into one of the hardcoded IPs concatenated with the file name converted to hex. Example for `"File_Name"` : `hxxp://140.238.218.94:8080/%46%69%6C%65%5F%4E%61%6D%65`  |
| DPAPI <File\> | Decodes file from base64 then uses `CryptUnprotectData` to decrypt file contents. (This API is used to decrypt protected data such as saved passwords in browsers as only a user with the same logon credential as the user who encrypted the data can decrypt the data) |
| LOADEXEC <File\> | Downloads a file into `LocalAppData` folder and executes it |
| cd <Path\> | Change directory |
| <Command\> | Executes command via hidden cmd window |

Here's a list of hardcoded IPs used to hold uploaded files :

```c#
public static readonly string[] IP_List = new string[]
 {
  "hxxp://140.238.218.94:8080",
  "hxxp://46.235.26.83:8080",
  "hxxp://168.119.121.16:8080",
  "hxxp://51.77.125.62:8080",
  "hxxp://185.189.159.121:8001",
  "hxxp://65.21.49.163:8080",
  "hxxp://167.86.115.218:9090",
  "hxxp://46.226.106.173:8080",
  "hxxps://89.46.80.136:443",
  "hxxp://77.240.38.138:8080",
  "hxxp://138.201.197.74:8080",
  "hxxps://164.90.185.9:443",
  "hxxp://92.63.70.131:8090",
  "hxxp://66.135.10.176:8080",
  "hxxp://107.161.20.142:8080",
  "hxxp://18.191.188.207:80",
  "hxxp://216.250.190.139:80",
  "hxxp://15.206.54.77:8080",
  "hxxp://39.96.33.40:8080",
  "hxxp://66.42.56.128:80",
  "hxxp://34.216.14.238:8080",
  "hxxp://116.196.97.232:8080",
  "hxxp://123.129.217.85:8080",
  "hxxp://139.224.8.231:8080",
  "hxxp://101.42.17.170:8080",
  "hxxp://47.100.180.12:80",
  "hxxp://115.231.163.168:8082",
  "hxxp://218.146.86.163:8888",
  "hxxp://85.8.181.218:80",
  "hxxp://121.63.250.132:88",
  "hxxp://124.223.67.212:5555",
  "hxxp://18.228.80.130:80",
  "hxxp://175.24.204.219:8080",
  "hxxp://106.52.28.126:8888",
  "hxxp://106.15.66.6:8080",
  "hxxp://47.110.140.182:8080",
  "hxxp://149.28.31.122:8080",
  "hxxps://192.99.196.191:443",
  "hxxps://44.228.161.50:443",
  "hxxp://189.115.56.226:8080",
  "hxxp://175.178.39.50:8080",
  "hxxps://52.68.125.8:443",
  "hxxps://138.2.92.67:443",
  "hxxps://54.178.235.46:443"
 };
```

## Dynamic API Resolving

WhiteSnake is liveraging the capability of using Native windows APIs (unmanaged code) in C# Applications (managed code). We can identify it by looking at the ImpMap we can see the following

![imp_map](assets/lib/img/posts/2024-05-01-WhiteSnake/native_api.png)

Here's a list of the loaded APIs :

```text
Kernel32.dll :
  GetModuleHandleA

User32.dll :
  GetForegroundWindow
  GetWindowTextLengthA
  GetWindowTextA
  GetWindowThreadProcessId
  SendMessageA
  SetWindowsHookExA
  UnhookWindowsHookEx
  CallNextHookEx
  GetKeyState
  GetKeyboardState
  GetKeyboardLayout
  ToUnicodeEx
  MapVirtualKeyA

avicap32.dll :
  capCreateCaptureWindowA

crypt32.dll :
  CryptUnprotectData
```
Another way is to use [Get-PDInvokeImports](https://github.com/Dump-GUY/Get-PDInvokeImports) to get the tokens of invoked modules and save it to a dnSpy bookmark file like so :

![Get-PDInvokeImports](assets/lib/img/posts/2024-05-01-WhiteSnake/dinvoke.png)

Here's a cleaned version :

![Get-PDInvokeImports_Cleaned](assets/lib/img/posts/2024-05-01-WhiteSnake/dinvoke_cleaned.png)

## Parsing Data

WhiteSnake uses a large hardcoded XML file as a config file for the type and location of data to steal. In addition to exfiltrting desktop documents with extentions : `*.txt, *.doc*, *.xls*, *.kbd*, *.pdf` , It parses saved credentials and wallets in Gecko and Chromium based browser.

Parses and steals wallet addresses, including the public and private keys and transaction history.

Steals tokens, user ID and authentication hash from VPNs in addition to software credentials indicated below..

It steals data from the following :

* Browsers :

  ```text
  Firefox (Gecko based)
  Thunderbird (Gecko based)
  Chrome
  YandexBrowser
  Vivaldi
  CocCoc
  CentBrowser
  Brave-Browser
  Edge
  Opera
  OperaGX
  ```

* Wallets :

  ```text
  atomic 
  Wasabi 
  Binance 
  Guarda 
  Coinomi 
  Bitcoin 
  Electrum 
  Zcash 
  Exodus 
  JaxxLiberty 
  JaxxClassic 
  Metamask
  Ronin
  BinanceChain
  TronLink
  Phantom
  ```

* VPNs :

  ```text
  Windscribe 
  AzireVPN 
  ```

* Software :

  | Software | Stolen Information |
  | ------ | ----------- |
  | Authy Desktop | Credentials |
  | WinAuth | Credentials |
  | The-Bat! | Account information |
  | WinSCP | HostName, UserName, Password and sessions |
  | CoreFTP | Host, Port, User, Password and sessions |
  | FileZilla | Configured sites and FTP servers Credentials |
  | snowflake | Sessions |
  | OBS Studio | OBS connected services (authentication tokens to twitch, youtube, etc..) |
  | Steam | Configurations, friends Steam ID, Library, etc.. |
  | Discord | Credentials |
  | Outlook | Emails, Passwords, SMTP/EAS Servers and Credentials |
  | Foxmail | Account |
  | Signal | Contact list and chat history |
  | Pidgin | Account |
  | Telegram | Secret chats |

I highly reccomend taking a look at [this playlist](https://www.youtube.com/playlist?list=PLgGJzr0D7lkn_hO1nkNQ8Ueq_yX6evv4z) <3 to get better insights on the dynamics of info stealers.

## Data Exfiltration

Stolen and gathered data are populated in the dollwing struct :

```c#
[XmlType("report")]
[Serializable]
public struct report
{
 [XmlArray("files")]
 public file_info[] files { get; set; }

 [XmlArray("information")]
 public information[] information { get; set; }
}
```

`file_info` struct :

```c#
[XmlType("file")]
[Serializable]
public struct file_info
{
 [XmlAttribute("filename")]
 public string filename { get; set; }

 [XmlAttribute("filedata")]
 public byte[] filedata { get; set; }

 [XmlAttribute("filesize")]
 public long filesize { get; set; }

 [XmlAttribute("createdDate")]
 public long createdDate { get; set; }

 [XmlAttribute("modifiedDate")]
 public long modifiedDate { get; set; }
}
```

`information` struct :

```c#
[XmlType("information")]
[Serializable]
public struct information
{
 [XmlAttribute("key")]
 public string key { get; set; }

 [XmlAttribute("value")]
 public string value { get; set; }
}
```

Parsed data from the XML config is saved in the `files`  field in addition to fingerpringint the system and populates the `information` field with the following :

```text
Username
PC name
OS version
Tag (an embedded string "Newtest56")
IP
Screen size
CPU name
GPU name
RAM size
Hard drive size
PC Model
Manufacturer
Onion Address (To allow C2 Communication/Remote Access)
WhiteSnake stub version (1.5.9.9 for this sample)
Execution path
Execution timestamp
Screenshot taken on execution
Loaded DLLs
Running processes
Installed Software
```

The report is `gzip` compressed then encrypted using an `RC4` Algorithm I belive, with a randomly generated 32 bytes key.

The key itself is encypted with a RSA public key :

```text
-----BEGIN RSA PRIVATE KEY-----
<RSAKeyValue><Modulus>uDshetz2ek4RVrjsP1dpASwqX0vSlWVvLDKhzZ3rXj
HXQLJsHN2J/1w9THSR4n0NGzeU1LbeJLFahvakZZs1OJXu+l+vp8oVLjfwszf+zn
feL6bxmkSj9nkNEqoT9kJCck+gR0DFAk8GyuQO9/+tgMhIBH0ZN/B9XpnUi42/+v
hpHMge4dOLaDLEVbXqGBaYNpErkOR9RURf+narhOCwm/zVYCl4PwXsBcVwbfKqIu
6XpIFjfttLWNXyyrVnlF9PtpxcSabe7ZhmgT9SfMcyb0DmdtwGk+iZ158KgRIN3m
BQo09WxTMSed110bM+SYHtNbdoTFtccJAu9qzs20/sGQ==</Modulus><Exponen
t>AQAB</Exponent></RSAKeyValue>
-----END RSA PRIVATE KEY-----
```

So the encrypted report blob will look like this : a `"WS$"` string converted to bytes  + `RC4_encrypted_report` + `RSA_encrypted_RC4_Key`

The report name will look like this : `W1bb3_admin@USER-PC_report.wsr`. 
It generates 5 charachter ID randomly picked from `[A-Za-z0-9]` concatenated with Username then PC name.

The file is then uploaded to one of the IPs from the previously mentioned IP list in the `Communication with C&C Servers` Section.

The report link and size will then be uploaded to a Telegram channel with ID : `2076277850` using Bot token : `6104192483:AAFCcnr4FR2XCO83zUSAWWZ9J3qw4tRYQoI`. It will also include information about the victim such as OS Version, Country, Username, Computer name as well as `#Wallets` and `#Beacon` tag indicating stolen wallets and the ability to access victim PC and the WhiteSnake Tag (which is `Newtest56` in our case).

## IOCs

* IPs :

  ```text
  "hxxp://140.238.218.94:8080",
  "hxxp://46.235.26.83:8080",
  "hxxp://168.119.121.16:8080",
  "hxxp://51.77.125.62:8080",
  "hxxp://185.189.159.121:8001",
  "hxxp://65.21.49.163:8080",
  "hxxp://167.86.115.218:9090",
  "hxxp://46.226.106.173:8080",
  "hxxps://89.46.80.136:443",
  "hxxp://77.240.38.138:8080",
  "hxxp://138.201.197.74:8080",
  "hxxps://164.90.185.9:443",
  "hxxp://92.63.70.131:8090",
  "hxxp://66.135.10.176:8080",
  "hxxp://107.161.20.142:8080",
  "hxxp://18.191.188.207:80",
  "hxxp://216.250.190.139:80",
  "hxxp://15.206.54.77:8080",
  "hxxp://39.96.33.40:8080",
  "hxxp://66.42.56.128:80",
  "hxxp://34.216.14.238:8080",
  "hxxp://116.196.97.232:8080",
  "hxxp://123.129.217.85:8080",
  "hxxp://139.224.8.231:8080",
  "hxxp://101.42.17.170:8080",
  "hxxp://47.100.180.12:80",
  "hxxp://115.231.163.168:8082",
  "hxxp://218.146.86.163:8888",
  "hxxp://85.8.181.218:80",
  "hxxp://121.63.250.132:88",
  "hxxp://124.223.67.212:5555",
  "hxxp://18.228.80.130:80",
  "hxxp://175.24.204.219:8080",
  "hxxp://106.52.28.126:8888",
  "hxxp://106.15.66.6:8080",
  "hxxp://47.110.140.182:8080",
  "hxxp://149.28.31.122:8080",
  "hxxps://192.99.196.191:443",
  "hxxps://44.228.161.50:443",
  "hxxp://189.115.56.226:8080",
  "hxxp://175.178.39.50:8080",
  "hxxps://52.68.125.8:443",
  "hxxps://138.2.92.67:443",
  "hxxps://54.178.235.46:443"
  ```

* Telegram Link

  ```text
  hxxps://api.telegram[.]org/bot6104192483:AAFCcnr4FR2XCO83zUSAWWZ9J3qw4tRYQoI/sendMessage?chat_id=2076277850&text=
  ```

* Files Created
  
  ```text
  %localappdata%\76spawx7mu
  %localappdata%\EsetSecurity
  ```

* Mutex 

  ```text
  mefr3hjdol
  ```
  
## Yara Rule

```yaml
rule WhiteSnake {
   meta:
      author = "@3weSxZero"
      date = "2023-06-07"
      hash1 = "c219beaecc91df9265574eea6e9d866c224549b7f41cdda7e85015f4ae99b7c7"
   
   strings:
      $xor_key1 = {C5 9D 1C 81} 
      $xor_key2 = {93 01 00 01} 
      $str1 = "<ProcessCommand>b__11" fullword ascii
      $str2 = "<ProcessCommand>b__6_0" fullword ascii
      $str3 = "b77a5c561934e089"
   condition:
      uint16(0) == 0x5a4d and 2 of them
} 
```

## Misc.

Just two funny things I found, looks like the Authors decided to do a little tease after evading ESET static detection with the newer version :

![eset](assets/lib/img/posts/2024-05-01-WhiteSnake/eset.png)

And a funny image in the resources :

![LoL](assets/lib/img/posts/2024-05-01-WhiteSnake/an_l.png)
