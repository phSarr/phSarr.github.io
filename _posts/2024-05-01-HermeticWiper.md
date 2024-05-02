---
title: "HermeticWiper"
date: 2023-05-10 18:34:00 +0000
categories: [Malware Analysis]
tags: [Malware Analysis, wiper, kernel, driver]
---

HermeticWiper is a destructive piece of malware that was used in the early stages of the Russian invasion of Ukraine early in 2022 against Ukranian facilities.

The way it wipes out the disk while remaining stealthy is pretty neat. It increases file [fragmentation](https://www.youtube.com/watch?v=XSvOfu2PfXk) and overwrites them with randomly generated junk data to render the data recovery pretty much impossible. It would also remain stealthy and avoids corrupting certain files that are important to the OS till it finishes its work. When it's done wiping all files (including its own), it will force a reboot and eventually and not surprisingly Windows OS will no longer work.

It needs admin privileges to do its thing but I have not found a UAC bypass or a privilege escalation technique and It's neither obfuscated nor packed so I would guess it could be dropped/delivered to the system as a second-stage as other Worms and Ransomware were used on this campaign.

## Sample Analysis

| Property | Value |
| ------ | ----------- |
| File Type   | 32-bit executable |
| SHA-256 | 1BC44EEF75779E3CA1EEFB8FF5A64807DBC942B1E4A2672D77B9F6928D292591 |
| SSDEEP    | 1536:sBOoa7Nn52wurilmw9BgjKu1sPPxaSLyqC:sBOoa7P2wxlPwV1qPkSuqC |

Loading it on DiE and pestudio shows us that it has a compiler stamp of `Feb 23rd, 2022` as well as it's not packed (and it's not obfuscated either) yet it has something interesting in its resources

![Embedded Drivers](assets/img/posts/2024-05-01-HermeticWiper/resources_drivers.png)

It has 4 drivers named `DRV_X64`, `DRV_X86`, `DRV_XP_X64` and `DRV_XP_X86` all are LZ compressed. it will later be decompressed and dropped into the system depending on the architecture and whether or not is a legacy WinXP system. We will look into those later.

Also, it has a Certificate signed by `Hermetica Digital Ltd`, probably a stolen one.

![Certificate](assets/img/posts/2024-05-01-HermeticWiper/cert.png)

### Behavioral Analysis

![Setting up Privileges](assets/img/posts/2024-05-01-HermeticWiper/hermeticwiper.png)

We are greeted with this 32-bit executable gift, let's launch `Process Monitor`, run our sample as Admin and see what it'll do. I'll explain later why we run it as admin and why we start its name with a `'C'`

A while after it started running we notice its I/O Rate is high which means it's reading/writing/moving a lot of data.

![iorate](assets/img/posts/2024-05-01-HermeticWiper/iorate.png)

Looking at `Process Monitor` as well we find it doing a lot of `IOCTL` calls to `FSCTL_GET_RETRIEVAL_POINTERS` and `FSCTL_MOVE_FILE`. These are both used in fragmentation/defragmentation.

![fragmentation](assets/img/posts/2024-05-01-HermeticWiper/fragmentation_behavior.png)

A little while after that we notice the system becomes nonresponsive, not long after, it will force a restart and BOOM!

![missing os](assets/img/posts/2024-05-01-HermeticWiper/missingOS.png)

## Usermode Agent Analysis

### Modifying Privileges

It starts with modifying some Privileges like `SeBackupPrivilege` and `SeShutdownPrivilege` but with a little twist, to set the `SeShutdownPrivilege` it needs the executable file to start with `'C'` (or `'c'` but it will be converted to lowercase anyways), I don't know why it's implemented this way, it could be an anti-sandbox technique as some sandboxes change the samples name.

![Setting up Privileges](assets/img/posts/2024-05-01-HermeticWiper/set_priv.png)

### Initializing Driver
First of all, a check is made to determine which version of the driver will be installed.

![Fingerprint System](assets/img/posts/2024-05-01-HermeticWiper/driver_type.png)

Then it proceeds to disable crash dumps, next it will generate a random name for the driver from a character set as shown here

![Naming Driver](assets/img/posts/2024-05-01-HermeticWiper/rename_driver.png)

>Why disabling crashdumps tho? well simply, crashdumps are automatically generated when there's an unhandled exception (or an "error") in the Kernel mode causing a "Blue screen of death" (BSOD).
>The dump file captures the system state at the time of the crash, so it can later be analyzed by loading the dump file into the debugger.

>So we can guess it's disabled to be more "stealthy" so if an error occurred during the driver is working (due to its actions or code error), the forensicators/users will have a harder time finding the reason.

All it has to do now is just decompress the driver and run it!

![Run driver](assets/img/posts/2024-05-01-HermeticWiper/run_drv.png)

Inside this subroutine we find it sets another privilege `SeLoadDriverPrivilege` then adds the driver as a service and runs it.

![start service](assets/img/posts/2024-05-01-HermeticWiper/start_service.png)

>Later on, it will delete its files but it won't matter as the drive is already running in memory. So no harm done..(?)

After the installation is done, it will carry on to disable VolumeShadowCopies/backups. This is also common in Ransomware, deleting ShadowCopies paralyzes the recovery.

![Disable VSS](assets/img/posts/2024-05-01-HermeticWiper/disable_vss.png)

Also, a change in Explorer registry is made to proceed to fragmentation without the user noticing

![change explorer registry](assets/img/posts/2024-05-01-HermeticWiper/explorer_reg.png)

### Information Gathering and Fragmentation

At that point, `HermeticWiper` starts using calls to `FSCTL_GET_RETRIEVAL_POINTERS IOCTL`, `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX`, `FSCTL_GET_VOLUME_BITMAP`, `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` and `IOCTL_DISK_GET_DRIVE_LAYOUT_EX` to gather information about the disk and file system such as :

+ Disk free space
+ Disk number and starting offset
+ Disk bitmap
+ Location and allocation pointers (important for fragmentation/defragmentation)
+ Disk type (NTFS/GPT/RAW)

With such info it starts fragmenting the disk according to filesystem type (NTFS/FAT) **avoiding** certain files/directories so it won't cause a system crash before completing its job!

![Fragmentation](assets/img/posts/2024-05-01-HermeticWiper/corrupt_system.png)

Additionally, it deletes the system event logs.

Fragmentation function :

![Fragmentation function](assets/img/posts/2024-05-01-HermeticWiper/fragmentation.png)

Some of the avoided files (as well as `ntuser`, `documents` and `settings`) :

![Avoided files](assets/img/posts/2024-05-01-HermeticWiper/avoided_files.png)

If that's not enough, it also overwrites the wiped data with randomly generated data to make it impossible to recover the data forensically (as "deleting" only means "deallocation").

![generate junk data](assets/img/posts/2024-05-01-HermeticWiper/gen_random.png)

If it finds that the system type is NTFS it would additionally overwrite the `$Bitmap` and `$LogFile` files.

![overwrite ntfs](assets/img/posts/2024-05-01-HermeticWiper/ntfs.png)

>The "$LogFile" is called the 'transaction logging file', It provides file system recoverability by logging, or recording, the operations required for any transaction that alters important file system data structures.

>The $BitMap is a special file within the NTFS file system, it keeps track of all of the used and unused clusters on an NTFS volume.

[comment]: <> (overwrite ntfs function : ntfs_routine.png)

## Kernel Driver

Using `pestudio` we can easily extract the drivers from the resource section. The drivers are `LZ Compressed` but they can easily be decompressed using `7z`.

I load it up to `IDA` I didn't find anything interesting/suspicious about it and to make sure I used `bindiff` to compare the dropped drive and an old drive and they were the same.

The `HermeticWiper` is using `epmntdrv.sys` that is a legitimate driver `EaseUS Partition Master Driver` it helps users to manage, create, delete, resize, extend, shrink, clone, convert, and migrate hard disk drives and partitions.


![bindiff](assets/img/posts/2024-05-01-HermeticWiper/bindiff.png)

The driver uses the device name `EPMNTDRV` and the way it works is that the user-mode uses `CreateFileW` to get a handle for the driver and passes it to `DeviceIoControl` so it can interact with the driver.


The driver will get a reference to the disk from the user-mode agent that it will use later for read/write operations

![device object](assets/img/posts/2024-05-01-HermeticWiper/dvc_obj.png)

It will then go to the lowest device object using `IoGetLowerDeviceObject` and store it in the `FsContext2` :

![fscontext2](assets/img/posts/2024-05-01-HermeticWiper/fscontext.png)

That will later be used in the `"DeviceControl"` along with the `IOCTL` :

![ioctl](assets/img/posts/2024-05-01-HermeticWiper/ioctl.png)

And using the device object it got earlier, it will perform write/read operations on the disk.

![driver read/write](assets/img/posts/2024-05-01-HermeticWiper/drv_read_write.png)

## YARA Rule

```vim
rule HermeticWiper {
   meta:
      author = "@3weSxZero"
      date = "2023-05-10"
      hash1 = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
   strings:
      $s1 = "\\\\?\\C:\\Windows\\System32\\winevt\\Logs" fullword wide
      $s2 = "\\\\?\\C:\\Documents and Settings" fullword wide
      $s3 = "tdrv.pdb" fullword ascii
      $s4 = "\\\\.\\EPMNTDRV\\%u" fullword wide
      $priv1 = {40 53 00 65}
      $priv2 = {4C 64 00 6F}
      $priv3 = {60 65 00 67}
      $priv4 = {5C 69 00 6C}
      $charset1 = {45 A8 61 00 62}
      $charset2 = {45 AC 63 00 64}
      $charset3 = {45 BC 6B 00 6C}
      $charset4 = {45 C4 6F 00 70}
   condition:
      uint16(0) == 0x5a4d and 2 of ($s1,$s2,$s3,$s4) and 2 of ($priv1,$priv2,$priv3,$priv4) and 2 of ($charset1,$charset2,$charset3,$charset4)
}
```
