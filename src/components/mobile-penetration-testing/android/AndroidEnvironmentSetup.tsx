
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Settings, Smartphone, Terminal, Download } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const AndroidEnvironmentSetup: React.FC = () => {
  return (
    <div className="space-y-6">
      <Card className="bg-cybr-card border-cybr-muted">
        <CardHeader>
          <CardTitle className="text-cybr-primary flex items-center gap-2">
            <Settings className="h-6 w-6" />
            הכנת סביבת הבדיקה
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="emulator-setup" className="w-full">
            <TabsList className="grid grid-cols-4 w-full mb-6">
              <TabsTrigger value="emulator-setup">Emulator Setup</TabsTrigger>
              <TabsTrigger value="device-rooting">Device Rooting</TabsTrigger>
              <TabsTrigger value="tools-installation">Tools Installation</TabsTrigger>
              <TabsTrigger value="proxy-setup">Proxy Setup</TabsTrigger>
            </TabsList>

            <TabsContent value="emulator-setup" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">הכנת Android Emulator</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Android Studio AVD Manager</h4>
                <CodeExample
                  language="bash"
                  title="יצירת AVD מהקונסול"
                  code={`# רשימת targets זמינים
avdmanager list target

# יצירת AVD חדש
avdmanager create avd -n TestDevice -k "system-images;android-29;google_apis;x86_64" -d "Nexus 5X"

# הפעלת האמולטור
emulator -avd TestDevice -writable-system -no-snapshot

# הפעלה עם proxy
emulator -avd TestDevice -http-proxy 127.0.0.1:8080

# הפעלה במצב root
emulator -avd TestDevice -writable-system -selinux permissive`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Genymotion Setup</h4>
                <CodeExample
                  language="bash"
                  title="התקנת Genymotion"
                  code={`# הורדת Genymotion
wget https://dl.genymotion.com/releases/genymotion-3.4.0/genymotion-3.4.0-linux_x64.bin

# התקנה
chmod +x genymotion-3.4.0-linux_x64.bin
./genymotion-3.4.0-linux_x64.bin

# הפעלת virtual device
genymotion-shell -c "devices list"
genymotion-shell -c "devices start 'Google Pixel 3'"

# ADB connection
adb connect 192.168.56.101:5555`}
                />
              </div>
            </TabsContent>

            <TabsContent value="device-rooting" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Rooting מכשירים</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Magisk Root</h4>
                <CodeExample
                  language="bash"
                  title="התקנת Magisk"
                  code={`# בדיקת bootloader unlock
adb shell getprop ro.boot.verifiedbootstate
adb shell getprop ro.boot.flash.locked

# התקנת Magisk Manager
adb install MagiskManager.apk

# Patching boot image
# 1. Extract boot.img from device firmware
# 2. Use Magisk Manager to patch boot.img
# 3. Flash patched image

fastboot flash boot magisk_patched.img
fastboot reboot

# וודא root
adb shell su -c "id"
adb shell su -c "mount -o remount,rw /system"`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">SuperSU (Legacy)</h4>
                <CodeExample
                  language="bash"
                  title="התקנת SuperSU"
                  code={`# התקנת TWRP Recovery
fastboot flash recovery twrp.img
fastboot boot twrp.img

# Flash SuperSU ZIP
adb push SR5-SuperSU-v2.82-SR5-20171001224502.zip /sdcard/
# Install via TWRP

# וודא root
adb shell su -c "which su"
adb shell su -c "ls -la /system/xbin/su"`}
                />
              </div>
            </TabsContent>

            <TabsContent value="tools-installation" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">התקנת כלי בדיקה</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">כלים בסיסיים</h4>
                <CodeExample
                  language="bash"
                  title="התקנת Android SDK Tools"
                  code={`# ADB ו-Fastboot
sudo apt-get install android-tools-adb android-tools-fastboot

# Android SDK
wget https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip
unzip commandlinetools-linux-9477386_latest.zip
export ANDROID_HOME=$HOME/Android/Sdk
export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin
export PATH=$PATH:$ANDROID_HOME/platform-tools

# Build tools
sdkmanager "build-tools;33.0.0"
sdkmanager "platforms;android-33"`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Frida Installation</h4>
                <CodeExample
                  language="bash"
                  title="התקנת Frida"
                  code={`# התקנת Frida על המחשב
pip install frida-tools

# הורדת Frida Server למכשיר
wget https://github.com/frida/frida/releases/download/16.0.8/frida-server-16.0.8-android-arm64.xz
unxz frida-server-16.0.8-android-arm64.xz

# העברה למכשיר
adb push frida-server-16.0.8-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"

# הפעלת Frida Server
adb shell "su -c '/data/local/tmp/frida-server &'"

# בדיקת חיבור
frida-ps -U`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">כלי ניתוח נוספים</h4>
                <CodeExample
                  language="bash"
                  title="התקנת כלים נוספים"
                  code={`# APKTool
wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.7.0.jar
chmod +x apktool

# JADX
wget https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip
unzip jadx-1.4.7.zip

# MobSF
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF
./setup.sh

# Objection
pip install objection

# Drozer
pip install drozer`}
                />
              </div>
            </TabsContent>

            <TabsContent value="proxy-setup" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">הגדרת Proxy ו-Certificate</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Burp Suite Setup</h4>
                <CodeExample
                  language="bash"
                  title="הגדרת Burp Proxy"
                  code={`# הגדרת proxy בטלפון
adb shell settings put global http_proxy 192.168.1.100:8080

# או דרך WiFi settings
adb shell am start -a android.intent.action.MAIN -n com.android.settings/.wifi.WifiSettings

# יצוא certificate מBurp
# 1. Browse to http://burp in device browser
# 2. Download CA Certificate
# 3. Save as cacert.der

# המרת certificate לפורמט נכון
openssl x509 -inform DER -in cacert.der -out cacert.pem
openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1
cp cacert.pem 9a5ba575.0

# העתקה למכשיר
adb push 9a5ba575.0 /sdcard/
adb shell "su -c 'mount -o remount,rw /system'"
adb shell "su -c 'cp /sdcard/9a5ba575.0 /system/etc/security/cacerts/'"
adb shell "su -c 'chmod 644 /system/etc/security/cacerts/9a5ba575.0'"
adb shell "su -c 'reboot'"`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Certificate Pinning Bypass</h4>
                <CodeExample
                  language="javascript"
                  title="Frida Script לbypass Certificate Pinning"
                  code={`// Universal SSL Kill Switch
Java.perform(function() {
    // TrustManager bypass
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    
    var TrustManagerImpl = Java.registerClass({
        name: "com.sensepost.test.TrustManagerImpl",
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    // OkHttp3 bypass  
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    OkHttpClient.Builder.prototype.build = function() {
        var client = this.build();
        var TrustAllCerts = Java.use("javax.net.ssl.X509TrustManager");
        // Implementation continues...
        return client;
    };
});`}
                />
              </div>
            </TabsContent>
          </Tabs>

          <div className="mt-6 p-4 bg-cybr-muted/20 rounded-lg">
            <h4 className="font-medium text-cybr-accent mb-2">טיפים חשובים</h4>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li>השתמש בemulators עם Google APIs לפונקציות מתקדמות</li>
              <li>ודא שיש לך מכשיר עם גישת root לבדיקות מתקדמות</li>
              <li>התקן את Frida Server בכל הפעלה של המכשיר</li>
              <li>בדוק את הגדרות ה-proxy לאחר כל reboot</li>
              <li>שמור backup של המכשיר לפני התקנת root</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default AndroidEnvironmentSetup;
