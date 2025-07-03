
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Settings, Smartphone, Terminal, Download, Shield, Container } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const AndroidEnvironmentSetup: React.FC = () => {
  return (
    <div className="space-y-6">
      <Card className="bg-cybr-card border-cybr-muted">
        <CardHeader>
          <CardTitle className="text-cybr-primary flex items-center gap-2">
            <Settings className="h-6 w-6" />
            Android Testing Environment Setup
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="mb-6 p-4 bg-cybr-muted/20 rounded-lg">
            <p className="text-cybr-foreground">
              Setting up a proper Android penetration testing environment is crucial for effective security assessments. 
              This comprehensive guide covers everything from basic emulator setup to advanced rooting techniques, 
              proxy configuration, and testing tool installation. Whether you're using physical devices or emulators, 
              proper environment setup ensures you can perform thorough security testing with all necessary tools and configurations.
            </p>
          </div>

          <Tabs defaultValue="emulator-setup" className="w-full">
            <TabsList className="grid grid-cols-6 w-full mb-6">
              <TabsTrigger value="emulator-setup">Emulator Setup</TabsTrigger>
              <TabsTrigger value="device-rooting">Device Rooting</TabsTrigger>
              <TabsTrigger value="tools-installation">Tools Installation</TabsTrigger>
              <TabsTrigger value="proxy-setup">Proxy Setup</TabsTrigger>
              <TabsTrigger value="docker-containers">Docker Containers</TabsTrigger>
              <TabsTrigger value="advanced-config">Advanced Config</TabsTrigger>
            </TabsList>

            <TabsContent value="emulator-setup" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Android Emulator Configuration</h3>
              <p className="text-cybr-foreground/80 mb-4">
                Android emulators provide a controlled environment for security testing. Learn how to configure 
                various emulator types including Android Studio AVD, Genymotion, and Android-x86 for optimal testing conditions.
              </p>

              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Android Studio AVD Manager</h4>
                <CodeExample
                  language="bash"
                  title="Creating AVD from Command Line"
                  code={`# List available targets and system images
avdmanager list target
avdmanager list avd
sdkmanager --list | grep system-images

# Create new AVD with Google APIs
avdmanager create avd -n TestDevice -k "system-images;android-29;google_apis;x86_64" -d "Nexus 5X"

# Create AVD with custom settings
avdmanager create avd -n SecurityTest \\
  -k "system-images;android-30;google_apis_playstore;x86_64" \\
  -d "pixel_3a" \\
  --sdcard 512M \\
  --tag google_apis_playstore

# Start emulator with security testing options
emulator -avd TestDevice -writable-system -no-snapshot -selinux permissive

# Start with network proxy
emulator -avd TestDevice -http-proxy 127.0.0.1:8080 -https-proxy 127.0.0.1:8080

# Start with custom DNS
emulator -avd TestDevice -dns-server 8.8.8.8,1.1.1.1

# Advanced emulator options
emulator -avd TestDevice \\
  -writable-system \\
  -no-snapshot \\
  -wipe-data \\
  -selinux permissive \\
  -prop persist.sys.root_access=3`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Genymotion Professional Setup</h4>
                <CodeExample
                  language="bash"
                  title="Installing and Configuring Genymotion"
                  code={`# Download and install Genymotion
wget https://dl.genymotion.com/releases/genymotion-3.4.0/genymotion-3.4.0-linux_x64.bin
chmod +x genymotion-3.4.0-linux_x64.bin
./genymotion-3.4.0-linux_x64.bin

# Create virtual device via command line
gmtool admin create "Google Pixel 3" "9.0" "Custom Pixel 3"

# Start virtual device
genymotion-shell -c "devices start 'Custom Pixel 3'"

# Configure network settings
genymotion-shell -c "devices edit 'Custom Pixel 3' network_mode bridge"

# Install ARM translation for x86 emulators
# Download Genymotion-ARM-Translation and flash via recovery

# ADB connection setup
adb connect 192.168.56.101:5555
adb devices`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Android-x86 VM Setup</h4>
                <CodeExample
                  language="bash"
                  title="Android-x86 Virtual Machine Configuration"
                  code={`# Download Android-x86 ISO
wget https://osdn.net/projects/android-x86/downloads/71931/android-x86_64-9.0-r2.iso

# Create VirtualBox VM
VBoxManage createvm --name "Android-x86" --ostype Linux26_64 --register
VBoxManage modifyvm "Android-x86" --memory 4096 --vram 128
VBoxManage modifyvm "Android-x86" --nic1 bridged --bridgeadapter1 "eth0"

# Create and attach virtual disk
VBoxManage createhd --filename Android-x86.vdi --size 8192
VBoxManage storagectl "Android-x86" --name "SATA Controller" --add sata
VBoxManage storageattach "Android-x86" --storagectl "SATA Controller" \\
  --port 0 --device 0 --type hdd --medium Android-x86.vdi

# Boot from ISO
VBoxManage storageattach "Android-x86" --storagectl "SATA Controller" \\
  --port 1 --device 0 --type dvddrive --medium android-x86_64-9.0-r2.iso

# Enable ADB over network
# In Android-x86: Settings > Developer Options > Android debugging (ADB over network)`}
                />
              </div>
            </TabsContent>

            <TabsContent value="device-rooting" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Device Rooting Techniques</h3>
              <p className="text-cybr-foreground/80 mb-4">
                Root access is essential for comprehensive Android security testing. This section covers modern rooting 
                methods including Magisk, traditional SuperSU, and custom recovery installation for various device types.
              </p>

              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Magisk Root (Modern Method)</h4>
                <CodeExample
                  language="bash"
                  title="Installing Magisk Root"
                  code={`# Check bootloader unlock status
adb shell getprop ro.boot.verifiedbootstate
adb shell getprop ro.boot.flash.locked
adb shell getprop sys.oem_unlock_allowed

# Download device firmware and extract boot.img
# Use manufacturer tools or online firmware databases

# Install Magisk Manager
wget https://github.com/topjohnwu/Magisk/releases/download/v25.2/Magisk-v25.2.apk
adb install Magisk-v25.2.apk

# Patch boot image using Magisk Manager
# 1. Copy boot.img to device
# 2. Use Magisk Manager to patch
# 3. Copy patched image back to host

# Flash patched boot image
fastboot flash boot magisk_patched_[random].img
fastboot reboot

# Verify root access
adb shell su -c "id"
adb shell su -c "mount -o remount,rw /system"
adb shell su -c "setenforce 0"

# Install Magisk modules for security testing
# - Riru (Xposed-like framework)
# - EdXposed (Xposed framework)
# - SSL Kill Switch (Certificate pinning bypass)`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Custom Recovery Installation</h4>
                <CodeExample
                  language="bash"
                  title="TWRP and Custom Recovery Setup"
                  code={`# Download TWRP for your device
# Check https://twrp.me/Devices/ for device-specific recovery

# Unlock bootloader (device-specific commands)
# For Google Pixels:
fastboot flashing unlock

# For Samsung devices:
# Use Odin tool and disable Knox

# Flash TWRP recovery
fastboot flash recovery twrp-3.6.2_9-0-device.img

# Boot into recovery
fastboot boot twrp-3.6.2_9-0-device.img

# Backup original firmware
# In TWRP: Backup > Select all partitions > Swipe to backup

# Flash SuperSU or Magisk ZIP
adb push Magisk-v25.2.zip /sdcard/
# In TWRP: Install > Select ZIP file > Flash

# Fix SELinux policies
adb shell su -c "supolicy --live \\
  'allow untrusted_app default_prop file { read getattr open }' \\
  'allow untrusted_app debug_prop file { read getattr open }' \\
  'allow untrusted_app shell_data_file dir search'"
`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Emulator Rooting</h4>
                <CodeExample
                  language="bash"
                  title="Rooting Android Emulators"
                  code={`# For AVD emulators (API < 30)
emulator -avd TestDevice -writable-system
adb root
adb remount
adb push su /system/xbin/su
adb shell chmod 06755 /system/xbin/su

# Install SuperSU APK
adb install SuperSU.apk

# For newer API levels, use Magisk canary builds
# Download Magisk canary: https://github.com/topjohnwu/Magisk/releases

# Genymotion rooting
# Use ARM Translation + SuperSU combination
# Or flash custom Genymotion images with root

# Install root checker
adb install RootChecker.apk

# Verify root functionality
adb shell su -c "mount | grep system"
adb shell su -c "ls -la /data/data/"
`}
                />
              </div>
            </TabsContent>

            <TabsContent value="tools-installation" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Security Testing Tools Installation</h3>
              <p className="text-cybr-foreground/80 mb-4">
                A comprehensive toolkit is essential for Android penetration testing. This section covers installation 
                and configuration of essential tools including Frida, Objection, MobSF, and various analysis frameworks.
              </p>

              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Android SDK and Platform Tools</h4>
                <CodeExample
                  language="bash"
                  title="Complete Android SDK Setup"
                  code={`# Install Android SDK Command Line Tools
wget https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip
unzip commandlinetools-linux-9477386_latest.zip -d android-sdk
export ANDROID_HOME=$HOME/android-sdk
export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools

# Install essential SDK components
sdkmanager "platform-tools"
sdkmanager "build-tools;33.0.0"
sdkmanager "platforms;android-33"
sdkmanager "system-images;android-29;google_apis;x86_64"
sdkmanager "emulator"

# Install ADB and Fastboot
sudo apt-get install android-tools-adb android-tools-fastboot

# Verify installation
adb version
fastboot --version
aapt version`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Frida Framework Installation</h4>
                <CodeExample
                  language="bash"
                  title="Complete Frida Setup"
                  code={`# Install Frida tools on host
pip install frida-tools
pip install frida-dexdump
pip install frida-apk

# Download Frida Server for target architecture
wget https://github.com/frida/frida/releases/download/16.0.8/frida-server-16.0.8-android-arm64.xz
unxz frida-server-16.0.8-android-arm64.xz

# For x86_64 emulators
wget https://github.com/frida/frida/releases/download/16.0.8/frida-server-16.0.8-android-x86_64.xz
unxz frida-server-16.0.8-android-x86_64.xz

# Transfer and setup Frida Server
adb push frida-server-16.0.8-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"

# Start Frida Server as daemon
adb shell "su -c '/data/local/tmp/frida-server &'"

# Verify connection
frida-ps -U
frida -U -l script.js com.target.app

# Install Frida Gadget for non-rooted testing
# Inject into APK during repackaging process`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Mobile Security Framework (MobSF)</h4>
                <CodeExample
                  language="bash"
                  title="MobSF Installation and Configuration"
                  code={`# Clone MobSF repository
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF

# Install dependencies
pip install -r requirements.txt

# Setup MobSF
python setup.py

# Start MobSF server
python manage.py runserver 0.0.0.0:8000

# Docker installation (alternative)
docker pull opensecurity/mobsf
docker run -it -p 8000:8000 opensecurity/mobsf:latest

# API automation example
curl -X POST -H "Content-Type: multipart/form-data" \\
     -F "file=@app.apk" \\
     http://127.0.0.1:8000/api/v1/upload

# Configure dynamic analysis
# Set up Android device connection
# Configure proxy settings for traffic interception`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Additional Analysis Tools</h4>
                <CodeExample
                  language="bash"
                  title="Comprehensive Tool Installation"
                  code={`# APK Analysis Tools
# APKTool
wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.7.0.jar
chmod +x apktool

# JADX Decompiler
wget https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip
unzip jadx-1.4.7.zip

# dex2jar
wget https://github.com/pxb1988/dex2jar/releases/download/v2.2/dex-tools-2.2.zip
unzip dex-tools-2.2.zip

# Dynamic Analysis Tools
# Objection
pip install objection

# Drozer
pip install drozer

# House (Objection GUI)
npm install -g @objection/house

# QARK (Quick Android Review Kit)
pip install qark

# AndroBugs Framework
git clone https://github.com/AndroBugs/AndroBugs_Framework.git

# Amoco (Binary Analysis)
pip install amoco

# Radare2 for reverse engineering
git clone https://github.com/radareorg/radare2
cd radare2
sys/install.sh`}
                />
              </div>
            </TabsContent>

            <TabsContent value="proxy-setup" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Proxy and Certificate Configuration</h3>
              <p className="text-cybr-foreground/80 mb-4">
                Network traffic interception is crucial for mobile security testing. Learn how to configure various 
                proxies, handle certificate pinning, and set up traffic analysis tools for comprehensive network testing.
              </p>

              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Burp Suite Configuration</h4>
                <CodeExample
                  language="bash"
                  title="Complete Burp Suite Setup"
                  code={`# Configure device proxy settings
adb shell settings put global http_proxy 192.168.1.100:8080

# Or configure via WiFi settings programmatically
adb shell am start -a android.intent.action.MAIN -n com.android.settings/.wifi.WifiSettings

# Export Burp certificate
# 1. Browse to http://burp in device browser
# 2. Download CA Certificate as DER format

# Convert certificate for Android
openssl x509 -inform DER -in cacert.der -out cacert.pem
openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1

# Example: if hash is 9a5ba575
cp cacert.pem 9a5ba575.0

# Install certificate on device
adb push 9a5ba575.0 /sdcard/
adb shell "su -c 'mount -o remount,rw /system'"
adb shell "su -c 'cp /sdcard/9a5ba575.0 /system/etc/security/cacerts/'"
adb shell "su -c 'chmod 644 /system/etc/security/cacerts/9a5ba575.0'"
adb shell "su -c 'chown root:root /system/etc/security/cacerts/9a5ba575.0'"
adb shell "su -c 'reboot'"

# For Android 14+ (user certificates)
adb shell "settings put global http_proxy 192.168.1.100:8080"
# Install via Settings > Security > Install certificates > CA certificates`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">OWASP ZAP Configuration</h4>
                <CodeExample
                  language="bash"
                  title="ZAP Proxy Mobile Setup"
                  code={`# Start ZAP in daemon mode
zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true

# Generate and install ZAP certificate
# Export ZAP root CA certificate
curl -k https://localhost:8080/OTHER/core/other/rootcert/ > zap_root_ca.crt

# Convert to Android format
openssl x509 -inform DER -in zap_root_ca.crt -out zap_root_ca.pem
openssl x509 -inform PEM -subject_hash_old -in zap_root_ca.pem | head -1
cp zap_root_ca.pem <hash>.0

# Install on device (same process as Burp)
adb push <hash>.0 /sdcard/
adb shell "su -c 'cp /sdcard/<hash>.0 /system/etc/security/cacerts/'"

# Configure ZAP for mobile testing
# API automation for mobile apps
curl -X GET "http://localhost:8080/JSON/core/action/newSession/?name=mobile_test"
curl -X GET "http://localhost:8080/JSON/core/action/setMode/?mode=standard"`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Certificate Pinning Bypass</h4>
                <CodeExample
                  language="javascript"
                  title="Advanced Frida SSL Pinning Bypass"
                  code={`// Universal SSL Kill Switch 2.0
Java.perform(function() {
    console.log("[+] Universal SSL Pinning Bypass Started");
    
    // Bypass TrustManager
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    
    var TrustManager = Java.registerClass({
        name: 'org.wooyun.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() {
                return [];
            }
        }
    });
    
    // Hook SSLContext.init()
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
        .implementation = function(keyManager, trustManager, secureRandom) {
        console.log('[+] SSLContext.init() called');
        this.init(keyManager, [TrustManager.$new()], secureRandom);
    };
    
    // Bypass OkHttp3 Certificate Pinning
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[+] OkHttp3 Certificate Pinning bypassed for: ' + hostname);
            return;
        };
    } catch(err) {
        console.log('[-] OkHttp3 not found');
    }
    
    // Bypass Network Security Config
    try {
        var NetworkSecurityPolicy = Java.use('android.security.NetworkSecurityPolicy');
        NetworkSecurityPolicy.getInstance().implementation = function() {
            console.log('[+] NetworkSecurityPolicy bypassed');
            return Java.use('android.security.NetworkSecurityPolicy').$new();
        };
    } catch(err) {
        console.log('[-] NetworkSecurityPolicy not found');
    }
    
    console.log("[+] SSL Pinning Bypass Completed");
});`}
                />
              </div>
            </TabsContent>

            <TabsContent value="docker-containers" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Docker-based Testing Environment</h3>
              <p className="text-cybr-foreground/80 mb-4">
                Containerized testing environments provide consistency and isolation. Learn how to set up Docker containers 
                for Android testing tools, automated analysis pipelines, and scalable testing infrastructure.
              </p>

              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">MobSF Docker Setup</h4>
                <CodeExample
                  language="dockerfile"
                  title="Custom MobSF Docker Configuration"
                  code={`# Dockerfile for enhanced MobSF
FROM opensecurity/mobsf:latest

# Install additional tools
RUN pip install frida-tools objection qark

# Add custom analysis scripts
COPY custom_scripts/ /home/mobsf/custom_scripts/
COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

# Configure for CI/CD
ENV MOBSF_API_ONLY=1
ENV MOBSF_ANALYZER_TIMEOUT=300

EXPOSE 8000
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Android Testing Container</h4>
                <CodeExample
                  language="dockerfile"
                  title="Complete Android Testing Environment"
                  code={`# Multi-stage Android testing container
FROM ubuntu:20.04 as android-base

# Install dependencies
RUN apt-get update && apt-get install -y \\
    openjdk-11-jdk \\
    python3 \\
    python3-pip \\
    wget \\
    unzip \\
    curl \\
    git \\
    android-tools-adb \\
    android-tools-fastboot

# Install Android SDK
ENV ANDROID_HOME=/opt/android-sdk
ENV PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools

# Install testing tools
RUN pip3 install frida-tools objection qark

# Download and setup tools
WORKDIR /opt/tools
RUN wget https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip && \\
    unzip jadx-1.4.7.zip

# Setup workspace
WORKDIR /workspace
COPY scripts/ /workspace/scripts/

CMD ["/bin/bash"]`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Docker Compose Testing Stack</h4>
                <CodeExample
                  language="yaml"
                  title="Complete Testing Infrastructure"
                  code={`version: '3.8'

services:
  mobsf:
    image: opensecurity/mobsf:latest
    ports:
      - "8000:8000"
    volumes:
      - ./uploads:/home/mobsf/uploads
      - ./reports:/home/mobsf/reports
    environment:
      - MOBSF_API_ONLY=0
    
  android-tools:
    build: ./android-tools
    volumes:
      - ./apks:/workspace/apks
      - ./scripts:/workspace/scripts
      - ./results:/workspace/results
    stdin_open: true
    tty: true
    
  proxy:
    image: owasp/zap2docker-stable
    ports:
      - "8080:8080"
    command: zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.*
    
  frida-server:
    build: ./frida-container
    volumes:
      - ./scripts:/scripts
    network_mode: "host"
    privileged: true
    
volumes:
  uploads:
  reports:
  results:`}
                />
              </div>
            </TabsContent>

            <TabsContent value="advanced-config" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Advanced Configuration and Optimization</h3>
              <p className="text-cybr-foreground/80 mb-4">
                Advanced configuration techniques for optimizing your Android testing environment, including performance 
                tuning, automation scripting, and enterprise-grade testing infrastructure setup.
              </p>

              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Automated Environment Setup</h4>
                <CodeExample
                  language="bash"
                  title="Complete Environment Setup Script"
                  code={`#!/bin/bash
# Android Penetration Testing Environment Setup Script

set -e

echo "[+] Starting Android PenTest Environment Setup"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install system dependencies
install_dependencies() {
    echo "[+] Installing system dependencies..."
    if command_exists apt-get; then
        sudo apt-get update
        sudo apt-get install -y \\
            openjdk-11-jdk \\
            python3 \\
            python3-pip \\
            nodejs \\
            npm \\
            git \\
            curl \\
            wget \\
            unzip \\
            android-tools-adb \\
            android-tools-fastboot
    fi
}

# Setup Android SDK
setup_android_sdk() {
    echo "[+] Setting up Android SDK..."
    export ANDROID_HOME=$HOME/android-sdk
    export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools
    
    mkdir -p $ANDROID_HOME
    cd $ANDROID_HOME
    
    wget -q https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip
    unzip -q commandlinetools-linux-9477386_latest.zip
    
    yes | sdkmanager "platform-tools"
    yes | sdkmanager "build-tools;33.0.0"
    yes | sdkmanager "platforms;android-33"
}

# Install security tools
install_security_tools() {
    echo "[+] Installing security tools..."
    
    # Python tools
    pip3 install --user frida-tools objection qark
    
    # Download JADX
    wget -q https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip
    unzip -q jadx-1.4.7.zip -d $HOME/tools/jadx
    
    # Download APKTool
    wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O $HOME/tools/apktool
    wget -q https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.7.0.jar -O $HOME/tools/apktool.jar
    chmod +x $HOME/tools/apktool
    
    # Clone MobSF
    git clone -q https://github.com/MobSF/Mobile-Security-Framework-MobSF.git $HOME/tools/MobSF
}

# Configure environment
configure_environment() {
    echo "[+] Configuring environment..."
    
    # Add to .bashrc
    cat >> $HOME/.bashrc << EOF

# Android PenTest Environment
export ANDROID_HOME=$HOME/android-sdk
export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$HOME/tools
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
EOF
    
    source $HOME/.bashrc
}

# Create testing directories
create_directories() {
    echo "[+] Creating testing directories..."
    mkdir -p $HOME/{tools,apks,reports,scripts,results}
}

# Main execution
main() {
    create_directories
    install_dependencies
    setup_android_sdk
    install_security_tools
    configure_environment
    
    echo "[+] Android PenTest Environment Setup Complete!"
    echo "Please restart your shell or run: source ~/.bashrc"
}

main "$@"`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Performance Optimization</h4>
                <CodeExample
                  language="bash"
                  title="Emulator Performance Tuning"
                  code={`# Enable hardware acceleration
# Ensure KVM is available
sudo apt-get install qemu-kvm
sudo usermod -a -G kvm $USER

# Check hardware acceleration
emulator -accel-check

# Start emulator with performance options
emulator -avd TestDevice \\
  -gpu host \\
  -accel on \\
  -memory 4096 \\
  -cores 4 \\
  -cache-size 1024 \\
  -no-boot-anim \\
  -no-window \\
  -skip-adb-auth

# Configure ADB for better performance  
adb kill-server
adb start-server
adb shell "settings put global animator_duration_scale 0"
adb shell "settings put global transition_animation_scale 0"
adb shell "settings put global window_animation_scale 0"

# Disable unnecessary services
adb shell "pm disable-user --user 0 com.google.android.music"
adb shell "pm disable-user --user 0 com.google.android.videos"
adb shell "pm disable-user --user 0 com.google.android.youtube"`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Testing Automation Scripts</h4>
                <CodeExample
                  language="python"
                  title="Automated Testing Pipeline"
                  code={`#!/usr/bin/env python3
"""
Android Security Testing Automation Script
"""

import subprocess
import os
import json
import time
from pathlib import Path

class AndroidTestSuite:
    def __init__(self, apk_path, output_dir):
        self.apk_path = apk_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
    def run_command(self, command, capture_output=True):
        """Execute shell command"""
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=capture_output, 
                text=True,
                timeout=300
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", 1
    
    def static_analysis(self):
        """Perform static analysis"""
        print("[+] Starting static analysis...")
        
        # APKTool analysis
        apktool_dir = self.output_dir / "apktool"
        cmd = f"apktool d {self.apk_path} -o {apktool_dir}"
        self.run_command(cmd)
        
        # JADX decompilation
        jadx_dir = self.output_dir / "jadx"
        cmd = f"jadx -d {jadx_dir} {self.apk_path}"
        self.run_command(cmd)
        
        # QARK scan
        qark_report = self.output_dir / "qark_report.json"
        cmd = f"qark --apk {self.apk_path} --report-type json --report-name {qark_report}"
        self.run_command(cmd)
        
        return True
    
    def dynamic_analysis(self):
        """Perform dynamic analysis"""
        print("[+] Starting dynamic analysis...")
        
        # Install APK
        cmd = f"adb install -r {self.apk_path}"
        self.run_command(cmd)
        
        # Get package name
        cmd = f"aapt dump badging {self.apk_path} | grep package"
        output, _, _ = self.run_command(cmd)
        package_name = output.split("name='")[1].split("'")[0]
        
        # Start application
        cmd = f"adb shell monkey -p {package_name} -c android.intent.category.LAUNCHER 1"
        self.run_command(cmd)
        
        # Frida analysis
        frida_script = """
        Java.perform(function() {
            console.log("[+] Frida attached to process");
            // Add your Frida scripts here
        });
        """
        
        with open(self.output_dir / "frida_analysis.js", "w") as f:
            f.write(frida_script)
        
        return True
    
    def generate_report(self):
        """Generate comprehensive report"""
        report = {
            "apk_path": str(self.apk_path),
            "analysis_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "static_analysis": "completed",
            "dynamic_analysis": "completed"
        }
        
        with open(self.output_dir / "analysis_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Analysis complete. Report saved to {self.output_dir}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python android_test_suite.py <apk_path> <output_dir>")
        sys.exit(1)
    
    suite = AndroidTestSuite(sys.argv[1], sys.argv[2])
    suite.static_analysis()
    suite.dynamic_analysis()
    suite.generate_report()`}
                />
              </div>
            </TabsContent>
          </Tabs>

          <div className="mt-6 p-4 bg-cybr-muted/20 rounded-lg">
            <h4 className="font-medium text-cybr-accent mb-2">Environment Setup Best Practices</h4>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li>Always use dedicated testing devices or isolated VMs for security testing</li>
              <li>Keep multiple Android versions available for compatibility testing</li>
              <li>Maintain separate environments for different testing scenarios</li>
              <li>Document your environment configuration for reproducibility</li>
              <li>Regularly update tools and security patches</li>
              <li>Use version control for your custom scripts and configurations</li>
              <li>Implement proper backup and restore procedures for testing environments</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default AndroidEnvironmentSetup;
