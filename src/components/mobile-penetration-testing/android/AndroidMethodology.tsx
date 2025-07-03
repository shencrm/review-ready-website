
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { CheckCircle, Search, Target, Bug, FileText } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const AndroidMethodology: React.FC = () => {
  return (
    <div className="space-y-6">
      <Card className="bg-cybr-card border-cybr-muted">
        <CardHeader>
          <CardTitle className="text-cybr-primary flex items-center gap-2">
            <CheckCircle className="h-6 w-6" />
            Step-by-Step Testing Methodology
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="information-gathering" className="w-full">
            <TabsList className="grid grid-cols-5 w-full mb-6">
              <TabsTrigger value="information-gathering">Information Gathering</TabsTrigger>
              <TabsTrigger value="threat-modeling">Threat Modeling</TabsTrigger>
              <TabsTrigger value="vulnerability-assessment">Vulnerability Assessment</TabsTrigger>
              <TabsTrigger value="exploitation">Exploitation</TabsTrigger>
              <TabsTrigger value="reporting">Reporting</TabsTrigger>
            </TabsList>

            <TabsContent value="information-gathering" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Phase 1: Information Gathering</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">APK Information Extraction</h4>
                <CodeExample
                  language="bash"
                  title="Basic APK Information Gathering"
                  code={`# Get basic information
aapt dump badging app.apk
aapt dump permissions app.apk
aapt dump configurations app.apk

# Extract APK from device
adb shell pm list packages | grep -i targetapp
adb shell pm path com.example.targetapp
adb pull /data/app/com.example.targetapp-1/base.apk

# Certificate information
jarsigner -verify -verbose -certs app.apk
keytool -printcert -jarfile app.apk

# Binary analysis
file app.apk
unzip -l app.apk | head -20
strings app.apk | grep -i "http\\|pass\\|key\\|secret" | head -10`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Manifest Analysis</h4>
                <CodeExample
                  language="bash"
                  title="AndroidManifest.xml Analysis"
                  code={`# Extract and analyze manifest
apktool d app.apk -o app_extracted
cat app_extracted/AndroidManifest.xml

# Check for exported components
grep -n "android:exported=\"true\"" app_extracted/AndroidManifest.xml

# Check permissions
grep -n "uses-permission" app_extracted/AndroidManifest.xml

# Custom permissions
grep -n "permission android:name" app_extracted/AndroidManifest.xml

# Backup settings
grep -n "android:allowBackup" app_extracted/AndroidManifest.xml

# Debug flag
grep -n "android:debuggable" app_extracted/AndroidManifest.xml

# Network security config
grep -n "networkSecurityConfig" app_extracted/AndroidManifest.xml`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Source Code Analysis</h4>
                <CodeExample
                  language="bash"
                  title="Source Code Analysis"
                  code={`# Decompile with JADX
jadx -d output_dir app.apk

# Search for sensitive information
grep -r "password\\|secret\\|key\\|token" output_dir/
grep -r "http://\\|https://" output_dir/
grep -r "sql\\|database" output_dir/
grep -r "crypto\\|encrypt" output_dir/

# Check for hardcoded values
grep -r "hardcoded\\|TODO\\|FIXME" output_dir/

# Look for native libraries
find output_dir/ -name "*.so" -type f
objdump -T output_dir/lib/arm64-v8a/libnative.so`}
                />
              </div>
            </TabsContent>

            <TabsContent value="threat-modeling" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Phase 2: Threat Modeling</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">STRIDE Analysis</h4>
                <div className="bg-cybr-muted/20 p-4 rounded-lg">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-cybr-muted">
                        <th className="text-left p-2">Threat</th>
                        <th className="text-left p-2">Description</th>
                        <th className="text-left p-2">Android Examples</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr className="border-b border-cybr-muted/50">
                        <td className="p-2 font-medium">Spoofing</td>
                        <td className="p-2">Identity impersonation</td>
                        <td className="p-2">Intent spoofing, App impersonation</td>
                      </tr>
                      <tr className="border-b border-cybr-muted/50">
                        <td className="p-2 font-medium">Tampering</td>
                        <td className="p-2">Data modification</td>
                        <td className="p-2">APK modification, Runtime manipulation</td>
                      </tr>
                      <tr className="border-b border-cybr-muted/50">
                        <td className="p-2 font-medium">Repudiation</td>
                        <td className="p-2">Denial of actions</td>
                        <td className="p-2">Missing audit logs, Weak authentication</td>
                      </tr>
                      <tr className="border-b border-cybr-muted/50">
                        <td className="p-2 font-medium">Information Disclosure</td>
                        <td className="p-2">Information exposure</td>
                        <td className="p-2">Data leakage, Insecure storage</td>
                      </tr>
                      <tr className="border-b border-cybr-muted/50">
                        <td className="p-2 font-medium">Denial of Service</td>
                        <td className="p-2">Service disruption</td>
                        <td className="p-2">Resource exhaustion, Crash attacks</td>
                      </tr>
                      <tr>
                        <td className="p-2 font-medium">Elevation of Privilege</td>
                        <td className="p-2">Permission escalation</td>
                        <td className="p-2">Permission escalation, Root exploits</td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                <h4 className="text-lg font-medium text-cybr-secondary">Attack Surface Mapping</h4>
                <CodeExample
                  language="bash"
                  title="Attack Surface Mapping"
                  code={`# Network attack surface
netstat -tuln | grep LISTEN
ss -tuln | grep LISTEN

# File system permissions
find /data/data/com.example.app -ls 2>/dev/null
find /sdcard/ -name "*com.example.app*" -ls 2>/dev/null

# IPC attack surface
dumpsys activity | grep -A5 -B5 "com.example.app"
dumpsys package com.example.app

# Exposed components
adb shell am start -n com.example.app/.MainActivity
adb shell am broadcast -a com.example.app.CUSTOM_ACTION
adb shell content query --uri content://com.example.app.provider/data`}
                />
              </div>
            </TabsContent>

            <TabsContent value="vulnerability-assessment" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Phase 3: Vulnerability Assessment</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">OWASP Mobile Top 10 Assessment</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-cybr-muted/20 p-3 rounded">
                    <h5 className="font-medium text-cybr-accent">M1: Improper Platform Usage</h5>
                    <ul className="text-sm mt-2 space-y-1">
                      <li>• Misuse of platform features</li>
                      <li>• Insecure inter-app communication</li>
                      <li>• Keychain/Keystore misuse</li>
                    </ul>
                  </div>
                  <div className="bg-cybr-muted/20 p-3 rounded">
                    <h5 className="font-medium text-cybr-accent">M2: Insecure Data Storage</h5>
                    <ul className="text-sm mt-2 space-y-1">
                      <li>• Unencrypted local storage</li>
                      <li>• Sensitive data in logs</li>
                      <li>• Insecure backup storage</li>
                    </ul>
                  </div>
                  <div className="bg-cybr-muted/20 p-3 rounded">
                    <h5 className="font-medium text-cybr-accent">M3: Insecure Communication</h5>
                    <ul className="text-sm mt-2 space-y-1">
                      <li>• Weak TLS implementation</li>
                      <li>• Certificate validation bypass</li>
                      <li>• Plaintext communication</li>
                    </ul>
                  </div>
                  <div className="bg-cybr-muted/20 p-3 rounded">
                    <h5 className="font-medium text-cybr-accent">M4: Insecure Authentication</h5>
                    <ul className="text-sm mt-2 space-y-1">
                      <li>• Weak authentication schemes</li>
                      <li>• Insecure credential storage</li>
                      <li>• Biometric bypass</li>
                    </ul>
                  </div>
                </div>

                <h4 className="text-lg font-medium text-cybr-secondary">Automated Vulnerability Scanning</h4>
                <CodeExample
                  language="bash"
                  title="Automated Vulnerability Scanning"
                  code={`# MobSF scanning
python manage.py runserver 127.0.0.1:8000
# Upload APK through web interface

# QARK scanning
qark --apk app.apk --report-type json

# AndroBugs scanning
python androbugs.py -f app.apk

# Semgrep for mobile
semgrep --config=auto --json -o results.json app_source/

# Custom grep patterns
grep -r "Log\\." app_source/ | grep -v "DEBUG"
grep -r "System\\.out\\.print" app_source/
grep -r "printStackTrace" app_source/`}
                />
              </div>
            </TabsContent>

            <TabsContent value="exploitation" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Phase 4: Vulnerability Exploitation</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Runtime Exploitation</h4>
                <CodeExample
                  language="javascript"
                  title="Frida Exploitation Script"
                  code={`Java.perform(function() {
    // Hook authentication method
    var AuthClass = Java.use("com.example.app.AuthManager");
    AuthClass.validateUser.implementation = function(username, password) {
        console.log("[+] Authentication bypass attempted");
        console.log("Username: " + username);
        console.log("Password: " + password);
        return true; // Always return successful authentication
    };
    
    // Hook encryption method
    var CryptoClass = Java.use("com.example.app.CryptoUtil");
    CryptoClass.encrypt.implementation = function(data) {
        console.log("[+] Encryption intercepted");
        console.log("Original data: " + data);
        var result = this.encrypt(data);
        console.log("Encrypted data: " + result);
        return result;
    };
    
    // Hook file operations
    var FileClass = Java.use("java.io.FileWriter");
    FileClass.$init.overload('java.lang.String').implementation = function(filename) {
        console.log("[+] File write attempt: " + filename);
        return this.$init(filename);
    };
});`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Component Exploitation</h4>
                <CodeExample
                  language="bash"
                  title="Application Component Exploitation"
                  code={`# Activity exploitation
adb shell am start -n com.example.app/.AdminActivity
adb shell am start -a android.intent.action.VIEW -d "myapp://admin/bypass"

# Service exploitation  
adb shell am startservice -n com.example.app/.BackupService
adb shell am startservice -a com.example.app.BACKUP_DATA

# Broadcast exploitation
adb shell am broadcast -a com.example.app.ADMIN_UNLOCK

# ContentProvider exploitation
adb shell content query --uri content://com.example.app.provider/users
adb shell content insert --uri content://com.example.app.provider/users --bind name:s:admin --bind role:s:administrator

# Deep link exploitation
adb shell am start -a android.intent.action.VIEW -d "myapp://transfer?amount=1000000&account=attacker"`}
                />
              </div>
            </TabsContent>

            <TabsContent value="reporting" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Phase 5: Reporting and Documentation</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Report Structure and Organization</h4>
                <div className="bg-cybr-muted/20 p-4 rounded-lg">
                  <h5 className="font-medium text-cybr-accent mb-2">Executive Summary</h5>
                  <ul className="text-sm space-y-1 mb-4">
                    <li>• High-level overview</li>
                    <li>• Vulnerability statistics</li>
                    <li>• Overall risk assessment</li>
                    <li>• Key recommendations</li>
                  </ul>
                  
                  <h5 className="font-medium text-cybr-accent mb-2">Technical Findings</h5>
                  <ul className="text-sm space-y-1 mb-4">
                    <li>• Detailed vulnerability descriptions</li>
                    <li>• Proof-of-concept for each vulnerability</li>
                    <li>• CVSS severity ratings</li>
                    <li>• Remediation recommendations</li>
                  </ul>
                  
                  <h5 className="font-medium text-cybr-accent mb-2">Appendices</h5>
                  <ul className="text-sm space-y-1">
                    <li>• Methodology overview</li>
                    <li>• Tools used</li>
                    <li>• Raw scan results</li>
                    <li>• Screenshots and evidence</li>
                  </ul>
                </div>

                <h4 className="text-lg font-medium text-cybr-secondary">CVSS Scoring</h4>
                <CodeExample
                  language="text"
                  title="CVSS Scoring Example"
                  code={`Vulnerability: Insecure Data Storage
Description: Application stores passwords in plaintext in SharedPreferences file

CVSS v3.1 Vector: AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
Base Score: 6.2 (Medium)

Calculation:
- Attack Vector (AV): Local (L) - Physical access to device required
- Attack Complexity (AC): Low (L) - Vulnerability is easy to exploit  
- Privileges Required (PR): None (N) - No special privileges needed
- User Interaction (UI): None (N) - No interaction required
- Scope (S): Unchanged (U) - Vulnerability is limited to application
- Confidentiality (C): High (H) - Complete exposure of passwords
- Integrity (I): None (N) - No impact on integrity
- Availability (A): None (N) - No impact on availability`}
                />
              </div>
            </TabsContent>
          </Tabs>

          <div className="mt-6 p-4 bg-cybr-muted/20 rounded-lg">
            <h4 className="font-medium text-cybr-accent mb-2">Recommended Methodologies</h4>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li><strong>OWASP MSTG</strong> - Comprehensive Mobile Security Testing Guide</li>
              <li><strong>NIST SP 800-124</strong> - Guidelines for Managing Mobile Device Security</li>
              <li><strong>PTES Mobile</strong> - Penetration Testing Execution Standard for Mobile</li>
              <li><strong>SANS Mobile Testing</strong> - SANS methodology for mobile testing</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default AndroidMethodology;
