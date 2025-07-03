import React, { useState } from 'react';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Copy, ExternalLink, Shield, MessageSquare, Database, Share2, Radio, Settings, AlertTriangle, CheckCircle, Code, Terminal, FileText, Bug } from 'lucide-react';

const AndroidIPCAnalysis: React.FC = () => {
  const [activeTab, setActiveTab] = useState('introduction');

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="space-y-6">
      {/* Introduction Section */}
      <div className="bg-gradient-to-r from-blue-50 to-purple-50 p-6 rounded-lg border">
        <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
          <Share2 className="text-blue-600" />
          Android IPC (Inter-Process Communication) Analysis
        </h2>
        <p className="text-lg text-gray-700 mb-4">
          Android's Inter-Process Communication (IPC) mechanisms are fundamental to how Android applications 
          interact with each other and the system. IPC security analysis focuses on testing the security 
          of Intents, Content Providers, Broadcast Receivers, and Services - the four main components that 
          enable communication between different parts of an Android system.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
          <div className="bg-white p-4 rounded-lg border">
            <h3 className="font-semibold text-green-700 mb-2">Why IPC Analysis Matters</h3>
            <ul className="text-sm text-gray-600 space-y-1">
              <li>• Detects component hijacking vulnerabilities</li>
              <li>• Identifies data exposure through improper exports</li>
              <li>• Prevents privilege escalation attacks</li>
              <li>• Ensures proper access control implementation</li>
            </ul>
          </div>
          <div className="bg-white p-4 rounded-lg border">
            <h3 className="font-semibold text-blue-700 mb-2">Common IPC Vulnerabilities</h3>
            <ul className="text-sm text-gray-600 space-y-1">
              <li>• Exported components without proper protection</li>
              <li>• Intent-based attacks and data leakage</li>
              <li>• Broadcast injection and eavesdropping</li>
              <li>• SQL injection in Content Providers</li>
            </ul>
          </div>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList className="grid grid-cols-2 md:grid-cols-4 gap-1 h-auto p-1">
          <TabsTrigger value="introduction" className="flex items-center gap-1 py-2 text-xs">
            <MessageSquare className="h-3 w-3" />
            <span className="hidden md:inline">Overview</span>
          </TabsTrigger>
          <TabsTrigger value="intent-analysis" className="flex items-center gap-1 py-2 text-xs">
            <Share2 className="h-3 w-3" />
            <span className="hidden md:inline">Intents</span>
          </TabsTrigger>
          <TabsTrigger value="content-providers" className="flex items-center gap-1 py-2 text-xs">
            <Database className="h-3 w-3" />
            <span className="hidden md:inline">Providers</span>
          </TabsTrigger>
          <TabsTrigger value="broadcast-services" className="flex items-center gap-1 py-2 text-xs">
            <Radio className="h-3 w-3" />
            <span className="hidden md:inline">Broadcast</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="introduction" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <MessageSquare className="h-5 w-5" />
                IPC Components Overview
              </CardTitle>
              <CardDescription>
                Understanding Android's four main IPC mechanisms and their security implications
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <div className="border rounded-lg p-4">
                    <h3 className="font-semibold text-blue-600 mb-2 flex items-center gap-2">
                      <Share2 className="h-4 w-4" />
                      Intents
                    </h3>
                    <p className="text-sm text-gray-600 mb-3">
                      Message objects used to communicate between app components
                    </p>
                    <div className="space-y-2">
                      <Badge variant="outline">Explicit Intents</Badge>
                      <Badge variant="outline">Implicit Intents</Badge>
                      <Badge variant="outline">Intent Filters</Badge>
                    </div>
                  </div>

                  <div className="border rounded-lg p-4">
                    <h3 className="font-semibold text-green-600 mb-2 flex items-center gap-2">
                      <Database className="h-4 w-4" />
                      Content Providers
                    </h3>
                    <p className="text-sm text-gray-600 mb-3">
                      Manage access to structured data sets
                    </p>
                    <div className="space-y-2">
                      <Badge variant="outline">Data Sharing</Badge>
                      <Badge variant="outline">URI Permissions</Badge>
                      <Badge variant="outline">SQL Queries</Badge>
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <div className="border rounded-lg p-4">
                    <h3 className="font-semibold text-purple-600 mb-2 flex items-center gap-2">
                      <Radio className="h-4 w-4" />
                      Broadcast Receivers
                    </h3>
                    <p className="text-sm text-gray-600 mb-3">
                      Respond to system-wide broadcast announcements
                    </p>
                    <div className="space-y-2">
                      <Badge variant="outline">System Broadcasts</Badge>
                      <Badge variant="outline">Custom Broadcasts</Badge>
                      <Badge variant="outline">Ordered Broadcasts</Badge>
                    </div>
                  </div>

                  <div className="border rounded-lg p-4">
                    <h3 className="font-semibold text-orange-600 mb-2 flex items-center gap-2">
                      <Settings className="h-4 w-4" />
                      Services
                    </h3>
                    <p className="text-sm text-gray-600 mb-3">
                      Background operations without user interface
                    </p>
                    <div className="space-y-2">
                      <Badge variant="outline">Background Services</Badge>
                      <Badge variant="outline">Bound Services</Badge>
                      <Badge variant="outline">AIDL Interfaces</Badge>
                    </div>
                  </div>
                </div>
              </div>

              <Alert>
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  IPC components are the primary attack vectors for privilege escalation and data theft in Android applications. 
                  Proper security analysis of these components is crucial for identifying vulnerabilities that could lead to 
                  unauthorized access to sensitive data or system resources.
                </AlertDescription>
              </Alert>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="intent-analysis" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Share2 className="h-5 w-5" />
                Intent Security Analysis
              </CardTitle>
              <CardDescription>
                Comprehensive analysis of Intent-based vulnerabilities and exploitation techniques
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <h3 className="text-lg font-semibold">Intent Vulnerability Categories</h3>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="border rounded-lg p-4">
                    <h4 className="font-semibold text-red-600 mb-2">Intent Hijacking</h4>
                    <p className="text-sm text-gray-600 mb-3">
                      Malicious apps intercepting implicit intents
                    </p>
                    <div className="bg-gray-50 p-3 rounded-md">
                      <code className="text-xs">
                        {`<intent-filter android:priority="1000">
  <action android:name="android.intent.action.VIEW" />
  <category android:name="android.intent.category.DEFAULT" />
  <data android:scheme="http" />
</intent-filter>`}
                      </code>
                    </div>
                  </div>

                  <div className="border rounded-lg p-4">
                    <h4 className="font-semibold text-orange-600 mb-2">Data Leakage</h4>
                    <p className="text-sm text-gray-600 mb-3">
                      Sensitive data exposed through Intent extras
                    </p>
                    <div className="bg-gray-50 p-3 rounded-md">
                      <code className="text-xs">
                        {`Intent intent = new Intent();
intent.putExtra("password", userPassword);
intent.setAction("com.app.LOGIN");
sendBroadcast(intent); // Vulnerable!`}
                      </code>
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <h4 className="font-semibold">Intent Analysis Tools & Techniques</h4>
                  
                  <div className="bg-black text-green-400 p-4 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-semibold">Intent Fuzzing Script</span>
                      <Button 
                        size="sm" 
                        variant="outline" 
                        onClick={() => copyToClipboard(`#!/bin/bash
# Intent fuzzing script for Android security testing

PACKAGE_NAME="com.example.target"
ACTIVITY_NAME="com.example.target.MainActivity"

echo "Starting Intent fuzzing for $PACKAGE_NAME"

# Test 1: Basic Intent with malicious extras
adb shell am start -n "$PACKAGE_NAME/$ACTIVITY_NAME" \\
  --es "username" "../../../etc/passwd" \\
  --es "password" "' OR 1=1--" \\
  --es "url" "javascript:alert('XSS')"

# Test 2: Intent with malicious URI
adb shell am start -a android.intent.action.VIEW \\
  -d "content://com.example.provider/../../sensitive_data"

# Test 3: Intent with oversized data
LARGE_STRING=$(python3 -c "print('A' * 10000)")
adb shell am start -n "$PACKAGE_NAME/$ACTIVITY_NAME" \\
  --es "data" "$LARGE_STRING"

# Test 4: Intent with special characters
adb shell am start -n "$PACKAGE_NAME/$ACTIVITY_NAME" \\
  --es "input" "\\x00\\x01\\x02\\xFF"

echo "Intent fuzzing completed"`)}
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                    <pre className="text-xs overflow-x-auto">
{`#!/bin/bash
# Intent fuzzing script for Android security testing

PACKAGE_NAME="com.example.target"
ACTIVITY_NAME="com.example.target.MainActivity"

echo "Starting Intent fuzzing for $PACKAGE_NAME"

# Test 1: Basic Intent with malicious extras
adb shell am start -n "$PACKAGE_NAME/$ACTIVITY_NAME" \\
  --es "username" "../../../etc/passwd" \\
  --es "password" "' OR 1=1--" \\
  --es "url" "javascript:alert('XSS')"

# Test 2: Intent with malicious URI
adb shell am start -a android.intent.action.VIEW \\
  -d "content://com.example.provider/../../sensitive_data"

# Test 3: Intent with oversized data
LARGE_STRING=$(python3 -c "print('A' * 10000)")
adb shell am start -n "$PACKAGE_NAME/$ACTIVITY_NAME" \\
  --es "data" "$LARGE_STRING"

# Test 4: Intent with special characters
adb shell am start -n "$PACKAGE_NAME/$ACTIVITY_NAME" \\
  --es "input" "\\x00\\x01\\x02\\xFF"

echo "Intent fuzzing completed"`}
                    </pre>
                  </div>

                  <div className="bg-blue-950 text-blue-100 p-4 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-semibold">Intent Monitoring with Frida</span>
                      <Button 
                        size="sm" 
                        variant="outline" 
                        onClick={() => copyToClipboard(`// Intent monitoring Frida script
Java.perform(function() {
    var Intent = Java.use("android.content.Intent");
    var Bundle = Java.use("android.os.Bundle");
    
    Intent.putExtra.overload('java.lang.String', 'java.lang.String').implementation = function(key, value) {
        console.log("[Intent] putExtra: " + key + " = " + value);
        return this.putExtra(key, value);
    };
    
    Intent.setAction.implementation = function(action) {
        console.log("[Intent] setAction: " + action);
        return this.setAction(action);
    };
    
    Intent.setData.implementation = function(data) {
        console.log("[Intent] setData: " + data);
        return this.setData(data);
    };
});`)}
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                    <pre className="text-xs overflow-x-auto">
{`// Intent monitoring Frida script
Java.perform(function() {
    var Intent = Java.use("android.content.Intent");
    var Bundle = Java.use("android.os.Bundle");
    
    Intent.putExtra.overload('java.lang.String', 'java.lang.String').implementation = function(key, value) {
        console.log("[Intent] putExtra: " + key + " = " + value);
        return this.putExtra(key, value);
    };
    
    Intent.setAction.implementation = function(action) {
        console.log("[Intent] setAction: " + action);
        return this.setAction(action);
    };
    
    Intent.setData.implementation = function(data) {
        console.log("[Intent] setData: " + data);
        return this.setData(data);
    };
});`}
                    </pre>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="content-providers" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Database className="h-5 w-5" />
                Content Provider Security Analysis
              </CardTitle>
              <CardDescription>
                Testing Content Providers for SQL injection, path traversal, and access control issues
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <h3 className="text-lg font-semibold">Content Provider Attack Vectors</h3>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="border rounded-lg p-4">
                    <h4 className="font-semibold text-red-600 mb-2">SQL Injection</h4>
                    <p className="text-sm text-gray-600 mb-3">
                      Exploiting unsafe SQL query construction
                    </p>
                    <div className="bg-gray-50 p-3 rounded-md">
                      <code className="text-xs">
                        {`// Vulnerable query construction
String query = "SELECT * FROM users WHERE id = " + id;
// Should use parameterized queries instead`}
                      </code>
                    </div>
                  </div>

                  <div className="border rounded-lg p-4">
                    <h4 className="font-semibold text-orange-600 mb-2">Path Traversal</h4>
                    <p className="text-sm text-gray-600 mb-3">
                      Directory traversal through content URIs
                    </p>
                    <div className="bg-gray-50 p-3 rounded-md">
                      <code className="text-xs">
                        {`content://com.app.provider/files/../../../data/sensitive.db`}
                      </code>
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <h4 className="font-semibold">Content Provider Testing Scripts</h4>
                  
                  <div className="bg-black text-green-400 p-4 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-semibold">Content Provider Enumeration</span>
                      <Button 
                        size="sm" 
                        variant="outline" 
                        onClick={() => copyToClipboard(`#!/bin/bash
# Content Provider enumeration and testing

PACKAGE_NAME="com.example.target"

echo "Enumerating Content Providers for $PACKAGE_NAME"

# Extract and analyze AndroidManifest.xml
aapt dump xmltree app.apk AndroidManifest.xml | grep -A 10 -B 2 "provider"

# Test common Content Provider URIs
COMMON_URIS=(
    "content://$PACKAGE_NAME.provider/"
    "content://$PACKAGE_NAME.provider/users"
    "content://$PACKAGE_NAME.provider/files"
    "content://$PACKAGE_NAME.provider/settings"
)

for uri in "\${COMMON_URIS[@]}"; do
    echo "Testing URI: $uri"
    adb shell content query --uri "$uri" 2>/dev/null || echo "URI not accessible"
done

# SQL Injection tests
echo "Testing SQL injection vulnerabilities..."
adb shell content query --uri "content://$PACKAGE_NAME.provider/users" \\
    --where "id=1' OR '1'='1"

# Path traversal tests
echo "Testing path traversal vulnerabilities..."
adb shell content query --uri "content://$PACKAGE_NAME.provider/files/../../../data"`)}
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                    <pre className="text-xs overflow-x-auto">
{`#!/bin/bash
# Content Provider enumeration and testing

PACKAGE_NAME="com.example.target"

echo "Enumerating Content Providers for $PACKAGE_NAME"

# Extract and analyze AndroidManifest.xml
aapt dump xmltree app.apk AndroidManifest.xml | grep -A 10 -B 2 "provider"

# Test common Content Provider URIs
COMMON_URIS=(
    "content://$PACKAGE_NAME.provider/"
    "content://$PACKAGE_NAME.provider/users"
    "content://$PACKAGE_NAME.provider/files"
    "content://$PACKAGE_NAME.provider/settings"
)

for uri in "\${COMMON_URIS[@]}"; do
    echo "Testing URI: $uri"
    adb shell content query --uri "$uri" 2>/dev/null || echo "URI not accessible"
done

# SQL Injection tests
echo "Testing SQL injection vulnerabilities..."
adb shell content query --uri "content://$PACKAGE_NAME.provider/users" \\
    --where "id=1' OR '1'='1"

# Path traversal tests
echo "Testing path traversal vulnerabilities..."
adb shell content query --uri "content://$PACKAGE_NAME.provider/files/../../../data"`}
                    </pre>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="broadcast-services" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Radio className="h-5 w-5" />
                Broadcast Receivers & Services Analysis
              </CardTitle>
              <CardDescription>
                Testing broadcast security, service exploitation, and AIDL interface vulnerabilities
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <h3 className="text-lg font-semibold">Broadcast Security Issues</h3>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="border rounded-lg p-4">
                    <h4 className="font-semibold text-red-600 mb-2">Broadcast Injection</h4>
                    <p className="text-sm text-gray-600 mb-3">
                      Sending malicious broadcasts to trigger unintended behavior
                    </p>
                    <div className="bg-gray-50 p-3 rounded-md">
                      <code className="text-xs">
                        {`adb shell am broadcast -a com.app.ACTION_LOGIN \\
  --es "username" "admin" --es "bypass" "true"`}
                      </code>
                    </div>
                  </div>

                  <div className="border rounded-lg p-4">
                    <h4 className="font-semibold text-orange-600 mb-2">Broadcast Eavesdropping</h4>
                    <p className="text-sm text-gray-600 mb-3">
                      Intercepting sensitive data from unprotected broadcasts
                    </p>
                    <div className="bg-gray-50 p-3 rounded-md">
                      <code className="text-xs">
                        {`// Malicious receiver
<receiver android:name=".EavesdropReceiver">
  <intent-filter>
    <action android:name="com.app.SENSITIVE_ACTION" />
  </intent-filter>
</receiver>`}
                      </code>
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <h4 className="font-semibold">Advanced Testing Techniques</h4>
                  
                  <div className="bg-black text-green-400 p-4 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-semibold">Broadcast Fuzzing Framework</span>
                      <Button 
                        size="sm" 
                        variant="outline" 
                        onClick={() => copyToClipboard(`#!/bin/bash
# Advanced broadcast fuzzing framework

PACKAGE_NAME="com.example.target"

# Extract all broadcast receivers
echo "Extracting broadcast receivers from $PACKAGE_NAME"
aapt dump xmltree app.apk AndroidManifest.xml | grep -A 20 "receiver" > receivers.txt

# Fuzz broadcast receivers with various payloads
PAYLOADS=(
    "javascript:alert('XSS')"
    "../../../etc/passwd"
    "' OR 1=1--"
    "\\x00\\x01\\x02"
    $(python3 -c "print('A' * 1000)")
)

ACTIONS=(
    "android.intent.action.BOOT_COMPLETED"
    "android.intent.action.USER_PRESENT"
    "com.app.CUSTOM_ACTION"
)

for action in "\${ACTIONS[@]}"; do
    for payload in "\${PAYLOADS[@]}"; do
        echo "Testing action: $action with payload: $payload"
        adb shell am broadcast -a "$action" --es "data" "$payload"
        sleep 1
    done
done`)}
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                    <pre className="text-xs overflow-x-auto">
{`#!/bin/bash
# Advanced broadcast fuzzing framework

PACKAGE_NAME="com.example.target"

# Extract all broadcast receivers
echo "Extracting broadcast receivers from $PACKAGE_NAME"
aapt dump xmltree app.apk AndroidManifest.xml | grep -A 20 "receiver" > receivers.txt

# Fuzz broadcast receivers with various payloads
PAYLOADS=(
    "javascript:alert('XSS')"
    "../../../etc/passwd"
    "' OR 1=1--"
    "\\x00\\x01\\x02"
    $(python3 -c "print('A' * 1000)")
)

ACTIONS=(
    "android.intent.action.BOOT_COMPLETED"
    "android.intent.action.USER_PRESENT"
    "com.app.CUSTOM_ACTION"
)

for action in "\${ACTIONS[@]}"; do
    for payload in "\${PAYLOADS[@]}"; do
        echo "Testing action: $action with payload: $payload"
        adb shell am broadcast -a "$action" --es "data" "$payload"
        sleep 1
    done
done`}
                    </pre>
                  </div>

                  <div className="bg-purple-950 text-purple-100 p-4 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-semibold">Service Exploitation Script</span>
                      <Button 
                        size="sm" 
                        variant="outline" 
                        onClick={() => copyToClipboard(`#!/bin/bash
# Service exploitation and analysis

PACKAGE_NAME="com.example.target"

echo "Analyzing services for $PACKAGE_NAME"

# List all services
adb shell dumpsys activity services | grep "$PACKAGE_NAME"

# Test service binding
adb shell am startservice -n "$PACKAGE_NAME/.VulnerableService" \\
    --es "command" "cat /data/data/$PACKAGE_NAME/sensitive.txt"

# AIDL interface testing
adb shell service call "$PACKAGE_NAME" 1 s16 "malicious_input"

# Service DoS testing
for i in {1..100}; do
    adb shell am startservice -n "$PACKAGE_NAME/.TestService" &
done

echo "Service exploitation tests completed"`)}
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                    <pre className="text-xs overflow-x-auto">
{`#!/bin/bash
# Service exploitation and analysis

PACKAGE_NAME="com.example.target"

echo "Analyzing services for $PACKAGE_NAME"

# List all services
adb shell dumpsys activity services | grep "$PACKAGE_NAME"

# Test service binding
adb shell am startservice -n "$PACKAGE_NAME/.VulnerableService" \\
    --es "command" "cat /data/data/$PACKAGE_NAME/sensitive.txt"

# AIDL interface testing
adb shell service call "$PACKAGE_NAME" 1 s16 "malicious_input"

# Service DoS testing
for i in {1..100}; do
    adb shell am startservice -n "$PACKAGE_NAME/.TestService" &
done

echo "Service exploitation tests completed"`}
                    </pre>
                  </div>
                </div>

                <Alert>
                  <CheckCircle className="h-4 w-4" />
                  <AlertDescription>
                    <strong>Best Practices for IPC Testing:</strong>
                    <br />• Always test with both valid and invalid inputs
                    <br />• Check for proper permission enforcement
                    <br />• Verify that sensitive data is not exposed through IPC
                    <br />• Test component interaction under various system states
                  </AlertDescription>
                </Alert>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default AndroidIPCAnalysis;
