
import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Copy, Share2 } from 'lucide-react';

const IntentAnalysisSection: React.FC = () => {
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
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
  );
};

export default IntentAnalysisSection;
