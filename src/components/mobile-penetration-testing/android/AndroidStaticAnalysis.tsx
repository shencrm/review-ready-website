
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Code, FileText, Search, Bug, Shield } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const AndroidStaticAnalysis: React.FC = () => {
  return (
    <div className="space-y-6">
      <Card className="bg-cybr-card border-cybr-muted">
        <CardHeader>
          <CardTitle className="text-cybr-primary flex items-center gap-2">
            <Code className="h-6 w-6" />
            Static Analysis - Deep APK Inspection
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="apk-extraction" className="w-full">
            <TabsList className="grid grid-cols-5 w-full mb-6">
              <TabsTrigger value="apk-extraction">APK Extraction</TabsTrigger>
              <TabsTrigger value="manifest-analysis">Manifest Analysis</TabsTrigger>
              <TabsTrigger value="code-review">Code Review</TabsTrigger>
              <TabsTrigger value="binary-analysis">Binary Analysis</TabsTrigger>
              <TabsTrigger value="automated-tools">Automated Tools</TabsTrigger>
            </TabsList>

            <TabsContent value="apk-extraction" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">APK Extraction and Decompilation</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">JADX Decompilation</h4>
                <CodeExample
                  language="bash"
                  title="Advanced JADX Usage"
                  code={`# Basic decompilation
jadx -d output_dir app.apk

# Advanced options
jadx --show-bad-code --escape-unicode -d output_dir app.apk

# Export as Gradle project
jadx --export-gradle -d gradle_project app.apk

# Decompile with debug info
jadx -d output_dir --show-bad-code --comments-level error app.apk

# Process specific classes
jadx -d output_dir --include-pkg com.example.sensitive app.apk

# Generate resources
jadx -r -d output_dir app.apk`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">APKTool Analysis</h4>
                <CodeExample
                  language="bash"
                  title="APKTool Deep Analysis"
                  code={`# Decode APK with resources
apktool d app.apk -o decoded_app

# Decode with no resources (faster)
apktool d --no-res app.apk -o decoded_app_no_res

# Force decode (ignore errors)
apktool d --force app.apk -o decoded_app_force

# Decode with custom framework
apktool d -f app.apk -o decoded_app_custom

# Analyze smali code
find decoded_app/smali* -name "*.smali" | xargs grep -l "password\\|secret\\|key"

# Check for obfuscation
find decoded_app/smali* -name "*.smali" | head -10 | xargs grep -H "class"`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">dex2jar and JD-GUI</h4>
                <CodeExample
                  language="bash"
                  title="Alternative Decompilation Methods"
                  code={`# Convert DEX to JAR
d2j-dex2jar app.apk -o app.jar

# View with JD-GUI
jd-gui app.jar

# Analyze with JAD
jad -r -d output_dir app.jar

# Batch decompilation
for file in *.apk; do
    echo "Processing $file"
    d2j-dex2jar "$file" -o "${file%.apk}.jar"
done`}
                />
              </div>
            </TabsContent>

            <TabsContent value="manifest-analysis" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">AndroidManifest.xml Deep Analysis</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Permissions Analysis</h4>
                <CodeExample
                  language="bash"
                  title="Comprehensive Permissions Check"
                  code={`# Extract all permissions
grep -n "uses-permission" AndroidManifest.xml | sort

# Check dangerous permissions
grep -E "CAMERA|LOCATION|MICROPHONE|SMS|CONTACTS|STORAGE" AndroidManifest.xml

# Custom permissions
grep -n "permission android:name" AndroidManifest.xml

# Permission groups
grep -n "permission-group" AndroidManifest.xml

# Uses-feature analysis
grep -n "uses-feature" AndroidManifest.xml

# Check for permission bypass attempts
grep -n "maxSdkVersion" AndroidManifest.xml`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Component Security Analysis</h4>
                <CodeExample
                  language="bash"
                  title="Component Exposure Analysis"
                  code={`# Find exported components
echo "=== EXPORTED ACTIVITIES ==="
grep -A 10 -B 2 'activity.*exported="true"' AndroidManifest.xml

echo "=== EXPORTED SERVICES ==="
grep -A 10 -B 2 'service.*exported="true"' AndroidManifest.xml

echo "=== EXPORTED RECEIVERS ==="
grep -A 10 -B 2 'receiver.*exported="true"' AndroidManifest.xml

echo "=== EXPORTED PROVIDERS ==="
grep -A 10 -B 2 'provider.*exported="true"' AndroidManifest.xml

# Check for intent filters on exported components
grep -A 20 -B 5 'intent-filter' AndroidManifest.xml | grep -B 25 -A 5 'exported="true"'

# Look for deep links
grep -A 5 -B 5 'android:scheme' AndroidManifest.xml`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Security Configuration Analysis</h4>
                <CodeExample
                  language="bash"
                  title="Security Settings Analysis"
                  code={`# Check backup settings
grep -n "allowBackup" AndroidManifest.xml

# Debug flag
grep -n "debuggable" AndroidManifest.xml

# Network security config
grep -n "networkSecurityConfig" AndroidManifest.xml

# Clear text traffic
grep -n "cleartextTrafficPermitted" AndroidManifest.xml

# File provider configurations
grep -A 10 -B 5 "FileProvider" AndroidManifest.xml

# Check for hardcoded values
grep -n "http://" AndroidManifest.xml
grep -n "192.168\\|10.\\|172." AndroidManifest.xml`}
                />
              </div>
            </TabsContent>

            <TabsContent value="code-review" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Source Code Security Review</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Sensitive Data Detection</h4>
                <CodeExample
                  language="bash"
                  title="Hunting for Sensitive Information"
                  code={`# Search for hardcoded secrets
grep -r -i "password\\|passwd\\|pwd" . --include="*.java" --include="*.kt"
grep -r -i "secret\\|key\\|token" . --include="*.java" --include="*.kt"
grep -r -i "api_key\\|apikey\\|api-key" . --include="*.java" --include="*.kt"

# Database credentials
grep -r -i "jdbc:\\|mysql:\\|postgresql:" . --include="*.java" --include="*.kt"

# Crypto keys and certificates
grep -r -i "BEGIN.*PRIVATE\\|BEGIN.*CERTIFICATE" . --include="*.java" --include="*.kt"

# IP addresses and URLs
grep -r -E "([0-9]{1,3}\\.){3}[0-9]{1,3}" . --include="*.java" --include="*.kt"
grep -r -i "http://\\|https://" . --include="*.java" --include="*.kt"

# AWS/Cloud credentials
grep -r -i "AKIA[0-9A-Z]{16}" . --include="*.java" --include="*.kt"
grep -r -i "aws_access_key\\|aws_secret" . --include="*.java" --include="*.kt"`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Crypto Implementation Review</h4>
                <CodeExample
                  language="bash"
                  title="Cryptography Implementation Analysis"
                  code={`# Weak encryption algorithms
grep -r -i "DES\\|MD5\\|SHA1" . --include="*.java" --include="*.kt"

# Crypto usage patterns
grep -r "Cipher\\|MessageDigest\\|KeyGenerator" . --include="*.java" --include="*.kt"

# Hardcoded IVs and salts
grep -r -i "\\\\x[0-9a-f][0-9a-f]" . --include="*.java" --include="*.kt"

# SSL/TLS implementation
grep -r "TrustManager\\|HostnameVerifier" . --include="*.java" --include="*.kt"
grep -r "checkServerTrusted\\|verify" . --include="*.java" --include="*.kt"

# Key storage
grep -r "KeyStore\\|SharedPreferences.*KEY" . --include="*.java" --include="*.kt"`}
                />

                <h4 className="text-lg font-medium text-cybr-security">Insecure Practices Detection</h4>
                <CodeExample
                  language="bash"
                  title="Common Security Anti-patterns"
                  code={`# Logging sensitive data
grep -r "Log\\.[dviwe]" . --include="*.java" --include="*.kt" | grep -i "password\\|token\\|key"

# SQL injection vulnerabilities
grep -r "rawQuery\\|execSQL" . --include="*.java" --include="*.kt"

# File operations
grep -r "openFileOutput.*MODE_WORLD" . --include="*.java" --include="*.kt"
grep -r "getExternalStorage" . --include="*.java" --include="*.kt"

# Intent vulnerabilities
grep -r "getIntent\\|putExtra" . --include="*.java" --include="*.kt"

# WebView security
grep -r "setJavaScriptEnabled.*true" . --include="*.java" --include="*.kt"
grep -r "addJavascriptInterface" . --include="*.java" --include="*.kt"

# Root detection bypasses
grep -r "su\\|Superuser\\|root" . --include="*.java" --include="*.kt"`}
                />
              </div>
            </TabsContent>

            <TabsContent value="binary-analysis" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Binary and Native Code Analysis</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Native Library Analysis</h4>
                <CodeExample
                  language="bash"
                  title="Analyzing Native Libraries"
                  code={`# Find native libraries
find . -name "*.so" -type f

# Analyze library architecture
for lib in $(find . -name "*.so"); do
    echo "=== $lib ==="
    file "$lib"
    readelf -h "$lib" 2>/dev/null | grep -E "Class|Machine"
done

# Check for symbols
nm -D lib/arm64-v8a/libnative.so 2>/dev/null | grep -i "password\\|secret\\|key"

# Strings analysis
strings lib/arm64-v8a/libnative.so | grep -E "http|password|key|secret"

# Function analysis
objdump -T lib/arm64-v8a/libnative.so | grep -i "encrypt\\|decrypt\\|auth"

# Security features check
readelf -l lib/arm64-v8a/libnative.so | grep -E "GNU_STACK|RELRO"`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">DEX Bytecode Analysis</h4>
                <CodeExample
                  language="bash"
                  title="DEX File Analysis"
                  code={`# Extract DEX files
unzip -j app.apk "*.dex"

# Analyze DEX structure
dexdump -d classes.dex | head -50

# Look for obfuscation patterns
dexdump -l json classes.dex | jq '.classes[].className' | head -20

# Check for packed/encrypted DEX
file classes*.dex

# Analyze method signatures
dexdump classes.dex | grep -E "method_name|descriptor" | head -20

# Look for reflection usage
dexdump classes.dex | grep -i "reflect\\|invoke\\|getmethod"`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Resource Analysis</h4>
                <CodeExample
                  language="bash"
                  title="Resources and Assets Analysis"
                  code={`# Analyze resources.arsc
aapt dump resources app.apk | grep -i "string\\|password\\|key\\|url"

# Extract assets
unzip -d assets app.apk assets/*
find assets/ -type f -exec file {} \\;

# Look for configuration files
find . -name "*.xml" -o -name "*.json" -o -name "*.properties" -o -name "*.config"

# Database files
find . -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3"

# Certificate and key files
find . -name "*.pem" -o -name "*.crt" -o -name "*.key" -o -name "*.p12" -o -name "*.jks"

# Hidden files
find . -name ".*" -type f`}
                />
              </div>
            </TabsContent>

            <TabsContent value="automated-tools" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Automated Analysis Tools</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">MobSF Analysis</h4>
                <CodeExample
                  language="bash"
                  title="Mobile Security Framework"
                  code={`# Start MobSF
cd Mobile-Security-Framework-MobSF
python manage.py runserver 127.0.0.1:8000

# API usage for automation
curl -X POST -H "Content-Type: multipart/form-data" \\
     -F "file=@app.apk" \\
     http://127.0.0.1:8000/api/v1/upload

# Get scan results
curl -X POST -H "Content-Type: application/json" \\
     -d '{"hash": "APP_HASH"}' \\
     http://127.0.0.1:8000/api/v1/scan

# Generate report
curl -X POST -H "Content-Type: application/json" \\
     -d '{"hash": "APP_HASH", "scan_type": "apk"}' \\
     http://127.0.0.1:8000/api/v1/report_json`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">QARK Analysis</h4>
                <CodeExample
                  language="bash"
                  title="Quick Android Review Kit"
                  code={`# Basic QARK scan
qark --apk app.apk

# Generate detailed report
qark --apk app.apk --report-type json --report-name detailed_report

# Source code analysis
qark --source /path/to/source --report-type html

# Custom rules scan
qark --apk app.apk --exploit-apk --report-type all

# CI/CD integration
qark --apk app.apk --report-type json | jq '.results[] | select(.severity == "HIGH")'`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Custom Analysis Scripts</h4>
                <CodeExample
                  language="python"
                  title="Custom Python Analysis Script"
                  code={`#!/usr/bin/env python3
import zipfile
import xml.etree.ElementTree as ET
import re
import os

def analyze_apk(apk_path):
    """Comprehensive APK analysis"""
    results = {}
    
    with zipfile.ZipFile(apk_path, 'r') as apk:
        # Extract AndroidManifest.xml
        try:
            manifest = apk.read('AndroidManifest.xml')
            results['manifest_issues'] = analyze_manifest(manifest)
        except KeyError:
            results['error'] = 'AndroidManifest.xml not found'
        
        # Analyze DEX files
        dex_files = [f for f in apk.namelist() if f.endswith('.dex')]
        results['dex_analysis'] = analyze_dex_files(apk, dex_files)
        
        # Check for sensitive files
        results['sensitive_files'] = find_sensitive_files(apk.namelist())
    
    return results

def analyze_manifest(manifest_content):
    """Analyze AndroidManifest.xml for security issues"""
    issues = []
    
    # Parse manifest (requires aapt dump first for binary XML)
    # This is a simplified example
    
    return issues

def find_sensitive_files(file_list):
    """Find potentially sensitive files"""
    sensitive_patterns = [
        r'.*\.key$', r'.*\.pem$', r'.*\.p12$',
        r'.*\.jks$', r'.*\.db$', r'.*config.*',
        r'.*secret.*', r'.*password.*'
    ]
    
    sensitive_files = []
    for pattern in sensitive_patterns:
        for filename in file_list:
            if re.match(pattern, filename, re.IGNORECASE):
                sensitive_files.append(filename)
    
    return sensitive_files

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python analyze_apk.py <apk_file>")
        sys.exit(1)
    
    results = analyze_apk(sys.argv[1])
    print("Analysis Results:")
    print(results)`}
                />
              </div>
            </TabsContent>
          </Tabs>

          <div className="mt-6 p-4 bg-cybr-muted/20 rounded-lg">
            <h4 className="font-medium text-cybr-accent mb-2">Static Analysis Best Practices</h4>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li>Always use multiple decompilation tools for comprehensive analysis</li>
              <li>Focus on exported components and their intent filters</li>
              <li>Check for hardcoded secrets, URLs, and credentials</li>
              <li>Analyze native libraries for additional attack vectors</li>
              <li>Use automated tools but verify findings manually</li>
              <li>Document all findings with evidence and impact assessment</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default AndroidStaticAnalysis;
