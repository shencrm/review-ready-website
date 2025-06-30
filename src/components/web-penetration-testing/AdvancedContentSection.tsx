import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { AlertTriangle, Info, Zap, Search, Globe, Code, Database, Shield, Eye, Target } from 'lucide-react';

const AdvancedContentSection: React.FC = () => {
  return (
    <div className="space-y-8">
      <div className="text-center mb-8">
        <h2 className="text-3xl font-bold text-cybr-primary mb-4">
          Advanced Web Penetration Testing Techniques
        </h2>
        <p className="text-lg opacity-80 max-w-4xl mx-auto">
          Master-level techniques and methodologies for comprehensive web application security assessment. 
          This section covers advanced reconnaissance, exploitation, and analysis techniques used by professional penetration testers.
        </p>
      </div>

      <Tabs defaultValue="advanced-reconnaissance" className="w-full">
        <TabsList className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 w-full bg-cybr-muted/30 p-1 mb-8">
          <TabsTrigger value="advanced-reconnaissance" className="text-xs">
            <Search className="h-4 w-4 mr-1" />
            Advanced Reconnaissance
          </TabsTrigger>
          <TabsTrigger value="exploitation-techniques" className="text-xs">
            <Zap className="h-4 w-4 mr-1" />
            Exploitation
          </TabsTrigger>
          <TabsTrigger value="post-exploitation" className="text-xs">
            <Target className="h-4 w-4 mr-1" />
            Post-Exploitation
          </TabsTrigger>
          <TabsTrigger value="evasion-techniques" className="text-xs">
            <Eye className="h-4 w-4 mr-1" />
            Evasion
          </TabsTrigger>
          <TabsTrigger value="automation-scripting" className="text-xs">
            <Code className="h-4 w-4 mr-1" />
            Automation
          </TabsTrigger>
          <TabsTrigger value="reporting-analysis" className="text-xs">
            <Database className="h-4 w-4 mr-1" />
            Analysis
          </TabsTrigger>
        </TabsList>

        {/* Advanced Reconnaissance Tab */}
        <TabsContent value="advanced-reconnaissance" className="space-y-6">
          <div className="grid gap-6">
            <Card className="bg-cybr-card border-cybr-muted">
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Globe className="h-6 w-6 text-cybr-primary" />
                  <CardTitle className="text-cybr-primary">Advanced OSINT & Information Gathering</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* OSINT Advanced Techniques */}
                <div className="space-y-4">
                  <h4 className="text-lg font-semibold text-cybr-accent">Search Engine Exploitation</h4>
                  
                  <div className="bg-cybr-muted/20 p-4 rounded-lg">
                    <h5 className="font-semibold mb-2 text-cybr-primary">Google Dorking - Advanced Queries</h5>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <p className="text-sm mb-2 font-medium">Administrative Interfaces:</p>
                        <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`site:example.com inurl:admin
site:example.com inurl:administrator  
site:example.com inurl:login
site:example.com inurl:wp-admin
site:example.com inurl:phpmyadmin
site:example.com intitle:"admin panel"
site:example.com inurl:management`}
                        </pre>
                      </div>
                      <div>
                        <p className="text-sm mb-2 font-medium">Configuration Files:</p>
                        <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`site:example.com filetype:xml
site:example.com ext:cfg | ext:env | ext:ini
site:example.com inurl:web.config
site:example.com inurl:.htaccess
site:example.com filetype:properties`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  <div className="bg-cybr-muted/20 p-4 rounded-lg">
                    <h5 className="font-semibold mb-2 text-cybr-primary">Database & Backup Files</h5>
                    <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Database Files Discovery
site:example.com filetype:sql | filetype:dbf | filetype:mdb
site:example.com ext:db | ext:sqlite | ext:sqlite3
site:example.com inurl:backup
site:example.com inurl:dump
site:example.com "phpMyAdmin" "running on"

# Backup Files
site:example.com ext:bak | ext:backup | ext:old | ext:orig
site:example.com inurl:backup
site:example.com filetype:tar | filetype:zip | filetype:rar`}
                    </pre>
                  </div>

                  <div className="bg-cybr-muted/20 p-4 rounded-lg">
                    <h5 className="font-semibold mb-2 text-cybr-primary">Sensitive Information Discovery</h5>
                    <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Credentials & API Keys
site:example.com "password" | "passwd" | "pwd"
site:example.com "api_key" | "apikey" | "api-key"
site:example.com "secret_key" | "secretkey"
site:example.com "access_token" | "accesstoken"
site:example.com "aws_access_key_id"

# Error Messages & Debug Info
site:example.com "error" | "exception" | "warning"
site:example.com "stack trace" | "debug"
site:example.com "database error" | "mysql error"`}
                    </pre>
                  </div>
                </div>

                {/* Advanced Web Application Mapping */}
                <div className="space-y-4">
                  <h4 className="text-lg font-semibold text-cybr-accent">Advanced Web Application Mapping</h4>
                  
                  <div className="bg-cybr-muted/20 p-4 rounded-lg">
                    <h5 className="font-semibold mb-2 text-cybr-primary">Single Page Application (SPA) Reconnaissance</h5>
                    <p className="text-sm mb-3 opacity-80">
                      Modern SPAs require specialized reconnaissance techniques due to their client-side routing and dynamic content loading.
                    </p>
                    
                    <div className="space-y-3">
                      <div>
                        <p className="text-sm font-medium mb-2">Client-Side Route Discovery:</p>
                        <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# JavaScript Route Analysis
grep -r "route\\|path\\|component" ./js/
grep -rE "(Route|Switch|Router)" ./js/
grep -rE "history\\.(push|replace)" ./js/

# React Router Discovery
curl -s https://target.com | grep -oE 'window\\.__INITIAL_STATE__[^;]*'
curl -s https://target.com | grep -oE 'window\\.__PRELOADED_STATE__[^;]*'`}
                        </pre>
                      </div>
                      
                      <div>
                        <p className="text-sm font-medium mb-2">Dynamic Content Discovery:</p>
                        <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# Headless Browser Reconnaissance
# Using Puppeteer/Playwright for SPA crawling
const browser = await puppeteer.launch();
const page = await browser.newPage();
await page.goto('https://target.com');

// Intercept network requests
page.on('request', request => {
  console.log('Request:', request.url());
});

// Execute JavaScript to trigger route changes
await page.evaluate(() => {
  // Trigger all possible routes
  if (window.history) {
    window.history.pushState({}, '', '/admin');
    window.history.pushState({}, '', '/api/users');
  }
});`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  <div className="bg-cybr-muted/20 p-4 rounded-lg">
                    <h5 className="font-semibold mb-2 text-cybr-primary">Progressive Web App (PWA) Analysis</h5>
                    <div className="space-y-3">
                      <div>
                        <p className="text-sm font-medium mb-2">Service Worker Analysis:</p>
                        <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# Service Worker Discovery
curl -s https://target.com/sw.js
curl -s https://target.com/service-worker.js
curl -s https://target.com/serviceworker.js

# Web App Manifest Analysis
curl -s https://target.com/manifest.json
curl -s https://target.com/manifest.webmanifest

# PWA Cache Analysis
# Service worker cache endpoints
curl -s https://target.com/sw.js | grep -oE 'cache\\.addAll\\([^)]*\\)'`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  <div className="bg-cybr-muted/20 p-4 rounded-lg">
                    <h5 className="font-semibold mb-2 text-cybr-primary">API Endpoint Discovery</h5>
                    <div className="space-y-3">
                      <div>
                        <p className="text-sm font-medium mb-2">Multiple Discovery Methods:</p>
                        <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# JavaScript API Endpoint Extraction
curl -s https://target.com | grep -oE 'api/[a-zA-Z0-9/_-]*'
curl -s https://target.com/app.js | grep -oE '"/api/[^"]*"'

# Network Tab Monitoring (Manual)
# 1. Open Developer Tools → Network Tab
# 2. Use application normally
# 3. Filter by XHR/Fetch requests
# 4. Document all API endpoints

# Webpack Bundle Analysis
curl -s https://target.com/static/js/main.*.js | grep -oE 'endpoint[^,]*'`}
                        </pre>
                      </div>
                    </div>
                  </div>
                </div>

                {/* HTTP/HTTPS Deep Analysis */}
                <div className="space-y-4">
                  <h4 className="text-lg font-semibold text-cybr-accent">HTTP/HTTPS Deep Analysis</h4>
                  
                  <div className="bg-cybr-muted/20 p-4 rounded-lg">
                    <h5 className="font-semibold mb-2 text-cybr-primary">HTTP Method Comprehensive Testing</h5>
                    <div className="space-y-3">
                      <div>
                        <p className="text-sm font-medium mb-2">Method Enumeration & Testing:</p>
                        <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# OPTIONS Method Discovery
curl -X OPTIONS https://target.com -v

# Comprehensive Method Testing
for method in GET POST PUT DELETE PATCH HEAD OPTIONS TRACE CONNECT; do
  echo "Testing $method:"
  curl -X $method https://target.com/api/users -v
done

# WebDAV Methods
curl -X PROPFIND https://target.com -v
curl -X MKCOL https://target.com/test -v
curl -X COPY https://target.com/file.txt -H "Destination: /copy.txt" -v`}
                        </pre>
                      </div>
                      
                      <div>
                        <p className="text-sm font-medium mb-2">Custom Header Injection:</p>
                        <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# X-HTTP-Method-Override Testing
curl -X POST https://target.com/api/users/1 -H "X-HTTP-Method-Override: DELETE"
curl -X POST https://target.com/api/users/1 -H "X-HTTP-Method-Override: PUT"

# Custom Headers for Bypass
curl https://target.com -H "X-Forwarded-For: 127.0.0.1"
curl https://target.com -H "X-Real-IP: 192.168.1.1"
curl https://target.com -H "X-Originating-IP: 10.0.0.1"
curl https://target.com -H "Client-IP: 172.16.0.1"`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  <div className="bg-cybr-muted/20 p-4 rounded-lg">
                    <h5 className="font-semibold mb-2 text-cybr-primary">SSL/TLS Certificate Deep Analysis</h5>
                    <div className="space-y-3">
                      <div>
                        <p className="text-sm font-medium mb-2">Certificate Transparency Analysis:</p>
                        <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# Certificate Transparency Logs
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# SSL Certificate Analysis
openssl s_client -connect target.com:443 -servername target.com < /dev/null 2>/dev/null | openssl x509 -text
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -subject -issuer -dates

# SNI (Server Name Indication) Testing
for subdomain in www api admin dev test; do
  echo "Testing SNI for $subdomain.target.com:"
  openssl s_client -connect target.com:443 -servername $subdomain.target.com -verify_return_error 2>/dev/null
done`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  <div className="bg-cybr-muted/20 p-4 rounded-lg">
                    <h5 className="font-semibold mb-2 text-cybr-primary">HTTP/2 & HTTP/3 Reconnaissance</h5>
                    <div className="space-y-3">
                      <div>
                        <p className="text-sm font-medium mb-2">Protocol-Specific Testing:</p>
                        <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# HTTP/2 Testing
curl --http2 https://target.com -v
curl --http2-prior-knowledge http://target.com -v

# HTTP/2 Server Push Detection
curl --http2 https://target.com -v 2>&1 | grep -i "push"

# HTTP/3 (QUIC) Testing
curl --http3 https://target.com -v
# Note: Requires curl with HTTP/3 support

# Protocol Downgrade Testing
curl --http1.1 https://target.com -v
curl --http2 https://target.com -H "Connection: Upgrade, HTTP2-Settings"  -v`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  <div className="bg-cybr-muted/20 p-4 rounded-lg">
                    <h5 className="font-semibold mb-2 text-cybr-primary">WebSocket Endpoint Discovery</h5>
                    <div className="space-y-3">
                      <div>
                        <p className="text-sm font-medium mb-2">WebSocket Reconnaissance:</p>
                        <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# WebSocket Endpoint Discovery
curl -s https://target.com | grep -oE 'ws://[^"]*|wss://[^"]*'
curl -s https://target.com/app.js | grep -oE 'WebSocket\\([^)]*\\)'

# WebSocket Connection Testing
wscat -c wss://target.com/socket
wscat -c ws://target.com:8080/websocket

# JavaScript WebSocket Discovery
# In browser console:
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() { console.log('Connected'); };
ws.onmessage = function(event) { console.log('Message:', event.data); };`}
                        </pre>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Advanced JavaScript Analysis */}
                <div className="space-y-4">
                  <h4 className="text-lg font-semibold text-cybr-accent">Advanced JavaScript Analysis</h4>
                  
                  <div className="bg-cybr-muted/20 p-4 rounded-lg">
                    <h5 className="font-semibold mb-2 text-cybr-primary">Source Map Discovery & Exploitation</h5>
                    <div className="space-y-3">
                      <div>
                        <p className="text-sm font-medium mb-2">Source Map Analysis:</p>
                        <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# Source Map Discovery
curl -s https://target.com/static/js/main.js | grep -oE 'sourceMappingURL=[^*]*'
curl -s https://target.com/static/js/main.js.map

# Automated Source Map Discovery
for js_file in $(curl -s https://target.com | grep -oE 'src="[^"]*\\.js"' | cut -d'"' -f2); do
  echo "Checking $js_file for source maps:"
  curl -s https://target.com$js_file | tail -5 | grep sourceMappingURL
done

# Source Map Analysis for Sensitive Info
curl -s https://target.com/static/js/main.js.map | jq -r '.sources[]' | grep -E '(config|secret|key|password|api)'`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  <div className="bg-cybr-muted/20 p-4 rounded-lg">
                    <h5 className="font-semibold mb-2 text-cybr-primary">Webpack Bundle Analysis</h5>
                    <div className="space-y-3">
                      <div>
                        <p className="text-sm font-medium mb-2">Bundle Decomposition:</p>
                        <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# Webpack Module Extraction
curl -s https://target.com/static/js/main.js | grep -oE 'function\\([^)]*\\)\\{[^}]*\\}' | head -10

# Configuration Extraction
curl -s https://target.com/static/js/main.js | grep -oE 'process\\.env\\.[A-Z_]*' | sort -u
curl -s https://target.com/static/js/main.js | grep -oE 'NODE_ENV|API_URL|BASE_URL' 

# Module Mapping
curl -s https://target.com/static/js/main.js | grep -oE '__webpack_require__\\([0-9]*\\)' | sort -u

# Webpack Externals Discovery
curl -s https://target.com/static/js/main.js | grep -oE 'externals:\\{[^}]*\\}'`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  <div className="bg-cybr-muted/20 p-4 rounded-lg">
                    <h5 className="font-semibold mb-2 text-cybr-primary">Hidden API Endpoints in JavaScript</h5>
                    <div className="space-y-3">
                      <div>
                        <p className="text-sm font-medium mb-2">Endpoint Extraction Techniques:</p>
                        <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# API Endpoint Regex Patterns
curl -s https://target.com/app.js | grep -oE '"/api/[a-zA-Z0-9/_-]*"' | sort -u
curl -s https://target.com/app.js | grep -oE "'\\/api\\/[a-zA-Z0-9\\/_-]*'" | sort -u
curl -s https://target.com/app.js | grep -oE 'endpoint:\\s*["\'][^"\']*["\']'

# GraphQL Schema Discovery
curl -s https://target.com/app.js | grep -oE 'query\\s*[A-Za-z]*\\s*\\{[^}]*\\}'
curl -s https://target.com/app.js | grep -oE 'mutation\\s*[A-Za-z]*\\s*\\{[^}]*\\}'

# REST API Pattern Discovery
curl -s https://target.com/app.js | grep -oE '\\$\\{[^}]*\\}\\/[a-zA-Z0-9/_-]*'
curl -s https://target.com/app.js | grep -oE 'baseURL[^,]*'`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  <div className="bg-cybr-muted/20 p-4 rounded-lg">
                    <h5 className="font-semibold mb-2 text-cybr-primary">JavaScript Deobfuscation</h5>
                    <div className="space-y-3">
                      <div>
                        <p className="text-sm font-medium mb-2">Deobfuscation Techniques:</p>
                        <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# Basic Deobfuscation
# 1. Beautify minified code
curl -s https://target.com/app.min.js | js-beautify

# 2. Variable name pattern analysis
curl -s https://target.com/app.js | grep -oE 'var [a-zA-Z_$][a-zA-Z0-9_$]*=' | sort | uniq -c

# 3. String decoding (common patterns)
# Hex encoding: \\x41\\x42\\x43 = ABC
# Unicode encoding: \\u0041\\u0042\\u0043 = ABC
# Base64 decoding in JavaScript

# 4. Function call analysis
curl -s https://target.com/app.js | grep -oE '[a-zA-Z_$][a-zA-Z0-9_$]*\\([^)]*\\)' | head -20`}
                        </pre>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-4">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-5 w-5 text-amber-500 mt-0.5 flex-shrink-0" />
                    <div>
                      <h5 className="font-semibold text-amber-500 mb-1">Legal & Ethical Notice</h5>
                      <p className="text-sm opacity-80">
                        These reconnaissance techniques should only be used on systems you own or have explicit permission to test. 
                        Unauthorized reconnaissance may violate laws and regulations. Always ensure proper authorization before testing.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
                  <div className="flex items-start gap-2">
                    <Info className="h-5 w-5 text-blue-500 mt-0.5 flex-shrink-0" />
                    <div>
                      <h5 className="font-semibold text-blue-500 mb-1">Advanced Tools Recommendation</h5>
                      <div className="text-sm space-y-2">
                        <p><strong>OSINT:</strong> theHarvester, Maltego, Recon-ng, Shodan, Censys</p>
                        <p><strong>Web App Mapping:</strong> Burp Suite, OWASP ZAP, Nuclei, Katana</p>
                        <p><strong>JavaScript Analysis:</strong> LinkFinder, SecretFinder, JSParser, Retire.js</p>
                        <p><strong>HTTP Analysis:</strong> HTTProbe, HTTPx, Subfinder, Amass</p>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Other tabs would go here - keeping them simple for now */}
        <TabsContent value="exploitation-techniques" className="space-y-6">
          <Card className="bg-cybr-card border-cybr-muted">
            <CardHeader>
              <CardTitle className="text-cybr-primary">Advanced Exploitation Techniques</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-cybr-foreground opacity-80">
                Advanced exploitation techniques content will be implemented here.
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="post-exploitation" className="space-y-6">
          <Card className="bg-cybr-card border-cybr-muted">
            <CardHeader>
              <CardTitle className="text-cybr-primary">Post-Exploitation Techniques</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-cybr-foreground opacity-80">
                Post-exploitation techniques content will be implemented here.
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="evasion-techniques" className="space-y-6">
          <Card className="bg-cybr-card border-cybr-muted">
            <CardHeader>
              <CardTitle className="text-cybr-primary">Evasion Techniques</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-cybr-foreground opacity-80">
                Evasion techniques content will be implemented here.
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="automation-scripting" className="space-y-6">
          <Card className="bg-cybr-card border-cybr-muted">
            <CardHeader>
              <CardTitle className="text-cybr-primary">Automation & Scripting</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-cybr-foreground opacity-80">
                Automation and scripting content will be implemented here.
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="reporting-analysis" className="space-y-6">
          <Card className="bg-cybr-card border-cybr-muted">
            <CardHeader>
              <CardTitle className="text-cybr-primary">Reporting & Analysis</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-cybr-foreground opacity-80">
                Reporting and analysis content will be implemented here.
              </p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default AdvancedContentSection;
