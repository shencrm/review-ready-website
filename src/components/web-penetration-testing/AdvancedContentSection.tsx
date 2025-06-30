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

                {/* NEW: Modern Reconnaissance Tools Arsenal */}
                <div className="bg-cybr-muted/20 p-5 rounded-lg border border-cybr-primary/10">
                  <div className="flex items-center gap-3 mb-4">
                    <Badge variant="outline" className="bg-cybr-primary/20 text-cybr-primary">Featured Tool</Badge>
                    <h5 className="text-lg font-bold text-cybr-primary">Modern Reconnaissance Tools Arsenal</h5>
                  </div>
                  <p className="text-sm opacity-90 mb-4">
                    Modern web applications require advanced reconnaissance techniques. This arsenal covers the latest tools 
                    that have revolutionized the field of web application reconnaissance, each optimized for specific scenarios 
                    and offering unique capabilities for comprehensive security assessment.
                  </p>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                    <div className="bg-cybr-muted/30 p-3 rounded">
                      <strong className="text-cybr-accent">Speed-Focused:</strong> Tools optimized for rapid enumeration
                    </div>
                    <div className="bg-cybr-muted/30 p-3 rounded">
                      <strong className="text-cybr-accent">Precision Tools:</strong> Advanced filtering and accuracy
                    </div>
                    <div className="bg-cybr-muted/30 p-3 rounded">
                      <strong className="text-cybr-accent">Integration Ready:</strong> Designed for automation workflows
                    </div>
                  </div>
                </div>

                {/* Directory & File Discovery Tools */}
                <div className="space-y-6">
                  <h4 className="text-xl font-bold text-cybr-accent border-b border-cybr-accent/30 pb-2">
                    Directory & File Discovery Tools
                  </h4>

                  {/* Dirsearch */}
                  <div className="bg-cybr-muted/20 p-5 rounded-lg border border-cybr-primary/10">
                    <div className="flex items-center gap-3 mb-4">
                      <Badge variant="outline" className="bg-cybr-primary/20 text-cybr-primary">Featured Tool</Badge>
                      <h5 className="text-lg font-bold text-cybr-primary">Dirsearch - Advanced Directory Brute Forcer</h5>
                    </div>
                    <p className="text-sm opacity-90 mb-4">
                      Dirsearch is a powerful web path scanner designed for comprehensive directory and file discovery. 
                      It supports recursive scanning, multiple extensions, and advanced filtering capabilities.
                    </p>
                    
                    <div className="space-y-4">
                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Basic Usage & Installation:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Installation
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch
pip3 install -r requirements.txt

# Basic scan
python3 dirsearch.py -u https://target.com

# Comprehensive scan with multiple extensions
python3 dirsearch.py -u https://target.com -e php,html,js,txt,xml,json

# Recursive scanning (subdirectories)
python3 dirsearch.py -u https://target.com -r

# Custom wordlist with specific extensions
python3 dirsearch.py -u https://target.com -w /path/to/wordlist.txt -e php,asp,aspx`}
                        </pre>
                      </div>

                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Advanced Parameters & Techniques:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Multi-threading for speed
python3 dirsearch.py -u https://target.com -t 50

# Custom User-Agent and headers
python3 dirsearch.py -u https://target.com --user-agent "Custom-Agent/1.0" 
python3 dirsearch.py -u https://target.com --headers "X-Forwarded-For: 127.0.0.1"

# Proxy through Burp Suite
python3 dirsearch.py -u https://target.com --proxy http://127.0.0.1:8080

# Filter responses by status code
python3 dirsearch.py -u https://target.com --exclude-status 404,403,500

# Include only specific status codes
python3 dirsearch.py -u https://target.com --include-status 200,301,302

# Filter by response size
python3 dirsearch.py -u https://target.com --exclude-sizes 1024,2048

# Delay between requests (stealth mode)
python3 dirsearch.py -u https://target.com --delay 2

# Save results to file
python3 dirsearch.py -u https://target.com -o /path/to/results.txt`}
                        </pre>
                      </div>

                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Advanced Wordlists & Strategies:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Technology-specific wordlists
python3 dirsearch.py -u https://target.com -w db/dicc.txt -e php
python3 dirsearch.py -u https://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Multiple wordlists combination
python3 dirsearch.py -u https://target.com -w wordlist1.txt,wordlist2.txt,wordlist3.txt

# Suffix and prefix combinations
python3 dirsearch.py -u https://target.com --suffixes .bak,.old,.tmp,.backup
python3 dirsearch.py -u https://target.com --prefixes test-,admin-,backup-

# Force extensions on every word
python3 dirsearch.py -u https://target.com --force-extensions

# Skip certificate verification (HTTPS)
python3 dirsearch.py -u https://target.com --disable-tls-checks`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  {/* FFuF */}
                  <div className="bg-cybr-muted/20 p-5 rounded-lg border border-cybr-primary/10">
                    <h5 className="text-lg font-bold text-cybr-primary mb-3">FFuF - Fast Web Fuzzer</h5>
                    <p className="text-sm opacity-90 mb-4">
                      FFuF (Fuzz Faster U Fool) is a fast web fuzzer written in Go, designed for discovering hidden content 
                      and testing input validation with advanced filtering capabilities.
                    </p>
                    
                    <div className="space-y-4">
                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Installation & Basic Usage:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Installation
go install github.com/ffuf/ffuf@latest

# Basic directory fuzzing
ffuf -w /usr/share/wordlists/dirb/common.txt -u https://target.com/FUZZ

# File extension fuzzing
ffuf -w /usr/share/wordlists/dirb/common.txt -u https://target.com/FUZZ.php

# Multiple wordlists (FUZZ and FUZZ2)
ffuf -w wordlist1.txt:FUZZ -w extensions.txt:FUZZ2 -u https://target.com/FUZZ.FUZZ2

# Subdomain fuzzing
ffuf -w subdomains.txt -u https://FUZZ.target.com/`}
                        </pre>
                      </div>

                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Advanced Filtering & Output:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Filter by status code
ffuf -w wordlist.txt -u https://target.com/FUZZ -fc 404,403

# Filter by response size
ffuf -w wordlist.txt -u https://target.com/FUZZ -fs 1024

# Filter by word count
ffuf -w wordlist.txt -u https://target.com/FUZZ -fw 100

# Match specific status codes only
ffuf -w wordlist.txt -u https://target.com/FUZZ -mc 200,301,302

# Match response size
ffuf -w wordlist.txt -u https://target.com/FUZZ -ms 500-2000

# Output to JSON for parsing
ffuf -w wordlist.txt -u https://target.com/FUZZ -o results.json -of json

# Colorized output with details
ffuf -w wordlist.txt -u https://target.com/FUZZ -c -v`}
                        </pre>
                      </div>

                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Parameter & Header Fuzzing:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# GET parameter fuzzing
ffuf -w params.txt -u https://target.com/search?FUZZ=test

# POST parameter fuzzing
ffuf -w params.txt -u https://target.com/login -X POST -d "FUZZ=admin" -H "Content-Type: application/x-www-form-urlencoded"

# Header fuzzing
ffuf -w headers.txt -u https://target.com/ -H "FUZZ: value"

# HTTP method fuzzing
ffuf -w methods.txt -u https://target.com/api/users -X FUZZ

# Combined parameter and value fuzzing
ffuf -w params.txt:PARAM -w values.txt:VALUE -u https://target.com/?PARAM=VALUE`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  {/* Feroxbuster */}
                  <div className="bg-cybr-muted/20 p-5 rounded-lg border border-cybr-primary/10">
                    <h5 className="text-lg font-bold text-cybr-primary mb-3">Feroxbuster - Fast, Simple, Recursive Scanner</h5>
                    <p className="text-sm opacity-90 mb-4">
                      Feroxbuster is a fast, simple, recursive content discovery tool written in Rust with advanced 
                      filtering and automatic recursive scanning capabilities.
                    </p>
                    
                    <div className="space-y-4">
                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Installation & Basic Usage:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Installation
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash

# Basic scan
feroxbuster -u https://target.com

# Custom wordlist
feroxbuster -u https://target.com -w /usr/share/wordlists/dirb/common.txt

# Specify extensions
feroxbuster -u https://target.com -x php,html,js,txt

# Control recursion depth
feroxbuster -u https://target.com --depth 3`}
                        </pre>
                      </div>

                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Advanced Configuration:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Threads and timeout
feroxbuster -u https://target.com -t 100 --timeout 10

# Filter status codes
feroxbuster -u https://target.com -C 404,403

# Filter response sizes
feroxbuster -u https://target.com -S 1024,2048

# Filter word count
feroxbuster -u https://target.com -W 100

# Save state for resuming
feroxbuster -u https://target.com --save-state state.ferox

# Resume from saved state
feroxbuster --resume-from state.ferox

# Output formats
feroxbuster -u https://target.com -o results.json --json
feroxbuster -u https://target.com -o results.txt`}
                        </pre>
                      </div>

                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Smart Filtering & Detection:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Auto-filter responses (smart filtering)
feroxbuster -u https://target.com --auto-tune

# Scan with auto-bail (stop on consistent 404s)
feroxbuster -u https://target.com --auto-bail

# Include query parameters in scope
feroxbuster -u https://target.com --query

# Follow redirects
feroxbuster -u https://target.com -r

# Extract links from response bodies
feroxbuster -u https://target.com --extract-links

# Proxy through Burp Suite
feroxbuster -u https://target.com -p http://127.0.0.1:8080`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  {/* Gobuster */}
                  <div className="bg-cybr-muted/20 p-5 rounded-lg border border-cybr-primary/10">
                    <h5 className="text-lg font-bold text-cybr-primary mb-3">Gobuster - Multi-Mode Scanner</h5>
                    <p className="text-sm opacity-90 mb-4">
                      Gobuster is a versatile tool written in Go that can perform directory/file, DNS, and virtual host enumeration 
                      with multiple scanning modes and excellent performance.
                    </p>
                    
                    <div className="space-y-4">
                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Installation & Directory Mode:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Installation
go install github.com/OJ/gobuster/v3@latest

# Directory brute force
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt

# Multiple extensions
gobuster dir -u https://target.com -w wordlist.txt -x php,html,js,txt

# Custom status codes
gobuster dir -u https://target.com -w wordlist.txt -s 200,204,301,302,307,403

# Exclude status codes
gobuster dir -u https://target.com -w wordlist.txt -b 404,403

# Custom User-Agent and headers
gobuster dir -u https://target.com -w wordlist.txt -a "Custom-Agent/1.0"
gobuster dir -u https://target.com -w wordlist.txt -H "X-Forwarded-For: 127.0.0.1"`}
                        </pre>
                      </div>

                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">DNS & VHost Modes:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# DNS subdomain enumeration
gobuster dns -d target.com -w /usr/share/wordlists/dnsmap.txt

# Custom DNS servers
gobuster dns -d target.com -w subdomains.txt -r 8.8.8.8,1.1.1.1

# Virtual host discovery
gobuster vhost -u https://target.com -w subdomains.txt

# Virtual host with specific domain
gobuster vhost -u https://target.com -w subdomains.txt --domain target.com`}
                        </pre>
                      </div>

                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Advanced Options:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Threads and timeout
gobuster dir -u https://target.com -w wordlist.txt -t 50 --timeout 30s

# Proxy configuration
gobuster dir -u https://target.com -w wordlist.txt -p http://127.0.0.1:8080

# Output to file
gobuster dir -u https://target.com -w wordlist.txt -o results.txt

# Verbose output
gobuster dir -u https://target.com -w wordlist.txt -v

# Follow redirects
gobuster dir -u https://target.com -w wordlist.txt -r

# Extract length information
gobuster dir -u https://target.com -w wordlist.txt -l`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  {/* WFuzz */}
                  <div className="bg-cybr-muted/20 p-5 rounded-lg border border-cybr-primary/10">
                    <h5 className="text-lg font-bold text-cybr-primary mb-3">WFuzz - Web Application Fuzzer</h5>
                    <p className="text-sm opacity-90 mb-4">
                      WFuzz is a Python-based web application fuzzer designed for discovering resources and vulnerabilities 
                      through comprehensive fuzzing techniques with advanced payload manipulation.
                    </p>
                    
                    <div className="space-y-4">
                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Installation & Basic Fuzzing:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Installation
pip3 install wfuzz

# Basic directory fuzzing
wfuzz -c -w /usr/share/wordlists/dirb/common.txt https://target.com/FUZZ

# File extension fuzzing
wfuzz -c -w common.txt -w extensions.txt https://target.com/FUZZ.FUZ2Z

# Hide 404 responses
wfuzz -c -w wordlist.txt --hc 404 https://target.com/FUZZ

# Hide specific response sizes
wfuzz -c -w wordlist.txt --hs 1024 https://target.com/FUZZ`}
                        </pre>
                      </div>

                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Parameter & Form Fuzzing:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# GET parameter fuzzing
wfuzz -c -w params.txt https://target.com/search?FUZZ=test

# POST parameter fuzzing
wfuzz -c -w params.txt -d "FUZZ=admin&password=test" https://target.com/login

# Header fuzzing
wfuzz -c -w headers.txt -H "FUZZ: value" https://target.com/

# Cookie fuzzing
wfuzz -c -w cookies.txt -b "FUZZ=value" https://target.com/

# Multiple parameter fuzzing
wfuzz -c -w users.txt -w passwords.txt -d "username=FUZZ&password=FUZ2Z" https://target.com/login`}
                        </pre>
                      </div>

                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Advanced Payloads & Filters:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Number range payload
wfuzz -c -z range,1-1000 https://target.com/user/FUZZ

# Custom charset payload
wfuzz -c -z charset,abc123 https://target.com/FUZZ

# Base64 encoding
wfuzz -c -w wordlist.txt -e base64 https://target.com/FUZZ

# Multiple filters
wfuzz -c -w wordlist.txt --hc 404,403 --hs 0 --hw 6 https://target.com/FUZZ

# Show only specific codes
wfuzz -c -w wordlist.txt --sc 200,301,302 https://target.com/FUZZ

# Regular expression filtering
wfuzz -c -w wordlist.txt --filter "r.code==200 and r.words<100" https://target.com/FUZZ`}
                        </pre>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Advanced Subdomain Enumeration */}
                <div className="space-y-6">
                  <h4 className="text-xl font-bold text-cybr-accent border-b border-cybr-accent/30 pb-2">
                    Advanced Subdomain Enumeration
                  </h4>

                  {/* Subfinder */}
                  <div className="bg-cybr-muted/20 p-5 rounded-lg border border-cybr-primary/10">
                    <h5 className="text-lg font-bold text-cybr-primary mb-3">Subfinder - Passive Subdomain Discovery</h5>
                    <p className="text-sm opacity-90 mb-4">
                      Subfinder is a subdomain discovery tool that discovers valid subdomains using passive online sources 
                      and provides integration with multiple APIs for comprehensive coverage.
                    </p>
                    
                    <div className="space-y-4">
                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Installation & Basic Usage:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Installation
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Basic subdomain enumeration
subfinder -d target.com

# Multiple domains
subfinder -dL domains.txt

# Output to file
subfinder -d target.com -o subdomains.txt

# Verbose output
subfinder -d target.com -v`}
                        </pre>
                      </div>

                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">API Integration & Configuration:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# List all sources
subfinder -ls

# Use specific sources only
subfinder -d target.com -sources censys,virustotal,shodan

# Exclude specific sources
subfinder -d target.com -exclude-sources waybackarchive

# API configuration file (~/.config/subfinder/provider-config.yaml)
# virustotal: ["your-api-key"]
# shodan: ["your-api-key"]
# censys: ["your-api-id", "your-api-secret"]

# Use all available sources with APIs
subfinder -d target.com -all`}
                        </pre>
                      </div>

                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Advanced Options:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Threads control
subfinder -d target.com -t 100

# Timeout configuration
subfinder -d target.com -timeout 30

# Rate limiting
subfinder -d target.com -rl 10

# Remove wildcards
subfinder -d target.com -nW

# JSON output
subfinder -d target.com -oJ -o results.json

# Integration with other tools
subfinder -d target.com | httpx -silent | nuclei -templates-path ~/nuclei-templates/`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  {/* Amass */}
                  <div className="bg-cybr-muted/20 p-5 rounded-lg border border-cybr-primary/10">
                    <h5 className="text-lg font-bold text-cybr-primary mb-3">Amass - Advanced Attack Surface Mapping</h5>
                    <p className="text-sm opacity-90 mb-4">
                      Amass is a comprehensive attack surface mapping tool that performs network mapping of attack surfaces 
                      and external asset discovery using both passive and active reconnaissance techniques.
                    </p>
                    
                    <div className="space-y-4">
                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Installation & Basic Enumeration:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Installation
go install -v github.com/OWASP/Amass/v3/...@master

# Basic enumeration
amass enum -d target.com

# Passive enumeration only
amass enum -passive -d target.com

# Active enumeration (includes DNS techniques)
amass enum -active -d target.com

# Brute force enumeration
amass enum -brute -d target.com`}
                        </pre>
                      </div>

                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Advanced Configuration:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Use configuration file
amass enum -config config.ini -d target.com

# Multiple domains from file
amass enum -df domains.txt

# Custom wordlist for brute forcing
amass enum -brute -w wordlist.txt -d target.com

# Minimum word length for brute force
amass enum -brute -min-for-recursive 3 -d target.com

# Output formats
amass enum -d target.com -o results.txt
amass enum -d target.com -json results.json

# Control sources
amass enum -src -d target.com  # List sources
amass enum -include censys,shodan -d target.com
amass enum -exclude wayback -d target.com`}
                        </pre>
                      </div>

                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Visualization & Analysis:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Database operations
amass db -dir database_directory -list
amass db -dir database_directory -d target.com -show

# Visualization
amass viz -d3 -dir database_directory
amass viz -gexf output.gexf -dir database_directory

# Intel gathering
amass intel -d target.com -whois

# Network mapping
amass enum -d target.com -p 80,443,8080,8443`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  {/* Assetfinder */}
                  <div className="bg-cybr-muted/20 p-5 rounded-lg border border-cybr-primary/10">
                    <h5 className="text-lg font-bold text-cybr-primary mb-3">Assetfinder - Fast Asset Discovery</h5>
                    <p className="text-sm opacity-90 mb-4">
                      Assetfinder is a simple tool for finding domains and subdomains potentially related to a given domain, 
                      designed for speed and integration with automation workflows.
                    </p>
                    
                    <div className="space-y-4">
                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Installation & Usage:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Installation
go install github.com/tomnomnom/assetfinder@latest

# Basic domain discovery
assetfinder target.com

# Include subdomains only
assetfinder --subs-only target.com

# Pipe to other tools
assetfinder target.com | httprobe | tee live_subdomains.txt

# Multiple domains
echo "target1.com\ntarget2.com" | assetfinder

# Save to file
assetfinder target.com > subdomains.txt`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  {/* KnockPy */}
                  <div className="bg-cybr-muted/20 p-5 rounded-lg border border-cybr-primary/10">
                    <h5 className="text-lg font-bold text-cybr-primary mb-3">KnockPy - DNS Subdomain Scanner</h5>
                    <p className="text-sm opacity-90 mb-4">
                      KnockPy is a Python tool designed to enumerate subdomains on a target domain through dictionary attacks 
                      and DNS resolution techniques.
                    </p>
                    
                    <div className="space-y-4">
                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Installation & Usage:</h6>
                        <pre className="bg-black/50 p-3 rounded text-xs text-green-400 overflow-x-auto">
{`# Installation
git clone https://github.com/guelfoweb/knock.git
cd knock
pip install -r requirements.txt

# Basic scan
python knockpy.py target.com

# Custom wordlist
python knockpy.py -w custom_wordlist.txt target.com

# Resolve IP addresses  
python knockpy.py -r target.com

# JSON output
python knockpy.py -j target.com

# Custom threads
python knockpy.py -t 100 target.com`}
                        </pre>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Modern Web Crawling & Analysis */}
                <div className="space-y-6">
                  <h4 className="text-xl font-bold text-cybr-accent border-b border-cybr-accent/30 pb-2">
                    Modern Web Crawling & Analysis Tools
                  </h4>

                  {/* Katana */}
                  <div className="bg-cybr-muted/20 p-5 rounded-lg border border-cybr-primary/10">
                    <h5 className="text-lg font-bold text-cybr-primary mb-3">Katana - Next-Generation Crawler</h5>
                    <p className="text-sm opacity-90 mb-4">
                      Katana is a fast crawler focused on execution in automation pipelines offering both headless and 
                      non-headless crawling with advanced JavaScript parsing capabilities.
                    </p>
                    
                    <div className="space-y-4">
                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Installation & Basic Crawling:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Installation
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Basic crawling
katana -u https://target.com

# Multiple URLs
katana -list urls.txt

# Depth control
katana -u https://target.com -depth 3

# JavaScript parsing
katana -u https://target.com -jc

# Headless mode
katana -u https://target.com -headless`}
                        </pre>
                      </div>

                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Advanced Configuration:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Custom headers
katana -u https://target.com -H "X-Forwarded-For: 127.0.0.1"

# Proxy configuration
katana -u https://target.com -proxy http://127.0.0.1:8080

# Rate limiting
katana -u https://target.com -delay 2s

# Scope control
katana -u https://target.com -scope "*.target.com,target.com"

# Form extraction
katana -u https://target.com -forms

# Output filtering
katana -u https://target.com -extension-filter png,jpg,gif,css

# JSON output
katana -u https://target.com -jsonl -o results.json`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  {/* Hakrawler */}
                  <div className="bg-cybr-muted/20 p-5 rounded-lg border border-cybr-primary/10">
                    <h5 className="text-lg font-bold text-cybr-primary mb-3">Hakrawler - Fast Web Crawler</h5>
                    <p className="text-sm opacity-90 mb-4">
                      Hakrawler is a fast web crawler designed for gathering URLs and JavaScript file locations, 
                      optimized for bug bounty reconnaissance workflows.
                    </p>
                    
                    <div className="space-y-4">
                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Installation & Usage:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Installation
go install github.com/hakluke/hakrawler@latest

# Basic crawling
echo "https://target.com" | hakrawler

# Depth control
echo "https://target.com" | hakrawler -depth 3

# Include subdomains
echo "https://target.com" | hakrawler -subs

# Show source of URLs
echo "https://target.com" | hakrawler -s

# Plain output (no colors)
echo "https://target.com" | hakrawler -plain

# Integration with other tools
subfinder -d target.com | httpx | hakrawler | grep -E "\\.(js|php|asp|aspx)$"`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  {/* HTTPx */}
                  <div className="bg-cybr-muted/20 p-5 rounded-lg border border-cybr-primary/10">
                    <h5 className="text-lg font-bold text-cybr-primary mb-3">HTTPx - HTTP Toolkit</h5>
                    <p className="text-sm opacity-90 mb-4">
                      HTTPx is a fast and multi-purpose HTTP toolkit that allows running multiple HTTP probes, 
                      designed for reconnaissance and vulnerability assessment workflows.
                    </p>
                    
                    <div className="space-y-4">
                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Installation & Basic Probing:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Installation
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Basic HTTP probing
httpx -l urls.txt

# Probe with status codes
httpx -l urls.txt -status-code

# Extract titles
httpx -l urls.txt -title

# Show response length
httpx -l urls.txt -content-length

# Technology detection
httpx -l urls.txt -tech-detect`}
                        </pre>
                      </div>

                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Advanced Features:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Custom ports
httpx -l hosts.txt -ports 80,443,8080,8443

# HTTP methods
httpx -l urls.txt -method GET,POST,PUT

# Response analysis
httpx -l urls.txt -content-type -server -method

# Screenshot capture
httpx -l urls.txt -screenshot

# Path probing
httpx -l urls.txt -path /admin,/login,/api

# Filter by status code
httpx -l urls.txt -mc 200,301,302

# JSON output
httpx -l urls.txt -json -o results.json

# Follow redirects
httpx -l urls.txt -follow-redirects`}
                        </pre>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Tool Integration & Automation */}
                <div className="space-y-6">
                  <h4 className="text-xl font-bold text-cybr-accent border-b border-cybr-accent/30 pb-2">
                    Tool Integration & Automation Workflows
                  </h4>

                  <div className="bg-gradient-to-r from-cybr-accent/10 to-cybr-primary/10 p-6 rounded-lg border border-cybr-accent/20">
                    <h5 className="text-lg font-bold text-cybr-primary mb-4">Complete Reconnaissance Automation</h5>
                    
                    <div className="space-y-4">
                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Subdomain to Content Discovery Pipeline:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`#!/bin/bash
# Complete reconnaissance automation script

TARGET=$1
echo "[+] Starting reconnaissance for $TARGET"

# Phase 1: Subdomain enumeration
echo "[+] Phase 1: Subdomain Discovery"
subfinder -d $TARGET -silent | tee subdomains.txt
amass enum -passive -d $TARGET | tee -a subdomains.txt
assetfinder --subs-only $TARGET | tee -a subdomains.txt

# Remove duplicates
sort -u subdomains.txt -o subdomains.txt

# Phase 2: HTTP probing
echo "[+] Phase 2: HTTP Probing"
cat subdomains.txt | httpx -silent -threads 100 | tee live_subdomains.txt

# Phase 3: Content discovery
echo "[+] Phase 3: Content Discovery"
while read -r url; do
    echo "[+] Scanning $url"
    dirsearch.py -u "$url" -e php,html,js,txt -t 50 --exclude-status 404,403 -q
    feroxbuster -u "$url" -w /usr/share/wordlists/dirb/common.txt -x php,html,js -q
done < live_subdomains.txt

# Phase 4: Technology detection
echo "[+] Phase 4: Technology Detection"
cat live_subdomains.txt | httpx -tech-detect -title -status-code -silent

# Phase 5: Vulnerability scanning
echo "[+] Phase 5: Basic Vulnerability Scanning"
cat live_subdomains.txt | nuclei -templates-path ~/nuclei-templates/ -silent

echo "[+] Reconnaissance completed for $TARGET"`}
                        </pre>
                      </div>

                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Advanced Filtering & Correlation:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Filter interesting endpoints
cat all_endpoints.txt | grep -E "(admin|login|api|dashboard|config|backup|dev|test)" | sort -u

# Extract JavaScript files for analysis
cat crawled_urls.txt | grep -E "\\.js$" | tee js_files.txt

# Find potential vulnerabilities in JS
while read -r js_url; do
    curl -s "$js_url" | grep -E "(api_key|password|secret|token)" && echo "Found in: $js_url"
done < js_files.txt

# Correlation with CVE databases
httpx -l live_subdomains.txt -tech-detect -json | jq -r '.tech[]' | sort -u | tee technologies.txt

# Generate wordlists based on discovered technologies
grep -i "wordpress" technologies.txt && echo "wp-content wp-admin wp-includes" >> custom_wordlist.txt
grep -i "drupal" technologies.txt && echo "sites modules themes" >> custom_wordlist.txt`}
                        </pre>
                      </div>

                      <div>
                        <h6 className="font-semibold text-cybr-accent mb-2">Continuous Monitoring Setup:</h6>
                        <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Cron job for continuous monitoring (daily at 2 AM)
# 0 2 * * * /path/to/recon_script.sh target.com >> /var/log/recon.log 2>&1

# Monitor for new subdomains
#!/bin/bash
DOMAIN=$1
OLD_SUBS="old_subdomains_$DOMAIN.txt"
NEW_SUBS="new_subdomains_$DOMAIN.txt"

# Get current subdomains
subfinder -d $DOMAIN -silent > $NEW_SUBS

# Compare with previous scan
if [ -f $OLD_SUBS ]; then
    comm -13 <(sort $OLD_SUBS) <(sort $NEW_SUBS) > new_findings.txt
    if [ -s new_findings.txt ]; then
        echo "New subdomains found for $DOMAIN:"
        cat new_findings.txt
        # Send notification (email, Slack, etc.)
    fi
fi

# Update old subdomains file
cp $NEW_SUBS $OLD_SUBS`}
                        </pre>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Best Practices & Tips */}
                <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-6">
                  <div className="flex items-start gap-3">
                    <Info className="h-6 w-6 text-blue-500 mt-0.5 flex-shrink-0" />
                    <div className="space-y-4">
                      <h5 className="font-bold text-blue-500 text-lg">Professional Reconnaissance Best Practices</h5>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                          <h6 className="font-semibold text-blue-400 mb-2">Tool Selection Strategy:</h6>
                          <ul className="text-sm space-y-1 list-disc list-inside opacity-90">
                            <li><strong>Speed-focused:</strong> Use ffuf, feroxbuster for large-scale scans</li>
                            <li><strong>Accuracy-focused:</strong> Use dirsearch, gobuster for thorough analysis</li>
                            <li><strong>Passive recon:</strong> Start with subfinder, amass passive mode</li>
                            <li><strong>Active recon:</strong> Follow up with active amass, DNS brute forcing</li>
                            <li><strong>Integration:</strong> Chain tools for comprehensive coverage</li>
                          </ul>
                        </div>
                        
                        <div>
                          <h6 className="font-semibold text-blue-400 mb-2">Performance Optimization:</h6>
                          <ul className="text-sm space-y-1 list-disc list-inside opacity-90">
                            <li><strong>Threading:</strong> Balance speed vs server load (50-100 threads)</li>
                            <li><strong>Rate limiting:</strong> Implement delays for stealth mode</li>
                            <li><strong>Wordlist optimization:</strong> Use technology-specific lists</li>
                            <li><strong>Filtering:</strong> Exclude common false positives early</li>
                            <li><strong>Proxy usage:</strong> Route through Burp for manual analysis</li>
                          </ul>
                        </div>
                        
                        <div>
                          <h6 className="font-semibold text-blue-400 mb-2">Data Management:</h6>
                          <ul className="text-sm space-y-1 list-disc list-inside opacity-90">
                            <li><strong>Output formats:</strong> Use JSON for parsing, text for reading</li>
                            <li><strong>Deduplication:</strong> Remove duplicates across tool outputs</li>
                            <li><strong>Correlation:</strong> Cross-reference findings between tools</li>
                            <li><strong>Version control:</strong> Track reconnaissance over time</li>
                            <li><strong>Documentation:</strong> Maintain detailed methodology notes</li>
                          </ul>
                        </div>
                        
                        <div>
                          <h6 className="font-semibold text-blue-400 mb-2">Automation Workflows:</h6>
                          <ul className="text-sm space-y-1 list-disc list-inside opacity-90">
                            <li><strong>Phased approach:</strong> Passive → Active → Content discovery</li>
                            <li><strong>Error handling:</strong> Implement retries and failure notifications</li>
                            <li><strong>Monitoring:</strong> Set up continuous discovery processes</li>
                            <li><strong>Integration:</strong> Connect with vulnerability scanners</li>
                            <li><strong>Reporting:</strong> Generate automated reconnaissance reports</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Legal & Ethical Considerations */}
                <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-6">
                  <div className="flex items-start gap-3">
                    <AlertTriangle className="h-6 w-6 text-amber-500 mt-0.5 flex-shrink-0" />
                    <div>
                      <h5 className="font-bold text-amber-500 text-lg mb-3">Legal & Ethical Reconnaissance Guidelines</h5>
                      <div className="space-y-3 text-sm">
                        <div>
                          <strong className="text-amber-400">Authorization Requirements:</strong>
                          <p className="opacity-90 mt-1">Always obtain explicit written permission before conducting reconnaissance on systems you don't own. Unauthorized reconnaissance may violate computer fraud and abuse laws.</p>
                        </div>
                        <div>
                          <strong className="text-amber-400">Rate Limiting & Respect:</strong>
                          <p className="opacity-90 mt-1">Implement appropriate delays and rate limiting to avoid overwhelming target systems. Excessive requests can be considered a denial of service attack.</p>
                        </div>
                        <div>
                          <strong className="text-amber-400">Data Handling:</strong>
                          <p className="opacity-90 mt-1">Handle discovered information responsibly. Don't share sensitive findings publicly and follow responsible disclosure practices for vulnerabilities.</p>
                        </div>
                        <div>
                          <strong className="text-amber-400">Scope Boundaries:</strong>
                          <p className="opacity-90 mt-1">Respect defined testing scope and boundaries. Reconnaissance that extends beyond authorized targets may breach agreements and legal boundaries.</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Other tabs content remains unchanged */}
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
