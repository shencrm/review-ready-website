import React from 'react';
import { Badge } from '@/components/ui/badge';
import { Info, AlertTriangle } from 'lucide-react';

const ModernToolsArsenal: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Featured Tool Introduction */}
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

        {/* Other tools abbreviated for brevity */}
        <div className="bg-cybr-muted/20 p-5 rounded-lg border border-cybr-primary/10">
          <h5 className="text-lg font-bold text-cybr-primary mb-3">Additional Directory Discovery Tools</h5>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div>
              <h6 className="font-semibold text-cybr-accent mb-2">Feroxbuster:</h6>
              <p className="opacity-90 mb-2">Fast, simple, recursive content discovery tool written in Rust</p>
              <pre className="bg-black/50 p-2 rounded text-xs text-green-400">
{`feroxbuster -u https://target.com
feroxbuster -u https://target.com -x php,html,js`}
              </pre>
            </div>
            <div>
              <h6 className="font-semibold text-cybr-accent mb-2">Gobuster:</h6>
              <p className="opacity-90 mb-2">Multi-mode scanner (directory, DNS, vhost)</p>
              <pre className="bg-black/50 p-2 rounded text-xs text-green-400">
{`gobuster dir -u https://target.com -w wordlist.txt
gobuster dns -d target.com -w subdomains.txt`}
              </pre>
            </div>
          </div>
        </div>
      </div>

      {/* Subdomain Enumeration Tools */}
      <div className="space-y-6">
        <h4 className="text-xl font-bold text-cybr-accent border-b border-cybr-accent/30 pb-2">
          Advanced Subdomain Enumeration
        </h4>

        <div className="bg-cybr-muted/20 p-5 rounded-lg border border-cybr-primary/10">
          <h5 className="text-lg font-bold text-cybr-primary mb-3">Subfinder - Passive Subdomain Discovery</h5>
          <p className="text-sm opacity-90 mb-4">
            Subfinder discovers valid subdomains using passive online sources with multiple API integrations.
          </p>
          
          <div className="space-y-4">
            <div>
              <h6 className="font-semibold text-cybr-accent mb-2">Basic Usage:</h6>
              <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Installation
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Basic subdomain enumeration
subfinder -d target.com

# Multiple domains
subfinder -dL domains.txt

# Output to file with verbose logging
subfinder -d target.com -o subdomains.txt -v`}
              </pre>
            </div>
          </div>
        </div>

        <div className="bg-cybr-muted/20 p-5 rounded-lg border border-cybr-primary/10">
          <h5 className="text-lg font-bold text-cybr-primary mb-3">Additional Subdomain Tools</h5>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div>
              <h6 className="font-semibold text-cybr-accent mb-2">Amass:</h6>
              <p className="opacity-90 mb-2">Advanced attack surface mapping</p>
              <pre className="bg-black/50 p-2 rounded text-xs text-green-400">
{`amass enum -d target.com
amass enum -passive -d target.com`}
              </pre>
            </div>
            <div>
              <h6 className="font-semibold text-cybr-accent mb-2">Assetfinder:</h6>
              <p className="opacity-90 mb-2">Fast asset discovery</p>
              <pre className="bg-black/50 p-2 rounded text-xs text-green-400">
{`assetfinder target.com
assetfinder --subs-only target.com`}
              </pre>
            </div>
          </div>
        </div>
      </div>

      {/* Tool Integration */}
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

echo "[+] Reconnaissance completed for $TARGET"`}
            </pre>
          </div>
        </div>
      </div>

      {/* Best Practices */}
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
                <p className="opacity-90 mt-1">Always obtain explicit written permission before conducting reconnaissance on systems you don't own.</p>
              </div>
              <div>
                <strong className="text-amber-400">Rate Limiting & Respect:</strong>
                <p className="opacity-90 mt-1">Implement appropriate delays and rate limiting to avoid overwhelming target systems.</p>
              </div>
              <div>
                <strong className="text-amber-400">Scope Boundaries:</strong>
                <p className="opacity-90 mt-1">Respect defined testing scope and boundaries. Reconnaissance that extends beyond authorized targets may breach agreements.</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ModernToolsArsenal;
