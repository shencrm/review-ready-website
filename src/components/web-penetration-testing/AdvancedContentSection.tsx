
import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  Search, 
  Globe, 
  Database, 
  Server, 
  Eye, 
  Target, 
  Shield, 
  Code, 
  Terminal,
  AlertTriangle,
  Info,
  CheckCircle,
  XCircle,
  Zap,
  Lock,
  Users,
  FileText,
  Network,
  Smartphone,
  Cloud,
  Wifi,
  Mail,
  Phone,
  MapPin,
  Camera,
  Calendar,
  Building,
  UserCheck,
  Key,
  Settings,
  Archive,
  Layers,
  GitBranch,
  Bug
} from 'lucide-react';

const AdvancedContentSection: React.FC = () => {
  const [activeTab, setActiveTab] = useState('reconnaissance');

  const tabs = [
    { id: 'reconnaissance', title: 'Advanced Reconnaissance', icon: <Search className="h-4 w-4" /> },
    { id: 'enumeration', title: 'Deep Enumeration', icon: <Database className="h-4 w-4" /> },
    { id: 'exploitation', title: 'Advanced Exploitation', icon: <Target className="h-4 w-4" /> },
    { id: 'persistence', title: 'Persistence & Evasion', icon: <Shield className="h-4 w-4" /> },
    { id: 'pivoting', title: 'Lateral Movement', icon: <Network className="h-4 w-4" /> },
    { id: 'exfiltration', title: 'Data Exfiltration', icon: <Archive className="h-4 w-4" /> },
    { id: 'reporting', title: 'Advanced Reporting', icon: <FileText className="h-4 w-4" /> }
  ];

  return (
    <div className="space-y-8">
      <div className="text-center">
        <h2 className="text-3xl font-bold text-cybr-primary mb-4">
          Advanced Web Penetration Testing Methodologies
        </h2>
        <p className="text-lg text-cybr-foreground/80 max-w-4xl mx-auto">
          Master-level techniques, cutting-edge exploitation methods, and comprehensive security assessment strategies 
          for modern web applications and infrastructure.
        </p>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <div className="flex justify-center mb-8">
          <TabsList className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 bg-cybr-muted/30 p-1 rounded-lg">
            {tabs.map(tab => (
              <TabsTrigger 
                key={tab.id}
                value={tab.id}
                className="flex items-center gap-2 text-xs sm:text-sm px-2 py-2"
              >
                {tab.icon}
                <span className="hidden lg:inline">{tab.title}</span>
              </TabsTrigger>
            ))}
          </TabsList>
        </div>

        {/* Advanced Reconnaissance Tab */}
        <TabsContent value="reconnaissance" className="space-y-8">
          <div className="grid gap-8">
            
            {/* Header Section */}
            <Card className="border-cybr-primary/20 bg-gradient-to-r from-cybr-primary/5 to-cybr-secondary/5">
              <CardHeader>
                <div className="flex items-center gap-3">
                  <Search className="h-8 w-8 text-cybr-primary" />
                  <div>
                    <CardTitle className="text-2xl text-cybr-primary">Advanced Reconnaissance Techniques</CardTitle>
                    <CardDescription className="text-lg">
                      Comprehensive intelligence gathering and attack surface mapping methodologies
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid md:grid-cols-2 gap-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-3 text-cybr-primary">What Attackers Try to Achieve:</h4>
                    <ul className="space-y-2 text-cybr-foreground/90">
                      <li className="flex items-start gap-2">
                        <Target className="h-4 w-4 text-cybr-primary mt-1 flex-shrink-0" />
                        <span>Map the entire attack surface and identify entry points</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <Users className="h-4 w-4 text-cybr-primary mt-1 flex-shrink-0" />
                        <span>Gather employee information and organizational structure</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <Server className="h-4 w-4 text-cybr-primary mt-1 flex-shrink-0" />
                        <span>Identify technology stack and infrastructure details</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <Key className="h-4 w-4 text-cybr-primary mt-1 flex-shrink-0" />
                        <span>Discover credentials and sensitive information leakage</span>
                      </li>
                    </ul>
                  </div>
                  <div>
                    <h4 className="text-lg font-semibold mb-3 text-cybr-primary">Commonly Vulnerable Components:</h4>
                    <ul className="space-y-2 text-cybr-foreground/90">
                      <li className="flex items-start gap-2">
                        <Globe className="h-4 w-4 text-orange-500 mt-1 flex-shrink-0" />
                        <span>Public-facing websites and applications</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <Database className="h-4 w-4 text-orange-500 mt-1 flex-shrink-0" />
                        <span>DNS records and subdomain configurations</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <GitBranch className="h-4 w-4 text-orange-500 mt-1 flex-shrink-0" />
                        <span>Code repositories and documentation</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <Smartphone className="h-4 w-4 text-orange-500 mt-1 flex-shrink-0" />
                        <span>Social media profiles and digital footprints</span>
                      </li>
                    </ul>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* OSINT Techniques */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Eye className="h-6 w-6 text-cybr-primary" />
                  OSINT (Open Source Intelligence) Techniques
                </CardTitle>
                <CardDescription>
                  Comprehensive passive information gathering from publicly available sources
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                
                {/* Google Dorking Section */}
                <div>
                  <h4 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Globe className="h-5 w-5 text-cybr-primary" />
                    Advanced Google Dorking
                  </h4>
                  
                  <div className="grid lg:grid-cols-2 gap-6">
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">Administrative Interfaces</h5>
                      <div className="bg-cybr-muted/20 p-4 rounded-lg font-mono text-sm space-y-2">
                        <div className="text-green-400">site:example.com inurl:admin</div>
                        <div className="text-green-400">site:example.com inurl:administrator</div>
                        <div className="text-green-400">site:example.com inurl:login</div>
                        <div className="text-green-400">site:example.com inurl:wp-admin</div>
                        <div className="text-green-400">site:example.com inurl:phpmyadmin</div>
                        <div className="text-green-400">site:example.com intitle:"admin panel"</div>
                      </div>
                    </div>
                    
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">Configuration Files</h5>
                      <div className="bg-cybr-muted/20 p-4 rounded-lg font-mono text-sm space-y-2">
                        <div className="text-blue-400">site:example.com filetype:xml</div>
                        <div className="text-blue-400">site:example.com filetype:conf</div>
                        <div className="text-blue-400">site:example.com inurl:web.config</div>
                        <div className="text-blue-400">site:example.com inurl:.htaccess</div>
                        <div className="text-blue-400">site:example.com ext:env</div>
                      </div>
                    </div>
                  </div>

                  <div className="mt-6 grid lg:grid-cols-2 gap-6">
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">Sensitive Information</h5>
                      <div className="bg-cybr-muted/20 p-4 rounded-lg font-mono text-sm space-y-2">
                        <div className="text-red-400">site:example.com "password"</div>
                        <div className="text-red-400">site:example.com "api_key"</div>
                        <div className="text-red-400">site:example.com "secret_key"</div>
                        <div className="text-red-400">site:example.com "private_key"</div>
                        <div className="text-red-400">site:example.com "access_token"</div>
                      </div>
                    </div>
                    
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">Error Messages & Debug</h5>
                      <div className="bg-cybr-muted/20 p-4 rounded-lg font-mono text-sm space-y-2">
                        <div className="text-yellow-400">site:example.com "error"</div>
                        <div className="text-yellow-400">site:example.com "exception"</div>
                        <div className="text-yellow-400">site:example.com "stack trace"</div>
                        <div className="text-yellow-400">site:example.com "database error"</div>
                        <div className="text-yellow-400">site:example.com "debug"</div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Social Media Intelligence */}
                <Separator />
                <div>
                  <h4 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Users className="h-5 w-5 text-cybr-primary" />
                    Social Media Intelligence (SOCMINT)
                  </h4>
                  
                  <div className="grid md:grid-cols-3 gap-4">
                    <Card className="border-cybr-muted/30">
                      <CardHeader className="pb-3">
                        <CardTitle className="text-base flex items-center gap-2">
                          <Building className="h-4 w-4" />
                          Employee Profiling
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="text-sm space-y-2">
                        <p>• LinkedIn reconnaissance for org structure</p>
                        <p>• Twitter analysis for personal information</p>
                        <p>• Facebook investigation for relationships</p>
                        <p>• GitHub profiles for technical skills</p>
                        <p>• Email pattern discovery</p>
                      </CardContent>
                    </Card>

                    <Card className="border-cybr-muted/30">
                      <CardHeader className="pb-3">
                        <CardTitle className="text-base flex items-center gap-2">
                          <Settings className="h-4 w-4" />
                          Technology Discovery
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="text-sm space-y-2">
                        <p>• Job postings for tech stack info</p>
                        <p>• Conference presentations</p>
                        <p>• Technical blog posts</p>
                        <p>• Open source contributions</p>
                        <p>• Technology mentions in posts</p>
                      </CardContent>
                    </Card>

                    <Card className="border-cybr-muted/30">
                      <CardHeader className="pb-3">
                        <CardTitle className="text-base flex items-center gap-2">
                          <MapPin className="h-4 w-4" />
                          Physical Intelligence
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="text-sm space-y-2">
                        <p>• Office photos and location data</p>
                        <p>• Badge systems and security measures</p>
                        <p>• Employee check-ins and locations</p>
                        <p>• Event attendance patterns</p>
                        <p>• Facility layout information</p>
                      </CardContent>
                    </Card>
                  </div>
                </div>

                {/* Tools Section */}
                <Separator />
                <div>
                  <h4 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Terminal className="h-5 w-5 text-cybr-primary" />
                    Essential OSINT Tools
                  </h4>
                  
                  <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {[
                      { name: 'theHarvester', purpose: 'Email & subdomain enumeration', command: 'theHarvester -d example.com -b google,bing,linkedin' },
                      { name: 'Sherlock', purpose: 'Username enumeration across platforms', command: 'python3 sherlock.py username' },
                      { name: 'Maltego', purpose: 'Visual link analysis and OSINT', command: 'GUI-based relationship mapping' },
                      { name: 'Recon-ng', purpose: 'Automated reconnaissance framework', command: 'recon-ng -w workspace_name' },
                      { name: 'SpiderFoot', purpose: 'Automated OSINT collection', command: 'python3 sf.py -l 127.0.0.1:5001' },
                      { name: 'FOCA', purpose: 'Metadata extraction from documents', command: 'Windows GUI application' }
                    ].map((tool, index) => (
                      <Card key={index} className="border-cybr-muted/30">
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm font-mono text-cybr-primary">{tool.name}</CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-2">
                          <p className="text-xs text-cybr-foreground/80">{tool.purpose}</p>
                          <div className="bg-cybr-muted/20 p-2 rounded text-xs font-mono text-green-400">
                            {tool.command}
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Subdomain Enumeration */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Network className="h-6 w-6 text-cybr-primary" />
                  Advanced Subdomain Enumeration
                </CardTitle>
                <CardDescription>
                  Comprehensive subdomain discovery techniques and methodologies
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                
                <div className="grid lg:grid-cols-2 gap-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-4 text-cybr-primary">Why Subdomain Enumeration Works</h4>
                    <ul className="space-y-2 text-cybr-foreground/90">
                      <li className="flex items-start gap-2">
                        <Bug className="h-4 w-4 text-orange-500 mt-1 flex-shrink-0" />
                        <span>Organizations often forget about subdomains and leave them unmonitored</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <Settings className="h-4 w-4 text-orange-500 mt-1 flex-shrink-0" />
                        <span>Development and staging environments are frequently exposed</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <Shield className="h-4 w-4 text-orange-500 mt-1 flex-shrink-0" />
                        <span>Security controls may not be consistently applied across all subdomains</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <Database className="h-4 w-4 text-orange-500 mt-1 flex-shrink-0" />
                        <span>DNS misconfigurations can lead to subdomain takeovers</span>
                      </li>
                    </ul>
                  </div>
                  
                  <div>
                    <h4 className="text-lg font-semibold mb-4 text-cybr-primary">Step-by-Step Methodology</h4>
                    <div className="space-y-3">
                      <div className="flex items-start gap-3">
                        <Badge variant="outline" className="text-xs">1</Badge>
                        <span className="text-sm">Start with passive enumeration using certificate transparency logs</span>
                      </div>
                      <div className="flex items-start gap-3">
                        <Badge variant="outline" className="text-xs">2</Badge>
                        <span className="text-sm">Use DNS aggregators and search engines for historical data</span>
                      </div>
                      <div className="flex items-start gap-3">
                        <Badge variant="outline" className="text-xs">3</Badge>
                        <span className="text-sm">Perform active DNS brute forcing with optimized wordlists</span>
                      </div>
                      <div className="flex items-start gap-3">
                        <Badge variant="outline" className="text-xs">4</Badge>
                        <span className="text-sm">Analyze discovered subdomains for takeover opportunities</span>
                      </div>
                      <div className="flex items-start gap-3">
                        <Badge variant="outline" className="text-xs">5</Badge>
                        <span className="text-sm">Perform recursive enumeration on discovered subdomains</span>
                      </div>
                    </div>
                  </div>
                </div>

                <Separator />

                {/* Enumeration Techniques */}
                <div>
                  <h4 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Search className="h-5 w-5 text-cybr-primary" />
                    Enumeration Techniques & Tools
                  </h4>
                  
                  <div className="space-y-6">
                    {/* Passive Enumeration */}
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">Passive Enumeration</h5>
                      <div className="grid md:grid-cols-2 gap-4">
                        <div className="bg-cybr-muted/20 p-4 rounded-lg">
                          <h6 className="font-medium mb-2">Certificate Transparency</h6>
                          <div className="font-mono text-sm space-y-1">
                            <div className="text-green-400"># Using crt.sh</div>
                            <div>curl "https://crt.sh/?q=%.example.com&output=json"</div>
                            <div className="text-green-400"># Using Amass</div>
                            <div>amass enum -passive -d example.com</div>
                          </div>
                        </div>
                        
                        <div className="bg-cybr-muted/20 p-4 rounded-lg">
                          <h6 className="font-medium mb-2">DNS Aggregators</h6>
                          <div className="font-mono text-sm space-y-1">
                            <div className="text-green-400"># Using Subfinder</div>
                            <div>subfinder -d example.com -silent</div>
                            <div className="text-green-400"># Using Assetfinder</div>
                            <div>echo example.com | assetfinder --subs-only</div>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Active Enumeration */}
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">Active Enumeration</h5>
                      <div className="grid md:grid-cols-2 gap-4">
                        <div className="bg-cybr-muted/20 p-4 rounded-lg">
                          <h6 className="font-medium mb-2">DNS Brute Forcing</h6>
                          <div className="font-mono text-sm space-y-1">
                            <div className="text-green-400"># Using Gobuster</div>
                            <div>gobuster dns -d example.com -w wordlist.txt</div>
                            <div className="text-green-400"># Using Amass Active</div>
                            <div>amass enum -active -d example.com -brute</div>
                          </div>
                        </div>
                        
                        <div className="bg-cybr-muted/20 p-4 rounded-lg">
                          <h6 className="font-medium mb-2">Zone Transfer Attempts</h6>
                          <div className="font-mono text-sm space-y-1">
                            <div className="text-green-400"># Using dig</div>
                            <div>dig axfr @ns1.example.com example.com</div>
                            <div className="text-green-400"># Using dnsrecon</div>
                            <div>dnsrecon -d example.com -t axfr</div>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Subdomain Takeover Detection */}
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">Subdomain Takeover Detection</h5>
                      <div className="bg-cybr-muted/20 p-4 rounded-lg">
                        <div className="font-mono text-sm space-y-2">
                          <div className="text-green-400"># Using SubOver</div>
                          <div>python3 subover.py -l subdomains.txt -t 50</div>
                          <div className="text-green-400"># Using Can I Take Over XYZ</div>
                          <div>python3 takeover.py -d example.com -t 20</div>
                          <div className="text-green-400"># Manual CNAME check</div>
                          <div>dig subdomain.example.com CNAME</div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Technology Stack Identification */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Layers className="h-6 w-6 text-cybr-primary" />
                  Technology Stack Identification
                </CardTitle>
                <CardDescription>
                  Comprehensive web application fingerprinting and technology detection
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                
                <div className="grid lg:grid-cols-2 gap-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-4 text-cybr-primary">Why Technology Fingerprinting is Critical</h4>
                    <ul className="space-y-2 text-cybr-foreground/90">
                      <li className="flex items-start gap-2">
                        <Target className="h-4 w-4 text-cybr-primary mt-1 flex-shrink-0" />
                        <span>Identifies specific vulnerabilities associated with technologies</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <Bug className="h-4 w-4 text-cybr-primary mt-1 flex-shrink-0" />
                        <span>Reveals version information for known exploit targeting</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <Code className="h-4 w-4 text-cybr-primary mt-1 flex-shrink-0" />
                        <span>Exposes framework-specific attack vectors and techniques</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <Settings className="h-4 w-4 text-cybr-primary mt-1 flex-shrink-0" />
                        <span>Helps understand the application architecture and flow</span>
                      </li>
                    </ul>
                  </div>
                  
                  <div>
                    <h4 className="text-lg font-semibold mb-4 text-cybr-primary">Detection Methodology</h4>
                    <div className="space-y-3">
                      <div className="flex items-start gap-3">
                        <Badge variant="outline" className="text-xs">1</Badge>
                        <span className="text-sm">Analyze HTTP headers for server signatures</span>
                      </div>
                      <div className="flex items-start gap-3">
                        <Badge variant="outline" className="text-xs">2</Badge>
                        <span className="text-sm">Examine HTML source code for framework indicators</span>
                      </div>
                      <div className="flex items-start gap-3">
                        <Badge variant="outline" className="text-xs">3</Badge>
                        <span className="text-sm">Identify JavaScript libraries and frameworks</span>
                      </div>
                      <div className="flex items-start gap-3">
                        <Badge variant="outline" className="text-xs">4</Badge>
                        <span className="text-sm">Check for default files and directory structures</span>
                      </div>
                      <div className="flex items-start gap-3">
                        <Badge variant="outline" className="text-xs">5</Badge>
                        <span className="text-sm">Analyze cookies and session management patterns</span>
                      </div>
                    </div>
                  </div>
                </div>

                <Separator />

                {/* Fingerprinting Techniques */}
                <div>
                  <h4 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Code className="h-5 w-5 text-cybr-primary" />
                    Advanced Fingerprinting Techniques
                  </h4>
                  
                  <div className="space-y-6">
                    {/* HTTP Header Analysis */}
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">HTTP Header Analysis</h5>
                      <div className="bg-cybr-muted/20 p-4 rounded-lg">
                        <div className="font-mono text-sm space-y-2">
                          <div className="text-green-400"># Common server headers revealing technology</div>
                          <div>Server: Apache/2.4.41 (Ubuntu)</div>
                          <div>X-Powered-By: PHP/7.4.3</div>
                          <div>X-AspNet-Version: 4.0.30319</div>
                          <div>Set-Cookie: JSESSIONID=... (Java/Tomcat)</div>
                          <div>X-Generator: Drupal 9</div>
                          <div>X-Frame-Options: SAMEORIGIN</div>
                        </div>
                      </div>
                    </div>

                    {/* Framework-specific Indicators */}
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">Framework-specific Indicators</h5>
                      <div className="grid md:grid-cols-2 gap-4">
                        <div className="bg-cybr-muted/20 p-4 rounded-lg">
                          <h6 className="font-medium mb-2">WordPress Indicators</h6>
                          <div className="font-mono text-sm space-y-1">
                            <div>/wp-content/</div>
                            <div>/wp-includes/</div>
                            <div>/wp-admin/</div>
                            <div>meta name="generator" content="WordPress"</div>
                          </div>
                        </div>
                        
                        <div className="bg-cybr-muted/20 p-4 rounded-lg">
                          <h6 className="font-medium mb-2">React/Angular Indicators</h6>
                          <div className="font-mono text-sm space-y-1">
                            <div>_next/ (Next.js)</div>
                            <div>ng-version (Angular)</div>
                            <div>react-root (React)</div>
                            <div>__webpack_require__</div>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Automated Tools */}
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">Automated Detection Tools</h5>
                      <div className="grid md:grid-cols-3 gap-4">
                        {[
                          { 
                            tool: 'Wappalyzer', 
                            usage: 'Browser extension or CLI',
                            example: 'wappalyzer https://example.com'
                          },
                          { 
                            tool: 'WhatWeb', 
                            usage: 'Command-line scanner',
                            example: 'whatweb https://example.com'
                          },
                          { 
                            tool: 'BuiltWith', 
                            usage: 'Online service & API',
                            example: 'builtwith.com lookup'
                          },
                          { 
                            tool: 'Retire.js', 
                            usage: 'JavaScript library scanner',
                            example: 'retire --url https://example.com'
                          },
                          { 
                            tool: 'Nuclei', 
                            usage: 'Template-based scanner',
                            example: 'nuclei -u https://example.com -t tech-detect/'
                          },
                          { 
                            tool: 'Nmap Scripts', 
                            usage: 'HTTP enumeration scripts',
                            example: 'nmap --script http-enum target'
                          }
                        ].map((item, index) => (
                          <div key={index} className="bg-cybr-muted/20 p-3 rounded-lg">
                            <h6 className="font-medium text-cybr-primary mb-1">{item.tool}</h6>
                            <p className="text-xs text-cybr-foreground/80 mb-2">{item.usage}</p>
                            <div className="font-mono text-xs text-green-400">{item.example}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Content Discovery */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FileText className="h-6 w-6 text-cybr-primary" />
                  Advanced Content Discovery
                </CardTitle>
                <CardDescription>
                  Comprehensive directory and file enumeration techniques
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                
                <Alert>
                  <Info className="h-4 w-4" />
                  <AlertDescription>
                    Content discovery is crucial for finding hidden admin panels, backup files, development environments, 
                    and forgotten endpoints that may contain vulnerabilities or sensitive information.
                  </AlertDescription>
                </Alert>

                <div className="grid lg:grid-cols-2 gap-6">
                  <div>
                    <h4 className="text-lg font-semibold mb-4 text-cybr-primary">Why Content Discovery is Effective</h4>
                    <ul className="space-y-2 text-cybr-foreground/90">
                      <li className="flex items-start gap-2">
                        <Eye className="h-4 w-4 text-orange-500 mt-1 flex-shrink-0" />
                        <span>Developers often leave debug/test files accessible</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <Archive className="h-4 w-4 text-orange-500 mt-1 flex-shrink-0" />
                        <span>Backup files may contain source code or credentials</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <Settings className="h-4 w-4 text-orange-500 mt-1 flex-shrink-0" />
                        <span>Admin interfaces are often hidden but not secured</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <FileText className="h-4 w-4 text-orange-500 mt-1 flex-shrink-0" />
                        <span>Documentation files may reveal system architecture</span>
                      </li>
                    </ul>
                  </div>
                  
                  <div>
                    <h4 className="text-lg font-semibold mb-4 text-cybr-primary">Discovery Methodology</h4>
                    <div className="space-y-3">
                      <div className="flex items-start gap-3">
                        <Badge variant="outline" className="text-xs">1</Badge>
                        <span className="text-sm">Start with robots.txt and sitemap.xml analysis</span>
                      </div>
                      <div className="flex items-start gap-3">
                        <Badge variant="outline" className="text-xs">2</Badge>
                        <span className="text-sm">Use technology-specific wordlists for targeted discovery</span>
                      </div>
                      <div className="flex items-start gap-3">
                        <Badge variant="outline" className="text-xs">3</Badge>
                        <span className="text-sm">Perform recursive directory enumeration</span>
                      </div>
                      <div className="flex items-start gap-3">
                        <Badge variant="outline" className="text-xs">4</Badge>
                        <span className="text-sm">Check for common backup file extensions</span>
                      </div>
                      <div className="flex items-start gap-3">
                        <Badge variant="outline" className="text-xs">5</Badge>
                        <span className="text-sm">Analyze JavaScript for hidden endpoints</span>
                      </div>
                    </div>
                  </div>
                </div>

                <Separator />

                {/* Discovery Tools and Techniques */}
                <div>
                  <h4 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Terminal className="h-5 w-5 text-cybr-primary" />
                    Discovery Tools and Payload Examples
                  </h4>
                  
                  <div className="space-y-6">
                    {/* Basic Directory Enumeration */}
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">Basic Directory Enumeration</h5>
                      <div className="grid md:grid-cols-2 gap-4">
                        <div className="bg-cybr-muted/20 p-4 rounded-lg">
                          <h6 className="font-medium mb-2">Gobuster</h6>
                          <div className="font-mono text-sm space-y-1">
                            <div className="text-green-400"># Directory enumeration</div>
                            <div>gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt</div>
                            <div className="text-green-400"># With extensions</div>
                            <div>gobuster dir -u http://example.com -w wordlist.txt -x php,html,txt</div>
                          </div>
                        </div>
                        
                        <div className="bg-cybr-muted/20 p-4 rounded-lg">
                          <h6 className="font-medium mb-2">FFuF</h6>
                          <div className="font-mono text-sm space-y-1">
                            <div className="text-green-400"># Fast directory fuzzing</div>
                            <div>ffuf -w wordlist.txt -u http://example.com/FUZZ</div>
                            <div className="text-green-400"># With filtering</div>
                            <div>ffuf -w wordlist.txt -u http://example.com/FUZZ -fc 404</div>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Advanced Enumeration */}
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">Advanced Enumeration Techniques</h5>
                      <div className="grid md:grid-cols-2 gap-4">
                        <div className="bg-cybr-muted/20 p-4 rounded-lg">
                          <h6 className="font-medium mb-2">JavaScript Endpoint Discovery</h6>
                          <div className="font-mono text-sm space-y-1">
                            <div className="text-green-400"># Using LinkFinder</div>
                            <div>python3 linkfinder.py -i http://example.com -o cli</div>
                            <div className="text-green-400"># Using JSParser</div>
                            <div>python3 jsparser.py -u http://example.com</div>
                          </div>
                        </div>
                        
                        <div className="bg-cybr-muted/20 p-4 rounded-lg">
                          <h6 className="font-medium mb-2">Backup File Discovery</h6>
                          <div className="font-mono text-sm space-y-1">
                            <div className="text-green-400"># Common backup extensions</div>
                            <div>index.php.bak, config.php~</div>
                            <div>database.sql.old, .DS_Store</div>
                            <div>web.config.bak, .git/</div>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Wordlist Strategy */}
                    <div>
                      <h5 className="font-medium mb-3 text-cybr-primary">Wordlist Strategy & Examples</h5>
                      <div className="bg-cybr-muted/20 p-4 rounded-lg">
                        <div className="grid md:grid-cols-3 gap-4 text-sm">
                          <div>
                            <h6 className="font-medium mb-2 text-cybr-primary">Common Directories</h6>
                            <div className="font-mono space-y-1">
                              <div>admin, administrator</div>
                              <div>backup, backups</div>
                              <div>config, configuration</div>
                              <div>test, testing, dev</div>
                              <div>api, v1, v2</div>
                              <div>uploads, files</div>
                            </div>
                          </div>
                          <div>
                            <h6 className="font-medium mb-2 text-cybr-primary">Technology-Specific</h6>
                            <div className="font-mono space-y-1">
                              <div>wp-admin (WordPress)</div>
                              <div>phpmyadmin (PHP)</div>
                              <div>manager (Tomcat)</div>
                              <div>console (JBoss)</div>
                              <div>admin (Django)</div>
                              <div>api/v1 (REST APIs)</div>
                            </div>
                          </div>
                          <div>
                            <h6 className="font-medium mb-2 text-cybr-primary">Sensitive Files</h6>
                            <div className="font-mono space-y-1">
                              <div>robots.txt</div>
                              <div>sitemap.xml</div>
                              <div>.htaccess</div>
                              <div>web.config</div>
                              <div>package.json</div>
                              <div>composer.json</div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Environment-Specific Considerations */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Cloud className="h-6 w-6 text-cybr-primary" />
                  Environment-Specific Reconnaissance
                </CardTitle>
                <CardDescription>
                  Tailored approaches for different development environments and deployment scenarios
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                
                <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
                  {/* Cloud Environments */}
                  <Card className="border-cybr-muted/30">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-base flex items-center gap-2">
                        <Cloud className="h-4 w-4 text-blue-500" />
                        Cloud Environments
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div>
                        <h6 className="font-medium mb-2 text-cybr-primary">AWS-specific</h6>
                        <div className="text-sm space-y-1">
                          <p>• S3 bucket enumeration</p>
                          <p>• CloudFront distributions</p>
                          <p>• EC2 metadata service</p>
                          <p>• Lambda function discovery</p>
                        </div>
                      </div>
                      <div>
                        <h6 className="font-medium mb-2 text-cybr-primary">Azure-specific</h6>
                        <div className="text-sm space-y-1">
                          <p>• Blob storage containers</p>
                          <p>• App service enumeration</p>
                          <p>• Key vault discovery</p>
                          <p>• Function app identification</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  {/* Development Environments */}
                  <Card className="border-cybr-muted/30">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-base flex items-center gap-2">
                        <Code className="h-4 w-4 text-green-500" />
                        Development Environments
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div>
                        <h6 className="font-medium mb-2 text-cybr-primary">Common Patterns</h6>
                        <div className="text-sm space-y-1">
                          <p>• dev.example.com</p>
                          <p>• staging.example.com</p>
                          <p>• test.example.com</p>
                          <p>• beta.example.com</p>
                        </div>
                      </div>
                      <div>
                        <h6 className="font-medium mb-2 text-cybr-primary">Git Repositories</h6>
                        <div className="text-sm space-y-1">
                          <p>• .git directory exposure</p>
                          <p>• GitHub/GitLab repositories</p>
                          <p>• Docker registry exposure</p>
                          <p>• CI/CD pipeline artifacts</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  {/* Mobile & IoT */}
                  <Card className="border-cybr-muted/30">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-base flex items-center gap-2">
                        <Smartphone className="h-4 w-4 text-purple-500" />
                        Mobile & IoT
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div>
                        <h6 className="font-medium mb-2 text-cybr-primary">Mobile APIs</h6>
                        <div className="text-sm space-y-1">
                          <p>• API endpoint discovery</p>
                          <p>• Version-specific paths</p>
                          <p>• Deep linking schemes</p>
                          <p>• Push notification services</p>
                        </div>
                      </div>
                      <div>
                        <h6 className="font-medium mb-2 text-cybr-primary">IoT Devices</h6>
                        <div className="text-sm space-y-1">
                          <p>• Default web interfaces</p>
                          <p>• Firmware update endpoints</p>
                          <p>• Configuration panels</p>
                          <p>• Device management APIs</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>

                <Separator />

                {/* Practical Examples */}
                <div>
                  <h4 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Terminal className="h-5 w-5 text-cybr-primary" />
                    Practical Reconnaissance Workflow
                  </h4>
                  
                  <div className="bg-cybr-muted/20 p-6 rounded-lg">
                    <div className="space-y-4">
                      <div className="flex items-start gap-4">
                        <Badge className="bg-cybr-primary/20 text-cybr-primary">Phase 1</Badge>
                        <div className="flex-1">
                          <h5 className="font-medium mb-2">Passive Information Gathering</h5>
                          <div className="font-mono text-sm bg-black/20 p-3 rounded">
                            <div className="text-green-400"># Start with basic domain information</div>
                            <div>whois example.com</div>
                            <div>dig example.com ANY</div>
                            <div>curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value'</div>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-start gap-4">
                        <Badge className="bg-cybr-primary/20 text-cybr-primary">Phase 2</Badge>
                        <div className="flex-1">
                          <h5 className="font-medium mb-2">Subdomain Enumeration</h5>
                          <div className="font-mono text-sm bg-black/20 p-3 rounded">
                            <div className="text-green-400"># Comprehensive subdomain discovery</div>
                            <div>amass enum -passive -d example.com</div>
                            <div>subfinder -d example.com -silent | httpx -silent</div>
                            <div>gobuster dns -d example.com -w subdomains.txt</div>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-start gap-4">
                        <Badge className="bg-cybr-primary/20 text-cybr-primary">Phase 3</Badge>
                        <div className="flex-1">
                          <h5 className="font-medium mb-2">Technology Identification</h5>
                          <div className="font-mono text-sm bg-black/20 p-3 rounded">
                            <div className="text-green-400"># Identify technologies and versions</div>
                            <div>whatweb https://example.com</div>
                            <div>wappalyzer https://example.com</div>
                            <div>nmap -sV -sC -p 80,443 example.com</div>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-start gap-4">
                        <Badge className="bg-cybr-primary/20 text-cybr-primary">Phase 4</Badge>
                        <div className="flex-1">
                          <h5 className="font-medium mb-2">Content Discovery</h5>
                          <div className="font-mono text-sm bg-black/20 p-3 rounded">
                            <div className="text-green-400"># Discover hidden content and endpoints</div>
                            <div>gobuster dir -u https://example.com -w common.txt</div>
                            <div>ffuf -w wordlist.txt -u https://example.com/FUZZ -fc 404</div>
                            <div>python3 linkfinder.py -i https://example.com -o cli</div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

          </div>
        </TabsContent>

        {/* Placeholder for other tabs */}
        <TabsContent value="enumeration" className="space-y-8">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Database className="h-6 w-6 text-cybr-primary" />
                Deep Enumeration Techniques
              </CardTitle>
              <CardDescription>
                Advanced enumeration methodologies for comprehensive security assessment
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-cybr-foreground/80">
                Deep enumeration content will be expanded in the next phase...
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="exploitation" className="space-y-8">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Target className="h-6 w-6 text-cybr-primary" />
                Advanced Exploitation Techniques
              </CardTitle>
              <CardDescription>
                Sophisticated exploitation methods and attack chain development
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-cybr-foreground/80">
                Advanced exploitation content will be expanded in the next phase...
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="persistence" className="space-y-8">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-6 w-6 text-cybr-primary" />
                Persistence & Evasion Techniques
              </CardTitle>
              <CardDescription>
                Maintaining access and evading detection mechanisms
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-cybr-foreground/80">
                Persistence and evasion content will be expanded in the next phase...
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="pivoting" className="space-y-8">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Network className="h-6 w-6 text-cybr-primary" />
                Lateral Movement Techniques
              </CardTitle>
              <CardDescription>
                Advanced techniques for network traversal and privilege escalation
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-cybr-foreground/80">
                Lateral movement content will be expanded in the next phase...
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="exfiltration" className="space-y-8">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Archive className="h-6 w-6 text-cybr-primary" />
                Data Exfiltration Techniques
              </CardTitle>
              <CardDescription>
                Advanced methods for data extraction and covert channels
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-cybr-foreground/80">
                Data exfiltration content will be expanded in the next phase...
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="reporting" className="space-y-8">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileText className="h-6 w-6 text-cybr-primary" />
                Advanced Reporting Methodologies
              </CardTitle>
              <CardDescription>
                Professional reporting standards and documentation techniques
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-cybr-foreground/80">
                Advanced reporting content will be expanded in the next phase...
              </p>
            </CardContent>
          </Card>
        </TabsContent>

      </Tabs>
    </div>
  );
};

export default AdvancedContentSection;
