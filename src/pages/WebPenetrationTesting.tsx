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

                    {/* XML External Entity */}
                    <section id="xxe" className="scroll-mt-20">
                      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">XML External Entity (XXE)</h3>
                      <p className="mb-6">
                        XML External Entity (XXE) attacks occur when an application processes XML from untrusted sources without
                        properly disabling external entity references. Attackers can exploit vulnerable XML processors to access
                        local files, perform server-side request forgery, internal port scanning, or remote code execution.
                      </p>
                      
                      <h4 className="text-xl font-semibold mt-6 mb-3">Example Attack</h4>
                      <CodeExample 
                        language="xml" 
                        isVulnerable={true}
                        title="Malicious XXE Payload" 
                        code={`<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<userInfo>
  <firstName>John</firstName>
  <lastName>&xxe;</lastName>
</userInfo>

<!-- When processed, this XML will try to read /etc/passwd and include its contents
     in the lastName field, potentially revealing sensitive system information -->`} 
                      />
                      
                      <CodeExample 
                        language="javascript" 
                        isVulnerable={false}
                        title="Secure XML Processing" 
                        code={`// Disable XXE in Java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

// Disable XXE in PHP
libxml_disable_entity_loader(true);

// Disable XXE in .NET
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;`} 
                      />
                    </section>

                    {/* Insecure Deserialization */}
                    <section id="deserial" className="scroll-mt-20">
                      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Insecure Deserialization</h3>
                      <p className="mb-6">
                        Insecure deserialization occurs when an application deserializes untrusted data without sufficient verification,
                        allowing attackers to manipulate serialized objects to achieve harmful results, including remote code execution.
                        This vulnerability can lead to serious attacks like authentication bypass, privilege escalation, and injection attacks.
                      </p>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                        <SecurityCard
                          title="Immediate Impact"
                          description="Remote code execution, application crashes, and complex replay attacks that bypass authentication and authorization."
                          severity="high"
                        />
                        <SecurityCard
                          title="Vulnerable Languages"
                          description="Java, PHP, Python, and .NET are commonly affected due to their powerful serialization frameworks."
                          severity="high"
                        />
                      </div>
                      
                      <CodeExample 
                        language="php" 
                        isVulnerable={true}
                        title="Vulnerable PHP Deserialization" 
                        code={`<?php
// Vulnerable code accepts serialized object from user
$userData = unserialize($_COOKIE['user_data']);

// Attacker-controlled cookie might contain:
// O:8:"UserInfo":2:{s:8:"username";s:5:"admin";s:5:"admin";b:1;}
// This could create an object with unauthorized admin privileges
?>`} 
                      />
                      
                      <CodeExample 
                        language="javascript" 
                        isVulnerable={false}
                        title="Safe Alternative" 
                        code={`// Use JSON instead of serialized objects
const userData = JSON.parse(cookie);

// Explicitly validate data after parsing
if (!isValidUserData(userData)) {
  throw new Error("Invalid user data");
}

// Explicitly set properties from the validated data
const user = {
  username: userData.username,
  // Don't directly copy admin flag from user input
};

// Check permissions through proper authorization system
const isAdmin = authorizationService.isAdmin(user.username);`} 
                      />
                    </section>

                    {/* Command Injection */}
                    <section id="cmd-injection" className="scroll-mt-20">
                      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Command Injection</h3>
                      <p className="mb-6">
                        Command injection occurs when an application passes unsafe user-supplied data to a system shell. 
                        Attackers can inject operating system commands to execute arbitrary code on the host server,
                        potentially leading to complete system compromise.
                      </p>
                      
                      <h4 className="text-xl font-semibold mt-6 mb-3">Example Attack</h4>
                      <CodeExample 
                        language="javascript" 
                        isVulnerable={true}
                        title="Vulnerable Implementation" 
                        code={`// Node.js example with command injection vulnerability
const { exec } = require('child_process');

app.get('/ping', (req, res) => {
  const host = req.query.host;
  // Vulnerable: user input directly concatenated into command
  exec('ping -c 4 ' + host, (error, stdout, stderr) => {
    res.send(stdout);
  });
});

// Attacker input: 8.8.8.8; cat /etc/passwd
// This will ping 8.8.8.8 and then output the passwd file`} 
                      />
                      
                      <CodeExample 
                        language="javascript" 
                        isVulnerable={false}
                        title="Secure Implementation" 
                        code={`// Using a safer method with parameter validation
const { execFile } = require('child_process');
const validator = require('validator');

app.get('/ping', (req, res) => {
  const host = req.query.host;
  
  // Validate input is a valid IP address or hostname
  if (!validator.isIP(host) && !validator.isFQDN(host)) {
    return res.status(400).send('Invalid host format');
  }
  
  // execFile doesn't invoke a shell and treats arguments separately
  execFile('ping', ['-c', '4', host], (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send('Error executing ping');
    }
    res.send(stdout);
  });
});`} 
                      />
                    </section>

                    {/* Security Misconfigurations */}
                    <section id="misconfig" className="scroll-mt-20">
                      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Security Misconfigurations</h3>
                      <p className="mb-6">
                        Security misconfigurations include improperly configured permissions, unnecessary features enabled, 
                        default accounts/passwords, overly informative error messages, and missing security hardening. 
                        These are often the result of insecure default configurations, incomplete configurations, or ad hoc changes.
                      </p>
                      
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                        <SecurityCard
                          title="Default Configurations"
                          description="Using default settings from sample applications, cloud services, or pre-configured development environments."
                          severity="high"
                        />
                        <SecurityCard
                          title="Unnecessary Features"
                          description="Unused features and frameworks that expand attack surface without providing value."
                          severity="medium"
                        />
                        <SecurityCard
                          title="Missing Updates"
                          description="Unpatched flaws in the application stack, including OS, web server, DBMS, and libraries."
                          severity="high"
                        />
                      </div>
                      
                      <h4 className="text-xl font-semibold mt-6 mb-3">Common Misconfigurations</h4>
                      <ul className="list-disc pl-6 space-y-2">
                        <li>Directory listing enabled on the server</li>
                        <li>Default or weak credentials for administrative interfaces</li>
                        <li>Application servers with debug mode enabled in production</li>
                        <li>Missing HTTP security headers or improper CORS settings</li>
                        <li>Error messages revealing stack traces or sensitive information</li>
                        <li>Outdated or vulnerable system components</li>
                        <li>Unnecessary services running on the server</li>
                      </ul>
                    </section>

                    {/* Path Traversal */}
                    <section id="file-traversal" className="scroll-mt-20">
                      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">File Inclusion/Path Traversal</h3>
                      <p className="mb-6">
                        Path traversal (also known as directory traversal) attacks exploit insufficient input validation to 
                        access files and directories
