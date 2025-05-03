
import React from 'react';
import { ShieldX } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const CSPBypass: React.FC = () => {
  return (
    <section id="csp" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Content Security Policy (CSP) Bypass</h3>
      <p className="mb-6">
        Content Security Policy (CSP) is a security feature that helps prevent cross-site scripting (XSS) and other code
        injection attacks. CSP bypass techniques exploit weaknesses in CSP configurations to execute malicious code
        despite the protections in place. Understanding these bypasses is crucial for implementing effective security controls.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Common CSP Bypass Techniques</h4>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li><strong>Unsafe Inline</strong>: Using 'unsafe-inline' directive that defeats the purpose of CSP by allowing inline scripts</li>
        <li><strong>JSONP Endpoints</strong>: Exploiting allowlisted domains with JSONP endpoints that allow arbitrary callback execution</li>
        <li><strong>Angular ng-src Bypass</strong>: Exploiting AngularJS template injection with ng-src in applications using Angular</li>
        <li><strong>DOM-based Bypasses</strong>: Using DOM manipulation techniques to bypass CSP through methods like innerHTML</li>
        <li><strong>Iframe Sandbox Bypass</strong>: Exploiting sandbox attribute permissions to execute scripts</li>
        <li><strong>Base-URI Exploitation</strong>: Using an unprotected base-uri directive to change the base URL for relative script paths</li>
        <li><strong>Data URIs</strong>: Utilizing data: URIs when allowed as a source in CSP directives</li>
        <li><strong>Nonce/Hash Leakage</strong>: Exploiting leaked nonce values to execute scripts that would otherwise be blocked</li>
      </ul>
      
      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable CSP Configuration" 
        code={`// Server setting a weak CSP header
app.use((req, res, next) => {
  // Vulnerable: using unsafe-inline and wildcard sources
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' *.trusted-cdn.com;"
  );
  next();
});

// HTML with inline script (allowed by unsafe-inline)
// <script>
//   document.write('<img src="' + location.hash.substring(1) + '" />');
// </script>
//
// Attacker can exploit via URL like:
// https://example.com/page#javascript:alert(document.cookie)

// Another vulnerability: JSONP endpoint on trusted domain
// If trusted-cdn.com hosts a JSONP endpoint:
// https://trusted-cdn.com/jsonp?callback=alert(document.cookie)
// This would be allowed by the CSP

// Vulnerable CSP allowing data URIs
res.setHeader(
  'Content-Security-Policy',
  "default-src 'self'; img-src 'self' data:; script-src 'self';"
);

// Attacker can inject: <img src="data:text/html,<script>alert(1)</script>">

// Missing base-uri directive
res.setHeader(
  'Content-Security-Policy',
  "default-src 'self'; script-src 'self'"
);

// Attacker can inject: <base href="https://evil.com">
// This changes the base for all relative URLs`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure CSP Implementation" 
        code={`// Server setting a strong CSP header
app.use((req, res, next) => {
  // Generate a random nonce for each request
  const cspNonce = crypto.randomBytes(16).toString('base64');
  res.locals.cspNonce = cspNonce;
  
  // Strict CSP with nonce-based script execution
  res.setHeader(
    'Content-Security-Policy',
    \`
      default-src 'none';
      script-src 'self' 'nonce-\${cspNonce}' https://specific-cdn.trusted-site.com;
      style-src 'self' https://specific-cdn.trusted-site.com;
      img-src 'self';
      font-src 'self';
      connect-src 'self' https://api.trusted-site.com;
      frame-src 'none';
      object-src 'none';
      base-uri 'none';
      form-action 'self';
      frame-ancestors 'none';
      block-all-mixed-content;
      upgrade-insecure-requests;
    \`.replace(/\\s+/g, ' ').trim()
  );
  
  next();
});

// In your template engine, use the nonce:
// Express with EJS example:
app.get('/page', (req, res) => {
  res.render('page', {
    nonce: res.locals.cspNonce
  });
});

// In EJS template:
// <script nonce="<%- nonce %>">
//   // Safe script that will execute with correct nonce
// </script>

// Additional security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer-when-downgrade');
  res.setHeader('Feature-Policy', "camera 'none'; microphone 'none'; geolocation 'none'");
  next();
});

// Regularly check CSP with security testing tools
// - Use CSP evaluator: https://csp-evaluator.withgoogle.com/
// - Implement Content-Security-Policy-Report-Only for testing
// - Configure report-uri for CSP violation reporting

// Best practices for protecting against specific bypasses
app.use((req, res, next) => {
  // 1. Avoid wildcards in source directives
  // 2. Avoid 'unsafe-inline' and 'unsafe-eval'
  // 3. Whitelist specific domains instead of using wildcards
  // 4. Use nonces or hashes instead of 'unsafe-inline'
  // 5. Set strict base-uri directive
  // 6. Disable dangerous features with restrictive directives
  // 7. Use CSP Level 3 features like 'strict-dynamic' for compatible browsers
  res.setHeader(
    'Content-Security-Policy',
    \`
      default-src 'none';
      script-src 'strict-dynamic' 'nonce-\${res.locals.cspNonce}' https://specific-cdn.com;
      style-src 'self';
      img-src 'self';
      connect-src 'self';
      base-uri 'self';
      form-action 'self';
      frame-ancestors 'none';
      object-src 'none';
      require-trusted-types-for 'script';
    \`.replace(/\\s+/g, ' ').trim()
  );
  next();
});`} 
      />
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Testing for CSP Bypasses</h4>
      <ul className="list-disc pl-6 space-y-2">
        <li>Analyze the current CSP configuration using tools like CSP Evaluator</li>
        <li>Check for dangerous directives like 'unsafe-inline', 'unsafe-eval', or overly permissive wildcards</li>
        <li>Review all allowlisted domains for JSONP endpoints or other scriptable features</li>
        <li>Test for DOM-based XSS even when CSP is present</li>
        <li>Investigate browser-specific CSP implementations and bypasses</li>
        <li>Look for missing directives (e.g., base-uri, object-src, frame-ancestors)</li>
        <li>Test nonce and hash implementations for proper randomization and usage</li>
      </ul>
    </section>
  );
};

export default CSPBypass;
