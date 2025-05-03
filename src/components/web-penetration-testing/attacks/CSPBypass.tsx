
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
        despite the protections in place.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Common CSP Bypass Techniques</h4>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li><strong>Unsafe Inline</strong>: Using 'unsafe-inline' directive that defeats the purpose of CSP</li>
        <li><strong>JSONP Endpoints</strong>: Exploiting allowlisted domains with JSONP endpoints</li>
        <li><strong>Angular ng-src Bypass</strong>: Exploiting AngularJS template injection with ng-src</li>
        <li><strong>DOM-based Bypasses</strong>: Using DOM manipulation techniques to bypass CSP</li>
        <li><strong>Iframe Sandbox Bypass</strong>: Exploiting sandbox attribute permissions</li>
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
// This would be allowed by the CSP`} 
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
// - Configure report-uri for CSP violation reporting`} 
      />
    </section>
  );
};

export default CSPBypass;
