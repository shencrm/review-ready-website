
import React from 'react';
import { Bug } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const WebCachePoisoning: React.FC = () => {
  return (
    <section id="cache" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Web Cache Poisoning</h3>
      <p className="mb-6">
        Web cache poisoning is an attack where an attacker manipulates a web cache to serve malicious content to users.
        This occurs when the application includes unvalidated input from request headers or parameters in the response,
        which is then cached and served to other users. Unlike most attacks that target a specific user, cache poisoning
        attacks can affect all users who access the cached resource.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">How Cache Poisoning Works</h4>
      <p className="mb-4">
        Web cache poisoning typically involves two phases:
      </p>
      <ol className="list-decimal pl-6 space-y-2 mb-4">
        <li><strong>Cache Probing</strong>: Identifying how the cache works, which headers are used in the cache key, and which are reflected in responses but not used in the key</li>
        <li><strong>Poisoning</strong>: Sending a request with malicious data in non-keyed inputs that get reflected in the response and cached</li>
      </ol>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Key Concepts in Cache Poisoning</h4>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li><strong>Cache Keys</strong>: Parameters used to identify cached responses (typically URL, host, query parameters)</li>
        <li><strong>Unkeyed Inputs</strong>: Headers or parameters that affect the response but aren't part of the cache key</li>
        <li><strong>Cache Variations</strong>: Different versions of a cached resource based on certain request attributes</li>
        <li><strong>Cache Lifetime</strong>: How long a poisoned response remains in the cache (impact duration)</li>
      </ul>
      
      <CodeExample 
        language="http" 
        isVulnerable={true}
        title="Vulnerable Scenario" 
        code={`# Example request with custom header that will be reflected but not included in cache key
GET /home HTTP/1.1
Host: example.com
X-Forwarded-Host: attacker.com

# The application uses this header for resource loading without validation
# Response might include:
<script src="//attacker.com/malicious.js"></script>

# This response gets cached and served to all users

# Another example - using Vary header to detect unkeyed inputs
GET /api/data HTTP/1.1
Host: example.com
X-Custom-Header: test

# If the response contains a Vary header that doesn't include X-Custom-Header,
# but the header influences the response content, it might be vulnerable

# Example of cache poisoning via HTTP request smuggling
POST / HTTP/1.1
Host: example.com
Content-Length: 128
Transfer-Encoding: chunked

0

GET /api/user HTTP/1.1
X-Forwarded-Host: evil.com
Content-Length: 5

x=1`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Prevention Techniques" 
        code={`// 1. Avoid using unvalidated input in cached responses
app.get('/home', (req, res) => {
  // Don't use user-controllable headers for resource loading
  const safeScriptUrl = 'https://example.com/script.js'; // Hardcoded URL
  
  res.send(\`
    <html>
      <head>
        <script src="\${safeScriptUrl}"></script>
      </head>
      <body>...</body>
    </html>
  \`);
});

// 2. Validate and sanitize all inputs, even headers
app.use((req, res, next) => {
  // Create a whitelist of allowed domains for certain headers
  const trustedHosts = ['example.com', 'static.example.com'];
  
  // Clean potentially dangerous headers
  if (req.headers['x-forwarded-host']) {
    if (!trustedHosts.includes(req.headers['x-forwarded-host'])) {
      // Either remove the header or set to a default trusted value
      req.headers['x-forwarded-host'] = 'example.com';
    }
  }
  
  next();
});

// 3. Configure your cache properly
// Cache-Control header to prevent caching of sensitive content
app.get('/user/profile', (req, res) => {
  res.setHeader('Cache-Control', 'private, no-store');
  // Rest of the handler...
});

// 4. Include all relevant inputs in the cache key
// Configure CDN/reverse proxy to include relevant headers in cache key
// Example Nginx configuration:
/*
proxy_cache_key "$scheme$request_method$host$request_uri$http_x_forwarded_host";
*/

// 5. Use Content-Security-Policy to mitigate damage
app.use((req, res, next) => {
  // Set strict CSP
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' https://trusted-scripts.example.com;"
  );
  next();
});

// 6. Regularly audit and purge caches
function auditAndPurgeCache() {
  // Code to periodically purge cache or when suspicious activity is detected
  cdn.purgeCache('/vulnerable-path/*');
}

// 7. Properly set Vary headers for headers that affect response
app.get('/api/localized-content', (req, res) => {
  // Tell cache to vary responses based on these headers
  res.setHeader('Vary', 'Accept-Language, Accept-Encoding');
  
  // Generate content based on these headers
  const language = req.headers['accept-language'] || 'en';
  const content = getLocalizedContent(language);
  
  res.json(content);
});`} 
      />
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Testing for Cache Poisoning</h4>
      <ul className="list-disc pl-6 space-y-2">
        <li><strong>Identify Caching Behavior:</strong> Check for cache headers like <code>Cache-Control</code> and <code>Vary</code></li>
        <li><strong>Probe for Unkeyed Inputs:</strong> Test different headers to see what affects responses</li>
        <li><strong>Check Cache Keys:</strong> Determine which parameters are used as cache keys</li>
        <li><strong>Test Reflection of Headers:</strong> Look for request headers reflected in responses</li>
        <li><strong>Investigate Cache-Buster Parameters:</strong> Identify parameters that create fresh cache entries</li>
        <li><strong>Test for HTTP Request Smuggling:</strong> Cache poisoning can be combined with request smuggling</li>
      </ul>
    </section>
  );
};

export default WebCachePoisoning;
