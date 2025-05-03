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
        which is then cached and served to other users.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">How Cache Poisoning Works</h4>
      <p className="mb-4">
        Web cache poisoning typically involves two phases:
      </p>
      <ol className="list-decimal pl-6 space-y-2 mb-4">
        <li><strong>Cache Probing</strong>: Identifying how the cache works, which headers are used in the cache key, and which are reflected in responses but not used in the key</li>
        <li><strong>Poisoning</strong>: Sending a request with malicious data in non-keyed inputs that get reflected in the response and cached</li>
      </ol>
      
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

# This response gets cached and served to all users`} 
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
});`} 
      />
    </section>
  );
};

export default WebCachePoisoning;
