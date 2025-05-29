
import React from 'react';
import CodeExample from '@/components/CodeExample';

const CSRFPreventionStrategies: React.FC = () => {
  return (
    <div>
      <h4 className="text-xl font-semibold mb-4">Comprehensive CSRF Prevention Strategies</h4>
      
      <div className="space-y-6">
        {/* Primary Defenses */}
        <div>
          <h5 className="text-lg font-semibold mb-3">Primary Defense Mechanisms</h5>
          
          <div className="p-4 bg-cybr-muted/50 rounded-md mb-4">
            <h6 className="font-medium mb-2">1. Synchronizer Token Pattern (CSRF Tokens)</h6>
            <p className="text-sm mb-3">
              The most robust CSRF protection involves generating unique, unpredictable tokens for each user session 
              and validating these tokens on every state-changing request. This method is effective because attackers 
              cannot guess or obtain these tokens through cross-site requests due to the Same-Origin Policy.
            </p>
            
            <div className="font-medium text-sm mb-2">Implementation Best Practices:</div>
            <ul className="list-disc pl-6 space-y-1 text-xs mb-3">
              <li>Generate cryptographically secure random tokens with sufficient entropy (at least 128 bits)</li>
              <li>Use a different token for each form or session, never reuse tokens</li>
              <li>Store tokens server-side tied to the user's session</li>
              <li>Validate tokens on every state-changing request (POST, PUT, DELETE)</li>
              <li>Implement token expiration to limit the window of vulnerability</li>
              <li>Use constant-time comparison to prevent timing attacks</li>
            </ul>
            
            <CodeExample
              language="javascript"
              title="CSRF Token Implementation"
              code={`// Express.js with CSRF protection
const express = require('express');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const session = require('express-session');

const app = express();
app.use(cookieParser());

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
}));

// Setup CSRF protection
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
});

// Apply CSRF protection to all state-changing routes
app.use('/api/', csrfProtection);

// Provide CSRF token to client applications
app.get('/api/csrf-token', (req, res) => {
  res.json({ 
    csrfToken: req.csrfToken(),
    expires: new Date(Date.now() + 3600000) // 1 hour
  });
});

// Protected endpoint example
app.post('/api/transfer', csrfProtection, (req, res) => {
  const { recipient, amount } = req.body;
  
  if (!recipient || !amount || amount <= 0) {
    return res.status(400).json({ error: 'Invalid transfer parameters' });
  }
  
  try {
    processTransfer(req.user.id, recipient, amount);
    res.json({ success: true, message: 'Transfer completed successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Transfer failed' });
  }
});`}
            />
          </div>
          
          <div className="p-4 bg-cybr-muted/50 rounded-md mb-4">
            <h6 className="font-medium mb-2">2. SameSite Cookie Attribute</h6>
            <p className="text-sm mb-3">
              The SameSite attribute provides browser-enforced protection against CSRF attacks by controlling 
              when cookies are sent with cross-site requests. This modern approach can significantly reduce 
              CSRF attack surface when properly configured.
            </p>
            
            <div className="font-medium text-sm mb-2">SameSite Values and Their Impact:</div>
            <ul className="list-disc pl-6 space-y-1 text-xs mb-3">
              <li><strong>Strict:</strong> Cookies never sent with cross-site requests, maximum protection but may break legitimate workflows</li>
              <li><strong>Lax:</strong> Cookies sent with top-level navigation but not with embedded requests, good balance of security and usability</li>
              <li><strong>None:</strong> Cookies sent with all cross-site requests, requires Secure flag and HTTPS</li>
            </ul>
            
            <CodeExample
              language="javascript"
              title="SameSite Cookie Configuration"
              code={`// Express.js session configuration with SameSite
const session = require('express-session');

app.use(session({
  secret: process.env.SESSION_SECRET,
  name: 'sessionId', // Don't use default session name
  cookie: {
    httpOnly: true, // Prevent XSS access to cookies
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    sameSite: 'strict', // Strongest CSRF protection
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    domain: '.example.com' // Explicit domain setting
  },
  resave: false,
  saveUninitialized: false
}));

// Manual cookie setting with SameSite
app.post('/login', (req, res) => {
  // Authenticate user...
  
  const token = generateSecureToken();
  
  // Set authentication cookie with proper security attributes
  res.cookie('auth-token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 8 * 60 * 60 * 1000, // 8 hours
    path: '/',
    domain: process.env.COOKIE_DOMAIN
  });
  
  res.json({ success: true, message: 'Login successful' });
});`}
            />
          </div>
          
          <div className="p-4 bg-cybr-muted/50 rounded-md mb-4">
            <h6 className="font-medium mb-2">3. Custom Headers for CSRF Protection</h6>
            <p className="text-sm mb-3">
              Custom headers provide an additional layer of CSRF protection by leveraging the Same-Origin Policy. 
              Browsers prevent cross-site requests from setting custom headers, making this an effective defense 
              for AJAX-heavy applications and APIs.
            </p>
            
            <CodeExample
              language="javascript"
              title="Custom Headers Implementation"
              code={`// Client-side: Add custom header to all AJAX requests
class CSRFProtectedAPI {
  constructor() {
    this.csrfToken = this.getCSRFToken();
    this.apiBaseUrl = '/api';
  }
  
  getCSRFToken() {
    const metaToken = document.querySelector('meta[name="csrf-token"]');
    return metaToken ? metaToken.getAttribute('content') : null;
  }
  
  async makeSecureRequest(endpoint, options = {}) {
    const defaultHeaders = {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      'X-CSRF-Token': this.csrfToken
    };
    
    const requestOptions = {
      ...options,
      headers: {
        ...defaultHeaders,
        ...options.headers
      },
      credentials: 'include'
    };
    
    const response = await fetch(this.apiBaseUrl + endpoint, requestOptions);
    
    if (!response.ok) {
      if (response.status === 403) {
        throw new Error('CSRF protection triggered');
      }
      throw new Error('HTTP ' + response.status + ': ' + response.statusText);
    }
    
    return await response.json();
  }
}

// Server-side: Validate custom headers
function requireCustomHeaders(req, res, next) {
  if (!req.headers['x-requested-with']) {
    return res.status(400).json({ 
      error: 'Missing required header: X-Requested-With'
    });
  }
  
  if (req.headers['x-requested-with'] !== 'XMLHttpRequest') {
    return res.status(400).json({ 
      error: 'Invalid X-Requested-With header value'
    });
  }
  
  next();
}

app.use('/api/', requireCustomHeaders);`}
            />
          </div>
          
          <div className="p-4 bg-cybr-muted/50 rounded-md mb-4">
            <h6 className="font-medium mb-2">4. Origin and Referer Validation</h6>
            <p className="text-sm mb-3">
              Origin and Referer header validation provides an additional defensive layer by ensuring requests 
              originate from expected domains. While not foolproof due to potential header spoofing or missing headers, 
              this validation can effectively block many CSRF attacks when implemented correctly.
            </p>
            
            <CodeExample
              language="javascript"
              title="Origin Validation Implementation"
              code={`// Origin validation middleware
function validateOrigin(req, res, next) {
  const origin = req.headers.origin;
  const host = req.headers.host;
  const allowedOrigins = ['https://app.example.com', 'https://admin.example.com'];
  
  // For same-origin requests, origin might be undefined
  if (!origin) {
    const referer = req.headers.referer;
    if (referer) {
      const refererUrl = new URL(referer);
      if (refererUrl.host === host) {
        return next(); // Same-origin request
      }
    }
    
    return res.status(403).json({ 
      error: 'Origin header required'
    });
  }
  
  // Validate against allowed origins
  if (!allowedOrigins.includes(origin)) {
    return res.status(403).json({ 
      error: 'Origin ' + origin + ' not allowed'
    });
  }
  
  next();
}

app.use('/api/sensitive/', validateOrigin);`}
            />
          </div>
        </div>
        
        {/* Secondary Defenses */}
        <div>
          <h5 className="text-lg font-semibold mb-3">Secondary Defense Mechanisms</h5>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h6 className="font-medium mb-2">User Interaction Requirements</h6>
              <p className="text-sm mb-3">
                Requiring explicit user interaction for sensitive operations can prevent automated CSRF attacks. 
                This includes CAPTCHA challenges, password re-authentication, or explicit confirmation steps.
              </p>
              <ul className="list-disc pl-6 space-y-1 text-xs">
                <li>CAPTCHA for high-value operations</li>
                <li>Password re-authentication for sensitive changes</li>
                <li>Email or SMS confirmation for critical actions</li>
                <li>Multi-step confirmation processes</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h6 className="font-medium mb-2">Request Analysis and Monitoring</h6>
              <p className="text-sm mb-3">
                Implementing behavioral analysis and monitoring can help detect and prevent CSRF attacks 
                by identifying unusual request patterns or suspicious activity.
              </p>
              <ul className="list-disc pl-6 space-y-1 text-xs">
                <li>Rate limiting on sensitive endpoints</li>
                <li>Geolocation-based request validation</li>
                <li>Device fingerprinting for anomaly detection</li>
                <li>Real-time monitoring and alerting</li>
              </ul>
            </div>
          </div>
        </div>
        
        {/* Framework-Specific Implementations */}
        <div>
          <h5 className="text-lg font-semibold mb-3">Framework-Specific CSRF Protection</h5>
          
          <div className="p-4 bg-cybr-muted/50 rounded-md">
            <h6 className="font-medium mb-2">Popular Framework Implementations</h6>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <div className="font-medium text-sm mb-1">Backend Frameworks:</div>
                <ul className="list-disc pl-6 space-y-1 text-xs">
                  <li><strong>Django:</strong> Built-in CSRF middleware with csrf_token template tag</li>
                  <li><strong>Ruby on Rails:</strong> protect_from_forgery method with authenticity tokens</li>
                  <li><strong>ASP.NET Core:</strong> Anti-forgery tokens with ValidateAntiForgeryToken</li>
                  <li><strong>Spring Security:</strong> CSRF protection enabled by default in newer versions</li>
                  <li><strong>Laravel:</strong> @csrf Blade directive and automatic validation</li>
                </ul>
              </div>
              <div>
                <div className="font-medium text-sm mb-1">Frontend Frameworks:</div>
                <ul className="list-disc pl-6 space-y-1 text-xs">
                  <li><strong>Angular:</strong> Built-in CSRF protection with HttpClientXsrfModule</li>
                  <li><strong>React:</strong> Manual implementation with libraries like axios interceptors</li>
                  <li><strong>Vue.js:</strong> CSRF token integration with axios or custom implementations</li>
                  <li><strong>jQuery:</strong> Global AJAX setup with CSRF token headers</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CSRFPreventionStrategies;
