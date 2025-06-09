
import React from 'react';
import { Code } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const APIVulnerabilities: React.FC = () => {
  return (
    <section id="api" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">API Vulnerabilities</h3>
      
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">What Attackers Try to Achieve</h4>
        <p className="mb-4">
          Modern applications heavily rely on APIs (Application Programming Interfaces) to communicate between 
          components and services. Attackers targeting API vulnerabilities aim to:
        </p>
        <ul className="list-disc pl-6 space-y-2 mb-6">
          <li><strong>Data Breach</strong>: Access sensitive user data, business information, or system configurations</li>
          <li><strong>Privilege Escalation</strong>: Gain administrative access through broken authorization checks</li>
          <li><strong>Service Disruption</strong>: Overwhelm APIs with requests to cause denial of service</li>
          <li><strong>Business Logic Bypass</strong>: Circumvent application workflows and business rules</li>
          <li><strong>System Compromise</strong>: Use APIs as entry points for deeper system penetration</li>
          <li><strong>Data Manipulation</strong>: Modify, delete, or corrupt critical business data</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Vulnerable Components</h4>
        <ul className="list-disc pl-6 space-y-2 mb-6">
          <li><strong>API Endpoints</strong>: Improperly secured REST, GraphQL, or SOAP endpoints</li>
          <li><strong>Authentication Mechanisms</strong>: Weak or bypassed API authentication systems</li>
          <li><strong>Authorization Logic</strong>: Flawed access control implementations</li>
          <li><strong>Input Validation</strong>: Missing or insufficient data validation and sanitization</li>
          <li><strong>Rate Limiting</strong>: Absent or inadequate request throttling mechanisms</li>
          <li><strong>Error Handling</strong>: Verbose error messages revealing system information</li>
          <li><strong>Documentation</strong>: Exposed API documentation revealing attack vectors</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Why API Attacks Work</h4>
        <ul className="list-disc pl-6 space-y-2 mb-6">
          <li><strong>Broken Object Level Authorization</strong>: APIs don't verify if users can access specific resources</li>
          <li><strong>Excessive Data Exposure</strong>: APIs return more data than necessary, revealing sensitive information</li>
          <li><strong>Mass Assignment</strong>: APIs accept and process unintended object properties</li>
          <li><strong>Security Misconfiguration</strong>: Default configurations, unnecessary endpoints, or improper CORS settings</li>
          <li><strong>Insufficient Logging</strong>: Lack of monitoring makes attacks difficult to detect</li>
          <li><strong>Business Logic Flaws</strong>: APIs don't enforce proper business rules and workflows</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Common API Attack Vectors</h4>
        
        <h5 className="text-lg font-medium mb-3">1. Broken Object Level Authorization (BOLA)</h5>
        <p className="mb-4">
          Attackers manipulate object identifiers to access resources belonging to other users.
        </p>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <p className="font-semibold mb-2">Attack Examples:</p>
          <pre className="text-sm bg-cybr-muted p-2 rounded">
{`# Accessing other user's data
GET /api/users/123/profile    # Legitimate request
GET /api/users/456/profile    # Attack - accessing user 456's data
GET /api/users/1/profile      # Attack - accessing admin profile

# Parameter manipulation
POST /api/orders
{
  "user_id": 123,    # Original user
  "user_id": 1       # Modified to admin user
}

# Path traversal in API
GET /api/files/user123/document.pdf
GET /api/files/../admin/secret.pdf`}
          </pre>
        </div>

        <h5 className="text-lg font-medium mb-3">2. Excessive Data Exposure</h5>
        <p className="mb-4">
          APIs return complete data objects, allowing attackers to extract sensitive information.
        </p>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <p className="font-semibold mb-2">Attack Scenarios:</p>
          <pre className="text-sm bg-cybr-muted p-2 rounded">
{`# API returns full user object including sensitive data
GET /api/users/profile
Response:
{
  "id": 123,
  "name": "John Doe",
  "email": "john@example.com",
  "password_hash": "$2b$10$...",     # Should not be exposed
  "ssn": "123-45-6789",             # Sensitive data
  "credit_card": "4111-1111-1111-1111", # Should not be exposed
  "internal_notes": "VIP customer",  # Internal data
  "admin": false
}`}
          </pre>
        </div>

        <h5 className="text-lg font-medium mb-3">3. Mass Assignment</h5>
        <p className="mb-4">
          APIs accept and process object properties that should not be modifiable by users.
        </p>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <p className="font-semibold mb-2">Attack Payloads:</p>
          <pre className="text-sm bg-cybr-muted p-2 rounded">
{`# User registration with privilege escalation
POST /api/users/register
{
  "name": "Attacker",
  "email": "attacker@evil.com",
  "password": "password123",
  "is_admin": true,        # Mass assignment attack
  "role": "administrator", # Unauthorized field
  "verified": true         # Bypassing email verification
}

# Order manipulation
POST /api/orders
{
  "product_id": 123,
  "quantity": 1,
  "price": 0.01,          # Mass assignment to change price
  "discount": 100,        # Unauthorized discount
  "shipping_fee": 0       # Removing shipping fees
}`}
          </pre>
        </div>

        <h5 className="text-lg font-medium mb-3">4. Lack of Rate Limiting</h5>
        <p className="mb-4">
          APIs without proper rate limiting are vulnerable to brute force and DoS attacks.
        </p>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <p className="font-semibold mb-2">Attack Methods:</p>
          <pre className="text-sm bg-cybr-muted p-2 rounded">
{`# Brute force login attempts
for password in password_list:
    POST /api/auth/login
    {
      "username": "admin",
      "password": password
    }

# Resource enumeration
for i in range(1, 10000):
    GET f"/api/users/{i}/profile"
    # Enumerate all user profiles

# DoS through resource exhaustion
while True:
    POST /api/search
    {
      "query": "*",           # Expensive query
      "limit": 999999         # Large result set
    }`}
          </pre>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Step-by-Step Exploitation Process</h4>
        
        <h5 className="text-lg font-medium mb-3">Phase 1: API Discovery and Reconnaissance</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li>Identify API endpoints through documentation, network traffic, or directory enumeration</li>
          <li>Analyze API structure (REST, GraphQL, SOAP) and authentication mechanisms</li>
          <li>Map available endpoints, parameters, and data structures</li>
          <li>Review API documentation if available (Swagger, OpenAPI)</li>
          <li>Identify API versioning schemes and test different versions</li>
        </ol>

        <h5 className="text-lg font-medium mb-3">Phase 2: Authentication and Authorization Testing</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li>Test for authentication bypass techniques</li>
          <li>Analyze token-based authentication implementations</li>
          <li>Test authorization controls with different user roles</li>
          <li>Attempt privilege escalation through parameter manipulation</li>
          <li>Test for session management vulnerabilities</li>
        </ol>

        <h5 className="text-lg font-medium mb-3">Phase 3: Input Validation and Business Logic Testing</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li>Test all input parameters for injection vulnerabilities</li>
          <li>Attempt mass assignment attacks on object properties</li>
          <li>Test for excessive data exposure in API responses</li>
          <li>Validate business logic enforcement and workflow controls</li>
          <li>Test error handling and information disclosure</li>
        </ol>

        <h5 className="text-lg font-medium mb-3">Phase 4: Rate Limiting and DoS Testing</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li>Test for rate limiting on authentication endpoints</li>
          <li>Attempt resource exhaustion through expensive operations</li>
          <li>Test for proper handling of concurrent requests</li>
          <li>Validate timeout and resource limit enforcement</li>
        </ol>
      </div>

      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable API Implementation" 
        code={`// Vulnerable Express.js API with multiple security issues
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const app = express();

app.use(express.json());

// In-memory database (simplified)
const users = [
  { id: 1, username: 'admin', password: 'admin123', role: 'admin', ssn: '123-45-6789' },
  { id: 2, username: 'user1', password: 'password', role: 'user', ssn: '987-65-4321' }
];

const orders = [
  { id: 1, user_id: 1, product: 'Laptop', price: 1000, status: 'completed' },
  { id: 2, user_id: 2, product: 'Phone', price: 500, status: 'pending' }
];

// Vulnerable: No authentication required
app.get('/api/users/:userId/profile', (req, res) => {
  const userId = parseInt(req.params.userId);
  
  // Vulnerable: No authorization check - any user can access any profile
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  // Vulnerable: Excessive data exposure - returns sensitive information
  res.json(user); // Includes password, SSN, etc.
});

// Vulnerable: No rate limiting on login endpoint
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  // Vulnerable: No input validation
  const user = users.find(u => u.username === username && u.password === password);
  
  if (!user) {
    // Vulnerable: Information disclosure through different error messages
    const userExists = users.find(u => u.username === username);
    if (userExists) {
      return res.status(401).json({ error: 'Invalid password' });
    } else {
      return res.status(404).json({ error: 'User not found' });
    }
  }
  
  // Vulnerable: Simple token that can be easily guessed
  const token = Buffer.from(\`\${user.id}:\${Date.now()}\`).toString('base64');
  
  res.json({ token, user: user }); // Exposing full user object
});

// Vulnerable: Mass assignment vulnerability
app.post('/api/users/register', (req, res) => {
  // Vulnerable: Accepts all properties from request body
  const newUser = {
    id: users.length + 1,
    ...req.body  // Mass assignment - attacker can set any property
  };
  
  users.push(newUser);
  
  // Vulnerable: Returns created user with potential sensitive data
  res.status(201).json(newUser);
});

// Vulnerable: No proper authorization
app.get('/api/orders/:orderId', (req, res) => {
  const orderId = parseInt(req.params.orderId);
  
  // Vulnerable: No check if user can access this order
  const order = orders.find(o => o.id === orderId);
  
  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }
  
  res.json(order);
});

// Vulnerable: No input validation and expensive operation
app.post('/api/search', (req, res) => {
  const { query, limit } = req.body;
  
  // Vulnerable: No validation on limit - could cause DoS
  // Vulnerable: No protection against expensive queries
  const results = users.filter(user => 
    user.username.includes(query) || user.role.includes(query)
  ).slice(0, limit || 1000);
  
  res.json(results);
});

app.listen(3000, () => {
  console.log('Vulnerable API server running on port 3000');
});`} 
      />

      <div className="mb-6">
        <p className="font-semibold mb-2">Attack Payloads for Above Code:</p>
        <div className="bg-red-900/20 p-4 rounded-lg">
          <pre className="text-sm">
{`# 1. BOLA Attack - Access any user's profile
GET /api/users/1/profile    # Access admin profile
GET /api/users/2/profile    # Access other user's profile

# 2. Mass Assignment Attack - Register as admin
POST /api/users/register
{
  "username": "attacker",
  "password": "password123",
  "role": "admin",          # Escalate privileges
  "id": 999,               # Set custom ID
  "is_verified": true      # Bypass verification
}

# 3. Information Disclosure - Username enumeration
POST /api/auth/login
{
  "username": "admin",
  "password": "wrong"      # Returns "Invalid password"
}

POST /api/auth/login
{
  "username": "nonexistent",
  "password": "wrong"      # Returns "User not found"
}

# 4. DoS Attack - Resource exhaustion
POST /api/search
{
  "query": "",
  "limit": 999999          # Causes memory exhaustion
}`}
          </pre>
        </div>
      </div>
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure API Implementation" 
        code={`// Secure Express.js API implementation
const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { body, param, validationResult } = require('express-validator');

const app = express();

// Security middleware
app.use(helmet());
app.use(express.json({ limit: '10mb' }));

// Rate limiting configuration
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP'
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 login attempts per windowMs
  message: 'Too many login attempts'
});

app.use('/api/', generalLimiter);

// Secure database simulation with hashed passwords
const users = [
  { 
    id: 1, 
    username: 'admin', 
    password: '$2b$10$...',  // Hashed password
    role: 'admin' 
  },
  { 
    id: 2, 
    username: 'user1', 
    password: '$2b$10$...',  // Hashed password
    role: 'user' 
  }
];

const orders = [
  { id: 1, user_id: 1, product: 'Laptop', price: 1000, status: 'completed' },
  { id: 2, user_id: 2, product: 'Phone', price: 500, status: 'pending' }
];

// Authentication middleware
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const token = authHeader.substring(7);
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Authorization middleware
function authorize(requiredRole) {
  return (req, res, next) => {
    if (req.user.role !== requiredRole && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// Secure user profile endpoint with proper authorization
app.get('/api/users/:userId/profile', 
  authenticate,
  param('userId').isInt({ min: 1 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const userId = parseInt(req.params.userId);
    
    // Authorization check: users can only access their own profile
    if (req.user.id !== userId && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const user = users.find(u => u.id === userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Return only safe user data
    const safeUserData = {
      id: user.id,
      username: user.username,
      role: user.role
      // Sensitive data like password, SSN are not included
    };
    
    res.json(safeUserData);
  }
);

// Secure login endpoint with rate limiting
app.post('/api/auth/login',
  authLimiter,
  [
    body('username').isString().trim().isLength({ min: 1, max: 50 }).escape(),
    body('password').isString().isLength({ min: 1, max: 100 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { username, password } = req.body;
    
    try {
      const user = users.find(u => u.username === username);
      
      if (!user) {
        // Use constant-time comparison to prevent timing attacks
        await bcrypt.compare(password, '$2b$10$invalidhashedpasswordforvirtualuser');
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      const isValidPassword = await bcrypt.compare(password, user.password);
      
      if (!isValidPassword) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      // Generate secure JWT token
      const token = jwt.sign(
        { 
          id: user.id, 
          username: user.username, 
          role: user.role 
        },
        process.env.JWT_SECRET,
        { 
          expiresIn: '1h',
          algorithm: 'HS256'
        }
      );
      
      // Return only necessary data
      res.json({ 
        token,
        user: {
          id: user.id,
          username: user.username,
          role: user.role
        }
      });
      
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ error: 'Authentication failed' });
    }
  }
);

// Secure user registration with input validation
app.post('/api/users/register',
  [
    body('username').isString().trim().isLength({ min: 3, max: 30 }).escape(),
    body('email').isEmail().normalizeEmail(),
    body('password').isString().isLength({ min: 8, max: 100 })
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage('Password must contain uppercase, lowercase, number and special character')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    // Only allow specific fields (prevent mass assignment)
    const { username, email, password } = req.body;
    
    // Check if user already exists
    const existingUser = users.find(u => u.username === username || u.email === email);
    if (existingUser) {
      return res.status(409).json({ error: 'User already exists' });
    }
    
    try {
      const hashedPassword = await bcrypt.hash(password, 12);
      
      const newUser = {
        id: users.length + 1,
        username,
        email,
        password: hashedPassword,
        role: 'user', // Default role, cannot be overridden
        created_at: new Date().toISOString()
      };
      
      users.push(newUser);
      
      // Return safe user data (no password)
      const { password: _, ...safeUser } = newUser;
      res.status(201).json(safeUser);
      
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({ error: 'Registration failed' });
    }
  }
);

// Secure order endpoint with proper authorization
app.get('/api/orders/:orderId',
  authenticate,
  param('orderId').isInt({ min: 1 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const orderId = parseInt(req.params.orderId);
    const order = orders.find(o => o.id === orderId);
    
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    // Authorization: users can only access their own orders
    if (order.user_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    res.json(order);
  }
);

// Secure search endpoint with input validation and limits
app.post('/api/search',
  authenticate,
  [
    body('query').isString().trim().isLength({ min: 1, max: 100 }).escape(),
    body('limit').optional().isInt({ min: 1, max: 50 })
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { query, limit = 10 } = req.body;
    
    // Implement efficient search with proper limits
    const results = users
      .filter(user => user.username.toLowerCase().includes(query.toLowerCase()))
      .slice(0, Math.min(limit, 50)) // Enforce maximum limit
      .map(user => ({
        id: user.id,
        username: user.username
        // Only return safe data
      }));
    
    res.json({ results, total: results.length });
  }
);

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('API Error:', error);
  
  // Don't expose internal error details
  res.status(500).json({ 
    error: 'Internal server error',
    requestId: req.id // For debugging purposes
  });
});

app.listen(3000, () => {
  console.log('Secure API server running on port 3000');
});`} 
      />

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Testing for API Vulnerabilities</h4>
        
        <h5 className="text-lg font-medium mb-3">Manual Testing Methodology</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li><strong>API Discovery</strong>
            <ul className="list-disc pl-6 mt-2 space-y-1">
              <li>Use Burp Suite or OWASP ZAP to intercept API calls</li>
              <li>Check for API documentation endpoints (swagger.json, openapi.json)</li>
              <li>Enumerate endpoints through directory brute-forcing</li>
              <li>Analyze JavaScript files for API endpoint references</li>
            </ul>
          </li>
          <li><strong>Authentication Testing</strong>
            <ul className="list-disc pl-6 mt-2 space-y-1">
              <li>Test authentication bypass techniques</li>
              <li>Analyze token implementation (JWT, OAuth, API keys)</li>
              <li>Test for weak authentication credentials</li>
              <li>Verify proper session management</li>
            </ul>
          </li>
          <li><strong>Authorization Testing</strong>
            <ul className="list-disc pl-6 mt-2 space-y-1">
              <li>Test for BOLA by manipulating object identifiers</li>
              <li>Test for privilege escalation through parameter manipulation</li>
              <li>Verify proper role-based access controls</li>
              <li>Test for horizontal and vertical privilege escalation</li>
            </ul>
          </li>
          <li><strong>Input Validation Testing</strong>
            <ul className="list-disc pl-6 mt-2 space-y-1">
              <li>Test for injection vulnerabilities (SQL, NoSQL, Command)</li>
              <li>Test for mass assignment vulnerabilities</li>
              <li>Verify proper data type validation</li>
              <li>Test for buffer overflow and size limit validation</li>
            </ul>
          </li>
        </ol>

        <h5 className="text-lg font-medium mb-3">Automated Testing Tools</h5>
        <ul className="list-disc pl-6 space-y-2 mb-4">
          <li><strong>OWASP ZAP</strong>: Free security scanner with API testing capabilities</li>
          <li><strong>Burp Suite Professional</strong>: Commercial web application security scanner</li>
          <li><strong>Postman</strong>: API development and testing platform with security testing features</li>
          <li><strong>REST API Fuzzer</strong>: Specialized tool for API fuzzing</li>
          <li><strong>APICheck</strong>: Open-source API security testing toolkit</li>
          <li><strong>Astra</strong>: API security scanning and testing platform</li>
          <li><strong>42Crunch</strong>: API security platform with static and dynamic analysis</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Prevention and Secure Implementation</h4>
        
        <h5 className="text-lg font-medium mb-3">Core Security Principles</h5>
        <ul className="list-disc pl-6 space-y-2 mb-4">
          <li><strong>Authentication and Authorization</strong>: Implement proper authentication and fine-grained authorization</li>
          <li><strong>Input Validation</strong>: Validate, sanitize, and whitelist all input data</li>
          <li><strong>Rate Limiting</strong>: Implement comprehensive rate limiting and throttling</li>
          <li><strong>Least Privilege</strong>: Return only necessary data and grant minimal required permissions</li>
          <li><strong>Security Headers</strong>: Implement proper HTTP security headers</li>
          <li><strong>Encryption</strong>: Use HTTPS for all API communications</li>
          <li><strong>Monitoring</strong>: Implement comprehensive logging and monitoring</li>
        </ul>

        <h5 className="text-lg font-medium mb-3">Environment-Specific Considerations</h5>
        
        <div className="mb-4">
          <h6 className="font-medium mb-2">Development Environment</h6>
          <ul className="list-disc pl-6 space-y-1">
            <li>Use API gateway for centralized security controls</li>
            <li>Implement automated security testing in CI/CD pipelines</li>
            <li>Use environment variables for sensitive configuration</li>
            <li>Enable detailed logging for security testing</li>
          </ul>
        </div>

        <div className="mb-4">
          <h6 className="font-medium mb-2">Production Environment</h6>
          <ul className="list-disc pl-6 space-y-1">
            <li>Deploy behind a Web Application Firewall (WAF)</li>
            <li>Implement real-time monitoring and alerting</li>
            <li>Use API management platforms for advanced security features</li>
            <li>Regular security assessments and penetration testing</li>
          </ul>
        </div>

        <div className="mb-4">
          <h6 className="font-medium mb-2">Cloud Environments</h6>
          <ul className="list-disc pl-6 space-y-1">
            <li>Leverage cloud-native security services (AWS API Gateway, Azure API Management)</li>
            <li>Implement proper IAM policies and service-to-service authentication</li>
            <li>Use service mesh for secure inter-service communication</li>
            <li>Enable cloud security monitoring and compliance tools</li>
          </ul>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Special Cases and Advanced Scenarios</h4>
        
        <h5 className="text-lg font-medium mb-3">GraphQL APIs</h5>
        <p className="mb-4">
          GraphQL APIs present unique challenges including query complexity attacks, introspection vulnerabilities, 
          and nested query depth issues requiring specialized security measures.
        </p>
        
        <h5 className="text-lg font-medium mb-3">Microservices Architecture</h5>
        <p className="mb-4">
          Microservices require special attention to service-to-service authentication, API gateway security, 
          and distributed authorization patterns.
        </p>
        
        <h5 className="text-lg font-medium mb-3">Third-Party API Integration</h5>
        <p className="mb-4">
          Integrating with external APIs introduces risks including data leakage, credential exposure, 
          and dependency on third-party security controls.
        </p>

        <h5 className="text-lg font-medium mb-3">Mobile API Considerations</h5>
        <p className="mb-4">
          Mobile applications require special API security considerations including certificate pinning, 
          token refresh mechanisms, and protection against reverse engineering.
        </p>
      </div>
    </section>
  );
};

export default APIVulnerabilities;
