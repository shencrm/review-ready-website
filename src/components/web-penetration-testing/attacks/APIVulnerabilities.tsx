
import React from 'react';
import { Code } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const APIVulnerabilities: React.FC = () => {
  return (
    <section id="api" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">API Vulnerabilities</h3>
      <p className="mb-6">
        Modern applications heavily rely on APIs (Application Programming Interfaces) to communicate between 
        components and services. API vulnerabilities can expose sensitive data, allow unauthorized actions, 
        or compromise entire systems when not properly secured.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Common API Vulnerabilities</h4>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li><strong>Broken Object Level Authorization</strong>: APIs exposing endpoints that handle object identifiers without proper authorization checks</li>
        <li><strong>Broken Authentication</strong>: Weak authentication mechanisms in API endpoints</li>
        <li><strong>Excessive Data Exposure</strong>: APIs returning more data than necessary</li>
        <li><strong>Lack of Resources & Rate Limiting</strong>: Susceptibility to denial of service attacks</li>
        <li><strong>Improper Input Validation</strong>: Not properly validating and sanitizing input data</li>
      </ul>
      
      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable API Implementation" 
        code={`// Express.js API endpoint with vulnerability
app.get('/api/users/:userId/profile', (req, res) => {
  const userId = req.params.userId;
  
  // Vulnerable: No authorization check
  // Attacker can access any user's data by changing userId
  db.getUserFullProfile(userId)
    .then(profile => {
      // Excessive data exposure: returns all user data
      res.json(profile);
    })
    .catch(err => res.status(500).json({ error: err.message }));
});

// No rate limiting implemented
app.post('/api/login', (req, res) => {
  // Vulnerable to brute force attacks
  authenticateUser(req.body.username, req.body.password)
    .then(token => res.json({ token }))
    .catch(() => res.status(401).json({ error: 'Invalid credentials' }));
});`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure API Implementation" 
        code={`const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

// Authentication middleware
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  
  try {
    const payload = verifyToken(token);
    req.user = payload;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Authorization middleware
function authorize(req, res, next) {
  const requestedUserId = req.params.userId;
  const currentUserId = req.user.id;
  
  // Only allow access to own data or admin access
  if (requestedUserId === currentUserId || req.user.role === 'ADMIN') {
    next();
  } else {
    res.status(403).json({ error: 'Access denied' });
  }
}

// Rate limiting middleware
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 login attempts per window
  message: { error: 'Too many login attempts, please try again later' }
});

// Secure API endpoints
app.get('/api/users/:userId/profile', authenticate, authorize, (req, res) => {
  const userId = req.params.userId;
  
  db.getUserSafeProfile(userId) // Method that returns only necessary data
    .then(profile => {
      res.json(profile);
    })
    .catch(err => res.status(500).json({ error: 'Failed to fetch profile' }));
});

// Input validation and rate limiting
app.post('/api/login', 
  loginLimiter,
  [
    body('username').isString().trim().escape(),
    body('password').isLength({ min: 8 })
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    authenticateUser(req.body.username, req.body.password)
      .then(token => res.json({ token }))
      .catch(() => res.status(401).json({ error: 'Invalid credentials' }));
  }
);`} 
      />
    </section>
  );
};

export default APIVulnerabilities;
