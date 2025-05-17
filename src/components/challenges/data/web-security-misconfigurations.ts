
import { Challenge } from './challenge-types';

export const webSecurityMisconfigurationsChallenges: Challenge[] = [
  {
    id: 'web-sec-misconfig-1',
    title: 'Insecure HTTP Headers',
    description: 'Review this Express.js server configuration. What security headers are missing?',
    difficulty: 'medium',
    category: 'Security Misconfigurations',
    languages: ['JavaScript', 'Node.js'],
    type: 'multiple-choice',
    vulnerabilityType: 'Missing Security Headers',
    code: `const express = require('express');
const app = express();

// Middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configure some security headers
app.use((req, res, next) => {
  // Cache control
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  
  // Server info
  res.setHeader('Server', 'Apache/2.4.1');
  
  // Basic XSS protection for older browsers
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  next();
});

// Serve static files
app.use(express.static('public'));

// API routes
app.use('/api', require('./routes/api'));

// Start server
app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});`,
    options: [
      'Content-Security-Policy header',
      'X-Frame-Options header',
      'Strict-Transport-Security header',
      'All of the above'
    ],
    answer: 3,
    explanation: "This Express.js server is missing several critical security headers: 1) Content-Security-Policy (CSP) which prevents XSS attacks by controlling which resources can be loaded; 2) X-Frame-Options which prevents clickjacking attacks by controlling whether the page can be embedded in frames; 3) Strict-Transport-Security (HSTS) which enforces secure HTTPS connections. Additionally, the server has a security anti-pattern by falsely identifying as 'Apache/2.4.1' in the Server header, which can help attackers by revealing (misleading) server information. A secure configuration would include these headers and either remove the Server header or use a generic value. Tools like Helmet.js can help implement these headers correctly in Express applications."
  },
  {
    id: 'web-sec-misconfig-2',
    title: 'Excessive Data Exposure in API',
    description: 'This Node.js API endpoint returns user data. What security issue is present?',
    difficulty: 'easy',
    category: 'API Security',
    languages: ['JavaScript', 'Node.js'],
    type: 'single',
    vulnerabilityType: 'Excessive Data Exposure',
    code: `const express = require('express');
const router = express.Router();
const User = require('../models/User');

/**
 * Get user profile
 * GET /api/users/:id
 */
router.get('/users/:id', async (req, res) => {
  try {
    // Verify user is logged in
    if (!req.session.userId) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    // Get requested user from database
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Return user data
    return res.json(user);
    
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;`,
    answer: false,
    explanation: "This API endpoint has a significant security issue: excessive data exposure. It returns the complete user object from the database, potentially including sensitive fields like password hashes, authentication tokens, personal information, or internal system data. There's also no filtering based on user role or relationship - any authenticated user can access any other user's complete data. To fix this, the API should: 1) Implement explicit data filtering to return only necessary non-sensitive fields; 2) Check if the requester has permission to access the requested user's data; and 3) Apply a data transformation layer or DTO (Data Transfer Object) pattern to ensure only appropriate data is exposed. This helps prevent information disclosure vulnerabilities that could lead to account takeovers or privacy breaches."
  },
  {
    id: 'web-sec-misconfig-3',
    title: 'Insecure Cookies Configuration',
    description: 'Compare these two cookie configurations. Which one implements secure cookie practices?',
    difficulty: 'easy',
    category: 'Security Misconfigurations',
    languages: ['JavaScript'],
    type: 'comparison',
    vulnerabilityType: 'Cookie Security',
    secureCode: `const express = require('express');
const app = express();

// Set secure cookie
app.get('/set-cookie', (req, res) => {
  res.cookie('sessionId', 'abc123', {
    httpOnly: true,     // Prevents client-side JavaScript from accessing cookie
    secure: true,       // Only sent over HTTPS
    sameSite: 'strict', // Prevents CSRF by restricting cross-site sending
    maxAge: 3600000,    // Expires after 1 hour (in milliseconds)
    path: '/',          // Accessible across the site
    domain: 'example.com',
    signed: true        // Signs the cookie to detect tampering
  });
  
  res.send('Cookie has been set securely');
});

// Use cookie-parser with a secret for signed cookies
const cookieParser = require('cookie-parser');
app.use(cookieParser('strong-secret-key'));

// Basic route that uses the cookie
app.get('/', (req, res) => {
  const sessionId = req.signedCookies.sessionId;
  
  if (sessionId) {
    res.send(\`Welcome back! Your session ID is \${sessionId}\`);
  } else {
    res.redirect('/set-cookie');
  }
});

app.listen(3000);`,
    vulnerableCode: `const express = require('express');
const app = express();

// Set cookie
app.get('/set-cookie', (req, res) => {
  res.cookie('sessionId', 'abc123', {
    maxAge: 31536000000,  // Expires after 1 year (in milliseconds)
    path: '/'             // Accessible across the site
  });
  
  res.send('Cookie has been set');
});

// Basic route that uses the cookie
app.get('/', (req, res) => {
  const sessionId = req.cookies.sessionId;
  
  if (sessionId) {
    res.send(\`Welcome back! Your session ID is \${sessionId}\`);
  } else {
    res.redirect('/set-cookie');
  }
});

const cookieParser = require('cookie-parser');
app.use(cookieParser());

app.listen(3000);`,
    answer: 'secure',
    explanation: "The secure implementation sets cookies with several important security attributes: 1) httpOnly flag prevents client-side JavaScript from accessing the cookie, protecting against XSS attacks; 2) secure flag ensures the cookie is only transmitted over HTTPS; 3) sameSite='strict' prevents the cookie from being sent in cross-site requests, mitigating CSRF attacks; 4) a reasonable expiration time (1 hour) limits the window of exploitation if a cookie is compromised; and 5) signed cookie validation helps detect tampering. The vulnerable implementation lacks these protections, setting a cookie with an excessive lifetime (1 year) and no security attributes. This makes it vulnerable to various attacks including session hijacking via XSS, man-in-the-middle attacks over HTTP, and cross-site request forgery."
  }
];
