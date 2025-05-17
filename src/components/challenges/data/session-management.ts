
import { Challenge } from './challenge-types';

export const sessionManagementChallenges: Challenge[] = [
  {
    id: 'session-mgmt-1',
    title: 'Insecure Session Configuration',
    description: 'This Express.js code configures session management. What security vulnerability is present?',
    difficulty: 'medium',
    category: 'Broken Authentication',
    languages: ['JavaScript', 'Node.js'],
    type: 'single',
    vulnerabilityType: 'Session Management',
    code: `const express = require('express');
const session = require('express-session');
const app = express();

// Configure express-session middleware
app.use(session({
  name: 'sessionId',
  secret: 'keyboard cat',
  resave: true,
  saveUninitialized: true,
  cookie: {
    httpOnly: false,  // Client-side JavaScript can access the cookie
    maxAge: 31536000000  // Cookie expiration (1 year in milliseconds)
  }
}));

// Routes
app.get('/', (req, res) => {
  if (req.session.views) {
    req.session.views++;
  } else {
    req.session.views = 1;
  }
  
  res.send(\`Views: \${req.session.views}\`);
});

app.get('/login', (req, res) => {
  const { username, password } = req.query;
  
  // Basic authentication (insecure, just for demo)
  if (username === 'admin' && password === 'password') {
    req.session.authenticated = true;
    req.session.user = { id: 1, username: 'admin', role: 'admin' };
    res.redirect('/dashboard');
  } else {
    res.send('Invalid credentials');
  }
});

app.get('/dashboard', (req, res) => {
  if (req.session.authenticated) {
    res.send(\`Welcome to your dashboard, \${req.session.user.username}!\`);
  } else {
    res.redirect('/login');
  }
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});`,
    answer: false,
    explanation: "This session management code has multiple security issues: 1) It sets httpOnly to false, allowing client-side JavaScript to access the session cookie and increasing the risk of XSS attacks stealing session data; 2) It uses an extremely long session timeout (1 year), which increases the window of opportunity for session hijacking; 3) It doesn't set secure: true, meaning cookies will be transmitted over HTTP connections; 4) It uses a hardcoded session secret ('keyboard cat') that should be an environment variable; 5) It sets resave and saveUninitialized to true without considering the security implications; and 6) It doesn't implement CSRF protection for session management. To fix these issues, enable httpOnly, set a reasonable session timeout, enable the secure flag, use a strong randomized secret, and consider the implications of the other session options."
  },
  {
    id: 'session-mgmt-2',
    title: 'JWT Token Security',
    description: 'Compare these two JWT token implementations. Which one follows security best practices?',
    difficulty: 'hard',
    category: 'Broken Authentication',
    languages: ['JavaScript', 'Node.js'],
    type: 'comparison',
    vulnerabilityType: 'JWT Configuration',
    secureCode: `const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const router = express.Router();

// Generate a strong secret key (in practice, this would be in env variables)
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES = '15m'; // Short-lived token

router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Authenticate user (simplified)
    const user = await authenticateUser(username, password);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Create JWT payload (avoid sensitive info)
    const payload = {
      sub: user.id,
      name: user.name,
      role: user.role,
      iat: Math.floor(Date.now() / 1000)
    };
    
    // Sign JWT with appropriate settings
    const token = jwt.sign(payload, JWT_SECRET, {
      expiresIn: JWT_EXPIRES,
      algorithm: 'HS256',
      jwtid: crypto.randomBytes(16).toString('hex'), // Unique token ID
      audience: 'api.myservice.com',
      issuer: 'auth.myservice.com'
    });
    
    // Set refresh token (for token renewal)
    setRefreshToken(user.id, res);
    
    return res.json({ 
      token,
      expiresIn: JWT_EXPIRES
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Authentication failed' });
  }
});

module.exports = router;`,
    vulnerableCode: `const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();

// Hardcoded secret
const JWT_SECRET = 'super-secret-key-123';

router.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // Basic authentication (simplified)
  if (username === 'admin' && password === 'password123') {
    // Create JWT with user data
    const payload = {
      id: 1,
      username: 'admin',
      password: password, // Including sensitive data
      role: 'admin',
      isAdmin: true
    };
    
    // Sign token
    const token = jwt.sign(
      payload,
      JWT_SECRET,
      { expiresIn: '365d' } // Very long expiration
    );
    
    return res.json({ token });
  }
  
  return res.status(401).json({ error: 'Invalid credentials' });
});

module.exports = router;`,
    answer: 'secure',
    explanation: "The secure implementation follows JWT best practices by: 1) Using a strong randomly-generated secret key (ideally stored in environment variables); 2) Setting a short token expiration time (15 minutes) to minimize damage from token theft; 3) Including only necessary user data in the payload (no sensitive information); 4) Using specific JWT claims like 'sub', 'iat', 'aud', and 'iss'; 5) Adding a unique token ID ('jwtid') to prevent token reuse; and 6) Implementing refresh tokens for a better user experience without compromising security. The vulnerable implementation has several issues: It uses a weak hardcoded secret, includes the user's password in the token payload, sets a long expiration period (365 days), and lacks critical JWT claims for proper validation. These mistakes expose the application to various attacks, including token forgery, information disclosure, and extended exploitation windows if a token is compromised."
  }
];
