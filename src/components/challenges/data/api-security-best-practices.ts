
import { Challenge } from './challenge-types';

export const apiSecurityBestPracticesChallenges: Challenge[] = [
  {
    id: 'api-security-bp-1',
    title: 'API Rate Limiting Implementation',
    description: 'Review this Express.js API rate limiting implementation. Is it properly secured against abuse?',
    difficulty: 'medium',
    category: 'API Security',
    languages: ['JavaScript', 'Node.js'],
    type: 'single',
    vulnerabilityType: 'Rate Limiting',
    code: `const express = require('express');
const app = express();

// Simple in-memory store for rate limiting
const requestCounts = {};

// Custom rate limiting middleware
const rateLimiter = (req, res, next) => {
  // Get client IP
  const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  
  // Initialize or increment request count
  requestCounts[clientIp] = requestCounts[clientIp] || { count: 0, lastReset: Date.now() };
  
  // Reset count if it's been more than a minute
  if (Date.now() - requestCounts[clientIp].lastReset > 60000) {
    requestCounts[clientIp] = { count: 0, lastReset: Date.now() };
  }
  
  requestCounts[clientIp].count++;
  
  // Check if rate limit exceeded
  if (requestCounts[clientIp].count > 100) {
    return res.status(429).json({ error: 'Rate limit exceeded. Try again later.' });
  }
  
  next();
};

// Apply rate limiting to all routes
app.use(rateLimiter);

// API routes
app.get('/api/data', (req, res) => {
  res.json({ message: 'Here is your data' });
});

app.post('/api/submit', (req, res) => {
  res.json({ message: 'Data received successfully' });
});

app.listen(3000, () => {
  console.log('API server running on port 3000');
});`,
    answer: false,
    explanation: "This API rate limiting implementation has several vulnerabilities: 1) It uses an in-memory store that doesn't scale across multiple servers and will be reset if the server restarts, allowing attackers to circumvent limits; 2) It relies solely on IP addresses from X-Forwarded-For headers which can be spoofed in some configurations; 3) The rate limiting is applied uniformly to all endpoints, not distinguishing between endpoints with different sensitivity levels; 4) There's no token bucket or sliding window algorithm to handle burst traffic appropriately; 5) Memory usage can grow unbounded as more unique IPs access the system, creating a potential DoS vector. A more secure implementation would use a distributed cache like Redis, implement proper token bucket algorithms, vary limits by endpoint sensitivity, and include authentication-based rate limiting alongside IP-based limiting."
  },
  {
    id: 'api-security-bp-2',
    title: 'API Authentication Design',
    description: 'Compare these two API authentication implementations. Which one follows better security practices?',
    difficulty: 'hard',
    category: 'API Security',
    languages: ['JavaScript', 'Node.js'],
    type: 'comparison',
    vulnerabilityType: 'Authentication',
    secureCode: `const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());

// Configure rate limiting for login attempts
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per windowMs per IP
  message: 'Too many login attempts, please try again after 15 minutes',
  standardHeaders: true,
  legacyHeaders: false,
});

// JWT secret using high-entropy value
const JWT_SECRET = process.env.JWT_SECRET;
// JWT expiration time - 15 minutes
const JWT_EXPIRY = '15m';

// Refresh token store with expiry capability
const refreshTokenStore = new Map();

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Validate input
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    // Get user from database (simplified)
    const user = await getUserFromDb(username);
    if (!user) {
      // Use constant-time comparison to prevent timing attacks
      await bcrypt.compare(password, '$2b$10$invalidhashforcomparison');
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Verify password with bcrypt
    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate access token
    const accessToken = jwt.sign(
      { 
        userId: user.id,
        username: user.username,
        // Don't include sensitive data in the token
      },
      JWT_SECRET,
      { 
        expiresIn: JWT_EXPIRY,
        jwtid: crypto.randomBytes(16).toString('hex')
      }
    );
    
    // Generate refresh token with expiry
    const refreshToken = crypto.randomBytes(40).toString('hex');
    const refreshExpiry = Date.now() + (7 * 24 * 60 * 60 * 1000); // 7 days
    
    // Store refresh token with user info and expiry
    refreshTokenStore.set(refreshToken, {
      userId: user.id,
      expires: refreshExpiry,
      family: crypto.randomBytes(16).toString('hex') // For token rotation
    });
    
    // Set HTTP-only cookie with refresh token
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true, 
      secure: true, 
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
    
    // Log authentication event
    console.log(\`User \${user.id} logged in successfully at \${new Date().toISOString()}\`);
    
    // Return access token
    return res.json({ 
      accessToken,
      expiresIn: JWT_EXPIRY,
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Authentication failed' });
  }
});

// Mock function to get user from database
async function getUserFromDb(username) {
  // In a real app, this would query a database
  return { 
    id: 123, 
    username: 'testuser', 
    passwordHash: '$2b$10$X8sCMXNyqa6uOWFxP5hZBeLD0yHkZtGy3NzeUjW3bvUDyOIu.QUNK' 
  };
}

app.listen(3000, () => {
  console.log('API server running on port 3000');
});`,
    vulnerableCode: `const express = require('express');
const app = express();
app.use(express.json());

// Hardcoded API keys
const API_KEYS = {
  'client1': 'secretkey123',
  'client2': 'secretkey456'
};

// Middleware to check API key
const checkApiKey = (req, res, next) => {
  // Get API key from query param or header
  const apiKey = req.query.api_key || req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({ error: 'Missing API key' });
  }
  
  // Check if API key is valid
  let found = false;
  for (const client in API_KEYS) {
    if (API_KEYS[client] === apiKey) {
      found = true;
      break;
    }
  }
  
  if (found) {
    next();
  } else {
    res.status(401).json({ error: 'Invalid API key' });
  }
};

// Add authentication middleware to all routes
app.use(checkApiKey);

// Login endpoint that returns a token
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  // Basic authentication check (simplified)
  if (username === 'admin' && password === 'password123') {
    // Generate simple token
    const token = Buffer.from(\`\${username}:\${Date.now()}\`).toString('base64');
    
    // Set session in memory
    sessions[token] = { username, loggedInAt: Date.now() };
    
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// In-memory session store
const sessions = {};

app.get('/api/data', (req, res) => {
  const token = req.headers.authorization;
  
  if (token && sessions[token]) {
    res.json({ message: 'Here is your data' });
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
});

app.listen(3000, () => {
  console.log('API server running on port 3000');
});`,
    answer: 'secure',
    explanation: "Implementation A (the secure one) demonstrates API authentication best practices including: 1) Using JWT with proper signing and expiration; 2) Implementing rate limiting for login attempts to prevent brute force attacks; 3) Using bcrypt for password hashing with constant-time comparison to prevent timing attacks; 4) Proper HTTP-only, secure cookies for refresh tokens; 5) Token rotation with a token family concept; 6) Environment variables for secrets rather than hardcoded values; 7) Proper error handling and logging. Implementation B has several serious vulnerabilities: 1) Hardcoded API keys in the source code; 2) Insecure comparison of API keys using a loop; 3) API keys transmitted as query parameters which appear in logs; 4) Storing sessions in memory which doesn't scale and is lost on restart; 5) Using a trivially-encoded token that contains predictable information; 6) No token expiration; 7) Hardcoded admin credentials; 8) No rate limiting against brute force attacks."
  }
];
