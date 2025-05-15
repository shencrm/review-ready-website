
import { Challenge } from './challenge-types';

export const webSecurityChallenges: Challenge[] = [
  {
    id: 'web-security-1',
    title: 'Security Headers Implementation',
    description: 'Review this Express.js middleware that adds security headers. Is it properly implemented?',
    difficulty: 'medium',
    category: 'Web Security',
    languages: ['JavaScript', 'Node.js'],
    type: 'single',
    vulnerabilityType: 'Missing Security Headers',
    code: `const express = require('express');
const app = express();

// Security headers middleware
function securityHeaders(req, res, next) {
  // Set security headers
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  
  // Continue to next middleware
  next();
}

// Apply middleware
app.use(securityHeaders);

// Routes
app.get('/', (req, res) => {
  res.send('Welcome to our secure app!');
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});`,
    answer: true,
    explanation: "This code correctly implements several important security headers: X-XSS-Protection to enable browser XSS filtering, X-Frame-Options to prevent clickjacking, X-Content-Type-Options to prevent MIME type sniffing, and Strict-Transport-Security (HSTS) to enforce HTTPS. The middleware is properly applied using app.use() and correctly calls next() to continue the request pipeline. However, to be even more secure, it could also implement Content-Security-Policy headers to restrict resource loading."
  },
  {
    id: 'web-security-2',
    title: 'Cookie Security Configuration',
    description: 'Compare these two cookie configurations in a Node.js application. Which one has secure settings?',
    difficulty: 'easy',
    category: 'Web Security',
    languages: ['JavaScript', 'Node.js'],
    type: 'comparison',
    vulnerabilityType: 'Insecure Cookie Configuration',
    secureCode: `const express = require('express');
const session = require('express-session');
const app = express();

app.use(session({
  secret: 'a-strong-secret-key-here',
  name: 'sessionId', // Custom name instead of default
  cookie: {
    httpOnly: true,   // Prevents client-side JavaScript access
    secure: true,     // Only sent over HTTPS
    sameSite: 'strict', // Restricts cross-site sending
    maxAge: 3600000,  // Session expires after 1 hour
    path: '/',
    domain: '.example.com',
  },
  resave: false,
  saveUninitialized: false
}));

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});`,
    vulnerableCode: `const express = require('express');
const session = require('express-session');
const app = express();

app.use(session({
  secret: 'secret',
  cookie: {
    maxAge: 86400000 * 30, // 30 days
    path: '/'
  },
  resave: true,
  saveUninitialized: true
}));

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});`,
    answer: 'secure',
    explanation: "The secure version implements multiple cookie security measures: 1) httpOnly flag prevents client-side JavaScript from accessing the cookie, reducing XSS risks, 2) secure flag ensures cookies are only sent over HTTPS, 3) sameSite='strict' prevents CSRF attacks by restricting cross-site cookie sending, 4) custom cookie name hides the technology used, 5) shorter session duration (1 hour vs 30 days), and 6) uses a stronger secret key. The vulnerable version lacks these security controls, making it susceptible to various attacks."
  }
];
