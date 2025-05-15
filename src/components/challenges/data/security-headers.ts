
import { Challenge } from './challenge-types';

export const securityHeadersChallenges: Challenge[] = [
  {
    id: 'security-headers-1',
    title: 'Missing Security Headers',
    description: 'This Express.js middleware adds security headers. Which critical header is missing?',
    difficulty: 'medium',
    category: 'Web Security',
    languages: ['JavaScript', 'Node.js'],
    type: 'multiple-choice',
    vulnerabilityType: 'Missing Security Headers',
    code: `const express = require('express');
const app = express();

// Security headers middleware
app.use((req, res, next) => {
  // Prevent browsers from interpreting files as a different MIME type
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // Prevent clickjacking attacks
  res.setHeader('X-Frame-Options', 'DENY');
  
  // Enable the XSS filter built into most browsers
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  // Prevent all domains from embedding your site in an iframe
  res.setHeader('X-Frame-Options', 'DENY');
  
  // Control DNS prefetching
  res.setHeader('X-DNS-Prefetch-Control', 'off');
  
  // Disable caching for sensitive information
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  
  // Pass to next layer
  next();
});

// Routes
app.get('/', (req, res) => {
  res.send('Hello World');
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});`,
    options: [
      'Strict-Transport-Security (HSTS)',
      'Content-Security-Policy (CSP)',
      'Referrer-Policy',
      'Feature-Policy/Permissions-Policy'
    ],
    answer: 1,
    explanation: "The code is missing the Content-Security-Policy (CSP) header, which is critical for preventing cross-site scripting (XSS) and other code injection attacks. CSP allows you to specify which content sources are approved for your website, significantly mitigating XSS risks by telling the browser exactly which resources are allowed to load. While the code includes X-XSS-Protection, this older header has limitations and is being deprecated in favor of CSP in modern browsers. The middleware also has a duplicate X-Frame-Options header and is missing other useful headers like Referrer-Policy and Strict-Transport-Security, but CSP is the most critical omission for comprehensive security."
  }
];
