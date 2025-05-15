
import { Challenge } from './challenge-types';

export const jwtSecurityChallenges: Challenge[] = [
  {
    id: 'jwt-security-1',
    title: 'JWT Algorithm Confusion',
    description: 'Review this Node.js JWT verification code. What security vulnerability is present?',
    difficulty: 'hard',
    category: 'Broken Authentication',
    languages: ['JavaScript', 'Node.js'],
    type: 'multiple-choice',
    vulnerabilityType: 'JWT Algorithm Confusion',
    code: `const jwt = require('jsonwebtoken');
const fs = require('fs');

// Load public key for verification
const publicKey = fs.readFileSync('public.pem');

function verifyToken(token) {
  try {
    // Verify the JWT token
    const decoded = jwt.verify(token, publicKey);
    return { valid: true, payload: decoded };
  } catch (error) {
    return { valid: false, error: error.message };
  }
}

// Express middleware to authenticate requests
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }
  
  const result = verifyToken(token);
  
  if (!result.valid) {
    return res.status(403).json({ message: 'Invalid token', error: result.error });
  }
  
  // Set user info for the request
  req.user = result.payload;
  next();
}`,
    options: [
      'The code uses fs.readFileSync which blocks the event loop',
      'No algorithm is specified in jwt.verify, allowing algorithm confusion attacks',
      'The public key is loaded only once, causing memory issues',
      'The token is not properly extracted from the Authorization header'
    ],
    answer: 1,
    explanation: "The code is vulnerable to JWT algorithm confusion attacks because it doesn't specify which algorithm should be used in the jwt.verify() call. An attacker could create a token using a symmetric algorithm (like HS256) with the public key as the secret. Since the public key is publicly available, the attacker can sign their own tokens. To fix this, explicitly specify the expected algorithm: jwt.verify(token, publicKey, { algorithms: ['RS256'] })."
  }
];
