
import { Challenge } from './challenge-types';

export const apiSecurityChallenges: Challenge[] = [
  {
    id: 'api-security-1',
    title: 'API Rate Limiting',
    description: 'Compare these two Express.js API implementations. Which one is properly protected against abuse with rate limiting?',
    difficulty: 'medium',
    category: 'API Security',
    languages: ['JavaScript', 'Node.js'],
    type: 'comparison',
    vulnerabilityType: 'Rate Limiting',
    secureCode: `const express = require('express');
const rateLimit = require('express-rate-limit');
const app = express();

// Configure rate limiting middleware
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true, // Return rate limit info in the RateLimit-* headers
  legacyHeaders: false, // Disable the X-RateLimit-* headers
  message: 'Too many requests from this IP, please try again after 15 minutes'
});

// Apply rate limiting to all authentication endpoints
app.use('/api/auth', apiLimiter);

// More strict limiter for login attempts to prevent brute force
const loginLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 login attempts per hour
  message: 'Too many login attempts, please try again later'
});

// Routes
app.use(express.json());

app.post('/api/auth/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  
  // Authentication logic here
  
  res.json({ success: true, token: 'jwt-token' });
});

app.post('/api/auth/register', apiLimiter, (req, res) => {
  // Registration logic here
  res.json({ success: true });
});

app.get('/api/data', (req, res) => {
  // Return data
  res.json({ data: 'This is protected data' });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});`,
    vulnerableCode: `const express = require('express');
const app = express();

// Routes
app.use(express.json());

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  // Authentication logic here
  
  res.json({ success: true, token: 'jwt-token' });
});

app.post('/api/auth/register', (req, res) => {
  // Registration logic here
  res.json({ success: true });
});

app.get('/api/data', (req, res) => {
  // Return data
  res.json({ data: 'This is protected data' });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});`,
    answer: 'secure',
    explanation: "The secure implementation uses express-rate-limit to protect API endpoints from abuse. It implements two types of rate limiting: 1) A general limiter for all authentication endpoints allowing 100 requests per IP in a 15-minute window, and 2) A stricter limiter for login attempts allowing only 5 attempts per hour to prevent brute force attacks. The implementation also returns appropriate HTTP headers to inform clients about rate limits. The vulnerable implementation has no rate limiting, allowing unlimited login attempts and API requests, making it susceptible to brute force attacks, credential stuffing, and DoS attacks."
  },
  {
    id: 'api-security-2',
    title: 'API Authentication',
    description: 'This Python Flask API uses JWT for authentication. Identify any security issues.',
    difficulty: 'hard',
    category: 'API Security',
    languages: ['Python'],
    type: 'single',
    vulnerabilityType: 'Insecure Authentication',
    code: `from flask import Flask, request, jsonify
import jwt
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'

# User database (in-memory for this example)
users = {
    'admin': {'password': 'admin123', 'role': 'admin'},
    'user': {'password': 'user123', 'role': 'user'}
}

@app.route('/login', methods=['POST'])
def login():
    auth = request.json
    
    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({'message': 'Could not verify'}), 401
    
    username = auth.get('username')
    password = auth.get('password')
    
    if username not in users or users[username]['password'] != password:
        return jsonify({'message': 'Invalid credentials'}), 401
    
    # Generate JWT token
    token = jwt.encode({
        'sub': username,
        'role': users[username]['role'],
        'iat': datetime.datetime.utcnow(),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'])
    
    return jsonify({'token': token})

@app.route('/admin', methods=['GET'])
def admin_resource():
    token = request.headers.get('Authorization')
    
    if not token:
        return jsonify({'message': 'Token is missing'}), 401
    
    try:
        # Verify the JWT token
        data = jwt.decode(token, app.config['SECRET_KEY'])
        
        # Check if user is admin
        if data['role'] != 'admin':
            return jsonify({'message': 'Admin access required'}), 403
        
        return jsonify({'message': 'Admin resource accessed successfully'})
    
    except:
        return jsonify({'message': 'Invalid token'}), 401

if __name__ == '__main__':
    app.run(debug=True)`,
    answer: false,
    explanation: "This API has several security issues: 1) The secret key is hardcoded in the code rather than stored in environment variables, 2) Passwords are stored in plaintext, not hashed, 3) The JWT token doesn't specify an algorithm which can lead to the 'alg:none' attack, 4) There's no protection against brute force attacks on the login endpoint, 5) Exception handling is too broad, catching all exceptions without proper logging, 6) The Authorization header doesn't follow the 'Bearer {token}' format standard, 7) There's no CSRF protection, 8) debug=True is enabled in production which can leak sensitive information, and 9) The JWT doesn't include standard claims like 'iss' (issuer) and 'aud' (audience)."
  }
];
