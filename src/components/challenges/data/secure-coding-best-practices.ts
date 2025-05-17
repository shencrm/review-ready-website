
import { Challenge } from './challenge-types';

export const securecodingBestPracticesChallenges: Challenge[] = [
  {
    id: 'secure-coding-bp-1',
    title: 'Secure Password Storage',
    description: 'Review this Node.js code for storing user passwords. Which security best practice is violated?',
    difficulty: 'medium',
    category: 'Secure Coding',
    languages: ['JavaScript', 'Node.js'],
    type: 'multiple-choice',
    vulnerabilityType: 'Password Storage',
    code: `const crypto = require('crypto');
const express = require('express');
const router = express.Router();
const db = require('./database');

// User registration endpoint
router.post('/register', async (req, res) => {
  try {
    const { username, password, email } = req.body;
    
    if (!username || !password || !email) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    // Check if user already exists
    const existingUser = await db.users.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ error: 'Username already taken' });
    }
    
    // Create a "secure" hash of the password
    const hash = crypto.createHash('md5').update(password).digest('hex');
    
    // Save user to database
    const newUser = await db.users.insertOne({
      username,
      password: hash,
      email,
      created: new Date()
    });
    
    res.status(201).json({ 
      message: 'User registered successfully',
      userId: newUser.insertedId
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error during registration' });
  }
});

module.exports = router;`,
    options: [
      'Not enforcing password complexity requirements',
      'Using MD5 for password hashing',
      'Not implementing rate limiting on registration',
      'Storing the email address without encryption'
    ],
    answer: 1,
    explanation: "The code uses MD5 for password hashing, which is a critical security vulnerability. MD5 is a fast cryptographic hash function that has been broken and is not suitable for password storage. It lacks both salt (making it vulnerable to rainbow table attacks) and slow computation (making brute-force attempts easier). Modern secure password storage should use specialized password hashing functions like bcrypt, Argon2, or PBKDF2 with appropriate work factors and unique salts for each password. These algorithms are designed to be slow and resource-intensive, making brute force attacks impractical."
  },
  {
    id: 'secure-coding-bp-2',
    title: 'Input Validation Best Practices',
    description: 'Compare these two API implementations for user data processing. Which one implements proper input validation?',
    difficulty: 'easy',
    category: 'Secure Coding',
    languages: ['JavaScript', 'Node.js'],
    type: 'comparison',
    vulnerabilityType: 'Input Validation',
    secureCode: `const express = require('express');
const { body, validationResult } = require('express-validator');
const router = express.Router();

router.post('/users', [
  // Input validation middleware
  body('name').trim().isLength({ min: 2, max: 50 }).withMessage('Name must be between 2 and 50 characters'),
  body('email').trim().isEmail().normalizeEmail().withMessage('Invalid email address'),
  body('age').isInt({ min: 18, max: 120 }).withMessage('Age must be a number between 18 and 120'),
  body('role').isIn(['user', 'admin', 'editor']).withMessage('Invalid role specified')
], async (req, res) => {
  // Check for validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  // Process validated data
  try {
    const { name, email, age, role } = req.body;
    
    // Add user to database (using parameterized query)
    const user = await db.users.insert({ name, email, age, role });
    
    res.status(201).json({ 
      message: 'User created successfully',
      userId: user.id
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create user' });
  }
});

module.exports = router;`,
    vulnerableCode: `const express = require('express');
const router = express.Router();

router.post('/users', async (req, res) => {
  try {
    // Extract user data from request body
    const name = req.body.name;
    const email = req.body.email;
    const age = req.body.age;
    const role = req.body.role;
    
    // Basic checks
    if (!name || !email) {
      return res.status(400).json({ error: 'Name and email are required' });
    }
    
    // Add user to database
    const query = \`INSERT INTO users (name, email, age, role) 
                 VALUES ('\${name}', '\${email}', \${age}, '\${role}')\`;
    
    const user = await db.query(query);
    
    res.status(201).json({ 
      message: 'User created successfully',
      userId: user.insertId
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create user' });
  }
});

module.exports = router;`,
    answer: 'secure',
    explanation: "The secure implementation properly validates input using express-validator middleware to ensure each field meets specific criteria before processing. It checks that: the name is between 2-50 characters, email is valid and normalized, age is between 18-120, and role is one of the allowed values. Validation errors are returned with clear messages. In contrast, the vulnerable code has minimal validation (only checking if name and email exist), doesn't validate data types or formats, and uses string interpolation to build SQL queries (creating SQL injection vulnerabilities). The secure code prevents various attacks including injection attacks, unexpected data handling errors, and business logic abuse by ensuring data conforms to expected formats."
  }
];
