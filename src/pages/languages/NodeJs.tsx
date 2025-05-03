
import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CodeExample from '@/components/CodeExample';
import { Link } from 'react-router-dom';
import { Shield, Server, Terminal, AlertTriangle } from 'lucide-react';

const NodeJs = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      
      <main className="flex-grow py-12">
        <div className="container mx-auto px-4">
          <div className="mb-12">
            <h1 className="text-4xl font-bold mb-6">Node.js Security</h1>
            <div className="h-1 w-24 bg-cybr-primary mb-6"></div>
            <p className="text-xl text-cybr-foreground/80">
              Security vulnerabilities and best practices for Node.js applications.
            </p>
          </div>
          
          <div className="card mb-8">
            <h2 className="text-2xl font-bold mb-4">About Node.js</h2>
            <p className="mb-4">
              Node.js is an open-source, cross-platform JavaScript runtime environment that executes JavaScript code outside a web browser.
              Created by Ryan Dahl in 2009, Node.js was designed to build scalable network applications by using an event-driven,
              non-blocking I/O model that makes it lightweight and efficient.
            </p>
            <p className="mb-4">
              Unlike traditional server environments where each connection spawns a new thread, consuming system RAM and eventually
              maxing out at the amount of RAM available, Node.js operates on a single-thread using non-blocking I/O calls. This allows
              it to support tens of thousands of concurrent connections without incurring the cost of thread context switching.
            </p>
            <p className="mb-4">
              Node.js has transformed JavaScript from being a browser-only language to a full-stack development platform. It's widely
              used for building backend services (REST APIs, microservices), real-time applications (chat, gaming), command-line tools,
              and even desktop applications. The Node Package Manager (npm) is the world's largest software registry, with millions of
              packages available for developers.
            </p>
            <p>
              However, Node.js applications face unique security challenges. The extensive use of third-party dependencies creates a large
              attack surface through the supply chain. Its asynchronous, event-driven architecture can lead to complex code that's difficult
              to secure. Common security issues include injection vulnerabilities, insecure dependencies, broken authentication, and
              security misconfiguration. Understanding these risks is essential for Node.js developers to build secure applications.
            </p>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 space-y-8">
              <section>
                <h2 className="text-2xl font-bold mb-4">Command Injection</h2>
                <p className="mb-4">
                  Command injection vulnerabilities occur when an application passes untrusted user data to a system shell.
                  In Node.js, this typically happens when using functions like child_process.exec() without proper sanitization.
                </p>
                
                <CodeExample
                  language="javascript"
                  title="Vulnerable Command Injection"
                  code={`// VULNERABLE: Using user input directly in command execution
const { exec } = require('child_process');

app.get('/check-domain', (req, res) => {
  const domain = req.query.domain;
  // Attacker can inject commands using characters like ; | && 
  exec('ping -c 1 ' + domain, (error, stdout, stderr) => {
    res.send(stdout);
  });
});

// Attacker input: "google.com && rm -rf /" could delete files`}
                />
                
                <CodeExample
                  language="javascript"
                  title="Secure Command Execution"
                  code={`// SECURE: Using execFile with arguments as an array
const { execFile } = require('child_process');

app.get('/check-domain', (req, res) => {
  const domain = req.query.domain;
  
  // Validate input first (simple example)
  if (!domain.match(/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\\.[a-zA-Z]{2,})+$/)) {
    return res.status(400).send('Invalid domain');
  }
  
  // execFile doesn't spawn a shell and takes arguments as array
  execFile('ping', ['-c', '1', domain], (error, stdout, stderr) => {
    res.send(stdout);
  });
});`}
                />

                <CodeExample
                  language="javascript"
                  title="Advanced Command Injection Protection"
                  code={`// More advanced solution with validator library
const { exec } = require('child_process');
const validator = require('validator');

app.get('/dns-lookup', (req, res) => {
  let domain = req.query.domain;
  
  // Ensure value is a valid domain
  if (!validator.isFQDN(domain)) {
    return res.status(400).json({ error: 'Invalid domain supplied' });
  }
  
  // Build command securely with validated argument
  const command = 'nslookup';
  const args = [domain];
  
  // Use spawn instead of exec for better control
  const { spawn } = require('child_process');
  const process = spawn(command, args);
  
  let output = '';
  let errorOutput = '';
  
  process.stdout.on('data', (data) => {
    output += data.toString();
  });
  
  process.stderr.on('data', (data) => {
    errorOutput += data.toString();
  });
  
  process.on('close', (code) => {
    if (code !== 0) {
      return res.status(500).json({ error: 'Command failed', details: errorOutput });
    }
    res.json({ result: output });
  });
});`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Path Traversal</h2>
                <p className="mb-4">
                  Path traversal vulnerabilities allow attackers to access files outside of intended directories,
                  potentially exposing sensitive data or configuration files.
                </p>
                
                <CodeExample
                  language="javascript"
                  title="Path Traversal Vulnerability"
                  code={`// VULNERABLE: Reading files with unsanitized user input
const fs = require('fs');
const path = require('path');

app.get('/download-file', (req, res) => {
  const filename = req.query.filename;
  // Vulnerable to path traversal
  const filePath = path.join(PUBLIC_FOLDER, filename);
  
  fs.readFile(filePath, (err, data) => {
    if (err) {
      return res.status(404).send('File not found');
    }
    res.send(data);
  });
});

// Attacker input: "../../../etc/passwd" could read sensitive files`}
                />
                
                <CodeExample
                  language="javascript"
                  title="Secure File Access"
                  code={`// SECURE: Using path.normalize and checking for path traversal
const fs = require('fs');
const path = require('path');

app.get('/download-file', (req, res) => {
  const filename = req.query.filename;
  
  // Normalize the path and check if it starts with the public folder
  const publicFolder = path.resolve(PUBLIC_FOLDER);
  const requestedPath = path.normalize(path.join(publicFolder, filename));
  
  // Check that requested path is inside the public folder
  if (!requestedPath.startsWith(publicFolder)) {
    return res.status(403).send('Access denied');
  }
  
  fs.readFile(requestedPath, (err, data) => {
    if (err) {
      return res.status(404).send('File not found');
    }
    res.send(data);
  });
});`}
                />

                <CodeExample
                  language="javascript"
                  title="Comprehensive Path Traversal Solution"
                  code={`// More comprehensive approach with additional input validation
const fs = require('fs');
const path = require('path');
const sanitize = require('sanitize-filename');

app.get('/serve-file', (req, res) => {
  // Get and sanitize the requested filename - cleans dangerous characters
  let requestedFileName = sanitize(req.query.filename || '');
  
  if (!requestedFileName || requestedFileName === '') {
    return res.status(400).send('Invalid filename');
  }
  
  // Limit to allowed file types only
  const allowedExtensions = ['.txt', '.pdf', '.png', '.jpg', '.jpeg', '.html'];
  const fileExt = path.extname(requestedFileName).toLowerCase();
  
  if (!allowedExtensions.includes(fileExt)) {
    return res.status(403).send('Unauthorized file type');
  }
  
  // Build secure file path
  const publicFolder = path.resolve('./public/files');
  const filePath = path.join(publicFolder, requestedFileName);
  const normalizedPath = path.normalize(filePath);
  
  // Verify final path is still within allowed directory
  if (!normalizedPath.startsWith(publicFolder)) {
    return res.status(403).send('Access forbidden');
  }
  
  // Check that the file exists
  fs.access(normalizedPath, fs.constants.F_OK, (err) => {
    if (err) {
      return res.status(404).send('File not found');
    }
    
    // Set appropriate content type based on file extension
    const mimeTypes = {
      '.txt': 'text/plain',
      '.pdf': 'application/pdf',
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.html': 'text/html'
    };
    
    res.setHeader('Content-Type', mimeTypes[fileExt] || 'application/octet-stream');
    // Use stream reading instead of loading entire file into memory
    fs.createReadStream(normalizedPath).pipe(res);
  });
});`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">HTTP Security Headers & Configuration</h2>
                <p className="mb-4">
                  Proper configuration of HTTP headers is essential for Node.js web applications to prevent a variety of attacks.
                </p>
                
                <CodeExample
                  language="javascript"
                  title="Implementing Secure HTTP Headers"
                  code={`// Secure HTTP headers with Helmet
const express = require('express');
const helmet = require('helmet');
const app = express();

// Apply various security headers
app.use(helmet());

// Or configure headers individually
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'", 'trusted-cdn.com'],
    styleSrc: ["'self'", "'unsafe-inline'", 'trusted-cdn.com'],
    imgSrc: ["'self'", 'data:', 'trusted-cdn.com'],
    connectSrc: ["'self'", 'api.trusted-domain.com'],
    fontSrc: ["'self'", 'trusted-cdn.com'],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
  }
}));

app.use(helmet.xssFilter());
app.use(helmet.noSniff());
app.use(helmet.ieNoOpen());
app.use(helmet.frameguard({ action: 'deny' }));`}
                />

                <CodeExample
                  language="javascript"
                  title="Comprehensive HTTP Security Implementation"
                  code={`// More comprehensive HTTP security configuration
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const app = express();

// Basic settings
app.disable('x-powered-by'); // Remove information disclosure header

// Use Helmet for security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: [],
    }
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: 'same-origin' },
  dnsPrefetchControl: { allow: false },
  expectCt: { maxAge: 86400, enforce: true },
  frameguard: { action: 'deny' },
  hidePoweredBy: true,
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  ieNoOpen: true,
  noSniff: true,
  originAgentCluster: true,
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  referrerPolicy: { policy: 'no-referrer' },
  xssFilter: true
}));

// Restrictive CORS settings
app.use(cors({
  origin: 'https://myapp.com', // specific origin only
  methods: ['GET', 'POST'], // specific methods only
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  credentials: true,
  maxAge: 3600
}));

// Rate limiting for brute force protection and DDoS
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests from this IP, please try again later'
});

// Request slowdown instead of blocking entirely
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 50,
  delayMs: 500, // adds 500ms of delay to each request after 50 requests
});

// Apply limits to sensitive authentication routes
app.use('/login', limiter);
app.use('/register', limiter);
app.use('/api/', speedLimiter);

// Set secure cookies
app.use(session({
  secret: 'super-secret-key',
  name: '__Secure-sessionId', // secure cookie name
  cookie: {
    secure: true, // requires HTTPS
    httpOnly: true, // not accessible via JavaScript
    domain: 'example.com',
    path: '/',
    maxAge: 60 * 60 * 1000, // 1 hour
    sameSite: 'strict'
  },
  resave: false,
  saveUninitialized: false
}));

// Add secure routes
app.get('/secure-data', (req, res) => {
  // Add additional request-specific headers
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  
  // Return secure content
  res.json({ secureData: 'Sensitive information here' });
});;`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Dependency Management</h2>
                <p className="mb-4">
                  Node.js applications often include numerous dependencies, which can introduce security vulnerabilities.
                </p>
                
                <CodeExample
                  language="bash"
                  title="Finding and Fixing Vulnerable Dependencies"
                  code={`# Check for vulnerabilities in dependencies
npm audit

# Fix vulnerabilities automatically when possible
npm audit fix

# Detailed report
npm audit --json

# Update specific package
npm update vulnerable-package

# Run security check with third-party tools
npx snyk test`}
                />

                <CodeExample
                  language="javascript"
                  title="Production Dependency Security Management"
                  code={`// Example script to ensure dependency security before deployment
// script: check-dependencies.js

const { execSync } = require('child_process');
const fs = require('fs');

try {
  // Check with npm audit
  console.log('Checking dependencies with npm audit...');
  const auditResults = execSync('npm audit --json').toString();
  const auditData = JSON.parse(auditResults);
  
  // Check for critical or high vulnerabilities
  const criticalVulns = Object.values(auditData.vulnerabilities || {})
    .filter(v => ['critical', 'high'].includes(v.severity));
  
  if (criticalVulns.length > 0) {
    console.error('Found critical or high vulnerabilities:');
    criticalVulns.forEach(v => {
      console.error(\`- \${v.name}: \${v.severity} - \${v.title}\`);
    });
    
    // Try to fix automatically
    console.log('Attempting to fix vulnerabilities automatically...');
    execSync('npm audit fix');
    
    // Check again if fixes resolved the issues
    const postFixResults = execSync('npm audit --json').toString();
    const postFixData = JSON.parse(postFixResults);
    
    const remainingCriticalVulns = Object.values(postFixData.vulnerabilities || {})
      .filter(v => ['critical', 'high'].includes(v.severity));
    
    if (remainingCriticalVulns.length > 0) {
      console.error('Vulnerabilities remain after auto-fix attempt');
      process.exit(1); // Failure - will stop CI/CD process
    }
  }
  
  // Check for abandoned packages
  console.log('Checking for abandoned packages...');
  const outdatedResults = execSync('npm outdated --json').toString();
  const outdatedData = JSON.parse(outdatedResults);
  
  // Alert on packages not updated for a long time
  const abandonedPackages = Object.keys(outdatedData)
    .filter(pkg => {
      const current = outdatedData[pkg].current;
      const latest = outdatedData[pkg].latest;
      const versionDiff = parseInt(latest.split('.')[0]) - parseInt(current.split('.')[0]);
      return versionDiff >= 2; // two or more major versions behind
    });
  
  if (abandonedPackages.length > 0) {
    console.warn('Packages with significant update lag:');
    abandonedPackages.forEach(pkg => console.warn(\`- \${pkg}: \${outdatedData[pkg].current} (latest: \${outdatedData[pkg].latest})\`));
    console.warn('Consider updating or replacing these packages');
  }
  
  // License information
  console.log('Checking package licenses...');
  const licenseData = execSync('license-checker --json').toString();
  const licenses = JSON.parse(licenseData);
  
  const restrictedLicenses = ['GPL', 'AGPL', 'LGPL']; // example of licenses that might be restricted
  const problematicPackages = Object.entries(licenses)
    .filter(([pkg, data]) => restrictedLicenses.some(l => data.licenses.includes(l)));
  
  if (problematicPackages.length > 0) {
    console.warn('Packages with potentially problematic licenses:');
    problematicPackages.forEach(([pkg, data]) => console.warn(\`- \${pkg}: \${data.licenses}\`));
  }
  
  console.log('Dependency check completed successfully');
  process.exit(0);

} catch (error) {
  console.error('Error checking dependencies:', error);
  process.exit(1);
}`}
                />
              </section>

              <section>
                <h2 className="text-2xl font-bold mb-4">Cryptography in Node.js</h2>
                <p className="mb-4">
                  Proper implementation of cryptographic functions is essential for securing data in Node.js.
                </p>
                
                <CodeExample
                  language="javascript"
                  title="Insecure Encryption"
                  code={`// VULNERABLE: Using outdated encryption algorithm and weak key
const crypto = require('crypto');

function encryptData(data) {
  // Error: Outdated algorithm (DES), too short key size, fixed initialization vector
  const algorithm = 'des';
  const key = 'short123'; // Too short key
  const iv = Buffer.alloc(8, 0); // Predictable IV
  
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// Issues:
// 1. DES algorithm is considered insecure
// 2. Key is too short
// 3. Fixed, non-random IV
// 4. No authentication of encrypted data (no MAC)`}
                />
                
                <CodeExample
                  language="javascript"
                  title="Secure Encryption"
                  code={`// SECURE: Modern encryption with authentication
const crypto = require('crypto');

// Function for secure encryption with AES-GCM (includes authentication)
async function encryptData(plaintext, password) {
  // Create secure key from password using PBKDF2 key derivation
  const salt = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha512');
  
  // Generate random initialization vector
  const iv = crypto.randomBytes(12); // 12 bytes recommended for AES-GCM
  
  // Create GCM cipher (Galois/Counter Mode - provides authentication)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
  // Encrypt the data
  let encrypted = cipher.update(plaintext, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  
  // Get authentication tag
  const authTag = cipher.getAuthTag().toString('base64');
  
  // Return all info needed for decryption
  return {
    encrypted,
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    authTag
  };
}

// Decryption function
async function decryptData(encData, password) {
  try {
    // Get the encrypted data and metadata
    const salt = Buffer.from(encData.salt, 'base64');
    const iv = Buffer.from(encData.iv, 'base64');
    const authTag = Buffer.from(encData.authTag, 'base64');
    const encryptedText = encData.encrypted;
    
    // Derive key from derivation method
    const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha512');
    
    // Create decipher
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag); // Set auth tag
    
    // Decrypt
    let decrypted = decipher.update(encryptedText, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    // If decryption error, likely data tampering or wrong key
    throw new Error('Encryption authentication failed: Data has been tampered with or key is incorrect');
  }
}

// Using the functions
async function example() {
  const password = 'very-strong-long-password-113542637!';
  const sensitiveData = 'Very sensitive information to store';
  
  try {
    // Encrypt the data
    const encrypted = await encryptData(sensitiveData, password);
    console.log('Encrypted data:', encrypted);
    
    // Decrypt the data
    const decrypted = await decryptData(encrypted, password);
    console.log('Decrypted data:', decrypted);
    
    // Try decryption with wrong password - should fail
    try {
      await decryptData(encrypted, 'wrong-password');
    } catch (error) {
      console.log('Decryption failed as expected with wrong password:', error.message);
    }
    
    // Try tampering with encrypted data - should fail
    try {
      const tamperedData = {...encrypted};
      tamperedData.encrypted = tamperedData.encrypted.replace('a', 'b');
      await decryptData(tamperedData, password);
    } catch (error) {
      console.log('Decryption failed as expected with tampered data:', error.message);
    }
    
  } catch (error) {
    console.error('Error:', error);
  }
}

example();`}
                />
              </section>

              <section>
                <h2 className="text-2xl font-bold mb-4">Database Access Security in Node.js</h2>
                <p className="mb-4">
                  Securing database connections against injection attacks and properly handling sensitive information.
                </p>
                
                <CodeExample
                  language="javascript"
                  title="Insecure Database Connection"
                  code={`// VULNERABLE: Hard-coded credentials and string query building
const mysql = require('mysql');

// Hard-coded credentials in code
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'my-secret-pw',
  database: 'my_db'
});

// Vulnerable usage - SQL Injection
app.get('/user', (req, res) => {
  const userId = req.query.id;
  // Vulnerable: directly inserting variable into query
  const query = 'SELECT * FROM users WHERE id = ' + userId;
  
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
});

// Attacker can send: ?id=1 OR 1=1 to retrieve all users`}
                />
                
                <CodeExample
                  language="javascript"
                  title="Secure Database Connection & Access"
                  code={`// SECURE: Using environment variables, connection pooling, and parameterized queries
const mysql = require('mysql2/promise');
require('dotenv').config();

// Secure connection credentials from environment variables
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: {
    rejectUnauthorized: true // Ensure secure SSL connection
  },
  connectionLimit: 10 // Connection pool limit
};

// Create connection pool instead of single connection
const pool = mysql.createPool(dbConfig);

// Helper function for secure query execution
async function query(sql, params) {
  try {
    const conn = await pool.getConnection();
    try {
      const [rows] = await conn.execute(sql, params);
      return rows;
    } finally {
      conn.release(); // Always release connection back to pool
    }
  } catch (error) {
    console.error('Database query error:', error);
    throw new Error('Database error');
  }
}

// Using parameterized arrays to prevent SQL Injection
app.get('/user', async (req, res) => {
  try {
    const userId = req.query.id;
    
    // Check that ID is a valid number
    if (!/^\\d+$/.test(userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }
    
    // Use parameterized queries
    const users = await query(
      'SELECT id, username, email FROM users WHERE id = ?', 
      [userId]
    );
    
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(users[0]);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Close pool on application shutdown
process.on('SIGINT', () => {
  pool.end();
  process.exit();
});`}
                />

                <CodeExample
                  language="javascript"
                  title="Securing MongoDB with Mongoose"
                  code={`// SECURE: Using Mongoose with input validation and output sanitization
const mongoose = require('mongoose');
const express = require('express');
require('dotenv').config();

// Secure connection with environment variables
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
  serverSelectionTimeoutMS: 5000,
  ssl: true,
  sslValidate: true,
  authSource: 'admin',
});

// Schema definition with validation
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters'],
    maxlength: [50, 'Username cannot exceed 50 characters'],
    match: [/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, dashes and underscores'],
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\\S+@\\S+\\.\\S+$/, 'Please enter a valid email address'],
  },
  password: {
    type: String,
    required: true,
    minlength: [8, 'Password must be at least 8 characters'],
    // Never return passwords in queries
    select: false,
  },
  role: {
    type: String,
    enum: ['user', 'admin', 'editor'],
    default: 'user',
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Add hooks before saving
userSchema.pre('save', async function(next) {
  // Hash passwords before saving
  if (this.isModified('password')) {
    try {
      const bcrypt = require('bcryptjs');
      this.password = await bcrypt.hash(this.password, 12);
    } catch (err) {
      return next(err);
    }
  }
  next();
});

// Don't return sensitive fields
userSchema.methods.toJSON = function() {
  const userObject = this.toObject();
  delete userObject.password;
  delete userObject.__v;
  return userObject;
};

// Define model
const User = mongoose.model('User', userSchema);

// Secure usage with mongoose
const app = express();
app.use(express.json());

// User search route
app.get('/api/users/search', async (req, res) => {
  try {
    // Note: No NoSQL injection here because we're building structured query
    const { username, limit = 10, page = 1 } = req.query;
    
    // Ensure limit is a number and within reasonable range
    const safeLimit = Math.min(parseInt(limit) || 10, 50);
    const safePage = parseInt(page) || 1;
    const skip = (safePage - 1) * safeLimit;
    
    const query = {};
    if (username) {
      // Safe search with regex
      query.username = { $regex: new RegExp('^' + username.replace(/[-\\/\\\\^$*+?.()|[\\]{}]/g, '\\\\$&')), $options: 'i' };
    }
    
    // Execute filtering query, but limit returned fields
    const users = await User.find(query)
      .select('username email role createdAt')
      .limit(safeLimit)
      .skip(skip)
      .sort({ createdAt: -1 });
    
    const totalUsers = await User.countDocuments(query);
    
    res.json({
      users,
      pagination: {
        total: totalUsers,
        page: safePage,
        limit: safeLimit,
        pages: Math.ceil(totalUsers / safeLimit)
      }
    });
  } catch (err) {
    console.error('User search error:', err);
    res.status(500).json({ error: 'An error occurred while searching for users' });
  }
});`}
                />
              </section>
            </div>
            
            <div className="lg:col-span-1">
              <div className="sticky top-24">
                <div className="card">
                  <h3 className="text-xl font-bold mb-4">Common Node.js Security Issues</h3>
                  <ul className="space-y-2 pl-4 text-cybr-foreground/80">
                    <li>Command Injection</li>
                    <li>Path Traversal</li>
                    <li>Unhandled Exceptions</li>
                    <li>Insecure Dependencies</li>
                    <li>Server-Side Request Forgery (SSRF)</li>
                    <li>Improper Error Handling</li>
                    <li>NoSQL Injection</li>
                    <li>File Permission Issues</li>
                    <li>Weak or Missing Encryption</li>
                    <li>Hard-coded Credentials</li>
                    <li>Session Management Weaknesses</li>
                    <li>Insecure Deserialization Functions</li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Essential Security Packages for Node.js</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://github.com/helmetjs/helmet" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Helmet</a></li>
                    <li><a href="https://github.com/expressjs/csurf" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">csurf (CSRF Protection)</a></li>
                    <li><a href="https://github.com/hapijs/joi" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">joi (Input Validation)</a></li>
                    <li><a href="https://github.com/auth0/node-jsonwebtoken" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">jsonwebtoken (JWT)</a></li>
                    <li><a href="https://github.com/validatorjs/validator.js" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">validator.js (String Validation)</a></li>
                    <li><a href="https://github.com/bcrypt-nodejs/bcrypt.js" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">bcrypt.js (Password Hashing)</a></li>
                    <li><a href="https://github.com/OWASP/NodeGoat" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">NodeGoat (OWASP Learning Project)</a></li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Related Technologies</h3>
                  <div className="space-y-3">
                    <Link to="/languages/javascript" className="block text-cybr-primary hover:underline">JavaScript Security</Link>
                    <Link to="/languages/react" className="block text-cybr-primary hover:underline">React Security</Link>
                    <Link to="/languages/golang" className="block text-cybr-primary hover:underline">Golang Security</Link>
                  </div>
                </div>

                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Node.js Security Scanning Tools</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://github.com/nodesecurity/nsp" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Node Security Platform</a></li>
                    <li><a href="https://github.com/snyk/snyk" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Snyk</a></li>
                    <li><a href="https://github.com/jeremylong/DependencyCheck" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP Dependency Check</a></li>
                    <li><a href="https://github.com/RetireJS/retire.js" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Retire.js</a></li>
                    <li><a href="https://github.com/ajinabraham/NodeJsScan" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">NodeJsScan</a></li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
      
      <Footer />
    </div>
  );
};

export default NodeJs;
