
import { Challenge } from './challenge-types';

export const brokenAuthChallenges: Challenge[] = [
  {
    id: 'broken-auth-1',
    title: 'Broken Authentication in Password Reset',
    description: 'This PHP code handles password reset functionality. Is it securely implemented?',
    difficulty: 'medium',
    category: 'Broken Authentication',
    languages: ['PHP'],
    type: 'single',
    vulnerabilityType: 'Weak Authentication',
    code: `<?php
// Password reset functionality
if (isset($_GET['action']) && $_GET['action'] === 'reset') {
    // Get user email from the request
    $email = $_POST['email'];
    
    // Check if email exists in database
    $user = findUserByEmail($email);
    
    if ($user) {
        // Generate a random token
        $resetToken = md5(time() . $email);
        
        // Store token in database
        storeResetToken($user['id'], $resetToken);
        
        // Generate reset link
        $resetLink = "https://example.com/reset.php?token=$resetToken";
        
        // Send email with reset link
        sendEmail($email, "Password Reset", "Click the link to reset your password: $resetLink");
        
        echo "Password reset email sent!";
    } else {
        echo "Email not found.";
    }
}

// Process password reset
if (isset($_GET['token'])) {
    $token = $_GET['token'];
    $newPassword = $_POST['new_password'];
    
    // Find user by token
    $user = findUserByToken($token);
    
    if ($user) {
        // Update password in database
        updatePassword($user['id'], $newPassword);
        
        // Invalidate token
        invalidateToken($user['id']);
        
        echo "Password updated successfully!";
    } else {
        echo "Invalid or expired token.";
    }
}
?>`,
    answer: false,
    explanation: "This password reset implementation has multiple security issues: 1) It uses MD5, which is cryptographically broken, for token generation, 2) The token doesn't expire (no time limit), 3) It doesn't rate-limit reset attempts, which allows enumeration of valid email addresses, 4) It doesn't validate or hash the new password, 5) It doesn't require the current password or other verification, 6) It doesn't enforce CSRF protection, 7) It reveals whether an email exists in the system, 8) It doesn't implement proper logging for security events, and 9) It doesn't force re-authentication after the password change."
  },
  {
    id: 'broken-auth-2',
    title: 'Session Management Security',
    description: 'Compare these two approaches to session management in Node.js. Which one is securely implemented?',
    difficulty: 'hard',
    category: 'Broken Authentication',
    languages: ['JavaScript', 'Node.js'],
    type: 'comparison',
    vulnerabilityType: 'Session Management',
    secureCode: `const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const crypto = require('crypto');
const app = express();

// Security headers
app.use(helmet());

// Generate secure random secret
const sessionSecret = crypto.randomBytes(32).toString('hex');

// Configure session middleware
app.use(session({
  secret: sessionSecret,
  name: 'sessionId', // Custom name instead of default connect.sid
  cookie: {
    httpOnly: true,      // Prevents client-side JS from reading the cookie
    secure: true,        // Ensures cookie is sent over HTTPS only
    sameSite: 'strict',  // Prevents CSRF by not sending cookie in cross-site requests
    maxAge: 3600000,     // Session expires after 1 hour (in milliseconds)
    path: '/',
  },
  resave: false,
  saveUninitialized: false,
  rolling: true          // Reset expiration countdown on each response
}));

// Authentication middleware
const authenticate = (req, res, next) => {
  if (req.session && req.session.authenticated) {
    // Regenerate session after authentication to prevent session fixation
    if (req.session.newLogin) {
      req.session.regenerate((err) => {
        if (err) {
          return res.status(500).json({ error: 'Authentication failed' });
        }
        // Maintain user data
        req.session.authenticated = true;
        req.session.userId = req.session.userId;
        req.session.newLogin = false;
        next();
      });
    } else {
      next();
    }
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

// Login route
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // Check credentials against database
  if (validateUser(username, password)) {
    req.session.authenticated = true;
    req.session.userId = getUserId(username);
    req.session.newLogin = true;
    
    // Log successful login attempt
    logActivity(req.session.userId, 'login_success', req.ip);
    
    res.json({ success: true });
  } else {
    // Delay response to prevent timing attacks
    setTimeout(() => {
      // Log failed login attempt
      logActivity(null, 'login_failure', req.ip, username);
      
      res.status(401).json({ error: 'Invalid credentials' });
    }, 200);
  }
});

// Logout route
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.clearCookie('sessionId');
    res.json({ success: true });
  });
});`,
    vulnerableCode: `const express = require('express');
const session = require('express-session');
const app = express();

// Configure session middleware
app.use(session({
  secret: 'session-secret-key',
  cookie: { maxAge: 86400000 }, // 24 hours
  resave: true,
  saveUninitialized: true
}));

// Authentication middleware
const authenticate = (req, res, next) => {
  if (req.session && req.session.user) {
    next();
  } else {
    res.redirect('/login');
  }
};

// Login route
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // Check credentials against database
  if (username === 'admin' && password === 'password') {
    req.session.user = username;
    res.redirect('/dashboard');
  } else {
    res.redirect('/login?error=1');
  }
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.user = null;
  res.redirect('/login');
});`,
    answer: 'secure',
    explanation: "The secure implementation includes many security best practices: 1) It uses helmet for security headers, 2) It generates a cryptographically secure random session secret, 3) It uses httpOnly, secure and sameSite flags for cookies, 4) It implements session regeneration to prevent session fixation attacks, 5) It includes session expiration and rolling sessions, 6) It uses POST for logout to prevent CSRF, 7) It properly destroys sessions and clears cookies on logout, 8) It implements activity logging, 9) It uses delayed responses to prevent timing attacks, and 10) It uses a custom session name. The vulnerable implementation has many issues: hardcoded secret, no secure/httpOnly cookie flags, excessively long session duration, no CSRF protection, weak authentication logic with hardcoded credentials, and improper session termination."
  },
  {
    id: 'broken-auth-3',
    title: 'Multi-Factor Authentication Implementation',
    description: 'This Python code implements two-factor authentication. Does it have security weaknesses?',
    difficulty: 'medium',
    category: 'Broken Authentication',
    languages: ['Python'],
    type: 'single',
    vulnerabilityType: 'MFA Implementation',
    code: `from flask import Flask, request, session, redirect, jsonify
import pyotp
import uuid
import sqlite3
import time

app = Flask(__name__)
app.secret_key = "super-secret-key"

# Database setup
def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize 2FA for a user
@app.route('/setup-2fa', methods=['POST'])
def setup_2fa():
    if 'user_id' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    user_id = session['user_id']
    
    # Generate a new TOTP secret
    totp_secret = pyotp.random_base32()
    
    # Save to database
    db = get_db()
    db.execute(
        'UPDATE users SET totp_secret = ? WHERE id = ?',
        (totp_secret, user_id)
    )
    db.commit()
    
    # Generate QR code URI for the user to scan
    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(
        name=session['email'],
        issuer_name="MyApplication"
    )
    
    return jsonify({
        "secret": totp_secret,
        "qr_uri": provisioning_uri
    })

# Verify 2FA code
@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    code = request.json.get('code')
    
    if 'temp_user_id' not in session:
        return jsonify({"error": "No pending authentication"}), 400
    
    user_id = session['temp_user_id']
    
    # Get user's TOTP secret from database
    db = get_db()
    user = db.execute(
        'SELECT totp_secret FROM users WHERE id = ?', 
        (user_id,)
    ).fetchone()
    
    if not user or not user['totp_secret']:
        return jsonify({"error": "2FA not set up for user"}), 400
    
    # Verify TOTP code
    totp = pyotp.TOTP(user['totp_secret'])
    if totp.verify(code):
        # Complete login
        session.pop('temp_user_id')
        session['user_id'] = user_id
        session['authenticated'] = True
        
        # Generate a new session ID to prevent session fixation
        session.regenerate()
        
        return jsonify({"success": True})
    else:
        return jsonify({"error": "Invalid 2FA code"}), 401

@app.route('/login', methods=['POST'])
def login():
    email = request.json.get('email')
    password = request.json.get('password')
    
    # Verify credentials
    db = get_db()
    user = db.execute(
        'SELECT id, password_hash, has_2fa FROM users WHERE email = ?', 
        (email,)
    ).fetchone()
    
    if user and verify_password(password, user['password_hash']):
        if user['has_2fa']:
            # Store user ID temporarily until 2FA is verified
            session['temp_user_id'] = user['id']
            return jsonify({"requires_2fa": True})
        else:
            # Login without 2FA
            session['user_id'] = user['id']
            session['authenticated'] = True
            return jsonify({"success": True})
    else:
        # Simulate work to prevent timing attacks
        time.sleep(1)
        return jsonify({"error": "Invalid credentials"}), 401`,
    answer: false,
    explanation: "This 2FA implementation has several security issues: 1) The TOTP secret is returned to the client during setup, which could lead to interception, 2) It lacks rate limiting for code verification, allowing brute force attacks, 3) The session key is hardcoded rather than using a secure random value, 4) There's no expiration time for the TOTP verification process, 5) It doesn't implement backup codes or alternative recovery methods, 6) There's no verification that the user actually completed the 2FA setup, 7) The code doesn't use HTTPS enforcement, 8) The call to 'session.regenerate()' isn't a standard Flask method (it should be using Flask-Session extensions properly), and 9) It lacks proper logging of authentication attempts and failures."
  }
];
