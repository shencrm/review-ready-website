
import React from 'react';
import { Lock } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';

const BrokenAuthentication: React.FC = () => {
  return (
    <section id="auth" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Broken Authentication</h3>
      <p className="mb-6">
        Broken Authentication refers to implementation flaws in authentication and session management that allow attackers
        to compromise passwords, keys, session tokens, or exploit other vulnerabilities to assume users' identities.
        These vulnerabilities can lead to complete account takeover and significant data breaches.
      </p>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        <SecurityCard
          title="Credential Stuffing"
          description="Automated injection of breached username/password pairs to gain unauthorized access to user accounts. Attackers leverage password reuse across multiple services."
          severity="high"
        />
        <SecurityCard
          title="Brute Force Attacks"
          description="Attempting to guess passwords through exhaustive trial-and-error methods. May target weak passwords or use dictionary attacks to systematically check all possible combinations."
          severity="high"
        />
      </div>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Common Authentication Vulnerabilities</h4>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li><strong>Weak Password Policies:</strong> Allowing short, common, or easily guessable passwords</li>
        <li><strong>Weak Credential Recovery:</strong> Insecure "forgot password" flows that can be exploited</li>
        <li><strong>Missing Multi-factor Authentication:</strong> Especially for sensitive operations or admin accounts</li>
        <li><strong>Session Fixation:</strong> Not generating new session IDs at login time</li>
        <li><strong>Insecure Session Storage:</strong> Storing session tokens in easily accessible locations</li>
        <li><strong>Missing Session Timeouts:</strong> Not invalidating sessions after periods of inactivity</li>
        <li><strong>Default/Hardcoded Credentials:</strong> Leaving default accounts enabled with known passwords</li>
      </ul>
      
      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable Authentication" 
        code={`// No rate limiting or account lockout
async function loginUser(email, password) {
  const user = await db.users.findOne({ email });
  
  if (user && user.password === md5(password)) {
    // Weak password hashing (MD5)
    // Create session without proper expiry
    const sessionId = generateRandomString(16);
    sessions[sessionId] = { userId: user.id };
    return sessionId;
  }
  return null;
}

// Weak password reset implementation
app.post('/reset-password', async (req, res) => {
  const { email } = req.body;
  const user = await db.users.findOne({ email });
  
  if (user) {
    // Generate short reset token
    const resetToken = Math.random().toString(36).substring(2, 8);
    user.resetToken = resetToken;
    await db.users.update(user);
    
    // Send email with reset link
    sendEmail(email, 
      \`Reset your password using this link: 
       https://example.com/reset?token=\${resetToken}\`);
  }
  
  // Always return success to prevent user enumeration
  res.json({ success: true });
});

// Insecure session management
app.use(session({
  secret: 'hardcoded-secret', // Fixed secret
  resave: false,
  saveUninitialized: true,
  cookie: {} // No secure flags, no proper expiration
}));`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure Authentication" 
        code={`// Secure authentication with rate limiting and strong hashing
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');

// Apply rate limiting middleware
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  skipSuccessfulRequests: true,
  message: 'Too many login attempts, please try again later'
});

app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await db.users.findOne({ email });
    
    // Use constant-time comparison to prevent timing attacks
    if (user) {
      // Compare with securely hashed password
      const match = await bcrypt.compare(password, user.passwordHash);
      if (match) {
        // Generate a new session ID after successful login (prevents session fixation)
        req.session.regenerate((err) => {
          if (err) {
            return res.status(500).json({ error: 'Authentication error' });
          }
          
          // Set session data
          req.session.userId = user.id;
          req.session.userRole = user.role;
          req.session.createdAt = Date.now();
          
          // Set secure session cookie
          res.cookie('sessionId', req.sessionID, {
            httpOnly: true,     // Prevents JavaScript access to cookie
            secure: true,       // Only send over HTTPS
            sameSite: 'strict', // Prevents CSRF
            maxAge: 3600000     // 1 hour expiration
          });
          
          return res.json({ success: true, user: { id: user.id, name: user.name } });
        });
      } else {
        // Delay response to prevent timing attacks
        setTimeout(() => {
          res.status(401).json({ error: 'Invalid credentials' });
        }, 100);
      }
    } else {
      // Same response for non-existent users to prevent user enumeration
      setTimeout(() => {
        res.status(401).json({ error: 'Invalid credentials' });
      }, 100);
    }
  } catch (error) {
    res.status(500).json({ error: 'Authentication error' });
  }
});

// Secure password reset implementation
app.post('/reset-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await db.users.findOne({ email });
    
    if (user) {
      // Generate secure random token
      const crypto = require('crypto');
      const resetToken = crypto.randomBytes(32).toString('hex');
      const tokenExpiry = Date.now() + 3600000; // 1 hour expiration
      
      // Store hashed version of token (prevents token stealing from database)
      const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
      user.resetTokenHash = tokenHash;
      user.resetTokenExpiry = tokenExpiry;
      await db.users.update(user);
      
      // Send email with reset link
      sendEmail(email, 
        \`Reset your password using this link (valid for 1 hour): 
         https://example.com/reset?token=\${resetToken}&email=\${encodeURIComponent(email)}\`);
    }
    
    // Same response whether user exists or not (prevents user enumeration)
    res.json({ success: true, message: 'If your email is registered, you will receive reset instructions' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to process request' });
  }
});

// Secure session management
const crypto = require('crypto');
app.use(session({
  secret: process.env.SESSION_SECRET, // Environment variable, not hardcoded
  resave: false,
  saveUninitialized: false,
  name: 'sessionId', // Custom name, not default
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // HTTPS in production
    sameSite: 'strict',
    maxAge: 3600000 // 1 hour
  },
  genid: (req) => {
    return crypto.randomBytes(32).toString('hex'); // Strong random session ID
  }
}));

// Session validation middleware
app.use((req, res, next) => {
  if (req.session && req.session.userId) {
    // Check if session is expired based on creation time
    const maxAge = 3600000; // 1 hour
    const currentTime = Date.now();
    const sessionCreationTime = req.session.createdAt || 0;
    
    if (currentTime - sessionCreationTime > maxAge) {
      // Destroy expired session
      return req.session.destroy(() => {
        res.redirect('/login');
      });
    }
    
    // Update session timestamp for sliding expiration
    req.session.touch();
  }
  next();
});`} 
      />
    </section>
  );
};

export default BrokenAuthentication;
