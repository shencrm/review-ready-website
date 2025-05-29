
import React from 'react';
import { Lock } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { InfoIcon } from 'lucide-react';

const BrokenAuthentication: React.FC = () => {
  return (
    <section id="auth" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Broken Authentication</h3>
      
      <div className="space-y-6">
        {/* Introduction */}
        <div>
          <p className="mb-4">
            Broken Authentication refers to implementation flaws in authentication and session management that allow attackers
            to compromise passwords, keys, session tokens, or exploit other vulnerabilities to assume users' identities.
            These vulnerabilities can lead to complete account takeover and significant data breaches.
          </p>
          
          <Alert className="mb-4 text-amber-900 dark:text-amber-200 bg-slate-50">
            <InfoIcon className="h-4 w-4" />
            <AlertTitle>Attacker's Goal</AlertTitle>
            <AlertDescription>
              Gain unauthorized access to user accounts by bypassing authentication mechanisms, stealing session tokens,
              or exploiting weak credential management to impersonate legitimate users.
            </AlertDescription>
          </Alert>
        </div>

        {/* Attack Types */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Common Broken Authentication Attack Types</h4>
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
            <SecurityCard
              title="Session Hijacking"
              description="Stealing or predicting valid session identifiers to impersonate authenticated users without knowing their credentials."
              severity="high"
            />
            <SecurityCard
              title="Password Spraying"
              description="Trying a few common passwords against many accounts to avoid account lockout mechanisms while still finding weak credentials."
              severity="medium"
            />
          </div>
        </div>

        {/* Vulnerable Components */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Commonly Vulnerable Components</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md">
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>Login Forms:</strong> Lack of rate limiting, weak password policies, no CAPTCHA protection</li>
              <li><strong>Password Reset Functions:</strong> Predictable tokens, no expiration, weak validation</li>
              <li><strong>Session Management:</strong> Weak session IDs, no secure flags, improper invalidation</li>
              <li><strong>Multi-Factor Authentication:</strong> Bypassable implementation, SMS vulnerabilities</li>
              <li><strong>Remember Me Functions:</strong> Insecure token storage, long-lived sessions</li>
              <li><strong>Account Registration:</strong> No email verification, weak validation</li>
              <li><strong>API Authentication:</strong> Weak API keys, no proper token refresh mechanisms</li>
            </ul>
          </div>
        </div>

        {/* Why These Attacks Work */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Why Broken Authentication Attacks Work</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Technical Weaknesses</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Weak password hashing algorithms (MD5, SHA1)</li>
                <li>No salt in password hashing</li>
                <li>Predictable session token generation</li>
                <li>Missing HTTPOnly and Secure cookie flags</li>
                <li>No session timeout implementation</li>
                <li>Client-side password validation only</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Implementation Flaws</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>No rate limiting on authentication attempts</li>
                <li>Inadequate account lockout mechanisms</li>
                <li>Poor error handling revealing information</li>
                <li>Insecure credential recovery processes</li>
                <li>Default or hardcoded credentials</li>
                <li>Missing multi-factor authentication</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Step-by-Step Attack Methodology */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Step-by-Step Attack Methodology</h4>
          <Tabs defaultValue="reconnaissance">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="reconnaissance">Reconnaissance</TabsTrigger>
              <TabsTrigger value="credential-attacks">Credential Attacks</TabsTrigger>
              <TabsTrigger value="session-attacks">Session Attacks</TabsTrigger>
              <TabsTrigger value="exploitation">Exploitation</TabsTrigger>
            </TabsList>
            
            <TabsContent value="reconnaissance" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 1: Authentication Reconnaissance</h5>
                <ol className="list-decimal pl-6 space-y-2">
                  <li><strong>Identify Authentication Mechanisms:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Map all login endpoints and forms</li>
                      <li>Identify authentication methods (username/password, OAuth, SAML)</li>
                      <li>Check for multi-factor authentication requirements</li>
                      <li>Analyze password reset and recovery mechanisms</li>
                    </ul>
                  </li>
                  <li><strong>Analyze Session Management:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Examine session tokens and their structure</li>
                      <li>Check cookie settings and security flags</li>
                      <li>Test session timeout behavior</li>
                      <li>Analyze logout functionality</li>
                    </ul>
                  </li>
                </ol>
              </div>
            </TabsContent>
            
            <TabsContent value="credential-attacks" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 2: Credential-Based Attacks</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Common Attack Vectors:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Password Spraying:</strong> Try common passwords against multiple accounts</li>
                    <li><strong>Credential Stuffing:</strong> Use leaked credential databases</li>
                    <li><strong>Brute Force:</strong> Systematically try password combinations</li>
                    <li><strong>Dictionary Attacks:</strong> Use wordlists of common passwords</li>
                    <li><strong>Default Credentials:</strong> Test for unchanged default passwords</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="session-attacks" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 3: Session-Based Attacks</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Session Attack Methods:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Session Fixation:</strong> Force user to use attacker-controlled session ID</li>
                    <li><strong>Session Hijacking:</strong> Steal valid session tokens via XSS or network sniffing</li>
                    <li><strong>Session Prediction:</strong> Predict session tokens if they're not random enough</li>
                    <li><strong>Cookie Theft:</strong> Extract session cookies from insecure storage</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="exploitation" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 4: Exploitation and Persistence</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Post-Authentication Actions:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Account Takeover:</strong> Change passwords and security settings</li>
                    <li><strong>Privilege Escalation:</strong> Attempt to gain higher-level access</li>
                    <li><strong>Data Extraction:</strong> Access sensitive user information</li>
                    <li><strong>Lateral Movement:</strong> Use compromised account to access other systems</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Example Payloads and Tools */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Common Attack Payloads and Techniques</h4>
          <CodeExample
            language="bash"
            title="Credential Stuffing and Brute Force Payloads"
            code={`# Hydra brute force attack
hydra -L userlist.txt -P passwordlist.txt http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials"

# Credential stuffing with Burp Suite Intruder
# Use leaked credential databases like:
# - Collection #1 (773M accounts)
# - Anti Public Combo List
# - Have I Been Pwned datasets

# Password spraying common passwords
usernames=(admin user administrator test guest)
passwords=(password 123456 admin password123)

for user in "\${usernames[@]}"; do
  for pass in "\${passwords[@]}"; do
    curl -X POST -d "username=\$user&password=\$pass" http://target.com/login
  done
done`}
          />
        </div>

        {/* Vulnerable Code Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Vulnerable Code Examples</h4>
          <CodeExample 
            language="javascript" 
            isVulnerable={true}
            title="Vulnerable Authentication Implementation" 
            code={`// Vulnerable Node.js/Express authentication
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // No rate limiting - allows unlimited attempts
  // No input validation
  const user = users.find(u => u.username === username);
  
  if (user && user.password === md5(password)) {
    // Weak hashing with MD5
    // Predictable session ID generation
    const sessionId = Math.random().toString(36);
    
    // Insecure session storage
    sessions[sessionId] = { userId: user.id };
    
    // Missing security flags
    res.cookie('sessionId', sessionId);
    res.json({ success: true });
  } else {
    // Information disclosure - reveals if username exists
    if (!user) {
      res.status(401).json({ error: 'Username does not exist' });
    } else {
      res.status(401).json({ error: 'Incorrect password' });
    }
  }
});

// Vulnerable password reset
app.post('/reset-password', (req, res) => {
  const { email } = req.body;
  const user = users.find(u => u.email === email);
  
  if (user) {
    // Predictable reset token
    const resetToken = user.id + Date.now();
    user.resetToken = resetToken;
    
    // Long-lived token with no expiration
    sendEmail(email, \`Reset link: /reset?token=\${resetToken}\`);
  }
  
  res.json({ message: 'Reset email sent' });
});`} 
          />
          
          <CodeExample 
            language="python" 
            isVulnerable={true}
            title="Vulnerable Python Flask Authentication" 
            code={`from flask import Flask, request, session
import hashlib

app = Flask(__name__)
app.secret_key = 'hardcoded_secret'  # Hardcoded secret key

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # No rate limiting or account lockout
    user = get_user(username)
    
    if user:
        # Weak password hashing without salt
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        if user.password_hash == password_hash:
            # Session fixation vulnerability - not regenerating session ID
            session['user_id'] = user.id
            session['role'] = user.role
            return 'Login successful'
    
    # Same error message but timing attack possible
    return 'Invalid credentials'

@app.route('/profile')
def profile():
    # No session validation
    if 'user_id' in session:
        return f"Welcome user {session['user_id']}"
    return 'Not logged in'`} 
          />
        </div>

        {/* Secure Code Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Secure Authentication Implementation</h4>
          <CodeExample 
            language="javascript" 
            isVulnerable={false}
            title="Secure Authentication with Rate Limiting and Strong Hashing" 
            code={`const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

// Rate limiting middleware
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window per IP
  skipSuccessfulRequests: true,
  message: { error: 'Too many login attempts, please try again later' }
});

// Account lockout tracking
const accountLockouts = new Map();

app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Input validation
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    // Check for account lockout
    const lockoutKey = \`lockout_\${username}\`;
    const lockout = accountLockouts.get(lockoutKey);
    if (lockout && lockout.until > Date.now()) {
      return res.status(423).json({ error: 'Account temporarily locked' });
    }
    
    const user = await User.findOne({ username });
    
    // Constant-time comparison to prevent timing attacks
    let isValidUser = false;
    let isValidPassword = false;
    
    if (user) {
      isValidUser = true;
      // Use bcrypt for secure password comparison
      isValidPassword = await bcrypt.compare(password, user.passwordHash);
    } else {
      // Perform dummy bcrypt operation to maintain constant time
      await bcrypt.compare(password, '\$2b\$10\$dummy.hash.to.prevent.timing.attacks');
    }
    
    if (isValidUser && isValidPassword) {
      // Clear any existing lockout
      accountLockouts.delete(lockoutKey);
      
      // Generate new session ID (prevents session fixation)
      req.session.regenerate(async (err) => {
        if (err) {
          return res.status(500).json({ error: 'Authentication error' });
        }
        
        // Set session data
        req.session.userId = user.id;
        req.session.role = user.role;
        req.session.createdAt = Date.now();
        
        // Update last login
        await User.updateOne(
          { _id: user.id },
          { 
            lastLogin: new Date(),
            \$unset: { loginAttempts: 1 }
          }
        );
        
        // Set secure cookie
        res.cookie('sessionId', req.sessionID, {
          httpOnly: true,     // Prevents XSS
          secure: process.env.NODE_ENV === 'production', // HTTPS only in production
          sameSite: 'strict', // CSRF protection
          maxAge: 3600000     // 1 hour
        });
        
        res.json({ 
          success: true, 
          user: { 
            id: user.id, 
            username: user.username,
            role: user.role 
          }
        });
      });
    } else {
      // Track failed attempts
      if (user) {
        const attempts = (user.loginAttempts || 0) + 1;
        await User.updateOne(
          { _id: user.id },
          { 
            loginAttempts: attempts,
            lastFailedLogin: new Date()
          }
        );
        
        // Lock account after 5 failed attempts
        if (attempts >= 5) {
          accountLockouts.set(lockoutKey, {
            until: Date.now() + (30 * 60 * 1000) // 30 minutes
          });
        }
      }
      
      // Generic error message to prevent user enumeration
      // Add delay to prevent timing attacks
      setTimeout(() => {
        res.status(401).json({ error: 'Invalid credentials' });
      }, 1000 + Math.random() * 1000); // Random delay 1-2 seconds
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Authentication error' });
  }
});

// Secure session validation middleware
const authenticateSession = async (req, res, next) => {
  try {
    if (!req.session || !req.session.userId) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    // Check session age
    const maxAge = 3600000; // 1 hour
    const sessionAge = Date.now() - (req.session.createdAt || 0);
    
    if (sessionAge > maxAge) {
      req.session.destroy();
      return res.status(401).json({ error: 'Session expired' });
    }
    
    // Verify user still exists
    const user = await User.findById(req.session.userId);
    if (!user) {
      req.session.destroy();
      return res.status(401).json({ error: 'Invalid session' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    console.error('Session validation error:', error);
    res.status(500).json({ error: 'Authentication error' });
  }
};`} 
          />
        </div>

        {/* Testing Methodology */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Step-by-Step Testing for Broken Authentication</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md">
            <h5 className="font-semibold mb-2">Testing Checklist:</h5>
            <ol className="list-decimal pl-6 space-y-2 text-sm">
              <li><strong>Password Policy Testing:</strong>
                <ul className="list-disc pl-6 mt-1 space-y-1">
                  <li>Test minimum/maximum password length</li>
                  <li>Check for complexity requirements</li>
                  <li>Verify password history enforcement</li>
                  <li>Test for common password rejection</li>
                </ul>
              </li>
              <li><strong>Brute Force Protection:</strong>
                <ul className="list-disc pl-6 mt-1 space-y-1">
                  <li>Test rate limiting on login attempts</li>
                  <li>Check for account lockout mechanisms</li>
                  <li>Verify CAPTCHA implementation</li>
                  <li>Test IP-based blocking</li>
                </ul>
              </li>
              <li><strong>Session Management:</strong>
                <ul className="list-disc pl-6 mt-1 space-y-1">
                  <li>Analyze session token entropy and randomness</li>
                  <li>Test session timeout functionality</li>
                  <li>Verify secure cookie flags</li>
                  <li>Check for session fixation vulnerabilities</li>
                </ul>
              </li>
              <li><strong>Password Reset Testing:</strong>
                <ul className="list-disc pl-6 mt-1 space-y-1">
                  <li>Test reset token predictability</li>
                  <li>Verify token expiration</li>
                  <li>Check for user enumeration</li>
                  <li>Test reset link reuse</li>
                </ul>
              </li>
            </ol>
          </div>
        </div>

        {/* Testing Tools */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Authentication Testing Tools</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Automated Testing Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Hydra:</strong> Network authentication cracker</li>
                <li><strong>Medusa:</strong> Parallel brute force tool</li>
                <li><strong>Burp Suite:</strong> Web application security testing</li>
                <li><strong>OWASP ZAP:</strong> Free security testing proxy</li>
                <li><strong>John the Ripper:</strong> Password cracking tool</li>
                <li><strong>Hashcat:</strong> Advanced password recovery</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Manual Testing Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Browser Developer Tools:</strong> Session analysis</li>
                <li><strong>Postman/Insomnia:</strong> API testing</li>
                <li><strong>curl/wget:</strong> Command-line testing</li>
                <li><strong>Custom Scripts:</strong> Automation and analysis</li>
                <li><strong>Credential Lists:</strong> SecLists, Have I Been Pwned</li>
                <li><strong>Token Analyzers:</strong> Session token analysis tools</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Prevention Strategies */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Comprehensive Prevention Strategies</h4>
          <Tabs defaultValue="implementation">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="implementation">Implementation</TabsTrigger>
              <TabsTrigger value="architecture">Architecture</TabsTrigger>
              <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
            </TabsList>
            
            <TabsContent value="implementation" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold mb-2">Secure Implementation Practices</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Use strong password hashing (bcrypt, scrypt, Argon2)</li>
                    <li>Implement proper session management with secure tokens</li>
                    <li>Enforce strong password policies and complexity requirements</li>
                    <li>Add multi-factor authentication for sensitive operations</li>
                    <li>Implement rate limiting and account lockout mechanisms</li>
                    <li>Use secure cookie flags (HttpOnly, Secure, SameSite)</li>
                    <li>Implement proper session timeout and invalidation</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="architecture" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold mb-2">Architectural Security Measures</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Use centralized authentication services (OAuth 2.0, SAML)</li>
                    <li>Implement Web Application Firewalls (WAF)</li>
                    <li>Use HTTPS everywhere with proper certificate management</li>
                    <li>Implement defense in depth with multiple security layers</li>
                    <li>Use security headers (HSTS, CSP, X-Frame-Options)</li>
                    <li>Implement proper error handling without information disclosure</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="monitoring" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold mb-2">Monitoring and Detection</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Monitor failed authentication attempts and patterns</li>
                    <li>Implement anomaly detection for unusual login behavior</li>
                    <li>Log and alert on administrative account usage</li>
                    <li>Monitor for credential stuffing attack patterns</li>
                    <li>Implement real-time security alerting</li>
                    <li>Regular security audits and penetration testing</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Special Cases and Environments */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Special Cases and Development Environments</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Framework-Specific Considerations</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Node.js/Express:</strong> Use express-session with secure store</li>
                <li><strong>Django:</strong> Configure session middleware and CSRF protection</li>
                <li><strong>Spring Boot:</strong> Use Spring Security with proper configuration</li>
                <li><strong>ASP.NET:</strong> Configure Identity framework securely</li>
                <li><strong>Laravel:</strong> Use built-in authentication with proper hashing</li>
                <li><strong>React/SPA:</strong> Implement secure token-based authentication</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Environment-Specific Issues</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Development:</strong> Avoid hardcoded credentials and weak secrets</li>
                <li><strong>Testing:</strong> Use realistic but safe test data</li>
                <li><strong>Staging:</strong> Mirror production security configurations</li>
                <li><strong>Production:</strong> Enable all security features and monitoring</li>
                <li><strong>Cloud:</strong> Use cloud-native identity and access management</li>
                <li><strong>Mobile:</strong> Implement secure token storage and biometric auth</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default BrokenAuthentication;
