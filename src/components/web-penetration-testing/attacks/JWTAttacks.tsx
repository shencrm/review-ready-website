
import React from 'react';
import { KeyRound } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const JWTAttacks: React.FC = () => {
  return (
    <section id="jwt" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">JWT Attacks</h3>
      
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">What Attackers Try to Achieve</h4>
        <p className="mb-4">
          JSON Web Tokens (JWTs) are commonly used for authentication and session management. Attackers targeting JWT implementations aim to:
        </p>
        <ul className="list-disc pl-6 space-y-2 mb-6">
          <li><strong>Bypass Authentication</strong>: Forge valid tokens to impersonate legitimate users</li>
          <li><strong>Privilege Escalation</strong>: Modify token claims to gain administrative access</li>
          <li><strong>Session Hijacking</strong>: Steal and reuse valid tokens from other users</li>
          <li><strong>Information Disclosure</strong>: Extract sensitive data encoded in JWT payloads</li>
          <li><strong>Persistent Access</strong>: Create long-lived tokens that survive legitimate session termination</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Vulnerable Components</h4>
        <ul className="list-disc pl-6 space-y-2 mb-6">
          <li><strong>JWT Libraries</strong>: Outdated or misconfigured JWT processing libraries</li>
          <li><strong>Token Validation Logic</strong>: Insufficient or missing signature verification</li>
          <li><strong>Secret Management</strong>: Weak or exposed signing keys</li>
          <li><strong>Algorithm Handling</strong>: Improper algorithm specification or validation</li>
          <li><strong>Token Storage</strong>: Insecure client-side token storage mechanisms</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Why JWT Attacks Work</h4>
        <ul className="list-disc pl-6 space-y-2 mb-6">
          <li><strong>Algorithm Confusion</strong>: Servers accept tokens with different algorithms than expected</li>
          <li><strong>Missing Signature Verification</strong>: Applications trust token content without validating signatures</li>
          <li><strong>Weak Secrets</strong>: Predictable or easily guessable signing keys enable token forgery</li>
          <li><strong>Client-Side Validation</strong>: Relying on client-side checks that can be bypassed</li>
          <li><strong>Token Reuse</strong>: Long expiration times and lack of proper token invalidation</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Common JWT Attack Vectors</h4>
        
        <h5 className="text-lg font-medium mb-3">1. Algorithm "None" Attack</h5>
        <p className="mb-4">
          Attackers modify the algorithm field to "none" to bypass signature validation entirely.
        </p>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <p className="font-semibold mb-2">Payload Example:</p>
          <pre className="text-sm bg-cybr-muted p-2 rounded">
{`// Original JWT Header
{
  "alg": "HS256",
  "typ": "JWT"
}

// Modified Header (Attack)
{
  "alg": "none",
  "typ": "JWT"
}

// The signature is removed or set to empty
// Resulting in: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.`}
          </pre>
        </div>

        <h5 className="text-lg font-medium mb-3">2. Weak Secret Brute Force</h5>
        <p className="mb-4">
          Attackers attempt to crack weak signing secrets to forge valid tokens.
        </p>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <p className="font-semibold mb-2">Common Weak Secrets:</p>
          <pre className="text-sm bg-cybr-muted p-2 rounded">
{`secret
password
123456
jwt_secret
your-256-bit-secret
admin
password123`}
          </pre>
        </div>

        <h5 className="text-lg font-medium mb-3">3. Algorithm Switching (RS256 to HS256)</h5>
        <p className="mb-4">
          Converting asymmetric tokens to symmetric ones using the public key as the secret.
        </p>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <p className="font-semibold mb-2">Attack Process:</p>
          <pre className="text-sm bg-cybr-muted p-2 rounded">
{`1. Obtain the public key (often available at /.well-known/jwks.json)
2. Change algorithm from "RS256" to "HS256" in header
3. Sign the token using the public key as HMAC secret
4. Submit the forged token`}
          </pre>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Step-by-Step Exploitation Process</h4>
        
        <h5 className="text-lg font-medium mb-3">Phase 1: Token Discovery</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li>Intercept legitimate authentication requests</li>
          <li>Identify JWT tokens in Authorization headers, cookies, or localStorage</li>
          <li>Decode the token to examine header and payload structure</li>
          <li>Note the algorithm used and any interesting claims</li>
        </ol>

        <h5 className="text-lg font-medium mb-3">Phase 2: Vulnerability Assessment</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li>Test for "none" algorithm acceptance</li>
          <li>Attempt algorithm switching attacks</li>
          <li>Check for weak secret patterns</li>
          <li>Verify signature validation is enforced</li>
          <li>Test token expiration and invalidation mechanisms</li>
        </ol>

        <h5 className="text-lg font-medium mb-3">Phase 3: Token Manipulation</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li>Modify claims (user ID, role, permissions)</li>
          <li>Extend expiration times</li>
          <li>Create entirely new tokens if secret is compromised</li>
          <li>Test the modified tokens against protected endpoints</li>
        </ol>
      </div>

      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable JWT Implementation" 
        code={`// Vulnerable Node.js JWT verification
const jwt = require('jsonwebtoken');
const fs = require('fs');

// Weak secret stored in code
const JWT_SECRET = 'secret123';

// Load public key for verification (vulnerable to algorithm confusion)
const publicKey = fs.readFileSync('public.pem');

function verifyToken(token) {
  try {
    // Vulnerable: No algorithm specification
    // Accepts any algorithm, including "none"
    const decoded = jwt.verify(token, JWT_SECRET);
    return { valid: true, payload: decoded };
  } catch (error) {
    // Fallback to public key verification
    try {
      const decoded = jwt.verify(token, publicKey);
      return { valid: true, payload: decoded };
    } catch (err) {
      return { valid: false, error: err.message };
    }
  }
}

// Express middleware with vulnerabilities
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }
  
  const result = verifyToken(token);
  
  if (!result.valid) {
    return res.status(403).json({ message: 'Invalid token' });
  }
  
  // No additional validation of claims
  req.user = result.payload;
  next();
}

// Token creation with vulnerabilities
function createToken(userId, role) {
  return jwt.sign(
    {
      userId: userId,
      role: role,
      // No expiration set - tokens never expire
      admin: false // Hardcoded claim that could be modified
    },
    JWT_SECRET // Using weak secret
  );
}`} 
      />

      <div className="mb-6">
        <p className="font-semibold mb-2">Attack Payload for Above Code:</p>
        <div className="bg-red-900/20 p-4 rounded-lg">
          <pre className="text-sm">
{`// Modified JWT with "none" algorithm
// Header: {"alg":"none","typ":"JWT"}
// Payload: {"userId":"1","role":"admin","admin":true}
// Signature: (empty)

const maliciousToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOiIxIiwicm9sZSI6ImFkbWluIiwiYWRtaW4iOnRydWV9.";

// This token will be accepted due to no algorithm validation`}
          </pre>
        </div>
      </div>
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure JWT Implementation" 
        code={`// Secure Node.js JWT implementation
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Strong secret from environment variables
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_ALGORITHM = 'HS256';
const JWT_EXPIRY = '15m'; // Short expiration time

// Blacklist for revoked tokens
const revokedTokens = new Set();

function verifyToken(token) {
  try {
    // Check if token is revoked
    if (revokedTokens.has(token)) {
      throw new Error('Token has been revoked');
    }

    // Secure verification with explicit algorithm
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: [JWT_ALGORITHM], // Only allow specific algorithm
      complete: true,              // Get full decoded token
      ignoreExpiration: false,     // Enforce expiration
      clockTolerance: 0           // No clock skew tolerance
    });
    
    // Validate additional claims
    const payload = decoded.payload;
    
    if (!payload.iss || payload.iss !== 'secure-app') {
      throw new Error('Invalid issuer');
    }
    
    if (!payload.aud || payload.aud !== 'secure-app-users') {
      throw new Error('Invalid audience');
    }
    
    // Validate user still exists and has required permissions
    if (!isValidUser(payload.sub)) {
      throw new Error('User no longer valid');
    }
    
    return { valid: true, payload: payload, jti: decoded.payload.jti };
  } catch (error) {
    return { valid: false, error: error.message };
  }
}

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authentication required' });
  }
  
  const token = authHeader.substring(7);
  const result = verifyToken(token);
  
  if (!result.valid) {
    return res.status(403).json({ message: 'Invalid token', error: result.error });
  }
  
  // Store minimal user info
  req.user = {
    id: result.payload.sub,
    role: result.payload.role,
    jti: result.jti
  };
  
  next();
}

function createToken(userId, role) {
  const jti = crypto.randomBytes(16).toString('hex'); // Unique token ID
  
  return jwt.sign(
    {
      sub: userId,                    // Subject (user ID)
      role: role,                     // User role
      iss: 'secure-app',             // Issuer
      aud: 'secure-app-users',       // Audience
      jti: jti,                      // JWT ID for revocation
      iat: Math.floor(Date.now() / 1000), // Issued at
      nbf: Math.floor(Date.now() / 1000)   // Not before
    },
    JWT_SECRET,
    {
      algorithm: JWT_ALGORITHM,
      expiresIn: JWT_EXPIRY
    }
  );
}

// Token revocation functionality
function revokeToken(token) {
  revokedTokens.add(token);
  // In production, store in Redis or database with TTL
}

// Periodic cleanup of expired revoked tokens
setInterval(() => {
  const now = Math.floor(Date.now() / 1000);
  for (const token of revokedTokens) {
    try {
      const decoded = jwt.decode(token);
      if (decoded && decoded.exp && decoded.exp < now) {
        revokedTokens.delete(token);
      }
    } catch (error) {
      revokedTokens.delete(token); // Remove invalid tokens
    }
  }
}, 60000); // Clean up every minute`} 
      />

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Testing for JWT Vulnerabilities</h4>
        
        <h5 className="text-lg font-medium mb-3">Manual Testing Steps</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li><strong>Token Structure Analysis</strong>
            <ul className="list-disc pl-6 mt-2 space-y-1">
              <li>Decode JWT using online tools or jwt.io</li>
              <li>Examine header for algorithm and key ID</li>
              <li>Review payload for sensitive information</li>
              <li>Check for proper expiration claims</li>
            </ul>
          </li>
          <li><strong>Algorithm Testing</strong>
            <ul className="list-disc pl-6 mt-2 space-y-1">
              <li>Change algorithm to "none" and remove signature</li>
              <li>Switch between HS256 and RS256</li>
              <li>Test with unsupported algorithms</li>
            </ul>
          </li>
          <li><strong>Signature Validation</strong>
            <ul className="list-disc pl-6 mt-2 space-y-1">
              <li>Modify payload without changing signature</li>
              <li>Remove or corrupt the signature</li>
              <li>Test with completely invalid signatures</li>
            </ul>
          </li>
          <li><strong>Claims Manipulation</strong>
            <ul className="list-disc pl-6 mt-2 space-y-1">
              <li>Modify user ID, role, or privilege claims</li>
              <li>Extend expiration times</li>
              <li>Add or remove custom claims</li>
            </ul>
          </li>
        </ol>

        <h5 className="text-lg font-medium mb-3">Automated Testing Tools</h5>
        <ul className="list-disc pl-6 space-y-2 mb-4">
          <li><strong>jwt_tool</strong>: Comprehensive JWT testing toolkit</li>
          <li><strong>JSON Web Token Attacker (Burp Extension)</strong>: GUI-based JWT testing</li>
          <li><strong>PyJWT</strong>: Python library for JWT manipulation</li>
          <li><strong>John the Ripper</strong>: JWT secret brute-forcing</li>
          <li><strong>Hashcat</strong>: GPU-accelerated JWT secret cracking</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Prevention and Secure Implementation</h4>
        
        <h5 className="text-lg font-medium mb-3">Key Security Measures</h5>
        <ul className="list-disc pl-6 space-y-2 mb-4">
          <li><strong>Algorithm Specification</strong>: Always specify allowed algorithms explicitly</li>
          <li><strong>Strong Secrets</strong>: Use cryptographically secure, high-entropy secrets</li>
          <li><strong>Short Expiration</strong>: Implement reasonable token lifetimes (15-60 minutes)</li>
          <li><strong>Proper Key Management</strong>: Store secrets securely, rotate regularly</li>
          <li><strong>Signature Validation</strong>: Never skip signature verification</li>
          <li><strong>Claims Validation</strong>: Validate all claims including issuer, audience, and expiration</li>
          <li><strong>Token Revocation</strong>: Implement blacklisting for compromised tokens</li>
        </ul>

        <h5 className="text-lg font-medium mb-3">Environment-Specific Considerations</h5>
        
        <div className="mb-4">
          <h6 className="font-medium mb-2">Development Environment</h6>
          <ul className="list-disc pl-6 space-y-1">
            <li>Use environment variables for secrets even in development</li>
            <li>Implement proper logging for JWT validation failures</li>
            <li>Test with various JWT manipulation tools</li>
          </ul>
        </div>

        <div className="mb-4">
          <h6 className="font-medium mb-2">Production Environment</h6>
          <ul className="list-disc pl-6 space-y-1">
            <li>Use Hardware Security Modules (HSMs) for key storage</li>
            <li>Implement rate limiting on authentication endpoints</li>
            <li>Monitor for unusual token patterns or validation failures</li>
            <li>Use Redis or similar for distributed token blacklisting</li>
          </ul>
        </div>

        <div className="mb-4">
          <h6 className="font-medium mb-2">Microservices Architecture</h6>
          <ul className="list-disc pl-6 space-y-1">
            <li>Centralize JWT validation in API gateways</li>
            <li>Use service mesh for secure inter-service communication</li>
            <li>Implement proper token propagation patterns</li>
          </ul>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Special Cases and Advanced Attacks</h4>
        
        <h5 className="text-lg font-medium mb-3">JWK Confusion Attacks</h5>
        <p className="mb-4">
          Attackers exploit the 'jku' (JWK Set URL) header parameter to point to attacker-controlled key sets.
        </p>
        
        <h5 className="text-lg font-medium mb-3">Kid (Key ID) Manipulation</h5>
        <p className="mb-4">
          The 'kid' parameter can be manipulated to perform path traversal or SQL injection in key lookup operations.
        </p>
        
        <h5 className="text-lg font-medium mb-3">X5U (X.509 URL) Attacks</h5>
        <p className="mb-4">
          Similar to JWK attacks, but using X.509 certificate chains from attacker-controlled URLs.
        </p>

        <h5 className="text-lg font-medium mb-3">Time-based Attacks</h5>
        <p className="mb-4">
          Exploiting timing differences in JWT validation to infer information about the signing process.
        </p>
      </div>
    </section>
  );
};

export default JWTAttacks;
