
import React from 'react';
import { KeyRound } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const JWTAttacks: React.FC = () => {
  return (
    <section id="jwt" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">JWT Attacks</h3>
      <p className="mb-6">
        JSON Web Tokens (JWTs) are commonly used for authentication and session management. JWT attacks exploit
        weaknesses in token generation, validation, or handling, allowing attackers to forge tokens, escalate
        privileges, or impersonate other users.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Common JWT Attacks</h4>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li><strong>Algorithm "None" Attack</strong>: Modifying the algorithm to "none" to bypass signature validation</li>
        <li><strong>Weak Secret Keys</strong>: Brute-forcing weak secrets used to sign tokens</li>
        <li><strong>Key Confusion (alg Switching)</strong>: Switching between symmetric and asymmetric algorithms</li>
        <li><strong>Token Replay</strong>: Reusing a valid token after it should be invalidated</li>
        <li><strong>Missing Signature Validation</strong>: Accepting tokens without proper signature checks</li>
      </ul>
      
      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable JWT Implementation" 
        code={`// Server-side JWT verification
const jwt = require('jsonwebtoken');

app.get('/api/user-data', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).send('No token provided');
  }
  
  try {
    // Vulnerable: No algorithm specification and weak secret
    const payload = jwt.verify(token, 'secret123');
    
    // Proceed with the request using payload data
    res.json(getUserData(payload.userId));
  } catch (err) {
    res.status(401).send('Invalid token');
  }
});`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure JWT Implementation" 
        code={`// Server-side secure JWT verification
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Generate a strong secret key (store securely in environment variables)
const SECRET_KEY = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

app.get('/api/user-data', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).send('No token provided');
  }
  
  try {
    // Securely verify token with explicit algorithm and other options
    const payload = jwt.verify(token, SECRET_KEY, {
      algorithms: ['HS256'], // Only allow specific algorithm
      complete: true,        // Get full decoded token
      ignoreExpiration: false // Enforce token expiration
    });
    
    // Check additional claims for extra security
    if (!payload.iss || payload.iss !== 'our-auth-server') {
      return res.status(401).send('Invalid token issuer');
    }
    
    res.json(getUserData(payload.sub)); // Use 'sub' claim for user ID
  } catch (err) {
    res.status(401).send('Invalid token');
  }
});

// When creating tokens, set appropriate expiration and claims
function createToken(userId) {
  return jwt.sign(
    {
      sub: userId,         // Subject (user identifier)
      iss: 'our-auth-server', // Issuer
      iat: Math.floor(Date.now() / 1000), // Issued at
      exp: Math.floor(Date.now() / 1000) + (60 * 60) // Expire in 1 hour
    },
    SECRET_KEY,
    { algorithm: 'HS256' }
  );
}`} 
      />
    </section>
  );
};

export default JWTAttacks;
