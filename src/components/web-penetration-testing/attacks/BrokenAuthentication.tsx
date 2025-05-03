
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
      </p>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        <SecurityCard
          title="Credential Stuffing"
          description="Automated injection of breached username/password pairs to gain unauthorized access to user accounts."
          severity="high"
        />
        <SecurityCard
          title="Brute Force Attacks"
          description="Attempting to guess passwords through exhaustive trial-and-error methods to gain access to accounts."
          severity="high"
        />
      </div>
      
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
    return generateToken(user);
  }
  return null;
}`} 
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
  message: 'Too many login attempts, please try again later'
});

async function loginUser(email, password) {
  const user = await db.users.findOne({ email });
  
  if (user) {
    // Compare with securely hashed password
    const match = await bcrypt.compare(password, user.passwordHash);
    if (match) {
      // Create session with proper expiry and rotation
      return {
        token: generateSecureToken(user),
        expiresAt: new Date(Date.now() + 3600000) // 1 hour
      };
    }
  }
  
  // Use constant-time comparison to prevent timing attacks
  await bcrypt.compare(password, '$2b$10$validHashForTimingAttackPrevention');
  return null;
}`} 
      />
    </section>
  );
};

export default BrokenAuthentication;
