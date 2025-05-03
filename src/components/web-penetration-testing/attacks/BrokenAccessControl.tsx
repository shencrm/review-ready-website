
import React from 'react';
import { KeyRound } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const BrokenAccessControl: React.FC = () => {
  return (
    <section id="access" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Broken Access Control</h3>
      <p className="mb-6">
        Broken Access Control occurs when restrictions on what authenticated users are allowed to do are not 
        properly enforced. Attackers can exploit these flaws to access unauthorized functionality or data.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Common Issues</h4>
      <ul className="list-disc pl-6 space-y-2 mb-6">
        <li>Insecure Direct Object References (IDOR)</li>
        <li>Vertical privilege escalation (accessing features requiring higher privileges)</li>
        <li>Horizontal privilege escalation (accessing data of other users at same privilege level)</li>
        <li>Missing access controls for API endpoints</li>
        <li>Bypassing access control checks by modifying URLs or HTML</li>
      </ul>
      
      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="IDOR Vulnerability" 
        code={`// No authorization check on user data access
app.get('/api/users/:userId/profile', (req, res) => {
  const userId = req.params.userId;
  
  // Vulnerable: retrieves user data without checking if the 
  // current user has permission to access this profile
  db.getUserProfile(userId)
    .then(profile => res.json(profile))
    .catch(err => res.status(500).json({ error: err.message }));
});

// An attacker can simply change the userId parameter to access other users' data`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure Access Control" 
        code={`// Authorization middleware
function checkAccessPermission(req, res, next) {
  const requestedUserId = req.params.userId;
  const currentUserId = req.user.id;
  
  // Allow access only if:
  // 1. User is accessing their own data, or
  // 2. User has admin privileges
  if (requestedUserId === currentUserId || req.user.role === 'ADMIN') {
    next(); // Authorized
  } else {
    res.status(403).json({ error: 'Access denied' });
  }
}

// Apply middleware to protected routes
app.get('/api/users/:userId/profile', checkAccessPermission, (req, res) => {
  const userId = req.params.userId;
  
  db.getUserProfile(userId)
    .then(profile => res.json(profile))
    .catch(err => res.status(500).json({ error: err.message }));
});`} 
      />
    </section>
  );
};

export default BrokenAccessControl;
