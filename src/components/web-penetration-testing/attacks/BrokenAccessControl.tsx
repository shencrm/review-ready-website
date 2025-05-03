
import React from 'react';
import { KeyRound } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const BrokenAccessControl: React.FC = () => {
  return (
    <section id="access" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Broken Access Control</h3>
      <p className="mb-6">
        Broken Access Control occurs when restrictions on what authenticated users are allowed to do are not 
        properly enforced. Attackers can exploit these flaws to access unauthorized functionality or data,
        potentially leading to data theft, modification, or destruction of sensitive information.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Common Access Control Vulnerabilities</h4>
      <ul className="list-disc pl-6 space-y-2 mb-6">
        <li><strong>Insecure Direct Object References (IDOR):</strong> Directly accessing objects via identifiers without proper authorization checks</li>
        <li><strong>Vertical Privilege Escalation:</strong> Accessing features requiring higher privileges than the user possesses</li>
        <li><strong>Horizontal Privilege Escalation:</strong> Accessing data of other users at the same privilege level</li>
        <li><strong>Missing Function Level Access Control:</strong> Failure to restrict access at the function or API level</li>
        <li><strong>Path Traversal:</strong> Accessing directories outside the intended directory structure</li>
        <li><strong>Parameter Tampering:</strong> Modifying parameters to bypass access controls</li>
        <li><strong>Client-Side Enforcement:</strong> Relying on hidden fields, JavaScript, or client-side restrictions for access control</li>
      </ul>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Testing for Access Control Issues</h4>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li>Modifying URL parameters, internal application state, or HTML page</li>
        <li>Changing user to admin or higher privilege role identifiers</li>
        <li>Forcing browsing to authenticated pages as anonymous user</li>
        <li>Accessing API without proper authentication tokens</li>
        <li>Testing different HTTP methods (GET vs POST) for the same endpoint</li>
        <li>Modifying data in requests to reference another user's data</li>
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

// An attacker can simply change the userId parameter to access other users' data

// Client-side access control (easily bypassed)
function showAdminPanel() {
  // Vulnerable: relying on client-side role check
  if (user.role === 'admin') {
    document.getElementById('adminPanel').style.display = 'block';
  }
}

// Hidden admin feature with no server-side check
app.get('/api/admin-stats', (req, res) => {
  // Vulnerable: no verification of admin status before returning sensitive data
  db.getSystemStatistics()
    .then(stats => res.json(stats))
    .catch(err => res.status(500).json({ error: err.message }));
});`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure Access Control" 
        code={`// Authentication middleware to ensure user is logged in
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  try {
    // Verify the token and extract user information
    const user = verifyToken(token);
    req.user = user; // Attach user to request for use in later middleware
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Authorization middleware
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
app.get('/api/users/:userId/profile', authenticate, checkAccessPermission, (req, res) => {
  const userId = req.params.userId;
  
  db.getUserProfile(userId)
    .then(profile => res.json(profile))
    .catch(err => res.status(500).json({ error: err.message }));
});

// Role-based access control middleware
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
}

// Apply admin-only middleware to admin routes
app.get('/api/admin-stats', authenticate, requireRole('ADMIN'), (req, res) => {
  db.getSystemStatistics()
    .then(stats => res.json(stats))
    .catch(err => res.status(500).json({ error: err.message }));
});

// Implement proper server-side rendering based on permissions
app.get('/dashboard', authenticate, (req, res) => {
  // Generate page with only the components the user has access to
  const userPermissions = getUserPermissions(req.user);
  
  res.render('dashboard', {
    user: req.user,
    showAdminPanel: userPermissions.includes('admin.access'),
    showReports: userPermissions.includes('reports.view')
  });
});`} 
      />
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Access Control Best Practices</h4>
      <ul className="list-disc pl-6 space-y-2">
        <li>Implement access control as server-side mechanisms, never client-side</li>
        <li>Deny access by default (whitelist approach) rather than allowing by default</li>
        <li>Implement ownership checks for all resource accesses</li>
        <li>Log access control failures and alert admins when appropriate</li>
        <li>Rate limit API access to minimize damage from automated attacks</li>
        <li>Invalidate JWT tokens when users log out or change their password</li>
        <li>Use principle of least privilege for service accounts and APIs</li>
      </ul>
    </section>
  );
};

export default BrokenAccessControl;
