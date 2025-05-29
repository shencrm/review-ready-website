
import React from 'react';
import { KeyRound } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { InfoIcon } from 'lucide-react';

const BrokenAccessControl: React.FC = () => {
  return (
    <section id="access" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Broken Access Control</h3>
      
      <div className="space-y-6">
        {/* Introduction */}
        <div>
          <p className="mb-4">
            Broken Access Control occurs when restrictions on what authenticated users are allowed to do are not 
            properly enforced. Attackers can exploit these flaws to access unauthorized functionality or data,
            potentially leading to data theft, modification, or destruction of sensitive information. This vulnerability
            consistently ranks in the OWASP Top 10 and can have severe business impact.
          </p>
          
          <Alert className="mb-4 text-amber-900 dark:text-amber-200 bg-slate-50">
            <InfoIcon className="h-4 w-4" />
            <AlertTitle>Attacker's Goal</AlertTitle>
            <AlertDescription>
              Access resources, data, or functionality beyond their authorized permissions level, potentially
              escalating privileges horizontally (accessing other users' data) or vertically (gaining admin access).
            </AlertDescription>
          </Alert>
        </div>

        {/* Attack Types */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Common Access Control Vulnerabilities</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <SecurityCard
              title="Insecure Direct Object References (IDOR)"
              description="Directly accessing objects via identifiers without proper authorization checks. Attackers can manipulate parameters to access other users' data or resources."
              severity="high"
            />
            <SecurityCard
              title="Vertical Privilege Escalation"
              description="Accessing features requiring higher privileges than the user possesses. Users gain admin or elevated role functionality without proper authorization."
              severity="high"
            />
            <SecurityCard
              title="Horizontal Privilege Escalation"
              description="Accessing data of other users at the same privilege level. Users can view or modify data belonging to other users with similar roles."
              severity="high"
            />
            <SecurityCard
              title="Missing Function Level Access Control"
              description="Failure to restrict access at the function or API level. Hidden or administrative functions can be accessed by unauthorized users."
              severity="medium"
            />
          </div>
        </div>

        {/* Vulnerable Components */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Commonly Vulnerable Components</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md">
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>API Endpoints:</strong> REST APIs without proper authorization checks on resources</li>
              <li><strong>Database Record Access:</strong> Direct object references using predictable IDs</li>
              <li><strong>File System Access:</strong> Direct file access via URLs or path parameters</li>
              <li><strong>Administrative Interfaces:</strong> Admin panels accessible without privilege verification</li>
              <li><strong>User Profile Management:</strong> Profile editing without ownership validation</li>
              <li><strong>Reporting Systems:</strong> Reports accessible beyond intended user scope</li>
              <li><strong>Configuration Settings:</strong> System configurations modifiable by regular users</li>
              <li><strong>Content Management:</strong> CMS functions available to non-authorized users</li>
            </ul>
          </div>
        </div>

        {/* Why These Attacks Work */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Why Broken Access Control Attacks Work</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Design Flaws</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Trust in client-side access control decisions</li>
                <li>Lack of centralized authorization logic</li>
                <li>Inconsistent access control implementation</li>
                <li>Missing authorization checks on critical functions</li>
                <li>Over-reliance on obscurity for security</li>
                <li>Default-allow instead of default-deny approach</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Implementation Weaknesses</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Predictable resource identifiers (sequential IDs)</li>
                <li>No ownership validation before resource access</li>
                <li>Insufficient role-based access control (RBAC)</li>
                <li>Missing attribute-based access control (ABAC)</li>
                <li>Inadequate testing of authorization logic</li>
                <li>Complex permission systems with gaps</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Step-by-Step Attack Methodology */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Step-by-Step Attack Methodology</h4>
          <Tabs defaultValue="mapping">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="mapping">Resource Mapping</TabsTrigger>
              <TabsTrigger value="idor">IDOR Testing</TabsTrigger>
              <TabsTrigger value="privilege">Privilege Escalation</TabsTrigger>
              <TabsTrigger value="exploitation">Exploitation</TabsTrigger>
            </TabsList>
            
            <TabsContent value="mapping" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 1: Access Control Mapping</h5>
                <ol className="list-decimal pl-6 space-y-2">
                  <li><strong>Identify Resource Access Patterns:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Map all application endpoints and their parameters</li>
                      <li>Identify resources accessed via direct object references</li>
                      <li>Document user roles and their intended permissions</li>
                      <li>Find hidden or administrative functionality</li>
                    </ul>
                  </li>
                  <li><strong>Analyze Authorization Mechanisms:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Understand how the application enforces access control</li>
                      <li>Identify client-side vs server-side access controls</li>
                      <li>Check for consistent authorization implementation</li>
                      <li>Look for bypass opportunities in the logic</li>
                    </ul>
                  </li>
                </ol>
              </div>
            </TabsContent>
            
            <TabsContent value="idor" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 2: IDOR Testing</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">IDOR Attack Vectors:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Sequential ID Manipulation:</strong> Change numeric IDs to access other records</li>
                    <li><strong>GUID/UUID Testing:</strong> Try to predict or brute force UUIDs</li>
                    <li><strong>Filename Manipulation:</strong> Access other users' files via filename changes</li>
                    <li><strong>API Parameter Testing:</strong> Modify API parameters to access unauthorized data</li>
                    <li><strong>Batch Operations:</strong> Test bulk operations with mixed authorization levels</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="privilege" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 3: Privilege Escalation Testing</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Escalation Techniques:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Role Parameter Manipulation:</strong> Change role parameters in requests</li>
                    <li><strong>HTTP Method Tampering:</strong> Try different HTTP methods (GET→POST→PUT→DELETE)</li>
                    <li><strong>Header Manipulation:</strong> Modify headers that might indicate user roles</li>
                    <li><strong>Cookie/Token Manipulation:</strong> Alter session data to gain elevated access</li>
                    <li><strong>URL Path Manipulation:</strong> Access admin paths directly</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="exploitation" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 4: Exploitation and Impact</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Post-Access Actions:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Data Extraction:</strong> Download sensitive data accessible through IDOR</li>
                    <li><strong>Configuration Changes:</strong> Modify system settings if admin access gained</li>
                    <li><strong>User Account Manipulation:</strong> Create or modify user accounts</li>
                    <li><strong>Content Modification:</strong> Change data belonging to other users</li>
                    <li><strong>System Compromise:</strong> Use admin access for further attacks</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Example Payloads and Attack Vectors */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Common Attack Payloads and Vectors</h4>
          <CodeExample
            language="bash"
            title="IDOR and Access Control Testing Payloads"
            code={`# Sequential ID manipulation
# Original request: GET /api/user/profile/123
# IDOR test: Change user ID to access other profiles
curl -H "Authorization: Bearer YOUR_TOKEN" http://target.com/api/user/profile/124
curl -H "Authorization: Bearer YOUR_TOKEN" http://target.com/api/user/profile/125

# File access IDOR
# Original: GET /files/user123_document.pdf
# Test: Access other users' files
curl -H "Cookie: session=abc123" http://target.com/files/user124_document.pdf

# API endpoint privilege escalation
# Try accessing admin endpoints with regular user token
curl -H "Authorization: Bearer REGULAR_USER_TOKEN" http://target.com/api/admin/users
curl -H "Authorization: Bearer REGULAR_USER_TOKEN" http://target.com/api/admin/settings

# HTTP method tampering
# If GET is restricted, try POST, PUT, DELETE
curl -X POST http://target.com/admin/delete-user/123
curl -X PUT -d '{"role":"admin"}' http://target.com/api/user/123

# Parameter pollution for access control bypass
curl "http://target.com/api/user/profile?id=123&id=124&admin=true"`}
          />
        </div>

        {/* Vulnerable Code Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Vulnerable Code Examples</h4>
          <CodeExample 
            language="javascript" 
            isVulnerable={true}
            title="IDOR Vulnerability - No Authorization Check" 
            code={`// Vulnerable Node.js/Express endpoint
app.get('/api/users/:userId/profile', (req, res) => {
  const userId = req.params.userId;
  
  // NO AUTHORIZATION CHECK - anyone can access any user's profile
  db.getUserProfile(userId)
    .then(profile => {
      if (profile) {
        res.json(profile); // Returns sensitive user data
      } else {
        res.status(404).json({ error: 'Profile not found' });
      }
    })
    .catch(err => res.status(500).json({ error: err.message }));
});

// Vulnerable admin function access
app.get('/api/admin/users', (req, res) => {
  // NO ROLE CHECK - any authenticated user can access admin data
  if (req.session.userId) {
    db.getAllUsers()
      .then(users => res.json(users))
      .catch(err => res.status(500).json({ error: err.message }));
  } else {
    res.status(401).json({ error: 'Authentication required' });
  }
});

// Vulnerable file access
app.get('/files/:filename', (req, res) => {
  const filename = req.params.filename;
  
  // NO OWNERSHIP CHECK - users can access any file
  const filePath = path.join(__dirname, 'uploads', filename);
  
  if (fs.existsSync(filePath)) {
    res.sendFile(filePath);
  } else {
    res.status(404).json({ error: 'File not found' });
  }
});

// Client-side access control (easily bypassed)
app.get('/dashboard', (req, res) => {
  const user = req.session.user;
  
  res.render('dashboard', {
    user: user,
    // Vulnerable: client-side role check only
    showAdminPanel: user && user.role === 'admin'
  });
});`} 
          />
          
          <CodeExample 
            language="python" 
            isVulnerable={true}
            title="Vulnerable Python Flask Access Control" 
            code={`from flask import Flask, request, session, jsonify
import sqlite3

app = Flask(__name__)

@app.route('/api/orders/<int:order_id>')
def get_order(order_id):
    # Vulnerable: No ownership check
    # Any authenticated user can access any order
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Direct query without authorization check
    cursor.execute('SELECT * FROM orders WHERE id = ?', (order_id,))
    order = cursor.fetchone()
    
    if order:
        return jsonify({
            'id': order[0],
            'user_id': order[1],
            'amount': order[2],
            'details': order[3]
        })
    else:
        return jsonify({'error': 'Order not found'}), 404

@app.route('/api/admin/delete-user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    # Vulnerable: No admin role verification
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Dangerous operation without proper authorization
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    
    return jsonify({'message': 'User deleted successfully'})

@app.route('/api/user/<int:user_id>/update', methods=['POST'])
def update_user(user_id):
    # Vulnerable: Users can update any user's data
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    data = request.get_json()
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # No check if the session user owns this profile
    cursor.execute(
        'UPDATE users SET name = ?, email = ? WHERE id = ?',
        (data.get('name'), data.get('email'), user_id)
    )
    conn.commit()
    
    return jsonify({'message': 'User updated successfully'})`} 
          />
        </div>

        {/* Secure Code Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Secure Access Control Implementation</h4>
          <CodeExample 
            language="javascript" 
            isVulnerable={false}
            title="Secure Authorization with Ownership and Role Checks" 
            code={`// Secure Node.js/Express with proper authorization
const authorize = {
  // Middleware to check if user owns the resource
  ownsResource: (resourceType) => {
    return async (req, res, next) => {
      try {
        const userId = req.user.id; // From authentication middleware
        const resourceId = req.params[resourceType + 'Id'];
        
        // Check ownership based on resource type
        let isOwner = false;
        
        switch (resourceType) {
          case 'user':
            isOwner = userId === parseInt(resourceId);
            break;
          case 'order':
            const order = await db.getOrder(resourceId);
            isOwner = order && order.userId === userId;
            break;
          case 'file':
            const file = await db.getFile(resourceId);
            isOwner = file && file.ownerId === userId;
            break;
        }
        
        if (!isOwner && req.user.role !== 'admin') {
          return res.status(403).json({ error: 'Access denied: insufficient permissions' });
        }
        
        req.resource = { id: resourceId, type: resourceType };
        next();
      } catch (error) {
        console.error('Authorization error:', error);
        res.status(500).json({ error: 'Authorization check failed' });
      }
    };
  },
  
  // Middleware to check user roles
  requireRole: (requiredRole) => {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
      }
      
      // Define role hierarchy
      const roleHierarchy = {
        'user': 1,
        'moderator': 2,
        'admin': 3,
        'superadmin': 4
      };
      
      const userRoleLevel = roleHierarchy[req.user.role] || 0;
      const requiredRoleLevel = roleHierarchy[requiredRole] || 0;
      
      if (userRoleLevel < requiredRoleLevel) {
        return res.status(403).json({ error: 'Insufficient role privileges' });
      }
      
      next();
    };
  },
  
  // Attribute-based access control
  checkPermission: (permission) => {
    return async (req, res, next) => {
      try {
        const hasPermission = await permissionService.userHasPermission(
          req.user.id,
          permission,
          req.resource
        );
        
        if (!hasPermission) {
          return res.status(403).json({ error: \`Permission denied: \${permission}\` });
        }
        
        next();
      } catch (error) {
        console.error('Permission check error:', error);
        res.status(500).json({ error: 'Permission check failed' });
      }
    };
  }
};

// Secure endpoint implementations
app.get('/api/users/:userId/profile', 
  authenticate, // Verify user is logged in
  authorize.ownsResource('user'), // Check ownership or admin role
  async (req, res) => {
    try {
      const userId = req.params.userId;
      const profile = await db.getUserProfile(userId);
      
      if (!profile) {
        return res.status(404).json({ error: 'Profile not found' });
      }
      
      // Filter sensitive data based on user role
      const filteredProfile = filterProfileData(profile, req.user);
      res.json(filteredProfile);
    } catch (error) {
      console.error('Profile fetch error:', error);
      res.status(500).json({ error: 'Failed to fetch profile' });
    }
  }
);

// Admin-only endpoint with proper role checking
app.get('/api/admin/users',
  authenticate,
  authorize.requireRole('admin'),
  authorize.checkPermission('read:all_users'),
  async (req, res) => {
    try {
      // Additional checks for sensitive operations
      await auditLog.logAdminAction(req.user.id, 'VIEW_ALL_USERS', req.ip);
      
      const users = await db.getAllUsers();
      
      // Filter data based on admin level
      const filteredUsers = users.map(user => filterUserData(user, req.user.role));
      
      res.json(filteredUsers);
    } catch (error) {
      console.error('Admin users fetch error:', error);
      res.status(500).json({ error: 'Failed to fetch users' });
    }
  }
);

// Secure file access with ownership validation
app.get('/files/:fileId',
  authenticate,
  authorize.ownsResource('file'),
  async (req, res) => {
    try {
      const fileId = req.params.fileId;
      const file = await db.getFile(fileId);
      
      if (!file) {
        return res.status(404).json({ error: 'File not found' });
      }
      
      // Additional security checks
      const isFileAccessible = await fileAccessService.checkAccess(
        file,
        req.user,
        req.ip
      );
      
      if (!isFileAccessible) {
        return res.status(403).json({ error: 'File access denied' });
      }
      
      // Log file access for audit
      await auditLog.logFileAccess(req.user.id, fileId, req.ip);
      
      // Secure file serving
      const sanitizedPath = path.normalize(file.path);
      const safePath = path.join(UPLOAD_DIR, path.basename(sanitizedPath));
      
      res.sendFile(safePath);
    } catch (error) {
      console.error('File access error:', error);
      res.status(500).json({ error: 'File access failed' });
    }
  }
);

// Utility functions for data filtering
function filterProfileData(profile, requestingUser) {
  const filtered = { ...profile };
  
  // Remove sensitive fields for non-owners
  if (profile.userId !== requestingUser.id && requestingUser.role !== 'admin') {
    delete filtered.email;
    delete filtered.phone;
    delete filtered.address;
    delete filtered.paymentMethods;
  }
  
  return filtered;
}

function filterUserData(user, requestingUserRole) {
  const filtered = {
    id: user.id,
    username: user.username,
    role: user.role,
    createdAt: user.createdAt
  };
  
  // Include sensitive data only for higher-level admins
  if (requestingUserRole === 'superadmin') {
    filtered.email = user.email;
    filtered.lastLogin = user.lastLogin;
    filtered.ipAddress = user.lastIpAddress;
  }
  
  return filtered;
}`} 
          />
        </div>

        {/* Testing Methodology */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Step-by-Step Testing for Broken Access Control</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md">
            <h5 className="font-semibold mb-2">Comprehensive Testing Checklist:</h5>
            <ol className="list-decimal pl-6 space-y-2 text-sm">
              <li><strong>Authentication Bypass Testing:</strong>
                <ul className="list-disc pl-6 mt-1 space-y-1">
                  <li>Access protected resources without authentication</li>
                  <li>Test forced browsing to admin panels</li>
                  <li>Check for default credentials on admin interfaces</li>
                  <li>Test session management and logout functionality</li>
                </ul>
              </li>
              <li><strong>Authorization Testing:</strong>
                <ul className="list-disc pl-6 mt-1 space-y-1">
                  <li>Test horizontal privilege escalation (accessing peer data)</li>
                  <li>Test vertical privilege escalation (accessing admin functions)</li>
                  <li>Verify role-based access control implementation</li>
                  <li>Test resource ownership validation</li>
                </ul>
              </li>
              <li><strong>IDOR Testing:</strong>
                <ul className="list-disc pl-6 mt-1 space-y-1">
                  <li>Manipulate object identifiers in URLs and parameters</li>
                  <li>Test sequential and random ID prediction</li>
                  <li>Check for UUID/GUID predictability</li>
                  <li>Test batch operations with mixed permissions</li>
                </ul>
              </li>
              <li><strong>HTTP Method Testing:</strong>
                <ul className="list-disc pl-6 mt-1 space-y-1">
                  <li>Test different HTTP methods on same endpoints</li>
                  <li>Check for method-based authorization bypass</li>
                  <li>Test OPTIONS, HEAD, TRACE methods</li>
                  <li>Verify proper method restrictions</li>
                </ul>
              </li>
            </ol>
          </div>
        </div>

        {/* Testing Tools */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Access Control Testing Tools</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Automated Testing Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Burp Suite Professional:</strong> Comprehensive access control testing</li>
                <li><strong>OWASP ZAP:</strong> Free access control scanner</li>
                <li><strong>Authz (by Burp):</strong> Specialized authorization testing</li>
                <li><strong>Auth Analyzer:</strong> Authorization bypass detection</li>
                <li><strong>Autorize:</strong> Automated authorization testing</li>
                <li><strong>AccessControlAllowOrigin:</strong> CORS testing</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Manual Testing Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Browser Developer Tools:</strong> Request manipulation</li>
                <li><strong>Postman/Insomnia:</strong> API authorization testing</li>
                <li><strong>curl:</strong> Command-line HTTP testing</li>
                <li><strong>Custom Scripts:</strong> Automated IDOR testing</li>
                <li><strong>Browser Extensions:</strong> Cookie/header manipulation</li>
                <li><strong>Proxy Tools:</strong> Request interception and modification</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Prevention Strategies */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Comprehensive Prevention Strategies</h4>
          <Tabs defaultValue="design">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="design">Secure Design</TabsTrigger>
              <TabsTrigger value="implementation">Implementation</TabsTrigger>
              <TabsTrigger value="testing">Testing & Monitoring</TabsTrigger>
            </TabsList>
            
            <TabsContent value="design" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold mb-2">Secure Design Principles</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Implement defense in depth with multiple authorization layers</li>
                    <li>Use principle of least privilege for all users and processes</li>
                    <li>Design with deny-by-default access control policies</li>
                    <li>Implement centralized authorization logic and services</li>
                    <li>Use attribute-based access control (ABAC) for complex scenarios</li>
                    <li>Design clear separation between authentication and authorization</li>
                    <li>Implement proper audit logging for all access decisions</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="implementation" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold mb-2">Secure Implementation Practices</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Validate authorization on every server-side request</li>
                    <li>Use unguessable identifiers (UUIDs) instead of sequential IDs</li>
                    <li>Implement proper ownership checks for all resources</li>
                    <li>Use server-side session management with secure tokens</li>
                    <li>Implement role-based access control with clear hierarchies</li>
                    <li>Validate HTTP methods and enforce proper restrictions</li>
                    <li>Use parameterized queries to prevent injection attacks</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="testing" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold mb-2">Testing and Monitoring</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Implement automated access control testing in CI/CD</li>
                    <li>Perform regular penetration testing focusing on authorization</li>
                    <li>Monitor and alert on unauthorized access attempts</li>
                    <li>Implement comprehensive audit logging</li>
                    <li>Use runtime application self-protection (RASP)</li>
                    <li>Regular review of user permissions and roles</li>
                    <li>Implement anomaly detection for unusual access patterns</li>
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
                <li><strong>Spring Security:</strong> Use method-level security annotations</li>
                <li><strong>Django:</strong> Implement proper permissions and decorators</li>
                <li><strong>Express.js:</strong> Use middleware for consistent authorization</li>
                <li><strong>ASP.NET:</strong> Use authorization policies and claims</li>
                <li><strong>Laravel:</strong> Implement gates and policies properly</li>
                <li><strong>React/SPA:</strong> Never rely on client-side access control</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Environment-Specific Challenges</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Microservices:</strong> Implement distributed authorization</li>
                <li><strong>API Gateway:</strong> Centralize authorization decisions</li>
                <li><strong>Cloud Environments:</strong> Use IAM roles and policies</li>
                <li><strong>Mobile Apps:</strong> Implement proper token-based auth</li>
                <li><strong>Third-party Integration:</strong> Validate external access</li>
                <li><strong>Legacy Systems:</strong> Wrap with modern authorization</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default BrokenAccessControl;
