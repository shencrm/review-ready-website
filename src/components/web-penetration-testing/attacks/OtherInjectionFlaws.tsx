import React from 'react';
import { Code, Bug, Database, FileText } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const OtherInjectionFlaws: React.FC = () => {
  return (
    <section id="other-injection" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Other Injection Flaws</h3>
      
      <div className="mb-8">
        <p className="mb-4">
          Beyond SQL injection, command injection, and XSS, there are various other injection vulnerabilities that can affect
          web applications. These occur when untrusted data is processed without proper validation or sanitization,
          allowing attackers to inject malicious content or commands into different interpreters and processing engines.
        </p>
        <p className="mb-4">
          These injection flaws exploit the fundamental weakness where user input is trusted and directly incorporated
          into queries, commands, or templates without proper bounds checking or escaping. Each type targets different
          backend systems and processing mechanisms, but they all share the common vulnerability pattern of insufficient
          input validation and output encoding.
        </p>
      </div>

      {/* LDAP Injection */}
      <div className="mb-12">
        <h4 className="text-xl font-semibold mb-6 flex items-center gap-2">
          <Database className="h-6 w-6 text-cybr-primary" />
          LDAP Injection
        </h4>
        
        <div className="mb-6">
          <h5 className="text-lg font-semibold mb-3">What is LDAP Injection?</h5>
          <p className="mb-4">
            LDAP (Lightweight Directory Access Protocol) injection occurs when user input is incorrectly filtered or 
            sanitized before being used in LDAP queries. This vulnerability allows attackers to manipulate LDAP queries
            to access unauthorized information, bypass authentication mechanisms, or modify directory data.
          </p>
          <p className="mb-4">
            LDAP injection is particularly dangerous in enterprise environments where LDAP directories store critical
            user authentication data, organizational structure, and access control information. A successful attack
            can lead to complete compromise of the directory service and all dependent applications.
          </p>
        </div>

        <div className="mb-6">
          <h5 className="text-lg font-semibold mb-3">Attacker Goals</h5>
          <ul className="list-disc pl-6 space-y-2">
            <li><strong>Authentication Bypass:</strong> Circumvent login mechanisms by manipulating authentication queries</li>
            <li><strong>Data Enumeration:</strong> Extract sensitive user information, group memberships, and organizational data</li>
            <li><strong>Privilege Escalation:</strong> Gain access to higher-privilege accounts or administrative functions</li>
            <li><strong>Directory Manipulation:</strong> Modify user attributes, passwords, or group memberships</li>
            <li><strong>Information Disclosure:</strong> Access confidential directory information like email addresses, phone numbers</li>
            <li><strong>Lateral Movement:</strong> Use directory information to identify and attack other systems</li>
          </ul>
        </div>

        <div className="mb-6">
          <h5 className="text-lg font-semibold mb-3">Vulnerable Components</h5>
          <ul className="list-disc pl-6 space-y-2">
            <li><strong>Authentication Systems:</strong> Login forms using LDAP for user verification</li>
            <li><strong>User Search Functions:</strong> Directory search and user lookup features</li>
            <li><strong>Group Management:</strong> Systems managing user groups and organizational units</li>
            <li><strong>Single Sign-On (SSO):</strong> LDAP-based SSO implementations</li>
            <li><strong>Enterprise Applications:</strong> HR systems, email clients, and corporate portals</li>
            <li><strong>Web Applications:</strong> Any application using LDAP for authentication or data retrieval</li>
          </ul>
        </div>

        <div className="mb-6">
          <h5 className="text-lg font-semibold mb-3">Why LDAP Injection Works</h5>
          <div className="bg-cybr-muted/30 p-6 rounded-lg mb-4">
            <p className="mb-3">
              LDAP injection exploits the way LDAP queries are constructed using string concatenation without proper
              input validation. LDAP uses special characters for logical operations (* & | ! = &lt; &gt; ( ) \ / , + " ;)
              that can be manipulated to alter query logic.
            </p>
            <p className="mb-3">
              The vulnerability occurs when user input containing these special characters is directly embedded into
              LDAP search filters, allowing attackers to inject additional conditions or completely change the query structure.
            </p>
          </div>
        </div>

        <div className="mb-6">
          <h5 className="text-lg font-semibold mb-3">Step-by-Step Exploitation Process</h5>
          <div className="space-y-4">
            <div className="bg-cybr-muted/20 p-4 rounded-lg">
              <h6 className="font-semibold text-cybr-primary mb-2">Phase 1: Target Identification</h6>
              <ol className="list-decimal pl-6 space-y-1">
                <li>Identify applications using LDAP authentication or directory services</li>
                <li>Locate login forms, search functions, or user management interfaces</li>
                <li>Test for LDAP error messages that reveal directory structure</li>
                <li>Analyze application responses for LDAP-specific behavior patterns</li>
              </ol>
            </div>
            
            <div className="bg-cybr-muted/20 p-4 rounded-lg">
              <h6 className="font-semibold text-cybr-primary mb-2">Phase 2: LDAP Query Structure Discovery</h6>
              <ol className="list-decimal pl-6 space-y-1">
                <li>Test input fields with LDAP special characters to trigger errors</li>
                <li>Analyze error messages to understand query structure</li>
                <li>Identify which user inputs are incorporated into LDAP queries</li>
                <li>Determine the LDAP attributes being searched (uid, cn, mail, etc.)</li>
              </ol>
            </div>
            
            <div className="bg-cybr-muted/20 p-4 rounded-lg">
              <h6 className="font-semibold text-cybr-primary mb-2">Phase 3: Injection Testing</h6>
              <ol className="list-decimal pl-6 space-y-1">
                <li>Craft payloads to modify query logic (using * | & operators)</li>
                <li>Test authentication bypass techniques</li>
                <li>Attempt to extract additional user attributes</li>
                <li>Try to enumerate directory structure and user accounts</li>
              </ol>
            </div>
            
            <div className="bg-cybr-muted/20 p-4 rounded-lg">
              <h6 className="font-semibold text-cybr-primary mb-2">Phase 4: Data Extraction</h6>
              <ol className="list-decimal pl-6 space-y-1">
                <li>Use wildcard characters to enumerate all users or groups</li>
                <li>Extract sensitive attributes like passwords, email addresses</li>
                <li>Map organizational structure and user relationships</li>
                <li>Identify high-privilege accounts for further targeting</li>
              </ol>
            </div>
          </div>
        </div>

        <CodeExample 
          language="java" 
          isVulnerable={true}
          title="Vulnerable LDAP Authentication Code" 
          code={`// Java LDAP authentication with injection vulnerability
public class LDAPAuthenticator {
    private DirContext ctx;
    
    public boolean authenticate(String username, String password) {
        try {
            // Vulnerable: Direct string concatenation without sanitization
            String searchFilter = "(&(objectClass=user)(uid=" + username + ")(userPassword=" + password + "))";
            
            SearchControls searchCtls = new SearchControls();
            searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            // Execute the vulnerable query
            NamingEnumeration<SearchResult> results = 
                ctx.search("ou=users,dc=company,dc=com", searchFilter, searchCtls);
            
            return results.hasMore(); // True if user found
            
        } catch (Exception e) {
            // Error messages might leak directory structure
            System.err.println("LDAP Error: " + e.getMessage());
            return false;
        }
    }
    
    public List<User> searchUsers(String searchTerm) {
        List<User> users = new ArrayList<>();
        try {
            // Vulnerable: User input directly in search filter
            String filter = "(|(cn=*" + searchTerm + "*)(mail=*" + searchTerm + "*))";
            
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[]{"cn", "mail", "department"});
            
            NamingEnumeration<SearchResult> results = 
                ctx.search("ou=users,dc=company,dc=com", filter, controls);
            
            while (results.hasMore()) {
                SearchResult result = results.next();
                // Process results...
                users.add(createUserFromResult(result));
            }
        } catch (Exception e) {
            logger.error("Search failed: " + e.getMessage());
        }
        return users;
    }
}

/* 
ATTACK PAYLOADS:

1. Authentication Bypass:
   Username: admin)(&(objectClass=*
   Password: anything
   Resulting query: (&(objectClass=user)(uid=admin)(&(objectClass=*)(userPassword=anything))
   This always returns true due to (objectClass=*) matching everything

2. Information Extraction:
   Username: *))(|(uid=*
   Password: ignored  
   This transforms the query to return all users

3. Wildcard Enumeration:
   Search term: *))(objectClass=*
   This returns all directory entries, not just users
*/`} 
        />

        <CodeExample 
          language="python" 
          isVulnerable={true}
          title="Vulnerable Python LDAP Implementation" 
          code={`import ldap
import ldap.filter

class VulnerableLDAPAuth:
    def __init__(self, server_url, base_dn):
        self.server_url = server_url
        self.base_dn = base_dn
        self.conn = ldap.initialize(server_url)
    
    def authenticate_user(self, username, password):
        try:
            # Vulnerable: Direct string formatting without escaping
            search_filter = f"(&(objectClass=person)(uid={username}))"
            
            # Search for user
            result = self.conn.search_s(
                self.base_dn, 
                ldap.SCOPE_SUBTREE, 
                search_filter
            )
            
            if not result:
                return False
            
            # Try to bind with user credentials
            user_dn = result[0][0]
            
            # Vulnerable: Password not properly handled
            test_conn = ldap.initialize(self.server_url)
            test_conn.simple_bind_s(user_dn, password)
            test_conn.unbind()
            
            return True
            
        except ldap.INVALID_CREDENTIALS:
            return False
        except Exception as e:
            # Vulnerable: Exposing LDAP errors
            print(f"LDAP Error: {str(e)}")
            return False
    
    def search_users(self, department, role=None):
        try:
            # Vulnerable: String concatenation in filter
            if role:
                filter_str = f"(&(objectClass=person)(department={department})(role={role}))"
            else:
                filter_str = f"(&(objectClass=person)(department={department}))"
            
            results = self.conn.search_s(
                self.base_dn,
                ldap.SCOPE_SUBTREE,
                filter_str,
                ['cn', 'mail', 'telephoneNumber']
            )
            
            return [{'name': r[1]['cn'][0], 'email': r[1]['mail'][0]} for r in results]
            
        except Exception as e:
            print(f"Search error: {e}")
            return []

# ATTACK EXAMPLES:
# 1. Authentication bypass:
#    username = "admin))(|(objectClass=*"
#    This makes the filter: (&(objectClass=person)(uid=admin))(|(objectClass=*)
#    Which will match any object due to the OR condition
#
# 2. Data extraction:
#    department = "IT*))(objectClass=*)(cn=*"
#    This extracts all users from all departments
#
# 3. Wildcard search:
#    department = "*"
#    role = "*))(|(mail=*"
#    This returns all users with email addresses`} 
        />

        <CodeExample 
          language="java" 
          isVulnerable={false}
          title="Secure LDAP Implementation" 
          code={`import javax.naming.directory.*;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import java.util.Hashtable;
import java.util.regex.Pattern;

public class SecureLDAPAuthenticator {
    private DirContext ctx;
    private static final Pattern VALID_USERNAME = Pattern.compile("^[a-zA-Z0-9._-]+$");
    private static final String[] LDAP_SPECIAL_CHARS = {"*", "(", ")", "\\\\", "/", "\\0"};
    
    public boolean authenticate(String username, String password) {
        // 1. Input validation
        if (!isValidUsername(username) || password == null || password.isEmpty()) {
            return false;
        }
        
        try {
            // 2. Use parameterized queries with proper escaping
            String escapedUsername = escapeLDAPFilter(username);
            String searchFilter = "(&(objectClass=user)(uid={0}))";
            
            // 3. Use SearchControls with limits
            SearchControls searchCtls = new SearchControls();
            searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            searchCtls.setCountLimit(1); // Limit results
            searchCtls.setTimeLimit(5000); // 5 second timeout
            searchCtls.setReturningAttributes(new String[]{"dn"}); // Only return what we need
            
            // 4. Execute search with parameter substitution
            NamingEnumeration<SearchResult> results = ctx.search(
                "ou=users,dc=company,dc=com", 
                searchFilter, 
                new Object[]{escapedUsername},
                searchCtls
            );
            
            if (!results.hasMore()) {
                return false;
            }
            
            SearchResult result = results.next();
            String userDN = result.getNameInNamespace();
            
            // 5. Authenticate by binding with user credentials
            return bindUser(userDN, password);
            
        } catch (NamingException e) {
            // 6. Log securely without exposing sensitive information
            logger.warn("Authentication failed for user: " + username.replaceAll("[^a-zA-Z0-9]", ""));
            return false;
        }
    }
    
    private boolean bindUser(String userDN, String password) {
        DirContext userCtx = null;
        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, ldapURL);
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, userDN);
            env.put(Context.SECURITY_CREDENTIALS, password);
            
            userCtx = new InitialDirContext(env);
            return true;
        } catch (NamingException e) {
            return false;
        } finally {
            if (userCtx != null) {
                try { userCtx.close(); } catch (NamingException ignored) {}
            }
        }
    }
    
    private boolean isValidUsername(String username) {
        return username != null && 
               VALID_USERNAME.matcher(username).matches() && 
               username.length() <= 64;
    }
    
    private String escapeLDAPFilter(String input) {
        if (input == null) return null;
        
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            switch (c) {
                case '*':  sb.append("\\2a"); break;
                case '(':  sb.append("\\28"); break;
                case ')':  sb.append("\\29"); break;
                case '\\': sb.append("\\5c"); break;
                case '/':  sb.append("\\2f"); break;
                case '\0': sb.append("\\00"); break;
                default:   sb.append(c); break;
            }
        }
        return sb.toString();
    }
}`} 
        />

        <div className="mb-6">
          <h5 className="text-lg font-semibold mb-3">Detection and Testing Methods</h5>
          <div className="space-y-4">
            <div>
              <h6 className="font-semibold mb-2">Manual Testing Steps</h6>
              <ol className="list-decimal pl-6 space-y-2">
                <li><strong>Input Field Analysis:</strong> Test login forms and search fields with LDAP special characters</li>
                <li><strong>Error Message Analysis:</strong> Submit malformed inputs to trigger LDAP errors</li>
                <li><strong>Authentication Bypass Testing:</strong> Try payloads like *)(&(objectClass=*) in username fields</li>
                <li><strong>Wildcard Testing:</strong> Use * characters to test for information disclosure</li>
                <li><strong>Logical Operator Testing:</strong> Test &, |, ! operators in various input fields</li>
              </ol>
            </div>
            
            <div>
              <h6 className="font-semibold mb-2">Automated Testing Tools</h6>
              <ul className="list-disc pl-6 space-y-1">
                <li><strong>LDAPExplorer:</strong> Specialized LDAP injection testing tool</li>
                <li><strong>Burp Suite LDAP Extensions:</strong> Automated LDAP injection detection</li>
                <li><strong>Custom Python Scripts:</strong> Using python-ldap library for testing</li>
                <li><strong>OWASP ZAP:</strong> With LDAP injection detection plugins</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* NoSQL Injection */}
      <div className="mb-12">
        <h4 className="text-xl font-semibold mb-6 flex items-center gap-2">
          <Database className="h-6 w-6 text-cybr-primary" />
          NoSQL Injection
        </h4>
        
        <div className="mb-6">
          <h5 className="text-lg font-semibold mb-3">What is NoSQL Injection?</h5>
          <p className="mb-4">
            NoSQL injection allows attackers to manipulate NoSQL database queries by injecting malicious input,
            potentially bypassing authentication, accessing unauthorized data, or executing arbitrary database operations.
            Unlike SQL injection, NoSQL injection exploits the flexible schema and query structure of NoSQL databases.
          </p>
          <p className="mb-4">
            NoSQL databases like MongoDB, CouchDB, and others use different query languages and data structures,
            creating new attack vectors. The injection can occur through JSON manipulation, operator injection,
            or by exploiting the dynamic nature of NoSQL query construction.
          </p>
        </div>

        <div className="mb-6">
          <h5 className="text-lg font-semibold mb-3">Attacker Goals</h5>
          <ul className="list-disc pl-6 space-y-2">
            <li><strong>Authentication Bypass:</strong> Circumvent login mechanisms using NoSQL operator injection</li>
            <li><strong>Data Extraction:</strong> Access sensitive documents and collections without authorization</li>
            <li><strong>Privilege Escalation:</strong> Modify user roles or permissions stored in NoSQL documents</li>
            <li><strong>Data Manipulation:</strong> Insert, update, or delete unauthorized data</li>
            <li><strong>Denial of Service:</strong> Execute resource-intensive queries to overwhelm the database</li>
            <li><strong>Information Disclosure:</strong> Extract database schema, collection names, and sensitive data</li>
          </ul>
        </div>

        <div className="mb-6">
          <h5 className="text-lg font-semibold mb-3">Vulnerable Components</h5>
          <ul className="list-disc pl-6 space-y-2">
            <li><strong>MongoDB Applications:</strong> Using dynamic query construction</li>
            <li><strong>CouchDB Interfaces:</strong> Views and queries built from user input</li>
            <li><strong>Redis Applications:</strong> Commands constructed from user data</li>
            <li><strong>DocumentDB Services:</strong> AWS DocumentDB and similar services</li>
            <li><strong>API Endpoints:</strong> REST APIs that translate HTTP parameters to NoSQL queries</li>
            <li><strong>Search Functions:</strong> Applications using NoSQL for search and filtering</li>
          </ul>
        </div>

        <CodeExample 
          language="javascript" 
          isVulnerable={true}
          title="Vulnerable MongoDB Authentication" 
          code={`// Node.js with MongoDB - vulnerable to NoSQL injection
const express = require('express');
const { MongoClient } = require('mongodb');

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Vulnerable: Direct object insertion without validation
    const query = { 
      username: username, 
      password: password 
    };
    
    const user = await db.collection('users').findOne(query);
    
    if (user) {
      // Set session and respond
      req.session.userId = user._id;
      res.json({ success: true, message: 'Login successful' });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/users', async (req, res) => {
  try {
    // Vulnerable: Query parameters directly used in database query
    const filter = {};
    
    if (req.query.department) {
      filter.department = req.query.department;
    }
    
    if (req.query.role) {
      filter.role = req.query.role;
    }
    
    if (req.query.active) {
      filter.active = req.query.active;
    }
    
    // This query is vulnerable to operator injection
    const users = await db.collection('users').find(filter).toArray();
    
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

/*
ATTACK PAYLOADS:

1. Authentication Bypass (JSON):
POST /login
Content-Type: application/json
{
  "username": "admin",
  "password": { "$ne": null }
}
This creates query: { username: "admin", password: { $ne: null } }
Matches any user 'admin' with a non-null password

2. Authentication Bypass (URL-encoded):
POST /login
username=admin&password[$ne]=
Creates: { username: "admin", password: { $ne: "" } }

3. Data Extraction:
GET /users?department[$ne]=&role[$exists]=true
Creates: { department: { $ne: "" }, role: { $exists: true } }
Returns all users with any department and existing role

4. Regex Injection:
GET /users?username[$regex]=.*admin.*&username[$options]=i
Performs case-insensitive regex search for admin users

5. Where Clause Injection (if enabled):
POST /search
{
  "criteria": {
    "$where": "this.username == 'admin' || '1'=='1'"
  }
}
*/`} 
        />

        <CodeExample 
          language="javascript" 
          isVulnerable={false}
          title="Secure NoSQL Implementation" 
          code={`const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const joi = require('joi');
const rateLimit = require('express-rate-limit');

// Input validation schemas
const loginSchema = joi.object({
  username: joi.string().alphanum().min(3).max(30).required(),
  password: joi.string().min(6).max(128).required()
});

const userFilterSchema = joi.object({
  department: joi.string().alphanum().max(50),
  role: joi.string().alphanum().max(30),
  active: joi.boolean(),
  page: joi.number().integer().min(1).max(100).default(1),
  limit: joi.number().integer().min(1).max(50).default(10)
});

// Rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: 'Too many login attempts, please try again later'
});

app.post('/login', loginLimiter, async (req, res) => {
  try {
    // 1. Validate input structure and types
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid input format' 
      });
    }
    
    const { username, password } = value;
    
    // 2. Use only string values in query, never objects
    const query = { 
      username: String(username).toLowerCase(),
      active: true 
    };
    
    // 3. Find user first, then verify password separately
    const user = await db.collection('users').findOne(query, {
      projection: { password: 1, username: 1, role: 1, _id: 1 }
    });
    
    if (!user) {
      // Use consistent timing to prevent username enumeration
      await bcrypt.compare('dummy', '$2b$10$dummyhashtopreventtimingattacks');
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }
    
    // 4. Use bcrypt for password verification
    const isValidPassword = await bcrypt.compare(password, user.password);
    
    if (!isValidPassword) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }
    
    // 5. Create secure session
    req.session.userId = user._id.toString();
    req.session.role = user.role;
    
    res.json({ 
      success: true, 
      message: 'Login successful',
      user: { 
        id: user._id, 
        username: user.username, 
        role: user.role 
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

app.get('/users', authenticateUser, async (req, res) => {
  try {
    // 1. Validate query parameters
    const { error, value } = userFilterSchema.validate(req.query);
    if (error) {
      return res.status(400).json({ error: 'Invalid query parameters' });
    }
    
    const { department, role, active, page, limit } = value;
    
    // 2. Build filter with explicit type checking and whitelisting
    const filter = {};
    
    // Only allow specific, validated values
    if (department) {
      const allowedDepartments = ['IT', 'HR', 'Finance', 'Marketing', 'Sales'];
      if (allowedDepartments.includes(department)) {
        filter.department = department;
      } else {
        return res.status(400).json({ error: 'Invalid department' });
      }
    }
    
    if (role) {
      const allowedRoles = ['admin', 'user', 'manager', 'guest'];
      if (allowedRoles.includes(role)) {
        filter.role = role;
      } else {
        return res.status(400).json({ error: 'Invalid role' });
      }
    }
    
    if (typeof active === 'boolean') {
      filter.active = active;
    }
    
    // 3. Use explicit projection to limit returned data
    const projection = {
      _id: 1,
      username: 1,
      email: 1,
      department: 1,
      role: 1,
      active: 1,
      createdAt: 1
      // Never return sensitive fields like password hashes
    };
    
    // 4. Implement pagination with limits
    const skip = (page - 1) * limit;
    
    const [users, totalCount] = await Promise.all([
      db.collection('users')
        .find(filter, { projection })
        .skip(skip)
        .limit(limit)
        .sort({ username: 1 })
        .toArray(),
      db.collection('users').countDocuments(filter)
    ]);
    
    res.json({
      users,
      pagination: {
        page,
        limit,
        total: totalCount,
        pages: Math.ceil(totalCount / limit)
      }
    });
    
  } catch (error) {
    console.error('User fetch error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Middleware for authentication
async function authenticateUser(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  try {
    // Validate session user still exists and is active
    const user = await db.collection('users').findOne({
      _id: new ObjectId(req.session.userId),
      active: true
    });
    
    if (!user) {
      req.session.destroy();
      return res.status(401).json({ error: 'Invalid session' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    res.status(500).json({ error: 'Authentication error' });
  }
}

// Additional security measures
app.use(express.json({ limit: '10mb' })); // Limit payload size
app.use((req, res, next) => {
  // Prevent NoSQL injection in nested objects
  function sanitizeObject(obj) {
    if (obj && typeof obj === 'object') {
      for (let key in obj) {
        if (typeof key === 'string' && key.startsWith('$')) {
          delete obj[key]; // Remove MongoDB operators
        } else if (typeof obj[key] === 'object') {
          sanitizeObject(obj[key]);
        }
      }
    }
  }
  
  if (req.body) {
    sanitizeObject(req.body);
  }
  
  next();
});`} 
        />

        <div className="mb-6">
          <h5 className="text-lg font-semibold mb-3">Environment-Specific Considerations</h5>
          <div className="space-y-4">
            <div className="bg-cybr-muted/20 p-4 rounded-lg">
              <h6 className="font-semibold text-cybr-primary mb-2">MongoDB</h6>
              <ul className="list-disc pl-6 space-y-1">
                <li>Disable JavaScript execution ($where operator) in production</li>
                <li>Use MongoDB's built-in validation rules and schema validation</li>
                <li>Enable authentication and use role-based access control</li>
                <li>Regularly update MongoDB to patch security vulnerabilities</li>
              </ul>
            </div>
            
            <div className="bg-cybr-muted/20 p-4 rounded-lg">
              <h6 className="font-semibold text-cybr-primary mb-2">Node.js Applications</h6>
              <ul className="list-disc pl-6 space-y-1">
                <li>Use parameterized queries and object validation libraries</li>
                <li>Implement input sanitization middleware</li>
                <li>Use TypeScript for better type safety</li>
                <li>Enable strict mode and proper error handling</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* Server-Side Template Injection (SSTI) */}
      <div className="mb-12">
        <h4 className="text-xl font-semibold mb-6 flex items-center gap-2">
          <FileText className="h-6 w-6 text-cybr-primary" />
          Server-Side Template Injection (SSTI)
        </h4>
        
        <div className="mb-6">
          <h5 className="text-lg font-semibold mb-3">What is Server-Side Template Injection?</h5>
          <p className="mb-4">
            Server-Side Template Injection (SSTI) occurs when user-supplied data is embedded into a template and then 
            executed on the server. This vulnerability can lead to remote code execution, allowing attackers to execute 
            arbitrary commands on the server hosting the application.
          </p>
          <p className="mb-4">
            SSTI exploits template engines like Jinja2, Twig, Freemarker, Velocity, and others. The vulnerability 
            arises when user input is directly incorporated into template code without proper sanitization, allowing 
            attackers to inject template directives that get executed server-side.
          </p>
        </div>

        <div className="mb-6">
          <h5 className="text-lg font-semibold mb-3">Attacker Goals</h5>
          <ul className="list-disc pl-6 space-y-2">
            <li><strong>Remote Code Execution:</strong> Execute arbitrary system commands on the server</li>
            <li><strong>File System Access:</strong> Read, write, or delete files on the server</li>
            <li><strong>Configuration Disclosure:</strong> Access application configuration and secrets</li>
            <li><strong>Database Access:</strong> Interact with databases through the application context</li>
            <li><strong>Privilege Escalation:</strong> Gain higher privileges within the application or system</li>
            <li><strong>Lateral Movement:</strong> Use server access to attack other systems on the network</li>
          </ul>
        </div>

        <div className="mb-6">
          <h5 className="text-lg font-semibold mb-3">Vulnerable Template Engines</h5>
          <ul className="list-disc pl-6 space-y-2">
            <li><strong>Jinja2 (Python):</strong> Flask, Django templates with user input</li>
            <li><strong>Twig (PHP):</strong> Symfony applications with dynamic templates</li>
            <li><strong>Freemarker (Java):</strong> Spring applications with template rendering</li>
            <li><strong>Velocity (Java):</strong> Web applications using Apache Velocity</li>
            <li><strong>Smarty (PHP):</strong> PHP applications with Smarty templating</li>
            <li><strong>Handlebars (Node.js):</strong> Express applications with dynamic templates</li>
          </ul>
        </div>

        <CodeExample 
          language="python" 
          isVulnerable={true}
          title="Vulnerable Flask Application with SSTI" 
          code={`# Python Flask application vulnerable to SSTI
from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

@app.route('/hello')
def hello():
    name = request.args.get('name', 'Guest')
    
    # Vulnerable: User input directly in template string
    template = f'''
    <html>
    <body>
        <h1>Hello {name}!</h1>
        <p>Welcome to our application.</p>
    </body>
    </html>
    '''
    
    # This renders and executes the template with user input
    return render_template_string(template)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # Vulnerable: Search term directly embedded in template
    template = '''
    <div class="search-container">
        <h2>Search Results for: ''' + query + '''</h2>
        <div class="results">
            <!-- Search results would go here -->
        </div>
    </div>
    '''
    
    return render_template_string(template)

@app.route('/profile/<username>')
def profile(username):
    # Vulnerable: Username in template construction
    template_content = f'''
    <div class="profile">
        <h1>Profile for {username}</h1>
        <p>User information would be displayed here.</p>
    </div>
    '''
    
    return render_template_string(template_content)

@app.route('/error')
def error_page():
    error_msg = request.args.get('msg', 'Unknown error')
    
    # Vulnerable: Error message in template
    error_template = '''
    <div class="error-page">
        <h1>Error Occurred</h1>
        <p>Error details: ''' + error_msg + '''</p>
    </div>
    '''
    
    return render_template_string(error_template)

'''
ATTACK PAYLOADS for Jinja2:

1. Basic Code Execution:
   /hello?name={{7*7}}
   Result: Hello 49! (proves template execution)

2. Configuration Access:
   /hello?name={{config}}
   /hello?name={{config.items()}}
   Reveals Flask configuration including secret keys

3. File System Access:
   /hello?name={{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}
   Attempts to read system files

4. Command Execution:
   /hello?name={{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}
   Executes system commands

5. Advanced RCE Chain:
   /hello?name={{''.__class__.__bases__[0].__subclasses__()[59].__init__.__globals__.os.popen('ls -la').read()}}
'''

if __name__ == '__main__':
    app.run(debug=True)  # Debug mode makes it even more dangerous`} 
        />

        <CodeExample 
          language="python" 
          isVulnerable={false}
          title="Secure Template Implementation" 
          code={`# Secure Flask application with proper template handling
from flask import Flask, request, render_template, escape
from jinja2 import Environment, BaseLoader, select_autoescape, StrictUndefined
import re
from markupsafe import Markup

app = Flask(__name__)

# Configure Jinja2 for security
app.jinja_env.undefined = StrictUndefined
app.jinja_env.autoescape = select_autoescape(['html', 'xml'])

# Whitelist allowed template variables and functions
ALLOWED_VARIABLES = ['username', 'query', 'results', 'error_message']
SAFE_FUNCTIONS = ['len', 'str', 'int', 'float']

def validate_input(input_data, max_length=100):
    """Validate and sanitize user input"""
    if not input_data:
        return None
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[{}()<>\[\]$]', '', str(input_data))
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized.strip()

@app.route('/hello')
def hello():
    name = request.args.get('name', 'Guest')
    
    # 1. Validate and sanitize input
    clean_name = validate_input(name, max_length=50)
    if not clean_name:
        clean_name = 'Guest'
    
    # 2. Use predefined template file, not string construction
    return render_template('hello.html', name=clean_name)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # 1. Validate search query
    clean_query = validate_input(query, max_length=200)
    if not clean_query:
        return render_template('search.html', error='Invalid search query')
    
    # 2. Perform safe search (mock results)
    results = perform_safe_search(clean_query)
    
    # 3. Use template with safe variable passing
    return render_template('search.html', 
                         query=clean_query, 
                         results=results)

@app.route('/profile/<username>')
def profile(username):
    # 1. Validate username format
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return render_template('error.html', 
                             error_message='Invalid username format'), 400
    
    # 2. Limit username length
    if len(username) > 30:
        return render_template('error.html', 
                             error_message='Username too long'), 400
    
    # 3. Use safe template rendering
    user_data = get_user_data(username)  # Safe database lookup
    
    return render_template('profile.html', 
                         username=username, 
                         user_data=user_data)

@app.route('/error')
def error_page():
    error_msg = request.args.get('msg', 'Unknown error')
    
    # 1. Sanitize error message
    clean_error = validate_input(error_msg, max_length=200)
    
    # 2. Use predefined error messages for security
    allowed_errors = {
        'not_found': 'The requested resource was not found.',
        'access_denied': 'Access denied.',
        'invalid_input': 'Invalid input provided.',
        'server_error': 'An internal server error occurred.'
    }
    
    if clean_error in allowed_errors:
        error_message = allowed_errors[clean_error]
    else:
        error_message = 'An error occurred.'
    
    return render_template('error.html', error_message=error_message)

# Custom Jinja2 environment for additional security
def create_secure_environment():
    """Create a sandboxed Jinja2 environment"""
    from jinja2.sandbox import SandboxedEnvironment
    
    env = SandboxedEnvironment(
        autoescape=select_autoescape(['html', 'xml']),
        undefined=StrictUndefined
    )
    
    # Remove dangerous built-ins
    env.globals.pop('range', None)
    env.globals.pop('dict', None)
    env.globals.pop('list', None)
    
    # Add only safe functions
    env.globals.update({
        'len': len,
        'str': str,
        'escape': escape
    })
    
    return env

# Helper functions
def perform_safe_search(query):
    """Perform database search with parameterized queries"""
    # This would typically use a database with parameterized queries
    # For demo purposes, returning mock data
    return [
        {'title': f'Result for {escape(query)}', 'snippet': 'Safe search result'}
    ]

def get_user_data(username):
    """Safely retrieve user data from database"""
    # Use parameterized database queries here
    return {
        'username': escape(username),
        'profile_complete': True,
        'last_login': '2024-01-01'
    }

# Content Security Policy header for additional protection
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

if __name__ == '__main__':
    # Never run debug mode in production
    app.run(debug=False, host='127.0.0.1')

# Template files should be stored separately:
# templates/hello.html:
# <html><body><h1>Hello {{ name|escape }}!</h1></body></html>
#
# templates/search.html:
# <div class="search">
#   <h2>Search Results for: {{ query|escape }}</h2>
#   {% for result in results %}
#     <div>{{ result.title|escape }}</div>
#   {% endfor %}
# </div>`} 
        />

        <div className="mb-6">
          <h5 className="text-lg font-semibold mb-3">Testing and Detection Methods</h5>
          <div className="space-y-4">
            <div>
              <h6 className="font-semibold mb-2">Manual Testing Approach</h6>
              <ol className="list-decimal pl-6 space-y-2">
                <li><strong>Template Expression Testing:</strong> Try basic expressions like {`{{7*7}}`} or ${`{7*7}`}</li>
                <li><strong>Template Syntax Detection:</strong> Test different template syntaxes to identify the engine</li>
                <li><strong>Error Message Analysis:</strong> Trigger template errors to reveal engine information</li>
                <li><strong>Configuration Access:</strong> Try to access application configuration through templates</li>
                <li><strong>File System Testing:</strong> Attempt to read files using template functionality</li>
              </ol>
            </div>
          </div>
        </div>
      </div>

      {/* XPath Injection */}
      <div className="mb-12">
        <h4 className="text-xl font-semibold mb-6 flex items-center gap-2">
          <Code className="h-6 w-6 text-cybr-primary" />
          XPath Injection
        </h4>
        
        <div className="mb-6">
          <h5 className="text-lg font-semibold mb-3">What is XPath Injection?</h5>
          <p className="mb-4">
            XPath injection occurs when user input is used to construct XPath queries to navigate XML documents,
            potentially allowing attackers to access unauthorized data or bypass authentication. XPath is used to
            navigate through elements and attributes in XML documents, and injection vulnerabilities arise when
            user input is directly incorporated into XPath expressions.
          </p>
          <p className="mb-4">
            This vulnerability is particularly dangerous in applications that use XML databases, configuration files,
            or authentication systems based on XML data structures. XPath injection can lead to authentication bypass,
            data extraction, and information disclosure.
          </p>
        </div>

        <div className="mb-6">
          <h5 className="text-lg font-semibold mb-3">Attacker Goals</h5>
          <ul className="list-disc pl-6 space-y-2">
            <li><strong>Authentication Bypass:</strong> Circumvent XML-based authentication mechanisms</li>
            <li><strong>Data Extraction:</strong> Access sensitive information stored in XML documents</li>
            <li><strong>Node Enumeration:</strong> Discover XML document structure and content</li>
            <li><strong>Privilege Escalation:</strong> Access higher-privilege data or user accounts</li>
            <li><strong>Configuration Disclosure:</strong> Extract application configuration from XML files</li>
            <li><strong>Blind Data Extraction:</strong> Extract data when direct output is not visible</li>
          </ul>
        </div>

        <CodeExample 
          language="java" 
          isVulnerable={true}
          title="Vulnerable Java XPath Implementation" 
          code={`// Java application vulnerable to XPath injection
import javax.xml.xpath.*;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

public class VulnerableXPathAuth {
    private Document xmlDoc;
    private XPath xpath;
    
    public VulnerableXPathAuth() {
        try {
            // Load XML document containing user data
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            xmlDoc = builder.parse("users.xml");
            
            XPathFactory xpathFactory = XPathFactory.newInstance();
            xpath = xpathFactory.newXPath();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public boolean authenticateUser(String username, String password) {
        try {
            // Vulnerable: Direct string concatenation in XPath
            String xpathQuery = "//user[username='" + username + 
                               "' and password='" + password + "']";
            
            System.out.println("XPath Query: " + xpathQuery); // Debug - reveals injection
            
            XPathExpression expr = xpath.compile(xpathQuery);
            NodeList result = (NodeList) expr.evaluate(xmlDoc, XPathConstants.NODESET);
            
            return result.getLength() > 0;
            
        } catch (Exception e) {
            // Vulnerable: Exposing XPath errors
            System.err.println("XPath Error: " + e.getMessage());
            return false;
        }
    }
    
    public String[] getUserInfo(String userId) {
        try {
            // Vulnerable: User ID directly in XPath
            String query = "//user[@id='" + userId + "']/info/*";
            
            XPathExpression expr = xpath.compile(query);
            NodeList nodes = (NodeList) expr.evaluate(xmlDoc, XPathConstants.NODESET);
            
            String[] info = new String[nodes.getLength()];
            for (int i = 0; i < nodes.getLength(); i++) {
                info[i] = nodes.item(i).getTextContent();
            }
            
            return info;
        } catch (Exception e) {
            return new String[]{"Error retrieving user info"};
        }
    }
    
    public String searchUsers(String searchTerm) {
        try {
            // Vulnerable: Search term in XPath without sanitization
            String searchQuery = "//user[contains(username, '" + searchTerm + 
                               "') or contains(email, '" + searchTerm + "')]";
            
            XPathExpression expr = xpath.compile(searchQuery);
            NodeList results = (NodeList) expr.evaluate(xmlDoc, XPathConstants.NODESET);
            
            StringBuilder output = new StringBuilder();
            for (int i = 0; i < results.getLength(); i++) {
                // Extract user information
                output.append("User found: ").append(results.item(i).getTextContent()).append("\\n");
            }
            
            return output.toString();
        } catch (Exception e) {
            return "Search error: " + e.getMessage();
        }
    }
}

/*
XML Document Structure (users.xml):
<?xml version="1.0" encoding="UTF-8"?>
<users>
    <user id="1">
        <username>admin</username>
        <password>secretpass123</password>
        <role>administrator</role>
        <email>admin@company.com</email>
        <info>
            <department>IT</department>
            <phone>555-1234</phone>
            <salary>75000</salary>
        </info>
    </user>
    <user id="2">
        <username>john_doe</username>
        <password>mypassword</password>
        <role>user</role>
        <email>john@company.com</email>
        <info>
            <department>Sales</department>
            <phone>555-5678</phone>
            <salary>50000</salary>
        </info>
    </user>
</users>

ATTACK PAYLOADS:

1. Authentication Bypass:
   Username: admin' or '1'='1
   Password: anything
   XPath: //user[username='admin' or '1'='1' and password='anything']
   Result: Always returns true due to '1'='1'

2. Password Extraction (Blind):
   Username: admin' and substring(password,1,1)='s
   Password: anything
   Tests if first character of admin's password is 's'

3. Comment Injection:
   Username: admin']/parent::*[/*
   This can be used to escape current context and access parent nodes

4. Node Enumeration:
   Username: ' or count(//user)>1 or '1'='2
   Tests how many user nodes exist

5. All Users Extraction:
   Username: '] | //user/* | //user[username='
   Password: anything
   Returns all user data from the XML

6. Blind Boolean-based:
   searchTerm: ') or string-length(//user[1]/password)>10 or ('1'='2
   Tests password length of first user

7. Data Type Discovery:
   userId: 1'] | //user[position()>0] | //user[@id='1
   Enumerates all users regardless of ID filter
*/`} 
        />

        <CodeExample 
          language="java" 
          isVulnerable={false}
          title="Secure XPath Implementation" 
          code={`// Secure Java XPath implementation
import javax.xml.xpath.*;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.util.regex.Pattern;
import java.util.HashMap;
import java.util.Map;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

public class SecureXPathAuth {
    private Document xmlDoc;
    private XPath xpath;
    private static final Pattern VALID_USERNAME = Pattern.compile("^[a-zA-Z0-9._-]{3,30}$");
    private static final Pattern VALID_USERID = Pattern.compile("^[0-9]+$");
    
    public SecureXPathAuth() {
        try {
            // Initialize XML document with security features
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            
            // Security configurations
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setExpandEntityReferences(false);
            
            DocumentBuilder builder = factory.newDocumentBuilder();
            xmlDoc = builder.parse("users.xml");
            
            XPathFactory xpathFactory = XPathFactory.newInstance();
            xpath = xpathFactory.newXPath();
            
            // Set up XPath variable resolver for parameterized queries
            xpath.setXPathVariableResolver(new SecureVariableResolver());
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize secure XML processor", e);
        }
    }
    
    public boolean authenticateUser(String username, String password) {
        // 1. Input validation
        if (!isValidInput(username, VALID_USERNAME) || 
            password == null || password.length() > 128) {
            return false;
        }
        
        try {
            // 2. Hash the password before comparison (assuming XML stores hashes)
            String hashedPassword = hashPassword(password);
            
            // 3. Use parameterized XPath with variable resolver
            String xpathQuery = "//user[username=$username and password=$password]";
            XPathExpression expr = xpath.compile(xpathQuery);
            
            // 4. Set variables securely
            Map<String, String> variables = new HashMap<>();
            variables.put("username", username);
            variables.put("password", hashedPassword);
            
            ((SecureVariableResolver) xpath.getXPathVariableResolver()).setVariables(variables);
            
            NodeList result = (NodeList) expr.evaluate(xmlDoc, XPathConstants.NODESET);
            return result.getLength() > 0;
            
        } catch (Exception e) {
            // 5. Secure error handling - don't expose XPath details
            logSecurityEvent("Authentication attempt failed for user: " + 
                            sanitizeForLogging(username));
            return false;
        }
    }
    
    public UserInfo getUserInfo(String userId) {
        // 1. Validate user ID format
        if (!isValidInput(userId, VALID_USERID)) {
            throw new IllegalArgumentException("Invalid user ID format");
        }
        
        try {
            // 2. Use parameterized query
            String query = "//user[@id=$userId]";
            XPathExpression expr = xpath.compile(query);
            
            Map<String, String> variables = new HashMap<>();
            variables.put("userId", userId);
            ((SecureVariableResolver) xpath.getXPathVariableResolver()).setVariables(variables);
            
            NodeList nodes = (NodeList) expr.evaluate(xmlDoc, XPathConstants.NODESET);
            
            if (nodes.getLength() == 0) {
                return null; // User not found
            }
            
            // 3. Safely extract only allowed fields
            return createUserInfoFromNode(nodes.item(0));
            
        } catch (Exception e) {
            logSecurityEvent("Failed to retrieve user info for ID: " + 
                            sanitizeForLogging(userId));
            throw new RuntimeException("Failed to retrieve user information");
        }
    }
    
    public List<UserSearchResult> searchUsers(String searchTerm, int maxResults) {
        // 1. Input validation and sanitization
        if (searchTerm == null || searchTerm.trim().isEmpty()) {
            return new ArrayList<>();
        }
        
        searchTerm = searchTerm.trim();
        if (searchTerm.length() > 50) {
            searchTerm = searchTerm.substring(0, 50);
        }
        
        // 2. Validate search term contains only safe characters
        if (!Pattern.matches("^[a-zA-Z0-9._@-\\s]+$", searchTerm)) {
            throw new IllegalArgumentException("Invalid search term format");
        }
        
        try {
            // 3. Use parameterized search
            String searchQuery = "//user[contains(translate(username, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', " +
                               "'abcdefghijklmnopqrstuvwxyz'), $searchTerm) or contains(translate(email, " +
                               "'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), $searchTerm)]";
            
            XPathExpression expr = xpath.compile(searchQuery);
            
            Map<String, String> variables = new HashMap<>();
            variables.put("searchTerm", searchTerm.toLowerCase());
            ((SecureVariableResolver) xpath.getXPathVariableResolver()).setVariables(variables);
            
            NodeList results = (NodeList) expr.evaluate(xmlDoc, XPathConstants.NODESET);
            
            // 4. Limit results and return safe data only
            List<UserSearchResult> searchResults = new ArrayList<>();
            int limit = Math.min(results.getLength(), maxResults);
            
            for (int i = 0; i < limit; i++) {
                searchResults.add(createSearchResultFromNode(results.item(i)));
            }
            
            return searchResults;
            
        } catch (Exception e) {
            logSecurityEvent("Search failed for term: " + sanitizeForLogging(searchTerm));
            return new ArrayList<>();
        }
    }
    
    // Security utility methods
    private boolean isValidInput(String input, Pattern pattern) {
        return input != null && pattern.matcher(input).matches();
    }
    
    private String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("Password hashing failed", e);
        }
    }
    
    private String sanitizeForLogging(String input) {
        if (input == null) return "null";
        return input.replaceAll("[^a-zA-Z0-9._@-]", "_");
    }
    
    private void logSecurityEvent(String message) {
        // Use proper logging framework in production
        System.out.println("SECURITY EVENT: " + message);
    }
    
    private UserInfo createUserInfoFromNode(org.w3c.dom.Node node) {
        // Safely extract user information without exposing sensitive fields
        UserInfo info = new UserInfo();
        
        NodeList children = node.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            org.w3c.dom.Node child = children.item(i);
            String nodeName = child.getNodeName();
            
            // Only extract non-sensitive information
            switch (nodeName) {
                case "username":
                    info.setUsername(child.getTextContent());
                    break;
                case "email":
                    info.setEmail(child.getTextContent());
                    break;
                case "role":
                    info.setRole(child.getTextContent());
                    break;
                // Never expose password, salary, or other sensitive data
            }
        }
        
        return info;
    }
    
    private UserSearchResult createSearchResultFromNode(org.w3c.dom.Node node) {
        // Create search result with limited, safe information
        UserSearchResult result = new UserSearchResult();
        
        NodeList children = node.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            org.w3c.dom.Node child = children.item(i);
            String nodeName = child.getNodeName();
            
            // Only include public information in search results
            if ("username".equals(nodeName)) {
                result.setUsername(child.getTextContent());
            } else if ("email".equals(nodeName)) {
                result.setEmail(child.getTextContent());
            }
        }
        
        return result;
    }
}

// Custom XPath variable resolver for parameterized queries
class SecureVariableResolver implements XPathVariableResolver {
    private Map<QName, Object> variables = new HashMap<>();
    
    public void setVariables(Map<String, String> vars) {
        variables.clear();
        for (Map.Entry<String, String> entry : vars.entrySet()) {
            variables.put(new QName(entry.getKey()), entry.getValue());
        }
    }
    
    @Override
    public Object resolveVariable(QName variableName) {
        return variables.get(variableName);
    }
}

// Data classes for safe information transfer
class UserInfo {
    private String username;
    private String email;
    private String role;
    
    // Getters and setters (sensitive fields like password are never included)
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
}

class UserSearchResult {
    private String username;
    private String email;
    
    // Only public information for search results
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
}`} 
        />

        <div className="mb-6">
          <h5 className="text-lg font-semibold mb-3">Prevention Best Practices</h5>
          <ul className="list-disc pl-6 space-y-2">
            <li><strong>Input Validation:</strong> Validate all user inputs against strict patterns and length limits</li>
            <li><strong>Parameterized Queries:</strong> Use XPath variable resolvers instead of string concatenation</li>
            <li><strong>Character Escaping:</strong> Properly escape XPath special characters in user input</li>
            <li><strong>Least Privilege:</strong> Limit XPath query scope and accessible document sections</li>
            <li><strong>Error Handling:</strong> Never expose XPath errors or document structure to users</li>
            <li><strong>Alternative Technologies:</strong> Consider using relational databases instead of XML for sensitive data</li>
          </ul>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Cross-Attack Prevention Strategy</h4>
        <p className="mb-4">
          All injection vulnerabilities share common prevention principles that can be applied across different attack types:
        </p>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>Input Validation:</strong> Validate all user inputs at application boundaries</li>
          <li><strong>Output Encoding:</strong> Properly encode data when incorporating it into queries or templates</li>
          <li><strong>Parameterized Queries:</strong> Use prepared statements and parameterized queries when available</li>
          <li><strong>Principle of Least Privilege:</strong> Limit application and database permissions</li>
          <li><strong>Security Testing:</strong> Implement automated testing for injection vulnerabilities</li>
          <li><strong>Error Handling:</strong> Never expose system details in error messages</li>
          <li><strong>Security Headers:</strong> Implement appropriate security headers like Content Security Policy</li>
          <li><strong>Regular Updates:</strong> Keep all frameworks, libraries, and systems updated</li>
        </ul>
      </div>
    </section>
  );
};

export default OtherInjectionFlaws;
