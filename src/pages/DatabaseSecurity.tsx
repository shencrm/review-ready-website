
import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Shield, Database, Key, Lock } from 'lucide-react';

const DatabaseSecurity = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      
      <main className="flex-grow py-12">
        <div className="container mx-auto px-4">
          <div className="mb-12">
            <h1 className="text-4xl font-bold mb-6">Database Security</h1>
            <div className="h-1 w-24 bg-cybr-primary mb-6"></div>
            <p className="text-xl text-cybr-foreground/80">
              Protecting your data layer from common security vulnerabilities.
            </p>
          </div>
          
          {/* Introduction section */}
          <div className="mb-10 prose prose-cybr max-w-none">
            <p className="text-lg">
              Databases serve as the foundation of modern applications, storing critical information from user credentials to business data. 
              As such, they're prime targets for attackers seeking unauthorized access or data theft. Database security vulnerabilities can lead to 
              data breaches that expose sensitive information, compromise user privacy, and potentially result in significant financial and reputational damage.
            </p>
            <p className="text-lg mt-4">
              Effective database security requires a multi-layered approach that encompasses proper query construction, access control, encryption, 
              configuration hardening, and regular auditing. By understanding common vulnerabilities and implementing appropriate countermeasures, 
              developers can significantly reduce the risk of security incidents and maintain data integrity. This guide explores the most prevalent 
              database security threats and provides practical guidance on protecting your applications' data layer.
            </p>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 space-y-8">
              <section>
                <h2 className="text-2xl font-bold mb-4">SQL Injection</h2>
                <p className="mb-4">
                  SQL injection occurs when hostile data is inserted into SQL statements, allowing attackers to manipulate your database.
                  It remains one of the most common and dangerous vulnerabilities in web applications.
                </p>
                
                <div className="card mb-6">
                  <h3 className="text-xl font-bold mb-3">Common SQL Injection Techniques</h3>
                  <ul className="list-disc list-inside space-y-2 pl-4 text-cybr-foreground/80">
                    <li><span className="text-cybr-secondary font-mono">'OR '1'='1</span> - Bypassing authentication by creating always-true conditions</li>
                    <li><span className="text-cybr-secondary font-mono">; DROP TABLE users; --</span> - Executing additional malicious queries</li>
                    <li><span className="text-cybr-secondary font-mono">UNION SELECT</span> - Combining result sets to extract additional data</li>
                    <li><span className="text-cybr-secondary font-mono">1; WAITFOR DELAY '0:0:10'--</span> - Time-based blind injection to infer data</li>
                  </ul>
                </div>
                
                <CodeExample
                  language="javascript"
                  title="Vulnerable SQL Code"
                  isVulnerable={true}
                  code={`// VULNERABLE: Direct string concatenation
function getUserProfile(username) {
  // This code builds a SQL query by directly concatenating the username parameter
  // into the SQL statement without any validation or sanitization
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  return db.execute(query);
}

// If an attacker provides input like: admin' OR '1'='1
// The resulting query becomes: SELECT * FROM users WHERE username = 'admin' OR '1'='1'
// This creates a condition that is always true, returning all user records`}
                />
                
                <CodeExample
                  language="javascript"
                  title="Secure SQL Code"
                  isVulnerable={false}
                  code={`// SECURE: Using parameterized queries
function getUserProfileSecure(username) {
  // This code uses parameterized queries where the parameter is 
  // handled separately from the SQL statement
  const query = "SELECT * FROM users WHERE username = ?";
  // The database driver ensures the parameter is properly escaped and handled
  // as data, not executable code, preventing SQL injection
  return db.execute(query, [username]);
}`}
                />
                
                <div className="mt-6">
                  <h3 className="text-xl font-bold mb-3">Prevention Techniques</h3>
                  <ul className="list-disc list-inside space-y-2 pl-4 text-cybr-foreground/80">
                    <li><span className="font-semibold">Use Parameterized Queries/Prepared Statements:</span> This ensures that user input is treated as data, not executable code</li>
                    <li><span className="font-semibold">ORM Frameworks:</span> Many modern ORMs provide built-in protection against SQL injection</li>
                    <li><span className="font-semibold">Input Validation:</span> Validate and sanitize all user inputs</li>
                    <li><span className="font-semibold">Principle of Least Privilege:</span> Database accounts should have minimal required permissions</li>
                  </ul>
                </div>

                <CodeExample
                  language="python"
                  title="Parameterized Queries in Different Languages"
                  isVulnerable={false}
                  code={`# Python example with parameterized queries
import sqlite3

def get_user_data(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Secure: Uses parameter binding
    cursor.execute("SELECT username, email FROM users WHERE id = ?", (user_id,))
    result = cursor.fetchone()
    
    conn.close()
    return result

# PHP example with prepared statements
<?php
$stmt = $pdo->prepare("SELECT username, email FROM users WHERE id = ?");
$stmt->execute([$user_id]);
$user = $stmt->fetch();

# Java example with PreparedStatement
PreparedStatement stmt = conn.prepareStatement(
    "SELECT username, email FROM users WHERE id = ?"
);
stmt.setInt(1, userId);
ResultSet rs = stmt.executeQuery();`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">NoSQL Injection</h2>
                <p className="mb-4">
                  NoSQL databases are not immune to injection attacks. While the attack vectors differ from SQL injection,
                  the underlying principle remains the same: unvalidated user input manipulating database queries.
                </p>
                
                <CodeExample
                  language="javascript"
                  title="MongoDB Injection Example"
                  isVulnerable={true}
                  code={`// VULNERABLE: Using string concatenation with JSON.parse
app.post('/login', (req, res) => {
  const usernameInput = req.body.username;
  const passwordInput = req.body.password;
  
  // This code constructs a query object using string interpolation
  // and then parses it as JSON, which can be manipulated by an attacker
  const query = \`{"username": "\${usernameInput}", "password": "\${passwordInput}"}\`;
  db.collection('users').find(JSON.parse(query)).toArray((err, result) => {
    // Handle login
  });
});

// An attacker could supply this input:
// username: "admin", password: "password" OR "a"=="a"
// The query becomes: {"username": "admin", "password": "password" OR "a"=="a"}
// This creates a condition that is always true`}
                />
                
                <CodeExample
                  language="javascript"
                  title="Secure MongoDB Query"
                  isVulnerable={false}
                  code={`// SECURE: Using direct object literals
app.post('/login', (req, res) => {
  const usernameInput = req.body.username;
  const passwordInput = req.body.password;
  
  // Safe from NoSQL injection because we're using a proper object structure
  // The values are treated as data, not part of the query structure
  db.collection('users').find({
    username: usernameInput,
    password: passwordInput
  }).toArray((err, result) => {
    // Handle login
  });
});

// BETTER: Adding input validation and proper password handling
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Input validation
  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid credentials format' });
  }
  
  try {
    // Find user by username only
    const user = await db.collection('users').findOne({ username });
    
    if (!user) {
      return res.status(401).json({ error: 'Authentication failed' });
    }
    
    // Compare password hash (NEVER store plaintext passwords)
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Authentication failed' });
    }
    
    // Authentication successful
    res.json({ user: { id: user._id, username: user.username } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});`}
                />

                <SecurityCard 
                  title="NoSQL Operator Injection"
                  description="In MongoDB, attackers can use special operators like $gt, $ne, or $regex to manipulate queries even when using proper objects."
                  severity="high"
                  icon={<Shield />}
                  className="mb-6"
                />
                
                <CodeExample
                  language="javascript"
                  title="Vulnerable to Operator Injection"
                  isVulnerable={true}
                  code={`// VULNERABLE: Passing user input directly to query operators
app.get('/users', (req, res) => {
  const filters = req.query.filters ? JSON.parse(req.query.filters) : {};
  
  // This directly passes user-provided filter objects to MongoDB
  // An attacker can include operators like $gt, $ne in their input
  db.collection('users').find(filters).toArray((err, users) => {
    res.json(users);
  });
});

// Attacker input: ?filters={"password":{"$exists":true}}
// This would return all users with a password field`}
                />
                
                <CodeExample
                  language="javascript"
                  title="Preventing Operator Injection"
                  isVulnerable={false}
                  code={`// SECURE: Sanitizing inputs to prevent MongoDB operator injection
app.get('/users', (req, res) => {
  let filters = {};
  
  // Explicitly define which fields are allowed and how they should be filtered
  if (req.query.name) {
    filters.name = req.query.name; // Simple equality match
  }
  
  if (req.query.age) {
    // Convert to number and validate
    const age = parseInt(req.query.age);
    if (!isNaN(age) && age > 0 && age < 120) {
      filters.age = age;
    }
  }
  
  // Advanced filtering with controlled operators
  if (req.query.minAge) {
    const minAge = parseInt(req.query.minAge);
    if (!isNaN(minAge) && minAge > 0) {
      filters.age = { $gte: minAge }; // Safe because we control the operator
    }
  }
  
  // Whitelist approach for sorting
  const allowedSortFields = ['name', 'age', 'createdAt'];
  let sort = { createdAt: -1 }; // Default sort
  
  if (req.query.sortBy && allowedSortFields.includes(req.query.sortBy)) {
    const direction = req.query.sortDir === 'asc' ? 1 : -1;
    sort = { [req.query.sortBy]: direction };
  }
  
  // Execute query with sanitized filters
  db.collection('users')
    .find(filters)
    .sort(sort)
    .limit(50)
    .toArray((err, users) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      // Never return sensitive fields
      const safeUsers = users.map(user => {
        const { password, passwordHash, ...safeUser } = user;
        return safeUser;
      });
      
      res.json(safeUsers);
    });
});`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Insecure Direct Object References (IDOR)</h2>
                <p className="mb-4">
                  IDOR vulnerabilities occur when a database reference (like an ID) is exposed to the user, allowing them to manipulate it
                  to access unauthorized resources.
                </p>
                
                <CodeExample
                  language="javascript"
                  title="Vulnerable IDOR Example"
                  isVulnerable={true}
                  code={`// VULNERABLE: No authorization check in database access
app.get('/api/documents/:documentId', (req, res) => {
  const documentId = req.params.documentId;
  
  // This query retrieves a document by ID without checking if the current user
  // should have access to it, creating an IDOR vulnerability
  db.collection('documents')
    .findOne({ _id: ObjectId(documentId) })
    .then(document => {
      if (!document) {
        return res.status(404).json({ error: 'Document not found' });
      }
      res.json(document);
    })
    .catch(err => res.status(500).json({ error: 'Database error' }));
});

// An attacker who knows or can guess document IDs can access any document
// by changing the ID parameter in the URL`}
                />
                
                <CodeExample
                  language="javascript"
                  title="Secure Document Access"
                  isVulnerable={false}
                  code={`// SECURE: Proper authorization check before retrieving data
app.get('/api/documents/:documentId', authenticate, async (req, res) => {
  const documentId = req.params.documentId;
  const userId = req.user.id; // From authentication middleware
  
  try {
    // Convert string ID to ObjectId (with validation)
    let docId;
    try {
      docId = ObjectId(documentId);
    } catch (err) {
      return res.status(400).json({ error: 'Invalid document ID' });
    }
    
    // Query includes both the document ID AND a check that the user has access
    const document = await db.collection('documents').findOne({
      _id: docId,
      $or: [
        { ownerId: userId },
        { sharedWith: userId },
        { isPublic: true }
      ]
    });
    
    if (!document) {
      // Don't reveal if the document exists but isn't accessible
      // by returning the same message for non-existent and unauthorized
      return res.status(404).json({ error: 'Document not found or access denied' });
    }
    
    res.json(document);
  } catch (err) {
    console.error('Document access error:', err);
    res.status(500).json({ error: 'An error occurred' });
  }
});

// Additional protection: Use random UUIDs instead of sequential IDs
// to make it harder to guess valid identifiers
function createDocument(data, userId) {
  const documentId = uuidv4(); // Generate random UUID
  
  return db.collection('documents').insertOne({
    _id: documentId,
    ownerId: userId,
    data,
    created: new Date(),
  });
}`}
                />

                <SecurityCard 
                  title="Access Control In Database Layer"
                  description="Properly implemented database-level access controls provide an additional layer of security beyond application-level checks."
                  severity="medium"
                  icon={<Lock />}
                  className="my-6"
                />

                <CodeExample
                  language="sql"
                  title="PostgreSQL Row-Level Security"
                  isVulnerable={false}
                  code={`-- PostgreSQL Row-Level Security (RLS) Example
-- This creates a policy that restricts what rows users can see

-- First, enable row-level security on the documents table
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

-- Create a policy that allows users to see only their own documents
-- or documents shared with them
CREATE POLICY user_documents ON documents
    USING (
        owner_id = current_user_id() OR
        current_user_id() = ANY(shared_with_user_ids) OR
        is_public = true
    );

-- Function to get the current user's ID from application context
CREATE OR REPLACE FUNCTION current_user_id()
RETURNS INTEGER AS $$
BEGIN
    RETURN current_setting('app.current_user_id')::INTEGER;
END;
$$ LANGUAGE plpgsql;

-- In your application code, set the user context before queries
-- JavaScript/Node.js example with pg library:
await client.query("SET app.current_user_id = $1", [userId]);

-- Now any query on the documents table will automatically filter
-- results based on the policy, even if the application forgets
-- to include the conditions`}
                />
              </section>

              <section>
                <h2 className="text-2xl font-bold mb-4">Mass Assignment Vulnerabilities</h2>
                <p className="mb-4">
                  Mass assignment vulnerabilities occur when an application automatically assigns user input to data models without proper filtering,
                  allowing attackers to override fields they shouldn't have access to.
                </p>

                <SecurityCard 
                  title="Automatic Model Binding Risks"
                  description="Many web frameworks automatically bind request data to models, which can lead to mass assignment vulnerabilities if not properly restricted."
                  severity="high"
                  icon={<Database />}
                  className="mb-6"
                />
                
                <CodeExample
                  language="javascript"
                  title="Vulnerable Mass Assignment"
                  isVulnerable={true}
                  code={`// VULNERABLE: Blindly passing request body to database update
app.put('/api/users/:id', authenticate, (req, res) => {
  const userId = req.params.id;
  const userData = req.body;
  
  // This directly passes all data from the request body to the update operation
  // allowing an attacker to update ANY field, including privileged ones
  db.collection('users')
    .updateOne({ _id: ObjectId(userId) }, { $set: userData })
    .then(() => res.json({ message: 'User updated successfully' }))
    .catch(err => res.status(500).json({ error: 'Update failed' }));
});

// An attacker could update their role to 'admin' by including
// it in the request body: { "name": "John", "role": "admin" }`}
                />
                
                <CodeExample
                  language="javascript"
                  title="Preventing Mass Assignment"
                  isVulnerable={false}
                  code={`// SECURE: Explicit field selection for updates
app.put('/api/users/:id', authenticate, (req, res) => {
  const userId = req.params.id;
  
  // Only allow specific fields to be updated by explicitly selecting them
  const allowedUpdates = {
    name: req.body.name,
    email: req.body.email,
    profilePicture: req.body.profilePicture,
    preferences: req.body.preferences
  };
  
  // Remove undefined fields (those not provided in the request)
  const updates = Object.entries(allowedUpdates)
    .filter(([key, value]) => value !== undefined)
    .reduce((obj, [key, value]) => {
      obj[key] = value;
      return obj;
    }, {});
  
  // Validate the user can only update their own profile (unless admin)
  if (req.user.id !== userId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  // Update only the allowed fields
  db.collection('users')
    .updateOne({ _id: ObjectId(userId) }, { $set: updates })
    .then(result => {
      if (result.matchedCount === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
      res.json({ message: 'User updated successfully' });
    })
    .catch(err => {
      console.error('Update error:', err);
      res.status(500).json({ error: 'Update failed' });
    });
});

// For sensitive operations, require additional verification
app.put('/api/users/:id/role', adminOnly, async (req, res) => {
  const userId = req.params.id;
  const { role } = req.body;
  
  // Only admins can update roles (enforced by adminOnly middleware)
  // Validate the role is one of the allowed values
  const allowedRoles = ['user', 'editor', 'admin'];
  if (!allowedRoles.includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  
  try {
    const result = await db.collection('users').updateOne(
      { _id: ObjectId(userId) },
      { $set: { role } }
    );
    
    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Log this sensitive operation for audit purposes
    await db.collection('auditLog').insertOne({
      operation: 'role_change',
      userId,
      performedBy: req.user.id,
      oldRole: null, // Would need to fetch this beforehand in production
      newRole: role,
      timestamp: new Date()
    });
    
    res.json({ message: 'Role updated successfully' });
  } catch (err) {
    console.error('Role update error:', err);
    res.status(500).json({ error: 'Role update failed' });
  }
});`}
                />
              </section>

              <section>
                <h2 className="text-2xl font-bold mb-4">Sensitive Data Exposure</h2>
                <p className="mb-4">
                  Databases often contain sensitive information that requires special protection both at rest and in transit. 
                  Improper handling of this data can lead to unauthorized exposure.
                </p>
                
                <SecurityCard 
                  title="Storage of Sensitive Data"
                  description="Sensitive data should be encrypted at rest using strong cryptographic algorithms and proper key management."
                  severity="high"
                  icon={<Key />}
                  className="mb-6"
                />
                
                <CodeExample
                  language="javascript"
                  title="Dangerous Sensitive Data Storage"
                  isVulnerable={true}
                  code={`// VULNERABLE: Storing sensitive data in plaintext
const createUser = async (userData) => {
  // This stores a plaintext password directly in the database
  const user = {
    username: userData.username,
    email: userData.email,
    password: userData.password, // Plaintext password!
    creditCard: userData.creditCard, // Plaintext credit card!
    ssn: userData.ssn, // Plaintext Social Security Number!
    dateCreated: new Date()
  };
  
  return await db.collection('users').insertOne(user);
};

// When retrieving user data, the sensitive information is also
// sent back to the client without any filtering
const getUserProfile = async (userId) => {
  return await db.collection('users').findOne({ _id: ObjectId(userId) });
};`}
                />
                
                <CodeExample
                  language="javascript"
                  title="Secure Sensitive Data Handling"
                  isVulnerable={false}
                  code={`// SECURE: Properly protecting sensitive data
const bcrypt = require('bcrypt');
const crypto = require('crypto');

// Encryption configuration
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; // Store securely!
const IV_LENGTH = 16; // For AES, this is always 16 bytes

// Function to encrypt sensitive data
function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(
    'aes-256-cbc', 
    Buffer.from(ENCRYPTION_KEY, 'hex'), 
    iv
  );
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// Function to decrypt sensitive data
function decrypt(text) {
  const parts = text.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const encryptedText = Buffer.from(parts[1], 'hex');
  const decipher = crypto.createDecipheriv(
    'aes-256-cbc', 
    Buffer.from(ENCRYPTION_KEY, 'hex'), 
    iv
  );
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

// Secure user creation
const createUser = async (userData) => {
  // Hash password using bcrypt (one-way hashing)
  const saltRounds = 12;
  const passwordHash = await bcrypt.hash(userData.password, saltRounds);
  
  // Encrypt sensitive data (two-way encryption for data that needs to be retrieved)
  const user = {
    username: userData.username,
    email: userData.email,
    passwordHash, // Hashed password, not plaintext
    // Encrypt sensitive fields that need to be retrieved later
    creditCard: userData.creditCard ? encrypt(userData.creditCard) : null,
    ssn: userData.ssn ? encrypt(userData.ssn) : null,
    dateCreated: new Date()
  };
  
  return await db.collection('users').insertOne(user);
};

// Only return necessary, non-sensitive data
const getUserProfile = async (userId) => {
  const user = await db.collection('users').findOne({ _id: ObjectId(userId) });
  
  if (!user) return null;
  
  // Strip out sensitive fields entirely
  const { passwordHash, ...safeUserData } = user;
  
  // Only decrypt and expose last 4 digits of the credit card
  if (safeUserData.creditCard) {
    const decryptedCreditCard = decrypt(safeUserData.creditCard);
    safeUserData.creditCardLastFour = decryptedCreditCard.slice(-4);
    delete safeUserData.creditCard; // Remove the encrypted version
  }
  
  // Remove SSN entirely from the return object
  delete safeUserData.ssn;
  
  return safeUserData;
};

// When sensitive data is actually needed (e.g., for payment processing)
// use a function that requires additional authentication/authorization
const getDecryptedCreditCard = async (userId, requestContext) => {
  // Additional security checks
  if (!requestContext.userHasPermission('process_payments')) {
    throw new Error('Unauthorized access to payment information');
  }
  
  // Log the access for audit purposes
  await db.collection('dataAccessLog').insertOne({
    userId,
    accessedField: 'creditCard',
    accessedBy: requestContext.currentUserId,
    reason: requestContext.accessReason,
    timestamp: new Date()
  });
  
  // Retrieve and decrypt
  const user = await db.collection('users').findOne({ _id: ObjectId(userId) });
  if (!user || !user.creditCard) return null;
  
  return decrypt(user.creditCard);
};`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Secure Database Practices</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="card">
                    <h3 className="text-xl font-bold mb-3">Authentication & Authorization</h3>
                    <ul className="list-disc list-inside space-y-2 pl-4 text-cybr-foreground/80">
                      <li>Use strong, unique credentials for database accounts</li>
                      <li>Implement proper role-based access control</li>
                      <li>Regularly audit database access permissions</li>
                      <li>Remove default or guest accounts</li>
                    </ul>
                  </div>
                  
                  <div className="card">
                    <h3 className="text-xl font-bold mb-3">Encryption</h3>
                    <ul className="list-disc list-inside space-y-2 pl-4 text-cybr-foreground/80">
                      <li>Encrypt sensitive data at rest</li>
                      <li>Use TLS/SSL for database connections</li>
                      <li>Store cryptographic keys separately from the data</li>
                      <li>Consider field-level encryption for highly sensitive data</li>
                    </ul>
                  </div>
                  
                  <div className="card">
                    <h3 className="text-xl font-bold mb-3">Configuration & Hardening</h3>
                    <ul className="list-disc list-inside space-y-2 pl-4 text-cybr-foreground/80">
                      <li>Disable unnecessary database features and services</li>
                      <li>Keep database software updated with security patches</li>
                      <li>Use network segmentation to isolate database servers</li>
                      <li>Enable comprehensive auditing and logging</li>
                    </ul>
                  </div>
                  
                  <div className="card">
                    <h3 className="text-xl font-bold mb-3">Backup & Recovery</h3>
                    <ul className="list-disc list-inside space-y-2 pl-4 text-cybr-foreground/80">
                      <li>Implement regular secure backup procedures</li>
                      <li>Encrypt backup data</li>
                      <li>Test restoration procedures regularly</li>
                      <li>Ensure backups are stored securely off-site</li>
                    </ul>
                  </div>
                </div>
              </section>

              <section>
                <h2 className="text-2xl font-bold mb-4">Excessive Data Exposure and Improper Error Handling</h2>
                <p className="mb-4">
                  Exposing too much data or revealing sensitive information through error messages can provide attackers with valuable insights.
                </p>
                
                <SecurityCard 
                  title="Database Error Disclosure"
                  description="Detailed database error messages can reveal database structure, query logic, and potential injection points to attackers."
                  severity="medium"
                  icon={<Shield />}
                  className="mb-6"
                />
                
                <CodeExample
                  language="javascript"
                  title="Dangerous Error Handling"
                  isVulnerable={true}
                  code={`// VULNERABLE: Exposing database errors to clients
app.get('/api/products/:id', (req, res) => {
  const productId = req.params.id;
  
  // Attempt to query the database
  db.collection('products')
    .findOne({ _id: ObjectId(productId) })
    .then(product => {
      if (!product) {
        return res.status(404).json({ error: 'Product not found' });
      }
      res.json(product);
    })
    .catch(err => {
      // This sends the raw database error message to the client
      // potentially revealing database details or query structure
      res.status(500).json({ 
        error: 'Database error', 
        details: err.message,
        stack: err.stack  // Very dangerous!
      });
    });
});

// A malformed ObjectId input could result in an error
// that reveals database implementation details`}
                />
                
                <CodeExample
                  language="javascript"
                  title="Secure Error Handling"
                  isVulnerable={false}
                  code={`// SECURE: Proper error handling and logging
const logger = require('./logger'); // Separate logging module

app.get('/api/products/:id', (req, res) => {
  const productId = req.params.id;
  
  // Validate ID format first to prevent unnecessary database errors
  try {
    if (!ObjectId.isValid(productId)) {
      return res.status(400).json({ error: 'Invalid product ID format' });
    }
    
    db.collection('products')
      .findOne({ _id: new ObjectId(productId) })
      .then(product => {
        if (!product) {
          return res.status(404).json({ error: 'Product not found' });
        }
        res.json(product);
      })
      .catch(err => {
        // Generate a unique error ID for tracking
        const errorId = uuidv4();
        
        // Log the full error details for debugging but only internally
        logger.error({
          message: 'Database query error',
          errorId,
          error: err.message,
          stack: err.stack,
          productId,
          user: req.user?.id || 'anonymous'
        });
        
        // Return a generic error to the client with the error ID
        // for support reference but no technical details
        res.status(500).json({
          error: 'An error occurred while retrieving the product',
          errorId  // Reference ID for support without exposing details
        });
      });
  } catch (err) {
    // Catch any other unexpected errors
    const errorId = uuidv4();
    logger.error({
      message: 'Unexpected error in product route',
      errorId,
      error: err.message,
      path: req.path
    });
    
    res.status(500).json({
      error: 'An unexpected error occurred',
      errorId
    });
  }
});`}
                />

                <CodeExample
                  language="javascript"
                  title="Controlling Data Exposure"
                  isVulnerable={false}
                  code={`// SECURE: Projections to limit exposed data
app.get('/api/users', async (req, res) => {
  try {
    // Use projection to explicitly select only the fields that should be visible
    const users = await db.collection('users')
      .find({}, {
        projection: {
          username: 1,
          email: 1,
          firstName: 1,
          lastName: 1,
          role: 1,
          // Exclude sensitive fields by explicitly setting them to 0
          // (though they'd be excluded anyway if not explicitly included above)
          password: 0,
          passwordHash: 0,
          creditCard: 0,
          ssn: 0
        }
      })
      .limit(100)
      .toArray();
    
    res.json(users);
  } catch (err) {
    logger.error('Error retrieving user list', err);
    res.status(500).json({ error: 'Failed to retrieve users' });
  }
});

// For different user roles, you can adjust the data returned
app.get('/api/users/:id', authenticate, async (req, res) => {
  const userId = req.params.id;
  const requestingUserRole = req.user.role;
  
  try {
    // Base projection for all roles
    const baseProjection = {
      username: 1,
      firstName: 1,
      lastName: 1,
      profilePicture: 1,
      createdAt: 1
    };
    
    // Additional fields for admins or self
    const isAdmin = requestingUserRole === 'admin';
    const isSelf = req.user.id === userId;
    
    // Add more fields for admins or the user viewing their own profile
    let projection = { ...baseProjection };
    
    if (isAdmin || isSelf) {
      projection.email = 1;
      projection.lastLogin = 1;
      projection.loginHistory = 1;
    }
    
    // Only admins can see role and account status
    if (isAdmin) {
      projection.role = 1;
      projection.accountStatus = 1;
      projection.notes = 1;  // Admin notes on user
    }
    
    const user = await db.collection('users').findOne(
      { _id: ObjectId(userId) },
      { projection }
    );
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(user);
  } catch (err) {
    logger.error('Error retrieving user details', err);
    res.status(500).json({ error: 'Failed to retrieve user details' });
  }
});`}
                />
              </section>

              <section>
                <h2 className="text-2xl font-bold mb-4">Database Connection Security</h2>
                <p className="mb-4">
                  Securing the connection between your application and database is critical to prevent data interception and credential theft.
                </p>
                
                <SecurityCard 
                  title="Connection String Security"
                  description="Database connection strings often contain sensitive credentials and should never be exposed in client-side code or version control systems."
                  severity="high"
                  icon={<Key />}
                  className="mb-6"
                />
                
                <CodeExample
                  language="javascript"
                  title="Insecure Database Connection"
                  isVulnerable={true}
                  code={`// VULNERABLE: Hardcoded database credentials
// This file might be checked into version control
const mongoose = require('mongoose');

// Direct hardcoding of connection string with credentials
const connectionString = 'mongodb://admin:Password123@database.example.com:27017/production_db';

mongoose.connect(connectionString, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// Even worse: No TLS/SSL for database connection
const mysql = require('mysql');
const connection = mysql.createConnection({
  host: 'database.example.com',
  user: 'root',
  password: 'root_password',
  database: 'customer_data'
});

connection.connect();`}
                />
                
                <CodeExample
                  language="javascript"
                  title="Secure Database Connection"
                  isVulnerable={false}
                  code={`// SECURE: Environment variables for credentials and proper SSL
require('dotenv').config(); // Load environment variables
const mongoose = require('mongoose');

// Get connection details from environment variables
const username = process.env.DB_USERNAME;
const password = process.env.DB_PASSWORD;
const host = process.env.DB_HOST;
const name = process.env.DB_NAME;

// Build connection string with environment variables
const connectionString = \`mongodb://\${username}:\${password}@\${host}:27017/\${name}\`;

// Connect with proper security options
mongoose.connect(connectionString, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  ssl: true,
  sslValidate: true,
  sslCA: require('fs').readFileSync('./rds-ca-2019-root.pem') // CA certificate
});

// For MySQL with connection pooling and SSL
const mysql = require('mysql2');

const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: {
    ca: require('fs').readFileSync('./ca-cert.pem'),
    rejectUnauthorized: true
  },
  connectionLimit: 10, // Connection pooling
  waitForConnections: true,
  queueLimit: 0
};

// Create a connection pool instead of a single connection
const pool = mysql.createPool(dbConfig);

// Utility to get a connection from the pool and run a query
async function query(sql, params) {
  try {
    const [rows] = await pool.promise().execute(sql, params);
    return rows;
  } catch (error) {
    console.error('Database query error:', error);
    throw error;
  }
}`}
                />

                <CodeExample
                  language="javascript"
                  title="Connection Pooling and Retry Strategy"
                  isVulnerable={false}
                  code={`// SECURE: Advanced connection handling with retries
const { MongoClient } = require('mongodb');
require('dotenv').config();

// Connection configuration with exponential backoff retry strategy
const dbConfig = {
  uri: process.env.MONGODB_URI,
  options: {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    ssl: true,
    sslValidate: true,
    sslCA: require('fs').readFileSync('./rds-ca-2019-root.pem'),
    poolSize: 10, // Connection pool size
    connectTimeoutMS: 30000, // 30 seconds
    socketTimeoutMS: 45000, // 45 seconds
    serverSelectionTimeoutMS: 60000, // 60 seconds
    retryWrites: true,
    retryReads: true,
    w: 'majority', // Write concern
    maxIdleTimeMS: 120000, // Close unused connections after 2 minutes
    // Retry logic for connection establishment
    reconnectTries: 10,
    reconnectInterval: 1000, // Start with 1 second delay
    useNewUrlParser: true
  }
};

// Singleton database client
let client = null;
let db = null;

// Function to connect with retry logic
async function connectWithRetry(retries = 5, delay = 1000) {
  try {
    if (client && client.isConnected()) {
      return client;
    }
    
    client = new MongoClient(dbConfig.uri, dbConfig.options);
    await client.connect();
    db = client.db();
    
    console.log('Successfully connected to the database');
    
    // Setup connection monitoring
    client.on('close', () => {
      console.log('Database connection closed');
    });
    
    client.on('reconnect', () => {
      console.log('Database reconnected');
    });
    
    client.on('error', (err) => {
      console.error('Database connection error:', err);
    });
    
    return client;
  } catch (err) {
    if (retries === 0) {
      console.error('Failed to connect to database after multiple retries', err);
      throw err;
    }
    
    console.log(\`Connection attempt failed, retrying in \${delay}ms...\`);
    await new Promise(resolve => setTimeout(resolve, delay));
    return connectWithRetry(retries - 1, delay * 2); // Exponential backoff
  }
}

// Graceful shutdown to properly close connections
process.on('SIGINT', async () => {
  try {
    if (client) {
      await client.close();
      console.log('Database connection closed due to application termination');
    }
    process.exit(0);
  } catch (err) {
    console.error('Error during graceful shutdown:', err);
    process.exit(1);
  }
});

// Export functions for database interaction
module.exports = {
  connect: connectWithRetry,
  getDb: () => {
    if (!db) {
      throw new Error('Database not connected. Call connect() first.');
    }
    return db;
  },
  closeConnection: async () => {
    if (client) {
      await client.close();
      client = null;
      db = null;
    }
  }
};`}
                />
              </section>
            </div>
            
            <div className="lg:col-span-1">
              <div className="sticky top-24">
                <div className="card">
                  <h3 className="text-xl font-bold mb-4">Quick Reference</h3>
                  <div className="space-y-6">
                    <div>
                      <h4 className="font-semibold text-cybr-secondary">Signs of SQL Injection Vulnerability</h4>
                      <ul className="list-disc list-inside pl-4 mt-1 text-cybr-foreground/80 text-sm">
                        <li>String concatenation in SQL queries</li>
                        <li>Lack of prepared statements</li>
                        <li>Error messages revealing SQL syntax</li>
                        <li>Direct use of user input in queries</li>
                      </ul>
                    </div>
                    
                    <div>
                      <h4 className="font-semibold text-cybr-secondary">Database Security Checklist</h4>
                      <ul className="list-disc list-inside pl-4 mt-1 text-cybr-foreground/80 text-sm">
                        <li>Use parameterized queries</li>
                        <li>Implement proper access control</li>
                        <li>Encrypt sensitive data</li>
                        <li>Regular security patching</li>
                        <li>Comprehensive logging & monitoring</li>
                        <li>Database firewall protection</li>
                        <li>Strong authentication</li>
                      </ul>
                    </div>

                    <div>
                      <h4 className="font-semibold text-cybr-secondary">Critical Database Vulnerabilities</h4>
                      <ul className="list-disc list-inside pl-4 mt-1 text-cybr-foreground/80 text-sm">
                        <li>SQL/NoSQL Injection</li>
                        <li>Insecure Direct Object References</li>
                        <li>Excessive Data Exposure</li>
                        <li>Mass Assignment</li>
                        <li>Unprotected Credentials</li>
                        <li>Missing Access Controls</li>
                        <li>Unsafe Configuration Defaults</li>
                      </ul>
                    </div>
                  </div>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Related Resources</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://owasp.org/www-community/attacks/SQL_Injection" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP SQL Injection Guide</a></li>
                    <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Query Parameterization Cheat Sheet</a></li>
                    <li><a href="https://owasp.org/www-project-top-ten/2017/A1_2017-Injection" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP Top 10: Injection</a></li>
                    <li><a href="https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP: Sensitive Data Exposure</a></li>
                    <li><a href="https://www.postgresql.org/docs/current/ddl-rowsecurity.html" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">PostgreSQL Row-Level Security</a></li>
                    <li><a href="https://docs.mongodb.com/manual/core/security-client-side-encryption/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">MongoDB Client-Side Field Level Encryption</a></li>
                  </ul>
                </div>

                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Database Encryption Types</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><span className="font-semibold">Transparent Data Encryption (TDE):</span> Encrypts database files at the storage level</li>
                    <li><span className="font-semibold">Column-Level Encryption:</span> Encrypts specific columns containing sensitive data</li>
                    <li><span className="font-semibold">Application-Level Encryption:</span> Encrypting data before storing it in the database</li>
                    <li><span className="font-semibold">Client-Side Field Level Encryption:</span> Data encrypted/decrypted only on the client</li>
                    <li><span className="font-semibold">Hashing:</span> One-way transformation for passwords and verification data</li>
                  </ul>
                </div>

                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Security Tools</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://www.zaproxy.org/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP ZAP</a> - For finding SQL injection vulnerabilities</li>
                    <li><a href="https://sqlmap.org/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">sqlmap</a> - Automated SQL injection tool</li>
                    <li><a href="https://www.metasploit.com/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Metasploit</a> - Penetration testing framework</li>
                    <li><a href="https://github.com/nodesecurity/eslint-plugin-security" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">ESLint Security Plugin</a> - Static analysis for JavaScript</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
      
      <Footer />
    </div>
  );
};

export default DatabaseSecurity;

