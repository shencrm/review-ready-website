
import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CodeExample from '@/components/CodeExample';

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
                  title="Vulnerable vs. Secure SQL Code"
                  code={`// VULNERABLE: Direct string concatenation
function getUserProfile(username) {
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  return db.execute(query);
}

// SECURE: Using parameterized queries
function getUserProfileSecure(username) {
  const query = "SELECT * FROM users WHERE username = ?";
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
                  code={`// VULNERABLE: Using string concatenation with JSON.parse
app.post('/login', (req, res) => {
  const usernameInput = req.body.username;
  const passwordInput = req.body.password;
  
  // Vulnerable to NoSQL injection
  const query = \`{"username": "${usernameInput}", "password": "${passwordInput}"}\`;
  db.collection('users').find(JSON.parse(query)).toArray((err, result) => {
    // Handle login
  });
});

// SECURE: Using direct object literals
app.post('/login', (req, res) => {
  const usernameInput = req.body.username;
  const passwordInput = req.body.password;
  
  // Safe from NoSQL injection
  db.collection('users').find({
    username: usernameInput,
    password: passwordInput
  }).toArray((err, result) => {
    // Handle login
  });
});`}
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
                  </div>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Related Resources</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://owasp.org/www-community/attacks/SQL_Injection" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP SQL Injection Guide</a></li>
                    <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Query Parameterization Cheat Sheet</a></li>
                    <li><a href="https://owasp.org/www-project-top-ten/2017/A1_2017-Injection" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP Top 10: Injection</a></li>
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
