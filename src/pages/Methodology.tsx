
import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CodeExample from '@/components/CodeExample';

const Methodology = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      
      <main className="flex-grow py-12">
        <div className="container mx-auto px-4">
          <div className="mb-12">
            <h1 className="text-4xl font-bold mb-6">Secure Code Review Methodology</h1>
            <div className="h-1 w-24 bg-cybr-primary mb-6"></div>
            <p className="text-xl text-cybr-foreground/80">
              A systematic approach to identifying security vulnerabilities in code.
            </p>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 space-y-8">
              <section>
                <h2 className="text-2xl font-bold mb-4">Understanding the Process</h2>
                <p className="mb-6">
                  Secure code review is a systematic examination of source code to identify security flaws and ensure 
                  that proper security controls are implemented. It's a crucial part of the software development lifecycle.
                </p>
                
                <div className="relative pl-4 mb-8">
                  <div className="absolute left-0 inset-y-0 w-1 bg-gradient-to-b from-cybr-primary to-cybr-secondary rounded-full"></div>
                  <p className="italic text-cybr-foreground/90">
                    "Security code reviews are one of the most effective techniques to find security bugs early in the development process."
                    <span className="block mt-2 text-sm text-cybr-secondary">— Microsoft Security Development Lifecycle</span>
                  </p>
                </div>
                
                <p>
                  Let's break down the key phases of an effective secure code review process:
                </p>
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Phase 1: Preparation</h2>
                
                <div className="card mb-6">
                  <ol className="list-decimal list-inside space-y-4 pl-4">
                    <li className="text-cybr-foreground">
                      <span className="font-bold">Understand the Application Context</span>
                      <p className="ml-7 text-cybr-foreground/80 mt-2">
                        Gather information about the application's purpose, architecture, data flow, and trust boundaries.
                      </p>
                    </li>
                    
                    <li className="text-cybr-foreground">
                      <span className="font-bold">Define Scope and Objectives</span>
                      <p className="ml-7 text-cybr-foreground/80 mt-2">
                        Determine which components to review, with focus on security-critical areas and known risk factors.
                      </p>
                    </li>
                    
                    <li className="text-cybr-foreground">
                      <span className="font-bold">Identify Security Requirements</span>
                      <p className="ml-7 text-cybr-foreground/80 mt-2">
                        Compile relevant security requirements, standards, and compliance needs applicable to the application.
                      </p>
                    </li>
                  </ol>
                </div>
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Phase 2: Review Process</h2>
                
                <div className="card mb-6">
                  <ol className="list-decimal list-inside space-y-4 pl-4" start={4}>
                    <li className="text-cybr-foreground">
                      <span className="font-bold">Automated Analysis</span>
                      <p className="ml-7 text-cybr-foreground/80 mt-2">
                        Run static analysis tools to identify potential security issues, focusing on areas like:
                      </p>
                      <ul className="ml-7 list-disc list-inside pl-4 mt-2 text-cybr-foreground/80">
                        <li>Input validation issues</li>
                        <li>Authentication/authorization flaws</li>
                        <li>Hardcoded credentials</li>
                        <li>Insecure cryptographic implementations</li>
                      </ul>
                    </li>
                    
                    <li className="text-cybr-foreground">
                      <span className="font-bold">Manual Code Review</span>
                      <p className="ml-7 text-cybr-foreground/80 mt-2">
                        Supplement automated tools with human expertise, focusing on logic flaws, business rules, 
                        and other complex vulnerabilities that automated tools might miss.
                      </p>
                    </li>
                  </ol>
                </div>
                
                <div className="my-8">
                  <CodeExample
                    language="javascript"
                    title="Example: Vulnerable JavaScript Code"
                    code={`// VULNERABLE: Direct use of user input in SQL query
function getUserData(userId) {
  // This is vulnerable to SQL injection
  const query = "SELECT * FROM users WHERE id = " + userId;
  return db.execute(query);
}

// SECURE: Parameterized query
function getUserDataSecure(userId) {
  // Using parameterized queries prevents SQL injection
  const query = "SELECT * FROM users WHERE id = ?";
  return db.execute(query, [userId]);
}`}
                  />
                </div>
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Phase 3: Documentation and Follow-Up</h2>
                
                <div className="card mb-6">
                  <ol className="list-decimal list-inside space-y-4 pl-4" start={6}>
                    <li className="text-cybr-foreground">
                      <span className="font-bold">Vulnerability Classification</span>
                      <p className="ml-7 text-cybr-foreground/80 mt-2">
                        Categorize identified issues based on severity, exploitability, and impact using frameworks 
                        like CVSS (Common Vulnerability Scoring System).
                      </p>
                    </li>
                    
                    <li className="text-cybr-foreground">
                      <span className="font-bold">Reporting</span>
                      <p className="ml-7 text-cybr-foreground/80 mt-2">
                        Document findings with clear descriptions, impact assessments, and remediation recommendations.
                      </p>
                    </li>
                    
                    <li className="text-cybr-foreground">
                      <span className="font-bold">Remediation Verification</span>
                      <p className="ml-7 text-cybr-foreground/80 mt-2">
                        Follow up on identified issues to ensure they are properly addressed in subsequent code revisions.
                      </p>
                    </li>
                  </ol>
                </div>
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Common Vulnerabilities</h2>
                
                <p className="mb-4">
                  During your code reviews, pay special attention to these frequently encountered security flaws:
                </p>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                  <div className="card border-l-4 border-l-cybr-accent">
                    <h3 className="text-lg font-bold mb-2">Injection Flaws</h3>
                    <p className="text-cybr-foreground/80">
                      SQL, NoSQL, OS command, and LDAP injection occurring when untrusted data is sent to an interpreter.
                    </p>
                  </div>
                  
                  <div className="card border-l-4 border-l-cybr-accent">
                    <h3 className="text-lg font-bold mb-2">Broken Authentication</h3>
                    <p className="text-cybr-foreground/80">
                      Implementation flaws in authentication and session management allowing attackers to compromise passwords or session tokens.
                    </p>
                  </div>
                  
                  <div className="card border-l-4 border-l-cybr-accent">
                    <h3 className="text-lg font-bold mb-2">Sensitive Data Exposure</h3>
                    <p className="text-cybr-foreground/80">
                      Inadequate protection of sensitive data such as financial information, credentials, or personal data.
                    </p>
                  </div>
                  
                  <div className="card border-l-4 border-l-cybr-accent">
                    <h3 className="text-lg font-bold mb-2">Broken Access Control</h3>
                    <p className="text-cybr-foreground/80">
                      Restrictions on authenticated users not properly enforced, allowing unauthorized actions or access to data.
                    </p>
                  </div>
                </div>
              </section>
            </div>
            
            <div className="lg:col-span-1">
              <div className="sticky top-24">
                <div className="card">
                  <h3 className="text-xl font-bold mb-4">Key Points</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li className="flex items-start">
                      <span className="inline-block w-5 h-5 bg-cybr-primary rounded-full mr-2 mt-1 flex-shrink-0"></span>
                      Combine automated and manual review techniques
                    </li>
                    <li className="flex items-start">
                      <span className="inline-block w-5 h-5 bg-cybr-primary rounded-full mr-2 mt-1 flex-shrink-0"></span>
                      Focus on high-risk areas first
                    </li>
                    <li className="flex items-start">
                      <span className="inline-block w-5 h-5 bg-cybr-primary rounded-full mr-2 mt-1 flex-shrink-0"></span>
                      Use a consistent scoring system for vulnerabilities
                    </li>
                    <li className="flex items-start">
                      <span className="inline-block w-5 h-5 bg-cybr-primary rounded-full mr-2 mt-1 flex-shrink-0"></span>
                      Document findings clearly with remediation steps
                    </li>
                    <li className="flex items-start">
                      <span className="inline-block w-5 h-5 bg-cybr-primary rounded-full mr-2 mt-1 flex-shrink-0"></span>
                      Verify fixes after implementation
                    </li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Tools</h3>
                  <div className="space-y-4">
                    <div>
                      <h4 className="font-semibold text-cybr-secondary">Static Analysis</h4>
                      <ul className="pl-4 mt-1 text-cybr-foreground/80">
                        <li>SonarQube</li>
                        <li>Fortify</li>
                        <li>Checkmarx</li>
                      </ul>
                    </div>
                    
                    <div>
                      <h4 className="font-semibold text-cybr-secondary">Dynamic Analysis</h4>
                      <ul className="pl-4 mt-1 text-cybr-foreground/80">
                        <li>OWASP ZAP</li>
                        <li>Burp Suite</li>
                        <li>WebInspect</li>
                      </ul>
                    </div>
                    
                    <div>
                      <h4 className="font-semibold text-cybr-secondary">Dependency Checking</h4>
                      <ul className="pl-4 mt-1 text-cybr-foreground/80">
                        <li>OWASP Dependency-Check</li>
                        <li>Snyk</li>
                        <li>WhiteSource</li>
                      </ul>
                    </div>
                  </div>
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

export default Methodology;
