
import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CodeExample from '@/components/CodeExample';

const GettingStarted = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      
      <main className="flex-grow py-12">
        <div className="container mx-auto px-4">
          <div className="mb-12">
            <h1 className="text-4xl font-bold mb-6">Getting Started with Secure Code Review</h1>
            <div className="h-1 w-24 bg-cybr-primary mb-6"></div>
            <p className="text-xl text-cybr-foreground/80">
              Begin your secure code review journey with these essential foundations.
            </p>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 space-y-8">
              <section>
                <h2 className="text-2xl font-bold mb-4">Prerequisites</h2>
                <p className="mb-4">
                  Before diving into secure code review, you should have:
                </p>
                
                <ul className="list-disc list-inside space-y-2 pl-4 text-cybr-foreground/80">
                  <li>Basic understanding of programming concepts</li>
                  <li>Familiarity with at least one programming language</li>
                  <li>Understanding of web application architecture</li>
                  <li>Basic knowledge of common security concepts</li>
                </ul>
                
                <p className="mt-4">
                  Don't worry if you're not an expert in all these areas. This guide will help you build your knowledge progressively.
                </p>
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Setting Up Your Environment</h2>
                <p className="mb-4">
                  An effective secure code review setup includes the right tools and resources:
                </p>
                
                <div className="card mb-6">
                  <h3 className="text-xl font-bold mb-3">Essential Tools</h3>
                  <ul className="list-disc list-inside space-y-2 pl-4 text-cybr-foreground/80">
                    <li>Source code repository access (Git)</li>
                    <li>IDE with security plugins (VS Code, IntelliJ, etc.)</li>
                    <li>Static Application Security Testing (SAST) tools</li>
                    <li>Dynamic Application Security Testing (DAST) tools</li>
                  </ul>
                </div>
                
                <p className="mb-4">
                  Let's look at a basic setup for a VS Code environment with security extensions:
                </p>
                
                <CodeExample
                  language="bash"
                  title="Installing Security Extensions for VS Code"
                  code={`# Install extensions via command line
code --install-extension ms-python.python
code --install-extension dbaeumer.vscode-eslint
code --install-extension sonarsource.sonarlint-vscode
code --install-extension snyk-security.snyk-vulnerability-scanner
`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Understanding Security Principles</h2>
                <p className="mb-4">
                  Before conducting code reviews, familiarize yourself with these core security principles:
                </p>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                  <div className="card">
                    <h3 className="text-lg font-bold mb-2">Defense in Depth</h3>
                    <p className="text-cybr-foreground/80">
                      Implementing multiple layers of security controls to protect systems.
                    </p>
                  </div>
                  
                  <div className="card">
                    <h3 className="text-lg font-bold mb-2">Least Privilege</h3>
                    <p className="text-cybr-foreground/80">
                      Granting only the minimum necessary access rights for users and processes.
                    </p>
                  </div>
                  
                  <div className="card">
                    <h3 className="text-lg font-bold mb-2">Input Validation</h3>
                    <p className="text-cybr-foreground/80">
                      Verifying all input data before processing to prevent injection attacks.
                    </p>
                  </div>
                  
                  <div className="card">
                    <h3 className="text-lg font-bold mb-2">Fail Securely</h3>
                    <p className="text-cybr-foreground/80">
                      Designing systems to handle failures in a secure manner without exposing sensitive information.
                    </p>
                  </div>
                </div>
              </section>
            </div>
            
            <div className="lg:col-span-1">
              <div className="sticky top-24">
                <div className="card">
                  <h3 className="text-xl font-bold mb-4">Learning Path</h3>
                  <ol className="space-y-4 pl-4 text-cybr-foreground/80">
                    <li className="relative pl-7">
                      <span className="absolute left-0 w-5 h-5 bg-cybr-primary rounded-full flex items-center justify-center text-xs text-cybr-background font-bold">1</span>
                      Getting Started (You are here)
                    </li>
                    <li className="relative pl-7 opacity-60">
                      <span className="absolute left-0 w-5 h-5 bg-cybr-secondary rounded-full flex items-center justify-center text-xs text-cybr-background font-bold">2</span>
                      Methodology
                    </li>
                    <li className="relative pl-7 opacity-60">
                      <span className="absolute left-0 w-5 h-5 bg-cybr-muted rounded-full flex items-center justify-center text-xs text-cybr-foreground font-bold">3</span>
                      Language-Specific Guides
                    </li>
                    <li className="relative pl-7 opacity-60">
                      <span className="absolute left-0 w-5 h-5 bg-cybr-muted rounded-full flex items-center justify-center text-xs text-cybr-foreground font-bold">4</span>
                      Advanced Topics
                    </li>
                  </ol>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Recommended Resources</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP Top 10</a></li>
                    <li><a href="https://cheatsheetseries.owasp.org/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP Cheat Sheet Series</a></li>
                    <li><a href="https://github.com/OWASP/CheatSheetSeries" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP GitHub Repository</a></li>
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

export default GettingStarted;
