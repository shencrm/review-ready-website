import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CodeExample from '@/components/CodeExample';
import { Link } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';

const NodeJs = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      
      <main className="flex-grow py-12">
        <div className="container mx-auto px-4">
          <div className="mb-12">
            <h1 className="text-4xl font-bold mb-6">Node.js Security</h1>
            <div className="h-1 w-24 bg-cybr-primary mb-6"></div>
            <p className="text-xl text-cybr-foreground/80">
              Understanding and mitigating security vulnerabilities in Node.js applications.
            </p>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 space-y-8">
              <section>
                <h2 className="text-2xl font-bold mb-4">Command Injection</h2>
                <p className="mb-4">
                  Command injection vulnerabilities occur when an application passes unsafe user-supplied data to a system shell.
                  In Node.js, this typically happens when using functions like child_process.exec() without proper sanitization.
                </p>
                
                <CodeExample
                  language="javascript"
                  title="Command Injection Vulnerability"
                  code={`// VULNERABLE: Using user input directly in command execution
const { exec } = require('child_process');

app.get('/check-domain', (req, res) => {
  const domain = req.query.domain;
  // User can inject commands using characters like ; | && 
  exec('ping -c 1 ' + domain, (error, stdout, stderr) => {
    res.send(stdout);
  });
});

// Attacker input: "google.com && rm -rf /" could delete files`}
                />
                
                <CodeExample
                  language="javascript"
                  title="Secure Command Execution"
                  code={`// SECURE: Using execFile with arguments as array
const { execFile } = require('child_process');

app.get('/check-domain', (req, res) => {
  const domain = req.query.domain;
  
  // Validate input first (simple example)
  if (!domain.match(/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\\.[a-zA-Z]{2,})+$/)) {
    return res.status(400).send('Invalid domain');
  }
  
  // execFile doesn't invoke a shell and accepts arguments as array
  execFile('ping', ['-c', '1', domain], (error, stdout, stderr) => {
    res.send(stdout);
  });
});`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Path Traversal</h2>
                <p className="mb-4">
                  Path traversal vulnerabilities allow attackers to access files outside of intended directories,
                  potentially exposing sensitive data or configuration files.
                </p>
                
                <CodeExample
                  language="javascript"
                  title="Path Traversal Vulnerability"
                  code={`// VULNERABLE: Reading files with unsanitized user input
const fs = require('fs');
const path = require('path');

app.get('/download-file', (req, res) => {
  const filename = req.query.filename;
  // Vulnerable to path traversal
  const filePath = path.join(PUBLIC_FOLDER, filename);
  
  fs.readFile(filePath, (err, data) => {
    if (err) {
      return res.status(404).send('File not found');
    }
    res.send(data);
  });
});

// Attacker input: "../../../etc/passwd" could read sensitive files`}
                />
                
                <CodeExample
                  language="javascript"
                  title="Secure File Access"
                  code={`// SECURE: Using path.normalize and checking for path traversal
const fs = require('fs');
const path = require('path');

app.get('/download-file', (req, res) => {
  const filename = req.query.filename;
  
  // Normalize path and check if it starts with the public folder
  const publicFolder = path.resolve(PUBLIC_FOLDER);
  const requestedPath = path.normalize(path.join(publicFolder, filename));
  
  // Check if requestedPath is within the public folder
  if (!requestedPath.startsWith(publicFolder)) {
    return res.status(403).send('Access forbidden');
  }
  
  fs.readFile(requestedPath, (err, data) => {
    if (err) {
      return res.status(404).send('File not found');
    }
    res.send(data);
  });
});`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Security Headers and HTTP Configuration</h2>
                <p className="mb-4">
                  Properly configuring HTTP headers is crucial for Node.js web applications to prevent various attacks.
                </p>
                
                <CodeExample
                  language="javascript"
                  title="Implementing Secure HTTP Headers"
                  code={`// Secure HTTP headers with Helmet
const express = require('express');
const helmet = require('helmet');
const app = express();

// Apply various security headers
app.use(helmet());

// Or configure headers individually
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'", 'trusted-cdn.com'],
    styleSrc: ["'self'", "'unsafe-inline'", 'trusted-cdn.com'],
    imgSrc: ["'self'", 'data:', 'trusted-cdn.com'],
    connectSrc: ["'self'", 'api.trusted-domain.com'],
    fontSrc: ["'self'", 'trusted-cdn.com'],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
  }
}));

app.use(helmet.xssFilter());
app.use(helmet.noSniff());
app.use(helmet.ieNoOpen());
app.use(helmet.frameguard({ action: 'deny' }));`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Dependency Management</h2>
                <p className="mb-4">
                  Node.js applications often have numerous dependencies, which can introduce security vulnerabilities.
                </p>
                
                <CodeExample
                  language="bash"
                  title="Finding and Fixing Vulnerable Dependencies"
                  code={`# Check for vulnerabilities in dependencies
npm audit

# Fix vulnerabilities automatically where possible
npm audit fix

# Detailed report
npm audit --json

# Update a specific package
npm update vulnerable-package

# Run security audit using third-party tools
npx snyk test`}
                />
              </section>
            </div>
            
            <div className="lg:col-span-1">
              <div className="sticky top-24">
                <div className="card">
                  <h3 className="text-xl font-bold mb-4">Common Node.js Security Issues</h3>
                  <ul className="space-y-2 pl-4 text-cybr-foreground/80">
                    <li>Command Injection</li>
                    <li>Path Traversal</li>
                    <li>Unhandled Exceptions</li>
                    <li>Insecure Dependencies</li>
                    <li>Server-Side Request Forgery</li>
                    <li>Improper Error Handling</li>
                    <li>NoSQL Injection</li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Essential Node.js Security Packages</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://github.com/helmetjs/helmet" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Helmet</a></li>
                    <li><a href="https://github.com/expressjs/csurf" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">csurf (CSRF Protection)</a></li>
                    <li><a href="https://github.com/hapijs/joi" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">joi (Input Validation)</a></li>
                    <li><a href="https://github.com/auth0/node-jsonwebtoken" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">jsonwebtoken (JWT)</a></li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Related Technologies</h3>
                  <div className="space-y-3">
                    <Link to="/languages/javascript" className="block text-cybr-primary hover:underline">JavaScript Security</Link>
                    <Link to="/languages/react" className="block text-cybr-primary hover:underline">React Security</Link>
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

export default NodeJs;
