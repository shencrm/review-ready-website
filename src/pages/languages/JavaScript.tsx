
import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Link } from 'react-router-dom';
import { Shield, Bug, Code } from 'lucide-react';

const JavaScript = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      
      <main className="flex-grow py-12">
        <div className="container mx-auto px-4">
          <div className="mb-12">
            <h1 className="text-4xl font-bold mb-6">JavaScript Security</h1>
            <div className="h-1 w-24 bg-cybr-primary mb-6"></div>
            <p className="text-xl text-cybr-foreground/80">
              Understanding and mitigating common JavaScript vulnerabilities.
            </p>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 space-y-8">
              <section>
                <h2 className="text-2xl font-bold mb-4">Cross-Site Scripting (XSS)</h2>
                <p className="mb-4">
                  XSS vulnerabilities allow attackers to inject client-side scripts into web pages viewed by other users.
                  These attacks can steal cookies, session tokens, and sensitive information, or redirect users to malicious sites.
                </p>
                
                <CodeExample
                  language="javascript"
                  title="Vulnerable XSS Code"
                  code={`// VULNERABLE: Directly inserting user input into DOM
function displayUsername(username) {
  // User input is directly inserted into HTML without sanitization
  document.getElementById('user-welcome').innerHTML = 
    '<h2>Welcome, ' + username + '!</h2>';
}

// Attacker could provide: <script>sendCookiesToAttacker()</script>
// Which would execute arbitrary JavaScript in the browser`}
                />
                
                <CodeExample
                  language="javascript"
                  title="Secure XSS Prevention"
                  code={`// SECURE: Using textContent instead of innerHTML
function displayUsernameSecure(username) {
  const element = document.getElementById('user-welcome');
  const heading = document.createElement('h2');
  // textContent does not parse HTML, preventing script execution
  heading.textContent = 'Welcome, ' + username + '!';
  element.appendChild(heading);
}

// ALTERNATIVE: Using a library to sanitize HTML
import DOMPurify from 'dompurify';

function displayFormattedContent(content) {
  document.getElementById('content').innerHTML = 
    DOMPurify.sanitize(content);
}`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Prototype Pollution</h2>
                <p className="mb-4">
                  Prototype pollution is a vulnerability specific to JavaScript, where attackers manipulate the prototype 
                  of base objects like Object, allowing them to inject properties that affect all object instances.
                </p>
                
                <CodeExample
                  language="javascript"
                  title="Prototype Pollution Vulnerability"
                  code={`// VULNERABLE: Unsafe deep merge function
function deepMerge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Attacker payload
const malicious = JSON.parse('{"__proto__": {"isAdmin": true}}');
const userConfig = {};

// Merging pollutes Object.prototype
deepMerge(userConfig, malicious);

// Now ALL objects have isAdmin=true!
console.log({}.isAdmin); // true - security bypass!`}
                />
                
                <CodeExample
                  language="javascript"
                  title="Secure Implementation"
                  code={`// SECURE: Protected deep merge function
function safeDeepMerge(target, source) {
  for (const key in source) {
    // Skip __proto__ and constructor properties
    if (key === '__proto__' || key === 'constructor') continue;
    
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      safeDeepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Or use Object.create(null) to create objects without prototype
const safeObj = Object.create(null);`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Insecure Deserialization</h2>
                <p className="mb-4">
                  Insecure deserialization occurs when untrusted data is used to abuse the logic of an application,
                  inflict a denial of service (DoS), or execute arbitrary code upon being deserialized.
                </p>
                
                <CodeExample
                  language="javascript"
                  title="Insecure Deserialization Example"
                  code={`// VULNERABLE: Using eval for JSON parsing (older code)
function parseUserData(userDataString) {
  // NEVER do this - allows arbitrary code execution
  return eval('(' + userDataString + ')');
}

// VULNERABLE: Deserializing untrusted data with node-serialize
const serialize = require('node-serialize');
const userObj = serialize.unserialize(untrustedDataFromUser);

// Attacker could send:
// {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('malicious command')}()"}
// Which would execute arbitrary code during deserialization`}
                />
                
                <CodeExample
                  language="javascript"
                  title="Secure Deserialization"
                  code={`// SECURE: Using JSON.parse instead of eval
function parseUserDataSecure(userDataString) {
  try {
    return JSON.parse(userDataString);
  } catch (e) {
    // Handle parsing errors gracefully
    console.error('Invalid JSON:', e);
    return null;
  }
}

// SECURE: Validate data after deserialization
function processUserConfig(configString) {
  let config;
  try {
    config = JSON.parse(configString);
  } catch (e) {
    return null;
  }
  
  // Validate the structure matches expected schema
  const validConfig = validateConfigSchema(config);
  if (!validConfig) {
    return null;
  }
  
  return config;
}`}
                />
              </section>
            </div>
            
            <div className="lg:col-span-1">
              <div className="sticky top-24">
                <div className="card">
                  <h3 className="text-xl font-bold mb-4">Common JavaScript Vulnerabilities</h3>
                  <ul className="space-y-2 pl-4 text-cybr-foreground/80">
                    <li>Cross-Site Scripting (XSS)</li>
                    <li>Prototype Pollution</li>
                    <li>Insecure Deserialization</li>
                    <li>Cross-Site Request Forgery (CSRF)</li>
                    <li>Insecure Dependencies</li>
                    <li>DOM-based Vulnerabilities</li>
                    <li>Client-Side Storage Exposure</li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Security Tools for JavaScript</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://eslint.org/docs/rules/no-eval" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">ESLint Security Rules</a></li>
                    <li><a href="https://github.com/nodesecurity/eslint-plugin-security" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">eslint-plugin-security</a></li>
                    <li><a href="https://snyk.io/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Snyk Dependency Scanner</a></li>
                    <li><a href="https://github.com/cure53/DOMPurify" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">DOMPurify</a></li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Related JavaScript Frameworks</h3>
                  <div className="space-y-3">
                    <Link to="/languages/nodejs" className="block text-cybr-primary hover:underline">Node.js Security</Link>
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

export default JavaScript;
