
import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Link } from 'react-router-dom';
import { AlertCircle, ShieldAlert, Terminal, FileCode, Bug, Code, FileWarning, Lock, KeyRound } from 'lucide-react';

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
              Security vulnerabilities and best practices for JavaScript applications.
            </p>
          </div>
          
          <div className="card mb-8">
            <h2 className="text-2xl font-bold mb-4">About JavaScript</h2>
            <p className="mb-4">
              JavaScript is a high-level, interpreted programming language that conforms to the ECMAScript specification. 
              Originally designed as a scripting language for web browsers to add dynamic functionality to web pages, 
              JavaScript has evolved to become one of the world's most widely used programming languages.
            </p>
            <p className="mb-4">
              As a multi-paradigm language, JavaScript supports event-driven, functional, and imperative programming styles. 
              It has API functions for working with text, arrays, dates, regular expressions, and the DOM (Document Object Model),
              but does not include any I/O functionality like networking, storage, or graphics facilities.
            </p>
            <p className="mb-4">
              In recent years, with the advent of Node.js, JavaScript has expanded beyond client-side scripting to 
              become a full-stack development language, allowing developers to build entire applications using JavaScript 
              for both front-end and back-end systems. This has led to an explosion in JavaScript frameworks and libraries
              like React, Angular, and Vue for front-end development, and Express.js for back-end services.
            </p>
            <p>
              However, JavaScript's flexibility and widespread use also make it a common target for security vulnerabilities. 
              Its client-side execution model, dynamic typing, and extensive ecosystem of third-party dependencies all 
              contribute to potential security risks that developers must understand and mitigate.
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
                
                <SecurityCard
                  title="Cross-Site Scripting (XSS)"
                  description="XSS attacks occur when untrusted data is included in a web page without proper validation or encoding, allowing attackers to execute malicious scripts in users' browsers."
                  icon={<Bug className="w-6 h-6" />}
                  severity="high"
                />
                
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
                  isVulnerable={true}
                />
                
                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>This vulnerable code takes a username parameter and directly inserts it into the page's HTML using <code>innerHTML</code>. If an attacker provides a username containing JavaScript code enclosed in <code>&lt;script&gt;</code> tags or other HTML with embedded scripts (like <code>onerror</code> handlers), that code will execute in the browser context of any user viewing the page. This allows the attacker to steal cookies, session tokens, or perform actions on behalf of the victim.</p>
                </div>
                
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
                  isVulnerable={false}
                />

                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>The secure version provides two safe alternatives. The first approach uses <code>textContent</code> instead of <code>innerHTML</code>, which treats the input as plain text and doesn't parse HTML, ensuring that any malicious markup is displayed rather than executed. The second approach uses the DOMPurify library to sanitize HTML content, removing any potentially dangerous elements or attributes while preserving safe HTML formatting. This allows for rich text while preventing script execution.</p>
                </div>
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Prototype Pollution</h2>
                <p className="mb-4">
                  Prototype pollution is a vulnerability specific to JavaScript, where attackers manipulate the prototype 
                  of base objects like Object, allowing them to inject properties that affect all object instances.
                </p>
                
                <SecurityCard
                  title="Prototype Pollution"
                  description="Prototype pollution allows attackers to modify JavaScript object prototypes, potentially affecting the behavior of the entire application and bypassing security checks."
                  icon={<Code className="w-6 h-6" />}
                  severity="high"
                />
                
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
                  isVulnerable={true}
                />
                
                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>This vulnerability occurs in the <code>deepMerge</code> function that recursively merges properties from a source object into a target object. The function doesn't check for special property names like <code>__proto__</code>. An attacker can exploit this by providing a malicious object with a <code>__proto__</code> property, which will modify the prototype of the target object and, by extension, all objects in the application that share that prototype. In this example, after merging the malicious payload, <em>every</em> JavaScript object in the application would have <code>isAdmin=true</code>, potentially bypassing authorization checks.</p>
                </div>
                
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
                  isVulnerable={false}
                />

                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>The secure implementation adds a simple check to skip the processing of special property names like <code>__proto__</code> and <code>constructor</code>. This prevents attackers from modifying object prototypes through the merge function. An alternative approach is to use <code>Object.create(null)</code> to create objects without a prototype chain, which makes them immune to prototype pollution attacks because they don't inherit from <code>Object.prototype</code>.</p>
                </div>
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Insecure Deserialization</h2>
                <p className="mb-4">
                  Insecure deserialization occurs when untrusted data is used to abuse the logic of an application,
                  inflict a denial of service (DoS), or execute arbitrary code upon being deserialized.
                </p>
                
                <SecurityCard
                  title="Insecure Deserialization"
                  description="Unsafe deserialization of untrusted data can lead to remote code execution, allowing attackers to run arbitrary code on your server or client."
                  icon={<FileWarning className="w-6 h-6" />}
                  severity="high"
                />
                
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
                  isVulnerable={true}
                />
                
                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>This code shows two dangerous deserialization vulnerabilities. The first uses <code>eval()</code> to parse JSON, which is extremely dangerous as it executes any JavaScript code in the input string. The second example uses the <code>node-serialize</code> library, which has a known vulnerability: it can deserialize and execute functions if they're marked with a special prefix (<code>_$$ND_FUNC$$_</code>). An attacker can craft a payload that executes arbitrary code when deserialized, potentially gaining complete control of the server.</p>
                </div>
                
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
                  isVulnerable={false}
                />

                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>The secure code uses <code>JSON.parse()</code> instead of <code>eval()</code> to safely parse JSON data. Unlike <code>eval()</code>, <code>JSON.parse()</code> only processes valid JSON and doesn't execute code. The second example adds schema validation after parsing to ensure the deserialized object has the expected structure and properties, providing an additional layer of security against malformed or malicious input.</p>
                </div>
              </section>

              <section>
                <h2 className="text-2xl font-bold mb-4">Client-Side Storage Exposure</h2>
                <p className="mb-4">
                  Storing sensitive information in client-side storage mechanisms like localStorage or sessionStorage can expose it to XSS attacks.
                </p>
                
                <SecurityCard
                  title="Insecure Client-Side Storage"
                  description="Storing sensitive data like authentication tokens or personal information in client-side storage can expose it to theft through XSS attacks."
                  icon={<Lock className="w-6 h-6" />}
                  severity="medium"
                />
                
                <CodeExample
                  language="javascript"
                  title="Insecure Client-Side Storage"
                  code={`// VULNERABLE: Storing sensitive information in localStorage
function loginUser(username, password) {
  fetch('/api/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
    headers: { 'Content-Type': 'application/json' }
  })
  .then(response => response.json())
  .then(data => {
    // INSECURE: Storing sensitive data in localStorage
    localStorage.setItem('token', data.token);
    localStorage.setItem('userRole', data.role);
    localStorage.setItem('userId', data.userId);
    localStorage.setItem('creditCard', data.paymentInfo.cardNumber);
    
    redirectToApp();
  });
}

// If an XSS vulnerability exists, an attacker can access all this data:
// const stolenData = {
//   token: localStorage.getItem('token'),
//   userRole: localStorage.getItem('userRole'),
//   userId: localStorage.getItem('userId'),
//   creditCard: localStorage.getItem('creditCard')
// };
// sendToAttackerServer(stolenData);`}
                  isVulnerable={true}
                />
                
                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>This vulnerable code stores sensitive information including authentication tokens and even credit card numbers in localStorage. The problem is that localStorage is accessible to any JavaScript running on the same domain. If an attacker can execute JavaScript through an XSS vulnerability, they can easily extract all this sensitive information. Additionally, localStorage persists even after the browser is closed, extending the window of vulnerability.</p>
                </div>
                
                <CodeExample
                  language="javascript"
                  title="Secure Storage Practices"
                  code={`// SECURE: Proper handling of sensitive information
function loginUserSecurely(username, password) {
  fetch('/api/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
    headers: { 'Content-Type': 'application/json' }
  })
  .then(response => response.json())
  .then(data => {
    // Store auth token in HttpOnly cookie (set by server, not accessible via JS)
    // The API response doesn't include the token as it's set as an HttpOnly cookie
    
    // Store non-sensitive UI state in localStorage
    localStorage.setItem('userName', data.displayName);
    localStorage.setItem('uiPreferences', JSON.stringify(data.preferences));
    
    // Store session-specific data in sessionStorage (cleared when tab closes)
    sessionStorage.setItem('lastAction', 'login');
    
    // Keep sensitive data in memory only (lost on page refresh)
    const userSession = {
      userId: data.userId,
      role: data.role
    };
    
    // Initialize app with in-memory data
    initializeApp(userSession);
  });
}

// Server-side implementation sets secure cookies
// res.cookie('authToken', token, {
//   httpOnly: true, // Not accessible via JavaScript
//   secure: true,   // Only sent over HTTPS
//   sameSite: 'strict', // Prevents CSRF
//   maxAge: 3600000 // 1 hour expiry
// });`}
                  isVulnerable={false}
                />

                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>The secure implementation follows several best practices: (1) Authentication tokens are stored in HttpOnly cookies set by the server, making them inaccessible to JavaScript and therefore protected from XSS attacks. (2) Sensitive data is kept in memory variables that aren't persisted and are lost when the page refreshes. (3) SessionStorage is used for temporary data that should be cleared when the browser tab closes. (4) Only non-sensitive data like UI preferences are stored in localStorage. This approach implements defense-in-depth by using the appropriate storage mechanism for each type of data based on its sensitivity.</p>
                </div>
              </section>

              <section>
                <h2 className="text-2xl font-bold mb-4">Weak Cryptography and Random Values</h2>
                <p className="mb-4">
                  JavaScript implementations often use cryptographically weak random number generation or outdated cryptographic methods.
                </p>
                
                <SecurityCard
                  title="Weak Cryptographic Practices"
                  description="Using insufficient cryptographic methods in JavaScript can lead to predictable values and compromised security measures."
                  icon={<KeyRound className="w-6 h-6" />}
                  severity="medium"
                />
                
                <CodeExample
                  language="javascript"
                  title="Insecure Random Value Generation"
                  code={`// VULNERABLE: Using Math.random() for security purposes
function generateAuthToken() {
  // INSECURE: Math.random() is not cryptographically strong
  return Math.random().toString(36).substring(2, 15);
}

// VULNERABLE: Creating weak user IDs
function createUserAccount(userData) {
  const userId = Date.now() + Math.floor(Math.random() * 1000);
  // Store predictable, sequential user IDs
  return saveUser({ ...userData, id: userId });
}

// VULNERABLE: Weak password reset token
function generatePasswordResetToken() {
  // Creates predictable token based on timestamp
  const timestamp = new Date().getTime();
  return 'reset_' + (timestamp * 2 - 100000).toString(16);
}`}
                  isVulnerable={true}
                />
                
                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>This vulnerable code uses <code>Math.random()</code> and predictable timestamps for security-sensitive operations. <code>Math.random()</code> is not cryptographically secure and can be predicted given enough samples. Using predictable values for authentication tokens or password reset tokens makes them susceptible to brute force or prediction attacks. The user ID generation creates IDs that are largely sequential and easily guessable, potentially allowing attackers to enumerate user accounts.</p>
                </div>
                
                <CodeExample
                  language="javascript"
                  title="Secure Cryptographic Implementations"
                  code={`// SECURE: Using cryptographically strong random values
function generateAuthTokenSecure() {
  // Create a buffer with cryptographically strong random values
  const buffer = new Uint8Array(32);
  crypto.getRandomValues(buffer);
  
  // Convert to URL-safe base64 string
  return btoa(String.fromCharCode.apply(null, buffer))
    .replace(/\\+/g, '-')
    .replace(/\\//g, '_')
    .replace(/=/g, '');
}

// SECURE: Creating strong user IDs with UUID
function createUserAccountSecure(userData) {
  // Generate a UUID (requires a UUID library or the crypto.randomUUID() in newer browsers)
  const userId = crypto.randomUUID ? crypto.randomUUID() : generateUUID();
  
  return saveUser({ ...userData, id: userId });
}

// Helper function for older browsers
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = crypto.getRandomValues(new Uint8Array(1))[0] % 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// SECURE: Strong password reset token with expiry
function generateSecureResetToken(userId) {
  // Create random bytes
  const buffer = new Uint8Array(32);
  crypto.getRandomValues(buffer);
  
  // Convert to hex string
  const token = Array.from(buffer)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
  
  // Store token with expiry and user association
  const expiresAt = new Date();
  expiresAt.setHours(expiresAt.getHours() + 1); // 1 hour expiry
  
  storeResetToken({
    userId,
    token,
    expiresAt
  });
  
  return token;
}`}
                  isVulnerable={false}
                />

                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>The secure implementation uses <code>crypto.getRandomValues()</code> to generate cryptographically strong random values, which are much harder to predict than <code>Math.random()</code>. For user IDs, it uses UUIDs (either via the modern <code>crypto.randomUUID()</code> API or a secure fallback implementation) to create globally unique, non-sequential identifiers. The password reset token function generates a secure random token, associates it with a specific user, and adds a short expiration time to limit the window of vulnerability. These approaches dramatically reduce the risk of token prediction or brute-forcing attacks.</p>
                </div>
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
                    <li>Weak Cryptography</li>
                    <li>Cross-Window Messaging</li>
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
