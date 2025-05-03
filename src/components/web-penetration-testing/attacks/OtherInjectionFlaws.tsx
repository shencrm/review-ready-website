
import React from 'react';
import { Code } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const OtherInjectionFlaws: React.FC = () => {
  return (
    <section id="other-injection" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Other Injection Flaws</h3>
      <p className="mb-6">
        Beyond SQL injection, command injection, and XSS, there are various other injection vulnerabilities that can affect
        web applications. These occur when untrusted data is processed without proper validation or sanitization,
        allowing attackers to inject malicious content or commands into different interpreters.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Types of Injection Flaws</h4>
      
      {/* LDAP Injection */}
      <h5 className="text-lg font-semibold mt-4 mb-2">LDAP Injection</h5>
      <p className="mb-3">
        LDAP injection occurs when user input is incorrectly filtered or sanitized before being used in LDAP queries,
        potentially allowing attackers to view, modify, or bypass authentication mechanisms.
      </p>
      <CodeExample 
        language="java" 
        isVulnerable={true}
        title="Vulnerable LDAP Query" 
        code={`// Java LDAP query with injection vulnerability
String username = request.getParameter("username");
// No sanitization of input
String ldapQuery = "(uid=" + username + ")";

// Attacker input: *)(|(password=*
// Resulting query: (uid=*)(|(password=*)) 
// This could return all users`} 
      />
      <CodeExample 
        language="java" 
        isVulnerable={false}
        title="Secure LDAP Implementation" 
        code={`// Java secure LDAP query
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchResult;

// Escape special characters in input
String username = request.getParameter("username");
// Properly escape special LDAP characters
username = LdapEncoder.filterEncode(username);

// Use a parameterized LDAP search
String[] attrIDs = {"cn", "mail"};
SearchControls searchCtls = new SearchControls();
searchCtls.setReturningAttributes(attrIDs);
searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

// Safe search with escaped values
NamingEnumeration<SearchResult> answer = 
    ctx.search("ou=users,dc=example,dc=com", 
               "(&(objectClass=user)(uid={0}))", 
               new Object[]{username}, 
               searchCtls);`} 
      />
      
      {/* NoSQL Injection */}
      <h5 className="text-lg font-semibold mt-6 mb-2">NoSQL Injection</h5>
      <p className="mb-3">
        NoSQL injection allows attackers to manipulate NoSQL database queries by injecting malicious input,
        potentially bypassing authentication or accessing unauthorized data.
      </p>
      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable MongoDB Query" 
        code={`// Node.js with MongoDB - vulnerable query
app.post('/login', async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  
  // Vulnerable: Direct string concatenation or object injection
  const query = { username: username, password: password };
  const user = await db.collection('users').findOne(query);
  
  if (user) {
    // Login successful
    res.json({ success: true });
  } else {
    res.status(401).json({ success: false });
  }
});

/* 
  Attacker payload (JSON):
  {
    "username": "admin",
    "password": { "$ne": null }
  }
  
  This creates a query: { username: "admin", password: { $ne: null } }
  Which returns any user with username "admin" and a password that is not null
*/`} 
      />
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure NoSQL Query" 
        code={`// Node.js with MongoDB - secure implementation
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');

// Validate input before processing
app.post('/login', [
  // Input validation
  body('username').isString().trim().escape(),
  body('password').isString()
], async (req, res) => {
  // Check for validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  try {
    const username = req.body.username;
    const password = req.body.password;
    
    // Retrieve user with just the username
    const user = await db.collection('users').findOne({ username: username });
    
    if (!user) {
      // Same response for security (timing attacks)
      return res.status(401).json({ success: false });
    }
    
    // Verify password with bcrypt
    const match = await bcrypt.compare(password, user.hashedPassword);
    
    if (match) {
      // Login successful
      return res.json({ success: true });
    } else {
      return res.status(401).json({ success: false });
    }
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});`} 
      />
      
      {/* Template Injection */}
      <h5 className="text-lg font-semibold mt-6 mb-2">Server-Side Template Injection (SSTI)</h5>
      <p className="mb-3">
        SSTI occurs when user-supplied data is embedded into a template and then executed on the server,
        potentially allowing remote code execution.
      </p>
      <CodeExample 
        language="python" 
        isVulnerable={true}
        title="Vulnerable Template Engine Usage" 
        code={`# Python Flask application with Jinja2 template injection
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    
    # Vulnerable: Directly inserting user input into template
    template = '''
    <h1>Hello, ''' + name + '''!</h1>
    <p>Welcome to our website.</p>
    '''
    
    # This renders and executes the template with user input
    return render_template_string(template)

# Attacker input: {{7*7}} will render 49
# More dangerous: {{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
# This would execute the 'ls' command on the server`} 
      />
      <CodeExample 
        language="python" 
        isVulnerable={false}
        title="Secure Template Usage" 
        code={`# Python Flask application with secure template handling
from flask import Flask, request, render_template
import re

app = Flask(__name__)

@app.route('/greet')
def greet():
    # Get user input
    name = request.args.get('name', '')
    
    # Option 1: Validate input against a strict pattern
    if not re.match(r'^[a-zA-Z0-9 ]+$', name):
        name = "Friend" # Default safe value
    
    # Option 2: Never include user input in the template itself
    # Instead, pass it as a parameter to a predefined template
    return render_template('greet.html', name=name)

# In greet.html:
# <h1>Hello, {{ name|escape }}!</h1>
# <p>Welcome to our website.</p>

# Additional security measures:
# 1. Use a template sandbox (Jinja2 has a SandboxedEnvironment)
# 2. Apply output encoding (most template engines have built-in autoescaping)
# 3. Use a content security policy
# 4. Minimize template privileges`} 
      />
      
      {/* XPATH Injection */}
      <h5 className="text-lg font-semibold mt-6 mb-2">XPath Injection</h5>
      <p className="mb-3">
        XPath injection occurs when user input is used to construct XPath queries to navigate XML documents,
        potentially allowing attackers to access unauthorized data or bypass authentication.
      </p>
      <CodeExample 
        language="java" 
        isVulnerable={true}
        title="Vulnerable XPath Query" 
        code={`// Java XPath injection vulnerability
String username = request.getParameter("username");
String password = request.getParameter("password");

// Vulnerable: Direct string concatenation in XPath
String xpathQuery = "//user[username='" + username + "' and password='" + password + "']";
XPathExpression expr = xpath.compile(xpathQuery);
Object result = expr.evaluate(doc, XPathConstants.NODESET);

// Attacker input for username: ' or '1'='1
// Resulting query: //user[username='' or '1'='1' and password='anything']
// This could bypass authentication by making the condition always true`} 
      />
      <CodeExample 
        language="java" 
        isVulnerable={false}
        title="Secure XPath Implementation" 
        code={`// Java secure XPath querying
import javax.xml.xpath.*;

// Sanitize input function
public static String sanitizeXPathInput(String input) {
    if (input == null) {
        return null;
    }
    
    // Remove characters that could be used in XPath injection
    return input.replaceAll("['\";()]", "");
}

// Processing login
String username = sanitizeXPathInput(request.getParameter("username"));
String password = sanitizeXPathInput(request.getParameter("password"));

// Better approach: Use XPath variables instead of string concatenation
XPathFactory factory = XPathFactory.newInstance();
XPath xpath = factory.newXPath();

// Prepare the XPath expression with placeholders
XPathExpression expr = xpath.compile("//user[username=$user and password=$pwd]");

// Create a simple variable resolver
SimpleVariableResolver resolver = new SimpleVariableResolver();
resolver.addVariable("user", username);
resolver.addVariable("pwd", password);

// Set the variable resolver
xpath.setXPathVariableResolver(resolver);

// Evaluate with variables properly resolved
NodeList result = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);

// Custom variable resolver class
class SimpleVariableResolver implements XPathVariableResolver {
    private Map<QName, Object> variables = new HashMap<QName, Object>();
    
    public void addVariable(String name, Object value) {
        variables.put(new QName(null, name), value);
    }
    
    @Override
    public Object resolveVariable(QName variableName) {
        return variables.get(variableName);
    }
}`} 
      />
    </section>
  );
};

export default OtherInjectionFlaws;
