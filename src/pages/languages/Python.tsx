
import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CodeExample from '@/components/CodeExample';
import { Link } from 'react-router-dom';

const Python = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      
      <main className="flex-grow py-12">
        <div className="container mx-auto px-4">
          <div className="mb-12">
            <h1 className="text-4xl font-bold mb-6">Python Security</h1>
            <div className="h-1 w-24 bg-cybr-primary mb-6"></div>
            <p className="text-xl text-cybr-foreground/80">
              Understanding and preventing security vulnerabilities in Python applications.
            </p>
          </div>
          
          {/* New introduction paragraphs */}
          <div className="mb-10 prose prose-cybr max-w-none">
            <p className="text-lg">
              Python has emerged as one of the most popular programming languages, particularly in web development, data science, and automation. Its readability and extensive library ecosystem make it attractive for rapid development, but these same characteristics can sometimes lead to security oversights. Python applications, especially web frameworks like Django and Flask, are regularly targeted by attackers looking to exploit security weaknesses in code, dependencies, or configurations.
            </p>
            <p className="text-lg mt-4">
              Unlike compiled languages, Python's interpreted nature means that certain vulnerabilities might only become apparent at runtime. The language's dynamic typing and flexible nature, while convenient for developers, require extra vigilance regarding input validation and type checking. Python's standard library and third-party packages also introduce potential security concerns, especially when handling serialization/deserialization, network connections, or system commands. Understanding these security implications is essential for Python developers to build applications that are both functional and secure.
            </p>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 space-y-8">
              <section>
                <h2 className="text-2xl font-bold mb-4">Insecure Deserialization</h2>
                <p className="mb-4">
                  Python's pickle module is powerful but can lead to code execution if untrusted data is deserialized.
                </p>
                
                <CodeExample
                  language="python"
                  title="Insecure Deserialization with pickle"
                  code={`# VULNERABLE: Deserializing untrusted data with pickle
import pickle
import base64
from flask import Flask, request

app = Flask(__name__)

@app.route('/api/load_settings')
def load_settings():
    serialized_data = request.args.get('data')
    binary_data = base64.b64decode(serialized_data)
    
    # VULNERABLE: Untrusted data goes into pickle.loads
    settings = pickle.loads(binary_data)
    
    return {'settings': settings}

# Attacker can craft malicious pickle data that executes code
# Example payload (simplified):
# class EvilPickle:
#     def __reduce__(self):
#         import os
#         return (os.system, ('rm -rf /',))
#
# pickle.dumps(EvilPickle())`}
                />
                
                <CodeExample
                  language="python"
                  title="Secure Alternatives to pickle"
                  code={`# SECURE: Using JSON instead of pickle
import json
from flask import Flask, request

app = Flask(__name__)

@app.route('/api/load_settings')
def load_settings():
    serialized_data = request.args.get('data')
    
    # JSON is safer as it can't execute code during deserialization
    settings = json.loads(serialized_data)
    
    # Validate against a schema to ensure expected structure
    if not validate_settings_schema(settings):
        return {'error': 'Invalid settings format'}, 400
    
    return {'settings': settings}

# ALTERNATIVE: If you must use pickle, use a signing mechanism
import hmac
import pickle
import hashlib

SECRET_KEY = b'your-secret-key-not-in-git-repo'

def secure_pickle_loads(data, signature):
    calculated_sig = hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calculated_sig, signature):
        raise ValueError("Signature verification failed")
    return pickle.loads(data)`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">SQL Injection</h2>
                <p className="mb-4">
                  SQL injection in Python typically happens when string formatting or concatenation is used for queries.
                </p>
                
                <CodeExample
                  language="python"
                  title="SQL Injection Vulnerability"
                  code={`# VULNERABLE: String formatting in SQL queries
import sqlite3

def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: String formatting in SQL query
    query = "SELECT * FROM users WHERE username = '%s'" % username
    cursor.execute(query)
    
    result = cursor.fetchone()
    conn.close()
    return result

# Attacker input: ' OR '1'='1
# Results in: SELECT * FROM users WHERE username = '' OR '1'='1'
# Which returns all users`}
                />
                
                <CodeExample
                  language="python"
                  title="Secure SQL Query"
                  code={`# SECURE: Using parameterized queries
import sqlite3

def get_user_safely(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # SECURE: Using query parameters
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    
    result = cursor.fetchone()
    conn.close()
    return result

# ALTERNATIVE: Using an ORM like SQLAlchemy
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

def get_user_with_orm(username):
    engine = create_engine("sqlite:///users.db")
    with Session(engine) as session:
        # ORM automatically handles parameterization
        user = session.query(User).filter_by(username=username).first()
    return user`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Command Injection</h2>
                <p className="mb-4">
                  Python's os.system, subprocess module, and other command execution functions can be vulnerable.
                </p>
                
                <CodeExample
                  language="python"
                  title="Command Injection Vulnerability"
                  code={`# VULNERABLE: Unsanitized input in command execution
import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/ping')
def ping_endpoint():
    hostname = request.args.get('host', 'localhost')
    
    # VULNERABLE: Unsanitized input used in command
    command = f"ping -c 4 {hostname}"
    output = os.system(command)
    
    return f"Ping result: {output}"

# Attacker could input: localhost; rm -rf /  
# This would execute both commands`}
                />
                
                <CodeExample
                  language="python"
                  title="Secure Command Execution"
                  code={`# SECURE: Using subprocess with arguments as list
import subprocess
import re
from flask import Flask, request

app = Flask(__name__)

@app.route('/ping')
def ping_endpoint():
    hostname = request.args.get('host', 'localhost')
    
    # Input validation
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\\.\\-]{0,253}[a-zA-Z0-9]$', hostname):
        return "Invalid hostname", 400
    
    # SECURE: Using list of arguments (no shell involved)
    try:
        result = subprocess.run(
            ['ping', '-c', '4', hostname],
            capture_output=True,
            text=True,
            timeout=10,
            check=False  # Don't raise exception for non-zero exit
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Ping timed out", 500`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Open Redirect</h2>
                <p className="mb-4">
                  Open redirects can happen when user input is used directly in a redirect URL.
                </p>
                
                <CodeExample
                  language="python"
                  title="Open Redirect Vulnerability"
                  code={`# VULNERABLE: Unsanitized redirect URL
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/login')
def login():
    # Process login...
    
    # VULNERABLE: Using user-provided redirect without validation
    next_url = request.args.get('next', '/')
    return redirect(next_url)
    
# Attacker could provide: ?next=https://evil.com
# User would be redirected to attacker's site after login`}
                />
                
                <CodeExample
                  language="python"
                  title="Secure Redirect"
                  code={`# SECURE: Validating redirect URL
from flask import Flask, request, redirect
from urllib.parse import urlparse

app = Flask(__name__)

@app.route('/login')
def login():
    # Process login...
    
    # Get the URL to redirect to
    next_url = request.args.get('next', '/')
    
    # SECURE: Validate it's a relative URL or in allowed domains
    parsed = urlparse(next_url)
    
    # Check if it's a relative URL or in our allowed domains
    is_safe = (
        not parsed.netloc or 
        parsed.netloc == request.host or
        parsed.netloc in ['subdomain.mysite.com', 'othersite.com']
    )
    
    if is_safe:
        return redirect(next_url)
    else:
        return redirect('/')  # Default safe redirect`}
                />
              </section>
            </div>
            
            <div className="lg:col-span-1">
              <div className="sticky top-24">
                <div className="card">
                  <h3 className="text-xl font-bold mb-4">Python Security Vulnerabilities</h3>
                  <ul className="space-y-2 pl-4 text-cybr-foreground/80">
                    <li>Insecure Deserialization</li>
                    <li>SQL Injection</li>
                    <li>Command Injection</li>
                    <li>Open Redirect</li>
                    <li>Path Traversal</li>
                    <li>XML External Entity (XXE)</li>
                    <li>Template Injection</li>
                    <li>Insecure Cryptography</li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Python Security Tools</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://github.com/PyCQA/bandit" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Bandit</a></li>
                    <li><a href="https://github.com/pyupio/safety" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Safety</a></li>
                    <li><a href="https://github.com/dlint-py/dlint" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Dlint</a></li>
                    <li><a href="https://github.com/python-security/pyt" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Python Taint</a></li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Resources</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://owasp.org/www-community/attacks/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP Attack Categories</a></li>
                    <li><a href="https://cheatsheetseries.owasp.org/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP Cheat Sheets</a></li>
                    <li><a href="https://docs.python.org/3/library/security.html" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Python Security Considerations</a></li>
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

export default Python;
