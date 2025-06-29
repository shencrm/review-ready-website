
import React from 'react';
import { FileText } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const SSTInjection: React.FC = () => {
  return (
    <div className="mb-12">
      <h4 className="text-xl font-semibold mb-6 flex items-center gap-2">
        <FileText className="h-6 w-6 text-cybr-primary" />
        Server-Side Template Injection (SSTI)
      </h4>
      
      <div className="mb-6">
        <h5 className="text-lg font-semibold mb-3">What is Server-Side Template Injection?</h5>
        <p className="mb-4">
          Server-Side Template Injection (SSTI) occurs when user-supplied data is embedded into a template and then 
          executed on the server. This vulnerability can lead to remote code execution, allowing attackers to execute 
          arbitrary commands on the server hosting the application.
        </p>
        <p className="mb-4">
          SSTI exploits template engines like Jinja2, Twig, Freemarker, Velocity, and others. The vulnerability 
          arises when user input is directly incorporated into template code without proper sanitization, allowing 
          attackers to inject template directives that get executed server-side.
        </p>
      </div>

      <div className="mb-6">
        <h5 className="text-lg font-semibold mb-3">Attacker Goals</h5>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>Remote Code Execution:</strong> Execute arbitrary system commands on the server</li>
          <li><strong>File System Access:</strong> Read, write, or delete files on the server</li>
          <li><strong>Configuration Disclosure:</strong> Access application configuration and secrets</li>
          <li><strong>Database Access:</strong> Interact with databases through the application context</li>
          <li><strong>Privilege Escalation:</strong> Gain higher privileges within the application or system</li>
          <li><strong>Lateral Movement:</strong> Use server access to attack other systems on the network</li>
        </ul>
      </div>

      <div className="mb-6">
        <h5 className="text-lg font-semibold mb-3">Vulnerable Template Engines</h5>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>Jinja2 (Python):</strong> Flask, Django templates with user input</li>
          <li><strong>Twig (PHP):</strong> Symfony applications with dynamic templates</li>
          <li><strong>Freemarker (Java):</strong> Spring applications with template rendering</li>
          <li><strong>Velocity (Java):</strong> Web applications using Apache Velocity</li>
          <li><strong>Smarty (PHP):</strong> PHP applications with Smarty templating</li>
          <li><strong>Handlebars (Node.js):</strong> Express applications with dynamic templates</li>
        </ul>
      </div>

      <CodeExample 
        language="python" 
        isVulnerable={true}
        title="Vulnerable Flask Application with SSTI" 
        code={`# Python Flask application vulnerable to SSTI
from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

@app.route('/hello')
def hello():
    name = request.args.get('name', 'Guest')
    
    # Vulnerable: User input directly in template string
    template = f'''
    <html>
    <body>
        <h1>Hello {name}!</h1>
        <p>Welcome to our application.</p>
    </body>
    </html>
    '''
    
    # This renders and executes the template with user input
    return render_template_string(template)

'''
ATTACK PAYLOADS for Jinja2:

1. Basic Code Execution:
   /hello?name={{7*7}}
   Result: Hello 49! (proves template execution)

2. Configuration Access:
   /hello?name={{config}}
   /hello?name={{config.items()}}
   Reveals Flask configuration including secret keys

3. File System Access:
   /hello?name={{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}
   Attempts to read system files

4. Command Execution:
   /hello?name={{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}
   Executes system commands
'''`} 
      />

      <CodeExample 
        language="python" 
        isVulnerable={false}
        title="Secure Template Implementation" 
        code={`# Secure Flask application with proper template handling
from flask import Flask, request, render_template, escape
from jinja2 import Environment, BaseLoader, select_autoescape, StrictUndefined
import re
from markupsafe import Markup

app = Flask(__name__)

# Configure Jinja2 for security
app.jinja_env.undefined = StrictUndefined
app.jinja_env.autoescape = select_autoescape(['html', 'xml'])

def validate_input(input_data, max_length=100):
    """Validate and sanitize user input"""
    if not input_data:
        return None
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[{}()<>\\[\\]$]', '', str(input_data))
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized.strip()

@app.route('/hello')
def hello():
    name = request.args.get('name', 'Guest')
    
    # 1. Validate and sanitize input
    clean_name = validate_input(name, max_length=50)
    if not clean_name:
        clean_name = 'Guest'
    
    # 2. Use predefined template file, not string construction
    return render_template('hello.html', name=clean_name)`} 
      />

      <div className="mb-6">
        <h5 className="text-lg font-semibold mb-3">Testing and Detection Methods</h5>
        <div className="space-y-4">
          <div>
            <h6 className="font-semibold mb-2">Manual Testing Approach</h6>
            <ol className="list-decimal pl-6 space-y-2">
              <li><strong>Template Expression Testing:</strong> Try basic expressions like {`{{7*7}}`} or ${`{7*7}`}</li>
              <li><strong>Template Syntax Detection:</strong> Test different template syntaxes to identify the engine</li>
              <li><strong>Error Message Analysis:</strong> Trigger template errors to reveal engine information</li>
              <li><strong>Configuration Access:</strong> Try to access application configuration through templates</li>
              <li><strong>File System Testing:</strong> Attempt to read files using template functionality</li>
            </ol>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SSTInjection;
