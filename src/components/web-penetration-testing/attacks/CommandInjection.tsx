
import React from 'react';
import { Code } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const CommandInjection: React.FC = () => {
  return (
    <section id="cmd-injection" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Command Injection</h3>
      <p className="mb-6">
        Command injection occurs when an application passes unsafe user-supplied data to a system shell. 
        Attackers can inject operating system commands to execute arbitrary code on the host server,
        potentially leading to complete system compromise, data theft, or service disruption.
        This vulnerability is especially severe as it often provides attackers with the same privileges
        as the application running the command.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">How Command Injection Works</h4>
      <p className="mb-4">
        Command injection attacks exploit applications that construct system commands using unsanitized user input.
        Attackers can append additional commands using shell operators like <code>;</code> (semicolon), <code>&&</code> (AND), <code>||</code> (OR), 
        <code>|</code> (pipe), or backticks/command substitution.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Common Attack Vectors</h4>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li>Input fields that interact with the filesystem (file upload, download)</li>
        <li>Network utilities (ping, traceroute, DNS lookup)</li>
        <li>System diagnostic utilities</li>
        <li>Features that generate reports or process documents</li>
        <li>Administrative interfaces that manage system resources</li>
      </ul>
      
      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable Implementation" 
        code={`// Node.js example with command injection vulnerability
const { exec } = require('child_process');

app.get('/ping', (req, res) => {
  const host = req.query.host;
  // Vulnerable: user input directly concatenated into command
  exec('ping -c 4 ' + host, (error, stdout, stderr) => {
    res.send(stdout);
  });
});

// Attacker input: 8.8.8.8; cat /etc/passwd
// This will ping 8.8.8.8 and then output the passwd file

// PHP example with command injection
<?php
$target = $_GET['ip'];
system("ping -c 4 " . $target);
?>

// Python example with command injection
import subprocess
ip = request.args.get('ip')
output = subprocess.check_output('ping -c 4 ' + ip, shell=True)
return output`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure Implementation" 
        code={`// Using a safer method with parameter validation
const { execFile } = require('child_process');
const validator = require('validator');

app.get('/ping', (req, res) => {
  const host = req.query.host;
  
  // Validate input is a valid IP address or hostname
  if (!validator.isIP(host) && !validator.isFQDN(host)) {
    return res.status(400).send('Invalid host format');
  }
  
  // execFile doesn't invoke a shell and treats arguments separately
  execFile('ping', ['-c', '4', host], (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send('Error executing ping');
    }
    res.send(stdout);
  });
});

// More secure Python implementation using subprocess.run
import subprocess
import re
import ipaddress

def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile(r"(?!-)[A-Z\\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def ping_host(request):
    host = request.args.get('ip')
    
    if not (is_valid_ip(host) or is_valid_hostname(host)):
        return "Invalid host format", 400
        
    try:
        # Use subprocess.run with shell=False and args as list
        result = subprocess.run(
            ['ping', '-c', '4', host],
            capture_output=True,
            text=True,
            timeout=10,
            shell=False
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Command timed out", 500
    except Exception as e:
        return f"Error: {str(e)}", 500`} 
      />
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Additional Security Controls</h4>
      <ul className="list-disc pl-6 space-y-2">
        <li><strong>Avoid System Commands:</strong> Use language-specific libraries instead of executing system commands</li>
        <li><strong>Input Validation:</strong> Strictly validate and sanitize all user-supplied data using allowlists</li>
        <li><strong>Parameter Separation:</strong> Use APIs that accept command and arguments separately</li>
        <li><strong>Principle of Least Privilege:</strong> Run applications with minimal system permissions</li>
        <li><strong>Command Allowlisting:</strong> Only allow specific pre-approved commands to be executed</li>
        <li><strong>Security Headers:</strong> Implement Content-Security-Policy to help mitigate the impact of successful attacks</li>
        <li><strong>Runtime Application Self-Protection (RASP):</strong> Implement technologies that can detect and block command injection attempts</li>
      </ul>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Testing for Command Injection</h4>
      <p className="mb-4">
        To test for command injection vulnerabilities, security testers typically try:
      </p>
      <ul className="list-disc pl-6 space-y-2">
        <li>Injecting command separators (<code>;</code>, <code>&&</code>, <code>||</code>)</li>
        <li>Using output redirection characters (<code>{`>`}</code>, <code>{`>>`}</code>)</li>
        <li>Command substitution with backticks (``) or <code>$()</code> syntax</li>
        <li>Semi-blind testing with time delays (e.g., <code>ping -c 10 127.0.0.1</code>)</li>
        <li>Out-of-band techniques to detect successful injections that don't produce visible output</li>
      </ul>
    </section>
  );
};

export default CommandInjection;
