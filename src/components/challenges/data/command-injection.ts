
import { Challenge } from './challenge-types';

export const commandInjectionChallenges: Challenge[] = [
  {
    id: 'command-injection-1',
    title: 'Command Injection in Node.js',
    description: 'Review this Node.js code that executes system commands. Is it vulnerable to command injection?',
    difficulty: 'medium',
    category: 'Injection Flaws',
    languages: ['JavaScript', 'Node.js'],
    type: 'single',
    vulnerabilityType: 'Command Injection',
    code: `const express = require('express');
const { exec } = require('child_process');
const app = express();

app.use(express.json());

app.post('/api/ping', (req, res) => {
  const { host } = req.body;
  
  if (!host) {
    return res.status(400).json({ error: 'Host parameter is required' });
  }
  
  // Execute ping command
  const cmd = 'ping -c 4 ' + host;
  
  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: error.message });
    }
    
    res.json({ 
      success: true, 
      output: stdout 
    });
  });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});`,
    answer: false,
    explanation: "This code is vulnerable to command injection because it directly concatenates user input into a shell command without sanitization. An attacker could submit a host value like '127.0.0.1; rm -rf /' to execute arbitrary commands. To fix this, use input validation with a strict regex pattern for hostnames/IPs, or use libraries like 'validator' to validate IP addresses, and consider using safer alternatives like the 'ping' library or 'child_process.execFile' which doesn't invoke a shell."
  },
  {
    id: 'command-injection-2',
    title: 'Command Injection in PHP',
    description: 'Compare these two PHP functions that execute system commands. Which implementation is secure against command injection?',
    difficulty: 'easy',
    category: 'Injection Flaws',
    languages: ['PHP'],
    type: 'comparison',
    vulnerabilityType: 'Command Injection',
    secureCode: `<?php
/**
 * Ping a host securely
 * @param string $host The hostname or IP to ping
 * @return array Result of the ping command
 */
function pingHost($host) {
    // Validate input - only allow valid hostnames and IP addresses
    if (!filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) && 
        !filter_var($host, FILTER_VALIDATE_IP)) {
        throw new InvalidArgumentException("Invalid hostname or IP address");
    }
    
    // Use escapeshellarg to properly escape the argument
    $escapedHost = escapeshellarg($host);
    
    // Execute the command with escaped argument
    $command = "ping -c 4 {$escapedHost}";
    $output = [];
    $returnValue = 0;
    
    exec($command, $output, $returnValue);
    
    return [
        'success' => ($returnValue === 0),
        'output' => $output,
        'command' => $command
    ];
}`,
    vulnerableCode: `<?php
/**
 * Ping a host
 * @param string $host The hostname or IP to ping
 * @return array Result of the ping command
 */
function pingHost($host) {
    // Execute ping command
    $command = "ping -c 4 " . $host;
    $output = [];
    $returnValue = 0;
    
    exec($command, $output, $returnValue);
    
    return [
        'success' => ($returnValue === 0),
        'output' => $output,
        'command' => $command
    ];
}`,
    answer: 'secure',
    explanation: "The secure implementation validates input using PHP's filter_var() function to ensure the host is either a valid domain name or IP address, and uses escapeshellarg() to properly escape shell arguments. The vulnerable version directly concatenates the user input into the command string without any validation or escaping, which allows attackers to inject additional commands using shell metacharacters like ; or && to execute arbitrary code."
  }
];
