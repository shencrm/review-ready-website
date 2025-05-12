
import { Challenge } from './challenge-types';

export const commandInjectionChallenges: Challenge[] = [
  {
    id: 'command-injection-1',
    title: 'Command Injection in PHP',
    description: 'Compare these two PHP functions that execute a ping command. Which implementation is secure against command injection?',
    difficulty: 'medium',
    category: 'Injection Flaws',
    languages: ['PHP'],
    type: 'comparison',
    vulnerabilityType: 'Command Injection',
    secureCode: `<?php
function pingHost($host) {
    // Validate input: only allow hostnames/IPs with standard characters
    if (!preg_match('/^[a-zA-Z0-9.-]+$/', $host)) {
        return "Invalid hostname format";
    }
    
    // Use escapeshellarg to properly escape the argument
    $escapedHost = escapeshellarg($host);
    
    // Execute the command with proper escaping
    $output = [];
    $returnVar = 0;
    exec("ping -c 4 " . $escapedHost, $output, $returnVar);
    
    return implode("\\n", $output);
}

// Usage
$host = $_POST['host'] ?? '';
echo pingHost($host);
?>`,
    vulnerableCode: `<?php
function pingHost($host) {
    // Directly use the input in the command
    $command = "ping -c 4 " . $host;
    
    // Execute the command without validation or escaping
    $output = shell_exec($command);
    
    return $output;
}

// Usage
$host = $_POST['host'] ?? '';
echo pingHost($host);
?>`,
    answer: 'secure',
    explanation: "The secure version prevents command injection by: 1) Validating the input using a regular expression to ensure it only contains safe characters, and 2) Using escapeshellarg() to properly escape the user input before including it in the command. The vulnerable version directly concatenates user input into the command string without any validation or escaping, allowing attackers to inject additional commands using operators like ';', '&&', or '|'."
  }
];
