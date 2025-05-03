
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
        potentially leading to complete system compromise.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Example Attack</h4>
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
// This will ping 8.8.8.8 and then output the passwd file`} 
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
});`} 
      />
    </section>
  );
};

export default CommandInjection;
