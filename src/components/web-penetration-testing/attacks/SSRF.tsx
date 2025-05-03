
import React from 'react';
import { ShieldAlert } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const SSRF: React.FC = () => {
  return (
    <section id="ssrf" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Server-Side Request Forgery (SSRF)</h3>
      <p className="mb-6">
        SSRF attacks occur when an attacker can make a server perform requests to internal resources or external systems
        that would normally be inaccessible. This vulnerability can lead to unauthorized access to internal services,
        data exfiltration, port scanning, and in some cases, remote code execution.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Example Attack</h4>
      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable Implementation" 
        code={`// Server-side code that makes requests to user-specified URLs
app.get('/fetch-data', (req, res) => {
  const url = req.query.url;
  
  // Vulnerable: No validation of URL parameter
  fetch(url)
    .then(response => response.json())
    .then(data => {
      res.json(data);
    })
    .catch(error => {
      res.status(500).json({ error: error.message });
    });
});

// Attacker input: http://localhost:8080/admin
// This makes the server access internal admin interface`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure Implementation" 
        code={`// Using URL validation and allowlisting
const { URL } = require('url');
const isAllowedHost = require('./security/host-validator');

app.get('/fetch-data', (req, res) => {
  try {
    // Parse the URL to validate it
    const urlObj = new URL(req.query.url);
    
    // Check against allowlist of domains
    if (!isAllowedHost(urlObj.hostname)) {
      return res.status(403).json({ 
        error: 'Access to this domain is not allowed' 
      });
    }
    
    // Prevent access to internal resources
    if (urlObj.hostname === 'localhost' || 
        urlObj.hostname === '127.0.0.1' ||
        urlObj.hostname.startsWith('192.168.') ||
        urlObj.hostname.startsWith('10.')) {
      return res.status(403).json({ 
        error: 'Access to internal resources is not allowed' 
      });
    }
    
    // Safe to proceed with the request
    fetch(req.query.url)
      .then(response => response.json())
      .then(data => res.json(data))
      .catch(error => res.status(500).json({ error: error.message }));
  } catch (error) {
    res.status(400).json({ error: 'Invalid URL' });
  }
});`} 
      />
    </section>
  );
};

export default SSRF;
