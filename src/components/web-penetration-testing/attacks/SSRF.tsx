
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
        data exfiltration, port scanning, and in some cases, remote code execution. SSRF is particularly dangerous in cloud environments,
        where metadata services can expose sensitive configuration and authentication data.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Types of SSRF Attacks</h4>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li><strong>Basic SSRF:</strong> Server makes requests to internal resources with results returned to the attacker</li>
        <li><strong>Blind SSRF:</strong> Server makes requests without returning results, requiring indirect detection methods</li>
        <li><strong>Semi-blind SSRF:</strong> Some limited information returns, such as success/failure or response time</li>
        <li><strong>SSRF via URL Scheme:</strong> Using non-HTTP URL schemes like file:// or gopher:// to access local resources</li>
        <li><strong>SSRF via Redirects:</strong> Using open redirects to bounce requests to internal targets</li>
      </ul>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Common SSRF Targets</h4>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li><strong>Cloud Metadata Services:</strong> AWS at 169.254.169.254, GCP at 169.254.169.254, Azure at 169.254.169.254</li>
        <li><strong>Internal Admin Interfaces:</strong> Often running on localhost or internal networks</li>
        <li><strong>Internal APIs:</strong> Services not intended for public access</li>
        <li><strong>Database Servers:</strong> Typically not exposed to the internet</li>
        <li><strong>Internal Network Scanning:</strong> Mapping internal network topology</li>
      </ul>
      
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

// Attacker input examples:
// 1. Access AWS metadata: http://169.254.169.254/latest/meta-data/iam/security-credentials/
// 2. Access internal admin interface: http://localhost:8080/admin
// 3. Port scan internal network: http://192.168.1.1:22
// 4. Access local file: file:///etc/passwd
// 5. Use gopher protocol for more complex attacks: gopher://127.0.0.1:25/

// PHP example with similar vulnerability
<?php
$url = $_GET['url'];
$content = file_get_contents($url);
echo $content;
?>

// Java vulnerable example
URL url = new URL(request.getParameter("url"));
URLConnection conn = url.openConnection();
BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
// ... read and return the response`} 
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
    
    // Only allow HTTP and HTTPS protocols
    if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
      return res.status(403).json({ 
        error: 'Only HTTP and HTTPS protocols are allowed' 
      });
    }
    
    // Check against allowlist of domains
    if (!isAllowedHost(urlObj.hostname)) {
      return res.status(403).json({ 
        error: 'Access to this domain is not allowed' 
      });
    }
    
    // Prevent access to internal resources
    const blockedIPs = [
      '127.0.0.1', 'localhost', '0.0.0.0',
      '::1', // IPv6 localhost
      '169.254.169.254', // Cloud metadata IP
    ];
    
    const blockedCIDRs = [
      '10.0.0.0/8',
      '172.16.0.0/12', 
      '192.168.0.0/16'
    ];
    
    if (blockedIPs.includes(urlObj.hostname) || 
        isInBlockedCIDR(urlObj.hostname, blockedCIDRs)) {
      return res.status(403).json({ 
        error: 'Access to internal resources is not allowed' 
      });
    }
    
    // Safe to proceed with the request
    fetch(req.query.url, {
      // Set a timeout to prevent hanging connections
      timeout: 5000
    })
      .then(response => response.json())
      .then(data => res.json(data))
      .catch(error => res.status(500).json({ error: 'Failed to fetch data' }));
  } catch (error) {
    res.status(400).json({ error: 'Invalid URL' });
  }
});

// More comprehensive protection
function createSecureAPIClient() {
  // Create a custom agent with restricted socket connections
  const agent = new http.Agent({
    // Disable direct access to IP ranges
    lookup: (hostname, options, callback) => {
      dns.lookup(hostname, (err, address, family) => {
        if (err) {
          return callback(err);
        }
        
        // Check if IP is in private ranges
        if (isPrivateIP(address)) {
          return callback(new Error('Access to private IPs is not allowed'));
        }
        
        callback(null, address, family);
      });
    }
  });
  
  return {
    fetch: (url, options = {}) => {
      return fetch(url, { ...options, agent });
    }
  };
}

// For defense in depth, use network-level controls too:
// 1. Use a firewall to restrict outbound connections from your server
// 2. Run services in isolated network segments
// 3. Implement egress filtering to block unexpected outbound traffic
// 4. Use cloud security groups to limit access to metadata services`} 
      />
      
      <h4 className="text-xl font-semibold mt-6 mb-3">SSRF Prevention Checklist</h4>
      <ul className="list-disc pl-6 space-y-2">
        <li><strong>Input Validation:</strong> Validate and sanitize all URL parameters</li>
        <li><strong>Allow List:</strong> Use a strict allowlist of permitted domains and protocols</li>
        <li><strong>Block List:</strong> Block access to localhost, private IP ranges, and metadata IPs</li>
        <li><strong>DNS Resolution:</strong> Perform DNS resolution and validate IPs before connecting</li>
        <li><strong>Disable Redirects:</strong> Or limit the number of redirects that can be followed</li>
        <li><strong>Network-Level Controls:</strong> Implement firewall rules to restrict server connections</li>
        <li><strong>Use Timeouts:</strong> Set connection timeouts to prevent hanging connections</li>
        <li><strong>Metadata Service Protection:</strong> In cloud environments, use Instance Metadata Service v2 (IMDSv2) or similar secure alternatives</li>
        <li><strong>Deploy WAFs:</strong> Use web application firewalls with SSRF detection rules</li>
      </ul>
    </section>
  );
};

export default SSRF;
