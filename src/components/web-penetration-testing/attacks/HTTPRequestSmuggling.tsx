
import React from 'react';
import { Bug } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const HTTPRequestSmuggling: React.FC = () => {
  return (
    <section id="http-smuggling" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">HTTP Request Smuggling</h3>
      <p className="mb-6">
        HTTP Request Smuggling exploits differences in how front-end and back-end servers process HTTP requests.
        When these servers disagree on where one request ends and the next begins, attackers can "smuggle" requests
        to the back-end server, potentially bypassing security controls, gaining unauthorized access to sensitive data,
        or poisoning the web cache to attack other users.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">How HTTP Request Smuggling Works</h4>
      <p className="mb-4">
        Request smuggling vulnerabilities arise in multi-server architectures (like load balancers or proxies in front of application servers)
        when servers interpret HTTP headers differently. The key HTTP headers involved are:
      </p>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li><strong>Content-Length</strong>: Specifies the size of the message body in bytes</li>
        <li><strong>Transfer-Encoding</strong>: Indicates that the message body uses chunked encoding</li>
      </ul>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Common Attack Types</h4>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li><strong>CL.TE</strong>: Front-end uses Content-Length, back-end uses Transfer-Encoding</li>
        <li><strong>TE.CL</strong>: Front-end uses Transfer-Encoding, back-end uses Content-Length</li>
        <li><strong>TE.TE</strong>: Both servers use Transfer-Encoding but handle it differently</li>
      </ul>
      
      <CodeExample 
        language="http" 
        isVulnerable={true}
        title="CL.TE Vulnerability Example" 
        code={`POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

# Explanation:
# Front-end server uses Content-Length: 13, so it forwards the whole request
# Back-end server uses Transfer-Encoding: chunked, so it sees:
#   - A chunk of size 0 (indicating the end of the chunked message)
#   - A new request starting with "SMUGGLED"

# TE.CL vulnerability example
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


# Explanation:
# Front-end uses Transfer-Encoding, so it processes:
#   - A chunk of size 8 containing "SMUGGLED"
#   - A zero-sized chunk indicating the end of the body
# Back-end uses Content-Length: 3, so it only reads "8\\r\\n" as the body
# The rest ("SMUGGLED\\r\\n0\\r\\n\\r\\n") is treated as the start of a new request`} 
      />
      
      <p className="my-4">
        An attacker can use these techniques to:
      </p>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li>Bypass security controls that operate at the front-end server</li>
        <li>Capture sensitive information from other users' requests</li>
        <li>Poison web caches to deliver malicious content to other users</li>
        <li>Perform web cache deception attacks</li>
        <li>Exploit cross-site request forgery (CSRF) vulnerabilities</li>
        <li>Achieve account takeover through cookie/session stealing</li>
      </ul>
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Mitigation Strategy" 
        code={`// Server configuration (Node.js example with Express)
const express = require('express');
const app = express();

// 1. Use consistent HTTP parsing
// 2. Configure explicit limits for request sizes
app.use(express.json({
  limit: '1mb',
  strict: true // Strict parsing of JSON
}));

// 3. Normalize request headers
app.use((req, res, next) => {
  // Reject requests with multiple Content-Length headers
  if (Array.isArray(req.headers['content-length'])) {
    return res.status(400).send('Invalid Content-Length header');
  }
  
  // Reject requests with both Content-Length and Transfer-Encoding
  if (req.headers['content-length'] && req.headers['transfer-encoding']) {
    return res.status(400).send('Conflicting headers detected');
  }
  
  next();
});

// Additional best practices:
// - Keep servers and libraries updated
// - Use HTTP/2 when possible (less susceptible to request smuggling)
// - Monitor for unusual requests or errors

// Nginx configuration example
/*
http {
  # Prevent request smuggling by rejecting ambiguous requests
  proxy_http_version 1.1;
  
  # Configure proper header handling
  proxy_request_buffering on;
  client_body_buffer_size 128k;
  client_max_body_size 10m;
  
  # Disable chunked transfer encoding if causing issues
  chunked_transfer_encoding off;
  
  # Reject requests with conflicting headers
  proxy_set_header Transfer-Encoding "";
  
  # Normalize headers
  underscores_in_headers off;
}
*/

// Apache configuration example
/*
# Enforce consistent parsing of request bodies
RequestReadTimeout header=20-40,MinRate=500
RequestReadTimeout body=20,MinRate=500

# Limit request sizes
LimitRequestBody 10485760
*/`} 
      />
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Testing for HTTP Request Smuggling</h4>
      <ul className="list-disc pl-6 space-y-2">
        <li><strong>Time-based testing:</strong> Send requests that might cause delays if smuggling is possible</li>
        <li><strong>Send different Content-Length/Transfer-Encoding combinations:</strong> Observe how servers process them</li>
        <li><strong>Use specialized tools:</strong> Burp Suite has specific tools for detecting request smuggling</li>
        <li><strong>Test obfuscated Transfer-Encoding headers:</strong> Like "Transfer-Encoding: chunked" with varied capitalization</li>
        <li><strong>Check for HTTP/2 desync attacks:</strong> A newer variant affecting HTTP/2 implementations</li>
      </ul>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Defense in Depth</h4>
      <ul className="list-disc pl-6 space-y-2">
        <li>Use gateway WAFs (Web Application Firewalls) that can detect smuggling patterns</li>
        <li>Implement proper request validation at every layer of your architecture</li>
        <li>Set appropriate timeouts to limit the window of opportunity for attacks</li>
        <li>Monitor server logs for unusual patterns or error messages</li>
        <li>Consider using HTTP/2 end-to-end to eliminate most traditional smuggling vulnerabilities</li>
      </ul>
    </section>
  );
};

export default HTTPRequestSmuggling;
