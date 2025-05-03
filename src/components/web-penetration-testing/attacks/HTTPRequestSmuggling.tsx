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
        to the back-end server, potentially bypassing security controls or poisoning the cache.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Example Attack</h4>
      <CodeExample 
        language="http" 
        isVulnerable={true}
        title="CL.TE Vulnerability Example" 
        code={`POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED`} 
      />
      
      <p className="my-4">
        In this example, the front-end server uses the Content-Length header (CL.TE vulnerability), 
        while the back-end server uses Transfer-Encoding. This discrepancy allows the "SMUGGLED" 
        content to be interpreted as the start of a new request by the back-end server.
      </p>
      
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
  if (req.headers['content-length'] && Array.isArray(req.headers['content-length'])) {
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
// - Monitor for unusual requests or errors`} 
      />
    </section>
  );
};

export default HTTPRequestSmuggling;
