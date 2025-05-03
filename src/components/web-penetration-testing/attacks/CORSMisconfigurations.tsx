
import React from 'react';
import { ShieldX } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const CORSMisconfigurations: React.FC = () => {
  return (
    <section id="cors" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">CORS Misconfigurations</h3>
      <p className="mb-6">
        Cross-Origin Resource Sharing (CORS) is a security mechanism that allows a web page from one domain to request 
        resources from another domain. CORS misconfigurations can lead to unauthorized cross-origin requests,
        potentially exposing sensitive data to malicious websites.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Common Misconfigurations</h4>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li><strong>Overly Permissive Access-Control-Allow-Origin</strong>: Using wildcards or reflecting Origin headers</li>
        <li><strong>Trusting Arbitrary Origins</strong>: Accepting any origin without validation</li>
        <li><strong>Improper Credential Handling</strong>: Misconfiguring Access-Control-Allow-Credentials</li>
        <li><strong>Insecure Pre-flight Request Handling</strong>: Not properly validating OPTIONS requests</li>
      </ul>
      
      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable CORS Configuration" 
        code={`// Express.js server with dangerous CORS setup
const express = require('express');
const app = express();

// Vulnerability 1: Reflecting any origin
app.use((req, res, next) => {
  // Dangerous: Reflects any origin header sent by the client
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  // Vulnerability 2: Allowing credentials with any origin
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

// API endpoint with sensitive data
app.get('/api/user/profile', (req, res) => {
  // Returns sensitive user data that could be stolen
  // by malicious sites due to misconfigured CORS
  res.json({
    name: 'John Doe',
    email: 'john@example.com',
    ssn: '123-45-6789', // Sensitive data
    creditCard: '1234-5678-9012-3456' // Sensitive data
  });
});`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure CORS Implementation" 
        code={`const express = require('express');
const cors = require('cors');
const app = express();

// Define allowed origins
const allowedOrigins = [
  'https://example.com',
  'https://subdomain.example.com',
  'https://app.example.com'
];

// Configure secure CORS
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl)
    if (!origin) return callback(null, true);
    
    // Check if origin is allowed
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  // Only set credentials true for trusted origins
  credentials: true,
  // Specify allowed methods
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  // Specify allowed headers
  allowedHeaders: ['Content-Type', 'Authorization'],
  // Set preflight cache time (in seconds)
  maxAge: 600
};

// Apply CORS configuration
app.use(cors(corsOptions));

// For routes with sensitive data, double-check origin
app.get('/api/user/sensitive-data', (req, res) => {
  // Additional validation for sensitive routes
  const origin = req.headers.origin;
  if (!origin || !allowedOrigins.includes(origin)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  // Process request and return data
  res.json({
    // Return only necessary data
    name: 'John Doe',
    email: 'john@example.com'
  });
});`} 
      />
    </section>
  );
};

export default CORSMisconfigurations;
