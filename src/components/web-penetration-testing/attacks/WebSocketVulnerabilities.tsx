
import React from 'react';
import { Bug } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const WebSocketVulnerabilities: React.FC = () => {
  return (
    <section id="websocket" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">WebSocket Vulnerabilities</h3>
      <p className="mb-6">
        WebSockets provide full-duplex communication channels over a single TCP connection, enabling real-time 
        data exchange between clients and servers. However, WebSockets can introduce unique security vulnerabilities
        when not properly implemented.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Common WebSocket Vulnerabilities</h4>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li><strong>Authentication Flaws</strong>: Missing or weak authentication for WebSocket connections</li>
        <li><strong>Missing Input Validation</strong>: Not validating messages received over WebSockets</li>
        <li><strong>Cross-Site WebSocket Hijacking</strong>: Allowing unauthorized origins to establish connections</li>
        <li><strong>Sensitive Data Exposure</strong>: Transmitting sensitive information without encryption</li>
        <li><strong>Denial of Service</strong>: No rate limiting for WebSocket connections</li>
      </ul>
      
      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable WebSocket Implementation" 
        code={`// Server-side WebSocket implementation
const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: 8080 });

// No authentication or origin checks
wss.on('connection', function connection(ws) {
  // No validation of client identity
  
  ws.on('message', function incoming(message) {
    try {
      // Vulnerable: Directly processing input without validation
      const data = JSON.parse(message);
      
      if (data.type === 'query') {
        // Vulnerable to injection attacks
        const result = executeQuery(data.query);
        ws.send(JSON.stringify(result));
      }
    } catch (e) {
      ws.send(JSON.stringify({ error: e.toString() }));
    }
  });
  
  // Send sensitive data immediately on connection
  ws.send(JSON.stringify({
    type: 'init',
    userData: getAllUsers() // Sending excessive data
  }));
});`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure WebSocket Implementation" 
        code={`const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const { validate } = require('./validator');

// Create WebSocket server with secure configuration
const wss = new WebSocket.Server({
  port: 8080,
  // Use HTTPS server for secure WebSocket (wss://)
  server: httpsServer,
  // Verify client origin and credentials
  verifyClient: (info, callback) => {
    const origin = info.origin;
    const allowedOrigins = ['https://example.com', 'https://app.example.com'];
    
    // Check origin
    if (!allowedOrigins.includes(origin)) {
      return callback(false, 403, 'Origin not allowed');
    }
    
    // Check for authentication token in request
    const url = new URL(info.req.url, 'https://example.com');
    const token = url.searchParams.get('token');
    
    if (!token) {
      return callback(false, 401, 'Authentication required');
    }
    
    // Verify JWT token
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      info.req.user = decoded; // Attach user info for later use
      callback(true);
    } catch (err) {
      callback(false, 401, 'Invalid token');
    }
  }
});

// Rate limiting for connections
const connections = new Map();
const MAX_CONNECTIONS_PER_IP = 5;
const MESSAGE_RATE_LIMIT = 50; // messages per minute

wss.on('connection', function connection(ws, req) {
  const ip = req.socket.remoteAddress;
  const user = req.user;
  
  // Rate limiting by IP
  const ipConnections = connections.get(ip) || 0;
  if (ipConnections >= MAX_CONNECTIONS_PER_IP) {
    ws.close(1008, 'Too many connections');
    return;
  }
  connections.set(ip, ipConnections + 1);
  
  // Setup message rate limiting
  let messageCount = 0;
  const resetInterval = setInterval(() => {
    messageCount = 0;
  }, 60000); // Reset counter every minute
  
  ws.on('message', function incoming(message) {
    // Apply rate limiting
    messageCount++;
    if (messageCount > MESSAGE_RATE_LIMIT) {
      ws.send(JSON.stringify({ error: 'Rate limit exceeded' }));
      return;
    }
    
    try {
      // Sanitize and validate input
      const data = JSON.parse(message);
      
      if (!validate(data)) {
        ws.send(JSON.stringify({ error: 'Invalid message format' }));
        return;
      }
      
      // Process message based on type with proper authorization
      switch (data.type) {
        case 'query':
          // Check authorization for this action
          if (!user.permissions.includes('read')) {
            ws.send(JSON.stringify({ error: 'Unauthorized' }));
            return;
          }
          
          // Use parameterized queries to prevent injection
          const result = executeSecureQuery(data.params);
          ws.send(JSON.stringify({ type: 'result', data: result }));
          break;
          
        // Handle other message types...
        
        default:
          ws.send(JSON.stringify({ error: 'Unknown message type' }));
      }
    } catch (e) {
      // Generic error to avoid leaking implementation details
      ws.send(JSON.stringify({ error: 'Failed to process message' }));
      console.error(e); // Log actual error server-side
    }
  });
  
  ws.on('close', () => {
    // Clean up resources
    clearInterval(resetInterval);
    connections.set(ip, connections.get(ip) - 1);
  });
});`} 
      />
    </section>
  );
};

export default WebSocketVulnerabilities;
