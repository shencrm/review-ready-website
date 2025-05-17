
import { Challenge } from './challenge-types';

export const advancedWebAttacksChallenges: Challenge[] = [
  {
    id: 'advanced-web-1',
    title: 'HTTP Parameter Pollution',
    description: 'Review this Node.js code processing query parameters. Can you identify the security vulnerability?',
    difficulty: 'hard',
    category: 'Web Security',
    languages: ['JavaScript', 'Node.js'],
    type: 'single',
    vulnerabilityType: 'Parameter Pollution',
    code: `const express = require('express');
const app = express();

// Product search endpoint
app.get('/api/products', (req, res) => {
  try {
    const category = req.query.category;
    const minPrice = req.query.minPrice;
    const maxPrice = req.query.maxPrice;
    const sort = req.query.sort || 'price_asc';
    
    console.log(\`Searching products in category: \${category}, price range: \${minPrice}-\${maxPrice}, sort: \${sort}\`);
    
    // Build SQL query
    let sql = 'SELECT * FROM products WHERE 1=1';
    
    if (category) {
      sql += \` AND category = '\${category}'\`;
    }
    
    if (minPrice) {
      sql += \` AND price >= \${minPrice}\`;
    }
    
    if (maxPrice) {
      sql += \` AND price <= \${maxPrice}\`;
    }
    
    // Add sorting
    if (sort === 'price_asc') {
      sql += ' ORDER BY price ASC';
    } else if (sort === 'price_desc') {
      sql += ' ORDER BY price DESC';
    } else if (sort === 'name_asc') {
      sql += ' ORDER BY name ASC';
    } else if (sort === 'name_desc') {
      sql += ' ORDER BY name DESC';
    }
    
    // Execute query (simplified)
    const products = executeQuery(sql);
    
    res.json({ products });
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// Mock function to simulate SQL query execution
function executeQuery(sql) {
  console.log('Executing SQL:', sql);
  // In a real app, this would query a database
  return [{ id: 1, name: 'Product 1', price: 99.99, category: 'electronics' }];
}

app.listen(3000, () => {
  console.log('Server running on port 3000');
});`,
    answer: false,
    explanation: "This code is vulnerable to both HTTP Parameter Pollution (HPP) and SQL Injection attacks. For HPP, Express.js by default takes the last occurrence of a parameter when multiple values are provided (like ?sort=price_asc&sort=name_desc), but the code doesn't handle this scenario explicitly, which could lead to unexpected behaviors or bypass validation logic. More critically, the code constructs SQL queries using string interpolation/concatenation, creating a severe SQL injection vulnerability. An attacker can easily manipulate the parameters (particularly category) to inject malicious SQL code. For example, sending '?category=electronics'--' would comment out the rest of the SQL query, while '?category=electronics' OR '1'='1' would return all products regardless of category. The fix would be to use parameterized queries with database-specific query builders or ORM libraries that handle proper escaping."
  },
  {
    id: 'advanced-web-2',
    title: 'HTTP Request Smuggling',
    description: 'Review this proxy server configuration. Is it vulnerable to HTTP request smuggling?',
    difficulty: 'hard',
    category: 'Web Security',
    languages: ['JavaScript'],
    type: 'multiple-choice',
    vulnerabilityType: 'Request Smuggling',
    code: `const http = require('http');
const httpProxy = require('http-proxy');

// Create a proxy server
const proxy = httpProxy.createProxyServer({});

// Front-end server
const frontendServer = http.createServer((req, res) => {
  // Log incoming request
  console.log(\`[Frontend] \${req.method} \${req.url}\`);
  
  // Basic request validation
  if (req.headers['content-length'] && req.headers['transfer-encoding']) {
    console.warn('Request contains both Content-Length and Transfer-Encoding headers');
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('Bad Request: Ambiguous body length');
    return;
  }
  
  // Set target server based on request path
  let target = 'http://backend-server:8080';
  
  // Forward the request to backend
  console.log(\`[Frontend] Forwarding to \${target}\`);
  proxy.web(req, res, { target });
});

// Error handling for proxy
proxy.on('error', (err, req, res) => {
  console.error('[Proxy] Error:', err);
  res.writeHead(502, { 'Content-Type': 'text/plain' });
  res.end('Bad Gateway');
});

// Start server
frontendServer.listen(80, () => {
  console.log('Frontend server running on port 80');
});`,
    options: [
      'Yes, because it doesn\'t normalize header names',
      'Yes, because it doesn\'t handle chunked encoding correctly',
      'No, it properly checks for ambiguous headers',
      'No, HTTP request smuggling only affects specific web servers, not Node.js'
    ],
    answer: 1,
    explanation: "While the code attempts to prevent HTTP Request Smuggling by checking for the presence of both Content-Length and Transfer-Encoding headers, it's still vulnerable because it doesn't properly handle chunked encoding variations. The check only detects when both standard header names are present, but attackers can bypass this by using header obfuscation techniques like 'transfer-encoding' vs 'Transfer-Encoding', or by using variations like 'Transfer-Encoding: chunked, identity'. Additionally, the code doesn't parse or normalize the Transfer-Encoding header value to handle these variations. A proper implementation would normalize header names (case-insensitive comparison), reject requests with ambiguous body length specifications, and carefully handle all transfer encoding edge cases. HTTP Request Smuggling is a complex vulnerability that exploits inconsistencies between how front-end and back-end servers interpret HTTP messages in a proxy chain."
  }
];
