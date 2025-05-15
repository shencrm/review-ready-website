
import { Challenge } from './challenge-types';

export const microserviceSecurityChallenges: Challenge[] = [
  {
    id: 'microservice-security-1',
    title: 'API Gateway Security',
    description: 'This Node.js code implements an API Gateway for a microservice architecture. Is it securely implemented?',
    difficulty: 'medium',
    category: 'Microservice Security',
    languages: ['JavaScript', 'Node.js'],
    type: 'single',
    vulnerabilityType: 'Insecure Gateway Configuration',
    code: `const express = require('express');
const http = require('http');
const app = express();

// Parse JSON request bodies
app.use(express.json());

// Simple request logging
app.use((req, res, next) => {
  console.log(\`\${req.method} \${req.url}\`);
  next();
});

// Service routing configuration
const serviceRoutes = {
  '/users': 'http://user-service:3001',
  '/orders': 'http://order-service:3002',
  '/payments': 'http://payment-service:3003',
  '/admin': 'http://admin-service:3004'
};

// Forward requests to appropriate microservices
app.use('/:service', (req, res) => {
  const servicePath = '/' + req.params.service;
  const serviceUrl = findServiceUrl(servicePath);
  
  if (!serviceUrl) {
    return res.status(404).json({ error: 'Service not found' });
  }
  
  // Forward the request to the microservice
  const options = {
    hostname: serviceUrl.hostname,
    port: serviceUrl.port,
    path: serviceUrl.path + req.url.replace(servicePath, ''),
    method: req.method,
    headers: req.headers
  };
  
  const proxyReq = http.request(options, proxyRes => {
    res.status(proxyRes.statusCode);
    proxyRes.pipe(res);
  });
  
  if (req.body) {
    proxyReq.write(JSON.stringify(req.body));
  }
  
  proxyReq.on('error', error => {
    res.status(500).json({ error: 'Service unavailable' });
  });
  
  proxyReq.end();
});

// Helper to get service URL
function findServiceUrl(servicePath) {
  const serviceBaseUrl = serviceRoutes[servicePath];
  if (!serviceBaseUrl) return null;
  
  const url = new URL(serviceBaseUrl);
  return {
    hostname: url.hostname,
    port: url.port || 80,
    path: url.pathname
  };
}

app.listen(3000, () => {
  console.log('API Gateway running on port 3000');
});`,
    answer: false,
    explanation: "This API Gateway has several security issues: 1) No authentication or authorization mechanisms to protect endpoints, 2) Uses unencrypted HTTP instead of HTTPS for internal service communication, 3) No rate limiting to prevent abuse, 4) No request validation or sanitization, 5) No CORS configuration to prevent cross-origin attacks, 6) Forwards all request headers which could include sensitive information or enable header injection attacks, 7) No timeouts for requests which could lead to DoS vulnerabilities, and 8) No protection against service enumeration. A secure API gateway should implement authentication, use HTTPS, validate requests, implement rate limiting, carefully manage headers, and add proper error handling."
  },
  {
    id: 'microservice-security-2',
    title: 'Service Mesh Authentication',
    description: 'Compare these two service mesh configurations for Kubernetes. Which one implements secure service-to-service authentication?',
    difficulty: 'hard',
    category: 'Microservice Security',
    languages: ['Kubernetes', 'YAML'],
    type: 'comparison',
    vulnerabilityType: 'Insecure Service Communication',
    secureCode: `# Secure service mesh configuration (Istio example)
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: prod
spec:
  mtls:
    mode: STRICT

---
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: api-service
  namespace: prod
spec:
  host: api-service
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL
    connectionPool:
      tcp:
        maxConnections: 100
      http:
        http1MaxPendingRequests: 10
        maxRequestsPerConnection: 10
    outlierDetection:
      consecutiveErrors: 5
      interval: 10s
      baseEjectionTime: 30s

---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: api-service
  namespace: prod
spec:
  hosts:
  - api-service
  http:
  - route:
    - destination:
        host: api-service
        subset: v1
    retries:
      attempts: 3
      perTryTimeout: 2s
      retryOn: gateway-error,connect-failure,refused-stream
    fault:
      delay:
        percentage:
          value: 0.1
        fixedDelay: 5s`,
    vulnerableCode: `# Basic service configuration (no authentication)
apiVersion: v1
kind: Service
metadata:
  name: api-service
  namespace: prod
spec:
  selector:
    app: api-service
  ports:
  - port: 80
    targetPort: 8080

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-service
  namespace: prod
spec:
  selector:
    matchLabels:
      app: api-service
  template:
    metadata:
      labels:
        app: api-service
    spec:
      containers:
      - name: api-service
        image: example/api-service:v1
        ports:
        - containerPort: 8080`,
    answer: 'secure',
    explanation: "The secure configuration uses Istio service mesh capabilities to implement robust security: 1) It enables STRICT mutual TLS (mTLS) mode which ensures that service-to-service communication is authenticated and encrypted, 2) It defines traffic policies including connection pooling and circuit breaking to prevent cascading failures, 3) It implements retry policies for resilience against transient errors, 4) It configures fault injection for testing resilience. The vulnerable configuration is a basic Kubernetes Service and Deployment with no authentication between services, no encryption for in-transit data, no traffic management policies, and no resilience features, leaving services vulnerable to unauthorized access, eavesdropping, and various network-based attacks."
  }
];
