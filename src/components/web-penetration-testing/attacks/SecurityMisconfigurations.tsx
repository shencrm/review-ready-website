
import React from 'react';
import { ShieldX, AlertTriangle, InfoIcon, Shield } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

const SecurityMisconfigurations: React.FC = () => {
  return (
    <section id="misconfig" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Security Misconfigurations</h3>
      
      <div className="space-y-6">
        {/* Introduction */}
        <div>
          <p className="mb-4">
            Security misconfigurations occur when applications, frameworks, web servers, databases, or platforms 
            are not configured securely. These vulnerabilities often arise from insecure default configurations, 
            incomplete configurations, or ad hoc changes. Unlike other vulnerabilities that exploit code flaws, 
            security misconfigurations exploit configuration weaknesses, making them particularly dangerous 
            as they can affect entire systems and infrastructure components.
          </p>
          
          <Alert className="mb-4 text-amber-900 dark:text-amber-200 bg-slate-50">
            <InfoIcon className="h-4 w-4" />
            <AlertTitle>Attacker's Goal</AlertTitle>
            <AlertDescription>
              Exploit configuration weaknesses to gain unauthorized access to systems, data, or functionality. 
              This includes bypassing security controls, accessing sensitive information, gaining administrative 
              privileges, or using the system as a stepping stone for further attacks.
            </AlertDescription>
          </Alert>
        </div>

        {/* Attack Types */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Common Security Misconfigurations</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <SecurityCard 
              title="Default Credentials" 
              description="Using default usernames and passwords for administrative interfaces, databases, or application accounts that are publicly known." 
              severity="high" 
            />
            <SecurityCard 
              title="Unnecessary Services" 
              description="Running unused features, frameworks, or services that expand the attack surface without providing business value." 
              severity="medium" 
            />
            <SecurityCard 
              title="Missing Security Headers" 
              description="Lack of HTTP security headers that protect against common attacks like XSS, clickjacking, and MIME sniffing." 
              severity="medium" 
            />
            <SecurityCard 
              title="Information Disclosure" 
              description="Exposing sensitive information through error messages, directory listings, debug information, or server banners." 
              severity="high" 
            />
            <SecurityCard 
              title="Insecure Permissions" 
              description="Overly permissive file system permissions, database access rights, or application-level authorization controls." 
              severity="high" 
            />
            <SecurityCard 
              title="Unpatched Systems" 
              description="Missing security patches and updates for operating systems, web servers, databases, libraries, and frameworks." 
              severity="high" 
            />
          </div>
        </div>

        {/* Vulnerable Components */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Commonly Vulnerable Components</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md">
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>Web Servers:</strong> Apache, Nginx, IIS with default configurations or enabled debug modes</li>
              <li><strong>Application Frameworks:</strong> Django, Rails, Express.js with development settings in production</li>
              <li><strong>Database Systems:</strong> MySQL, PostgreSQL, MongoDB with weak authentication or default accounts</li>
              <li><strong>Cloud Services:</strong> AWS S3 buckets, Azure storage containers with public access</li>
              <li><strong>Content Management Systems:</strong> WordPress, Drupal with default installations and plugins</li>
              <li><strong>Administrative Interfaces:</strong> phpMyAdmin, Adminer, Jenkins with default credentials</li>
              <li><strong>Development Tools:</strong> Git repositories, IDEs, and development servers exposed in production</li>
              <li><strong>Monitoring Systems:</strong> Elasticsearch, Kibana, Grafana with open access</li>
            </ul>
          </div>
        </div>

        {/* Why These Attacks Work */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Why Security Misconfigurations Occur</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Human Factors</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Lack of security awareness during deployment</li>
                <li>Pressure to deploy quickly without security review</li>
                <li>Insufficient documentation of secure configuration practices</li>
                <li>Poor communication between development and operations teams</li>
                <li>Inadequate training on security configuration best practices</li>
                <li>Assumption that default settings are secure</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Technical Issues</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Complex configuration requirements with unclear documentation</li>
                <li>Insecure default configurations in software packages</li>
                <li>Lack of automated security configuration validation</li>
                <li>Configuration drift over time without monitoring</li>
                <li>Inconsistent configurations across environments</li>
                <li>Missing security hardening checklists and procedures</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Step-by-Step Attack Methodology */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Step-by-Step Attack Methodology</h4>
          <Tabs defaultValue="reconnaissance">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="reconnaissance">Reconnaissance</TabsTrigger>
              <TabsTrigger value="scanning">Scanning</TabsTrigger>
              <TabsTrigger value="exploitation">Exploitation</TabsTrigger>
              <TabsTrigger value="escalation">Escalation</TabsTrigger>
            </TabsList>
            
            <TabsContent value="reconnaissance" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 1: Information Gathering</h5>
                <ol className="list-decimal pl-6 space-y-2">
                  <li><strong>Server Banner Analysis:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Identify web server types and versions from HTTP headers</li>
                      <li>Check for detailed error messages revealing system information</li>
                      <li>Look for technology stack indicators in response headers</li>
                      <li>Analyze JavaScript libraries and framework signatures</li>
                    </ul>
                  </li>
                  <li><strong>Directory and File Discovery:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Check for common administrative directories (/admin, /management)</li>
                      <li>Look for backup files, configuration files, and logs</li>
                      <li>Test for directory listing vulnerabilities</li>
                      <li>Search for development and testing endpoints</li>
                    </ul>
                  </li>
                </ol>
              </div>
            </TabsContent>
            
            <TabsContent value="scanning" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 2: Configuration Analysis</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Scanning Techniques:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>HTTP Header Analysis:</strong> Check for missing security headers</li>
                    <li><strong>SSL/TLS Configuration:</strong> Test encryption settings and certificate validity</li>
                    <li><strong>Default Credential Testing:</strong> Try common username/password combinations</li>
                    <li><strong>Service Enumeration:</strong> Identify running services and their versions</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="exploitation" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 3: Misconfiguration Exploitation</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Exploitation Methods:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Administrative Access:</strong> Use default credentials to gain admin access</li>
                    <li><strong>Information Extraction:</strong> Access exposed configuration files and databases</li>
                    <li><strong>Service Abuse:</strong> Exploit unnecessarily exposed services</li>
                    <li><strong>Privilege Escalation:</strong> Use misconfigurations to gain higher privileges</li>
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
                    <li><strong>System Compromise:</strong> Use gained access to compromise the entire system</li>
                    <li><strong>Data Exfiltration:</strong> Access and steal sensitive information</li>
                    <li><strong>Persistence:</strong> Install backdoors or modify configurations for continued access</li>
                    <li><strong>Lateral Movement:</strong> Use compromised system to attack other network resources</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Example Payloads and Attacks */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Common Misconfiguration Attack Vectors</h4>
          
          <CodeExample 
            language="bash" 
            isVulnerable={true}
            title="Information Gathering Commands" 
            code={`# HTTP header analysis to identify server information
curl -I https://target.com
# Look for: Server, X-Powered-By, X-AspNet-Version headers

# Directory scanning for exposed administrative interfaces
dirb https://target.com /usr/share/wordlists/dirb/common.txt
# Common targets: /admin, /phpmyadmin, /wp-admin, /manager

# Default credential testing
curl -X POST https://target.com/admin/login \\
  -d "username=admin&password=admin"
curl -X POST https://target.com/admin/login \\
  -d "username=admin&password=password"

# SSL/TLS configuration testing
sslscan target.com
nmap --script ssl-enum-ciphers -p 443 target.com

# Check for exposed Git repositories
curl https://target.com/.git/config
curl https://target.com/.git/HEAD

# Test for directory listing
curl https://target.com/uploads/
curl https://target.com/backup/

# Check for exposed database interfaces
curl https://target.com:9200/_cluster/health  # Elasticsearch
curl https://target.com/phpmyadmin/
curl https://target.com:27017/  # MongoDB

# Look for backup and configuration files
curl https://target.com/config.php.backup
curl https://target.com/web.config
curl https://target.com/.env`} 
          />
        </div>

        {/* Vulnerable Code Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Vulnerable Configuration Examples</h4>
          
          <CodeExample 
            language="javascript" 
            isVulnerable={true}
            title="Insecure Express.js Configuration" 
            code={`const express = require('express');
const app = express();

// VULNERABLE: Running in debug mode in production
process.env.NODE_ENV = 'development';

// VULNERABLE: No security headers
app.use(express.static('public'));

// VULNERABLE: Detailed error messages in production
app.use((err, req, res, next) => {
  // Exposes stack traces and internal paths
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    details: err
  });
});

// VULNERABLE: Default session configuration
const session = require('express-session');
app.use(session({
  secret: 'defaultsecret',  // Weak secret
  secure: false,            // Not requiring HTTPS
  httpOnly: false,          // Accessible via JavaScript
  sameSite: false          // No CSRF protection
}));

// VULNERABLE: CORS misconfiguration
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');  // Too permissive
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

// VULNERABLE: Exposing internal information
app.get('/debug', (req, res) => {
  res.json({
    environment: process.env,
    version: process.version,
    platform: process.platform,
    memory: process.memoryUsage()
  });
});

app.listen(3000);`} 
          />

          <CodeExample 
            language="nginx" 
            isVulnerable={true}
            title="Insecure Nginx Configuration" 
            code={`# VULNERABLE: Nginx configuration with security issues
server {
    listen 80;
    server_name example.com;
    
    # VULNERABLE: No security headers
    # Missing: X-Frame-Options, X-Content-Type-Options, etc.
    
    # VULNERABLE: Server version disclosure
    server_tokens on;  # Exposes Nginx version
    
    # VULNERABLE: Directory listing enabled
    location /uploads/ {
        autoindex on;  # Lists directory contents
        alias /var/www/uploads/;
    }
    
    # VULNERABLE: Exposing sensitive files
    location ~ /\\.git {
        # Should deny access but it's not configured
        allow all;
    }
    
    # VULNERABLE: PHP configuration exposure
    location ~ \\.php$ {
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        
        # VULNERABLE: Exposing PHP errors
        fastcgi_param PHP_ADMIN_VALUE "display_errors=On";
    }
    
    # VULNERABLE: Weak SSL configuration (if HTTPS was enabled)
    # ssl_protocols TLSv1 TLSv1.1 TLSv1.2;  # Includes weak protocols
    # ssl_ciphers 'ALL';  # Allows weak ciphers
    
    # VULNERABLE: Default error pages revealing information
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
}`} 
          />

          <CodeExample 
            language="apache" 
            isVulnerable={true}
            title="Insecure Apache Configuration" 
            code={`# VULNERABLE: Apache configuration with security issues

# VULNERABLE: Server signature disclosure
ServerTokens Full
ServerSignature On

# VULNERABLE: Directory listing enabled globally
Options Indexes FollowSymLinks

# VULNERABLE: Exposing sensitive files
<Files ".htaccess">
    # Should be denied but not properly configured
    Require all granted
</Files>

# VULNERABLE: Exposing configuration files
<Files "*.conf">
    Require all granted
</Files>

# VULNERABLE: PHP configuration issues
<IfModule mod_php7.c>
    # VULNERABLE: Exposing PHP errors
    php_admin_value display_errors "On"
    php_admin_value display_startup_errors "On"
    php_admin_value log_errors "On"
    php_admin_value error_log "/var/log/apache2/php_errors.log"
    
    # VULNERABLE: Dangerous PHP functions not disabled
    # php_admin_value disable_functions ""
</IfModule>

# VULNERABLE: Missing security headers
# No Content-Security-Policy
# No X-Frame-Options
# No X-Content-Type-Options

# VULNERABLE: Weak SSL configuration
<IfModule mod_ssl.c>
    SSLProtocol all -SSLv2 -SSLv3  # Still allows TLSv1 and TLSv1.1
    SSLCipherSuite HIGH:MEDIUM:!aNULL:!MD5
    SSLHonorCipherOrder off
</IfModule>

# VULNERABLE: Default virtual host configuration
<VirtualHost *:80>
    DocumentRoot /var/www/html
    
    # VULNERABLE: Directory browsing enabled
    <Directory "/var/www/html">
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    # VULNERABLE: Backup files accessible
    <Directory "/var/www/html/backup">
        Require all granted
    </Directory>
</VirtualHost>`} 
          />
        </div>

        {/* Secure Configuration Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Secure Configuration Examples</h4>
          
          <CodeExample 
            language="javascript" 
            isVulnerable={false}
            title="Secure Express.js Configuration" 
            code={`const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const crypto = require('crypto');

const app = express();

// SECURE: Proper environment configuration
const isProduction = process.env.NODE_ENV === 'production';

// SECURE: Use Helmet for security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      fontSrc: ["'self'"],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

// SECURE: Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP'
});
app.use(limiter);

// SECURE: Proper session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
  resave: false,
  saveUninitialized: false,
  secure: isProduction, // Require HTTPS in production
  httpOnly: true,       // Prevent XSS
  sameSite: 'strict',   // CSRF protection
  maxAge: 1000 * 60 * 60 * 24, // 24 hours
  name: 'sessionId'     // Don't use default session name
}));

// SECURE: Proper CORS configuration
const allowedOrigins = ['https://yourdomain.com', 'https://www.yourdomain.com'];
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

// SECURE: Error handling without information disclosure
app.use((err, req, res, next) => {
  // Log error internally
  console.error(err);
  
  // Return generic error message in production
  const errorMessage = isProduction 
    ? 'An error occurred' 
    : err.message;
    
  res.status(500).json({ error: errorMessage });
});

// SECURE: Remove debug endpoints in production
if (!isProduction) {
  app.get('/debug', (req, res) => {
    res.json({ message: 'Debug endpoint only available in development' });
  });
}

// SECURE: Hide server information
app.disable('x-powered-by');

// SECURE: Input validation middleware
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(\`Server running on port \${PORT}\`);
});`} 
          />

          <CodeExample 
            language="nginx" 
            isVulnerable={false}
            title="Secure Nginx Configuration" 
            code={`# SECURE: Nginx configuration with proper security settings
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com www.example.com;
    
    # SECURE: Hide server version
    server_tokens off;
    
    # SECURE: SSL/TLS configuration
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # SECURE: Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self';" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    
    # SECURE: Disable directory listing
    autoindex off;
    
    # SECURE: Deny access to sensitive files
    location ~ /\\.(git|svn|env) {
        deny all;
        return 404;
    }
    
    location ~ \\.(conf|config|bak|backup|old|orig|original)$ {
        deny all;
        return 404;
    }
    
    # SECURE: Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/m;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/m;
    
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://backend;
    }
    
    location /login {
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://backend;
    }
    
    # SECURE: Proper file serving
    location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        add_header X-Content-Type-Options nosniff;
    }
    
    # SECURE: PHP configuration
    location ~ \\.php$ {
        try_files $uri =404;
        fastcgi_pass unix:/var/run/php/php8.0-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        
        # SECURE: Hide PHP errors in production
        fastcgi_param PHP_ADMIN_VALUE "display_errors=Off";
        fastcgi_param PHP_ADMIN_VALUE "log_errors=On";
    }
    
    # SECURE: Custom error pages without information disclosure
    error_page 400 401 403 404 /error.html;
    error_page 500 502 503 504 /error.html;
    
    location = /error.html {
        internal;
        root /var/www/html;
    }
}

# SECURE: Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;
    return 301 https://$server_name$request_uri;
}`} 
          />
        </div>

        {/* Testing and Detection */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Testing for Security Misconfigurations</h4>
          <div className="space-y-4">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Manual Testing Checklist</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Check HTTP response headers for missing security headers</li>
                <li>Test for default credentials on administrative interfaces</li>
                <li>Verify SSL/TLS configuration and certificate validity</li>
                <li>Look for directory listing vulnerabilities</li>
                <li>Check for exposed configuration files and backups</li>
                <li>Test error handling for information disclosure</li>
                <li>Verify proper access controls on sensitive endpoints</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Automated Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Nmap:</strong> Service discovery and version detection</li>
                <li><strong>Nikto:</strong> Web server vulnerability scanner</li>
                <li><strong>SSLScan/SSLyze:</strong> SSL/TLS configuration analysis</li>
                <li><strong>Dirb/Gobuster:</strong> Directory and file discovery</li>
                <li><strong>SecurityHeaders.com:</strong> HTTP security header analysis</li>
                <li><strong>OWASP ZAP:</strong> Comprehensive web application security testing</li>
                <li><strong>Nessus/OpenVAS:</strong> Network vulnerability scanners</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Prevention Strategies */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Prevention and Mitigation Strategies</h4>
          
          <Alert className="mb-6">
            <Shield className="h-4 w-4" />
            <AlertTitle>Defense in Depth</AlertTitle>
            <AlertDescription>
              Implement multiple layers of security controls and regular security assessments to prevent 
              and detect misconfigurations before they can be exploited.
            </AlertDescription>
          </Alert>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <div className="p-4 rounded-md border border-green-200 dark:border-green-800 bg-cybr-muted">
              <h5 className="font-semibold mb-3 text-green-800 dark:text-green-200">Configuration Management</h5>
              <ul className="list-disc pl-6 space-y-2 text-sm">
                <li><strong>Security Baselines:</strong> Establish and maintain secure configuration baselines</li>
                <li><strong>Infrastructure as Code:</strong> Use automated deployment with security controls</li>
                <li><strong>Configuration Reviews:</strong> Regular audits of system and application configurations</li>
                <li><strong>Change Management:</strong> Proper approval processes for configuration changes</li>
                <li><strong>Documentation:</strong> Maintain current documentation of security settings</li>
              </ul>
            </div>
            
            <div className="p-4 rounded-md border border-blue-200 dark:border-blue-800 bg-cybr-muted">
              <h5 className="font-semibold mb-3 text-blue-800 dark:text-blue-200">Operational Security</h5>
              <ul className="list-disc pl-6 space-y-2 text-sm">
                <li><strong>Automated Scanning:</strong> Regular vulnerability and configuration scans</li>
                <li><strong>Security Monitoring:</strong> Continuous monitoring for configuration drift</li>
                <li><strong>Patch Management:</strong> Systematic approach to applying security updates</li>
                <li><strong>Least Privilege:</strong> Minimal necessary permissions for all components</li>
                <li><strong>Security Training:</strong> Education for development and operations teams</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Environment-Specific Considerations */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Environment-Specific Considerations</h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Cloud Environments</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Secure IAM roles and policies</li>
                <li>Proper security group configurations</li>
                <li>Encrypted storage and transmission</li>
                <li>Regular security assessments</li>
                <li>Compliance with cloud security best practices</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Container Environments</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Secure base images and minimal attack surface</li>
                <li>Proper secrets management</li>
                <li>Network segmentation and policies</li>
                <li>Runtime security monitoring</li>
                <li>Regular vulnerability scanning of images</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Development Environments</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Separate configurations for dev/test/prod</li>
                <li>Secure handling of development data</li>
                <li>Regular security testing integration</li>
                <li>Developer security training</li>
                <li>Secure coding practices enforcement</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default SecurityMisconfigurations;
