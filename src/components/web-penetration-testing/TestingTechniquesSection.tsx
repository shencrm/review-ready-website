
import React from 'react';

const TestingTechniquesSection: React.FC = () => {
  return (
    <div className="space-y-8">
      <h2 className="section-title">Web Penetration Testing Techniques</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <div className="card">
          <h3 className="text-xl font-bold mb-4">Reconnaissance Techniques</h3>
          <ul className="list-disc pl-6 space-y-2">
            <li><strong>OSINT Gathering</strong> - Collecting publicly available information</li>
            <li><strong>Subdomain Enumeration</strong> - Finding all subdomains of a target</li>
            <li><strong>Technology Stack Identification</strong> - Determining what technologies are in use</li>
            <li><strong>Port Scanning</strong> - Identifying open ports and services</li>
            <li><strong>Content Discovery</strong> - Finding hidden files and directories</li>
          </ul>
        </div>

        <div className="card">
          <h3 className="text-xl font-bold mb-4">Vulnerability Scanning</h3>
          <ul className="list-disc pl-6 space-y-2">
            <li><strong>Automated Tools</strong> - Using scanners like Burp Suite, OWASP ZAP</li>
            <li><strong>Fuzzing</strong> - Testing with random or unexpected inputs</li>
            <li><strong>Static Analysis</strong> - Scanning source code for security issues</li>
            <li><strong>Dynamic Analysis</strong> - Testing running applications</li>
            <li><strong>Configuration Analysis</strong> - Examining security settings</li>
          </ul>
        </div>
        
        <div className="card">
          <h3 className="text-xl font-bold mb-4">Manual Testing</h3>
          <ul className="list-disc pl-6 space-y-2">
            <li><strong>Session Management Testing</strong> - Evaluating session handling</li>
            <li><strong>Authentication Testing</strong> - Checking login mechanisms</li>
            <li><strong>Authorization Testing</strong> - Validating access controls</li>
            <li><strong>Business Logic Testing</strong> - Finding flaws in application logic</li>
            <li><strong>API Testing</strong> - Examining API endpoints for vulnerabilities</li>
          </ul>
        </div>
        
        <div className="card">
          <h3 className="text-xl font-bold mb-4">Exploitation Techniques</h3>
          <ul className="list-disc pl-6 space-y-2">
            <li><strong>Payload Crafting</strong> - Creating custom payloads for specific vulnerabilities</li>
            <li><strong>Chaining Vulnerabilities</strong> - Combining multiple issues for greater impact</li>
            <li><strong>Privilege Escalation</strong> - Moving from low to high permissions</li>
            <li><strong>Session Hijacking</strong> - Taking over user sessions</li>
            <li><strong>Data Exfiltration</strong> - Techniques to extract sensitive information</li>
          </ul>
        </div>
      </div>
      
      <div className="card">
        <h3 className="text-xl font-bold mb-4">Methodology Frameworks</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <h4 className="font-semibold mb-2">OWASP Testing Guide</h4>
            <p>Comprehensive framework covering various aspects of web application security testing.</p>
          </div>
          <div>
            <h4 className="font-semibold mb-2">PTES</h4>
            <p>Penetration Testing Execution Standard provides technical guidelines for penetration testing.</p>
          </div>
          <div>
            <h4 className="font-semibold mb-2">OSSTMM</h4>
            <p>Open Source Security Testing Methodology Manual offers a scientific methodology for security tests.</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default TestingTechniquesSection;
