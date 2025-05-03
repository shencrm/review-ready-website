
import React from 'react';
import { Shield, Check, Lock, Code, AlertTriangle } from 'lucide-react';

const MitigationStrategiesSection: React.FC = () => {
  return (
    <div className="space-y-8">
      <h2 className="section-title">Mitigation Strategies</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="card">
          <div className="flex items-center gap-3 mb-4">
            <Code className="h-6 w-6 text-cybr-primary" />
            <h3 className="text-xl font-bold">Secure Coding</h3>
          </div>
          <ul className="list-disc pl-6 space-y-2">
            <li>Input validation and sanitization</li>
            <li>Output encoding</li>
            <li>Parameterized queries</li>
            <li>Safe API usage</li>
            <li>Code reviews and security audits</li>
          </ul>
        </div>
        
        <div className="card">
          <div className="flex items-center gap-3 mb-4">
            <Lock className="h-6 w-6 text-cybr-primary" />
            <h3 className="text-xl font-bold">Authentication Controls</h3>
          </div>
          <ul className="list-disc pl-6 space-y-2">
            <li>Multi-factor authentication</li>
            <li>Strong password policies</li>
            <li>Rate limiting and account lockout</li>
            <li>Secure session management</li>
            <li>Modern authentication protocols</li>
          </ul>
        </div>
        
        <div className="card">
          <div className="flex items-center gap-3 mb-4">
            <Shield className="h-6 w-6 text-cybr-primary" />
            <h3 className="text-xl font-bold">Defense in Depth</h3>
          </div>
          <ul className="list-disc pl-6 space-y-2">
            <li>Web Application Firewalls (WAF)</li>
            <li>Network segmentation</li>
            <li>Least privilege principles</li>
            <li>Regular patching and updates</li>
            <li>Security headers implementation</li>
          </ul>
        </div>
      </div>
      
      <div className="card">
        <h3 className="text-xl font-bold mb-4">OWASP Proactive Controls</h3>
        <p className="mb-4">
          The OWASP Top 10 Proactive Controls is a list of security techniques that should be included in every software development project.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="flex gap-2 items-start">
            <Check className="h-5 w-5 text-green-500 mt-1 flex-shrink-0" />
            <p><strong>Define Security Requirements</strong> - Establish security requirements early in development</p>
          </div>
          <div className="flex gap-2 items-start">
            <Check className="h-5 w-5 text-green-500 mt-1 flex-shrink-0" />
            <p><strong>Leverage Security Frameworks</strong> - Use secure frameworks and libraries</p>
          </div>
          <div className="flex gap-2 items-start">
            <Check className="h-5 w-5 text-green-500 mt-1 flex-shrink-0" />
            <p><strong>Secure Database Access</strong> - Use ORM tools, parameterized queries</p>
          </div>
          <div className="flex gap-2 items-start">
            <Check className="h-5 w-5 text-green-500 mt-1 flex-shrink-0" />
            <p><strong>Encode and Escape Data</strong> - Context-sensitive encoding for untrusted data</p>
          </div>
          <div className="flex gap-2 items-start">
            <Check className="h-5 w-5 text-green-500 mt-1 flex-shrink-0" />
            <p><strong>Validate All Inputs</strong> - Validate inputs on both client and server side</p>
          </div>
          <div className="flex gap-2 items-start">
            <Check className="h-5 w-5 text-green-500 mt-1 flex-shrink-0" />
            <p><strong>Implement Digital Identity</strong> - Secure authentication and session management</p>
          </div>
        </div>
      </div>
      
      <div className="bg-yellow-50 dark:bg-yellow-900/20 border-l-4 border-yellow-400 p-4 rounded">
        <div className="flex gap-3 items-center">
          <AlertTriangle className="h-6 w-6 text-yellow-500" />
          <p className="text-lg font-semibold">Security is a Continuous Process</p>
        </div>
        <p className="mt-2">
          Implement a continuous security testing program, integrating security throughout the SDLC.
          Regular penetration testing and security audits help identify new vulnerabilities as they emerge.
        </p>
      </div>
    </div>
  );
};

export default MitigationStrategiesSection;
