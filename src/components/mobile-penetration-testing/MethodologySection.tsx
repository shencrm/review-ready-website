
import React from 'react';
import { Shield, Smartphone } from 'lucide-react';

const MobileMethodologySection: React.FC = () => {
  return (
    <section className="space-y-12">
      <div className="mb-12">
        <h2 className="text-3xl font-bold mb-6">Mobile Penetration Testing Methodology</h2>
        <p className="mb-8">
          A structured approach to mobile application security assessment ensures thorough coverage of potential vulnerabilities.
          The methodology outlined below provides a framework for conducting comprehensive mobile penetration tests.
        </p>
      </div>
      
      <div className="space-y-8">
        <div className="card">
          <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Shield className="text-cybr-primary" /> 
            1. Reconnaissance and Information Gathering
          </h3>
          <ul className="list-disc pl-6 space-y-2">
            <li>Identify application store presence and analyze metadata</li>
            <li>Review permissions requested by the application</li>
            <li>Examine public information about the app (documentation, forums, known issues)</li>
            <li>Identify backend services and APIs used by the application</li>
            <li>Determine the frameworks and third-party libraries in use</li>
          </ul>
        </div>
        
        <div className="card">
          <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Shield className="text-cybr-primary" /> 
            2. Static Analysis
          </h3>
          <ul className="list-disc pl-6 space-y-2">
            <li>Extract and decompile the application (APK for Android, IPA for iOS)</li>
            <li>Review source code for security vulnerabilities</li>
            <li>Identify hardcoded credentials, API keys, and other sensitive information</li>
            <li>Analyze manifest files and permissions</li>
            <li>Review cryptographic implementations</li>
            <li>Scan for known vulnerable dependencies</li>
          </ul>
        </div>
        
        <div className="card">
          <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Shield className="text-cybr-primary" /> 
            3. Dynamic Analysis
          </h3>
          <ul className="list-disc pl-6 space-y-2">
            <li>Configure a controlled testing environment with proxy interception</li>
            <li>Monitor network traffic during application usage</li>
            <li>Analyze data storage during runtime</li>
            <li>Test authentication and session management</li>
            <li>Perform runtime manipulation of the application</li>
            <li>Conduct API security testing</li>
          </ul>
        </div>
        
        <div className="card">
          <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Shield className="text-cybr-primary" /> 
            4. Platform-Specific Testing
          </h3>
          <ul className="list-disc pl-6 space-y-2">
            <li>Android: Test inter-component communication, content providers, broadcast receivers</li>
            <li>iOS: Test app extensions, keychain usage, app transport security settings</li>
            <li>Assess platform-specific permission implementations</li>
            <li>Evaluate secure storage mechanisms</li>
            <li>Test platform crypto APIs usage</li>
          </ul>
        </div>
        
        <div className="card">
          <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Shield className="text-cybr-primary" /> 
            5. Client-Side Attack Vectors
          </h3>
          <ul className="list-disc pl-6 space-y-2">
            <li>Attempt to bypass root/jailbreak detection</li>
            <li>Test for insecure local storage</li>
            <li>Evaluate clipboard vulnerabilities</li>
            <li>Test input validation and sanitization</li>
            <li>Check for sensitive data exposure in app backups</li>
            <li>Assess biometric authentication implementations</li>
          </ul>
        </div>
        
        <div className="card">
          <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Shield className="text-cybr-primary" /> 
            6. Reporting and Remediation
          </h3>
          <ul className="list-disc pl-6 space-y-2">
            <li>Document findings with clear reproduction steps</li>
            <li>Provide severity ratings based on impact and exploitability</li>
            <li>Offer specific remediation recommendations</li>
            <li>Provide code examples for fixes when applicable</li>
            <li>Present findings to development teams</li>
            <li>Verify fixes in follow-up assessments</li>
          </ul>
        </div>
      </div>
    </section>
  );
};

export default MobileMethodologySection;
