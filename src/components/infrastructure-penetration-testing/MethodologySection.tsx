
import React from 'react';
import { Shield, Network, Server, Bug } from 'lucide-react';

const InfraMethodologySection: React.FC = () => {
  return (
    <section className="space-y-8">
      <div className="mb-8">
        <h2 className="text-3xl font-bold mb-6 flex items-center gap-2">
          <Shield className="text-cybr-primary" />
          Infrastructure Penetration Testing Methodology
        </h2>
        <p className="mb-4">
          A structured approach to infrastructure penetration testing ensures comprehensive coverage and reliable results.
          Following a proven methodology helps identify vulnerabilities across different infrastructure components.
        </p>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <div className="card">
          <div className="flex items-center gap-3 mb-4">
            <div className="bg-cybr-primary/10 p-3 rounded-full">
              <span className="text-xl font-bold text-cybr-primary">1</span>
            </div>
            <h3 className="text-xl font-bold">Reconnaissance</h3>
          </div>
          <ul className="space-y-2 pl-12">
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Network range identification</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Asset discovery and enumeration</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Operating system fingerprinting</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Active Directory structure mapping</span>
            </li>
          </ul>
        </div>
        
        <div className="card">
          <div className="flex items-center gap-3 mb-4">
            <div className="bg-cybr-primary/10 p-3 rounded-full">
              <span className="text-xl font-bold text-cybr-primary">2</span>
            </div>
            <h3 className="text-xl font-bold">Scanning & Enumeration</h3>
          </div>
          <ul className="space-y-2 pl-12">
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Port scanning (TCP/UDP)</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Service identification and version detection</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Vulnerability scanning</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>User and group enumeration</span>
            </li>
          </ul>
        </div>
        
        <div className="card">
          <div className="flex items-center gap-3 mb-4">
            <div className="bg-cybr-primary/10 p-3 rounded-full">
              <span className="text-xl font-bold text-cybr-primary">3</span>
            </div>
            <h3 className="text-xl font-bold">Vulnerability Analysis</h3>
          </div>
          <ul className="space-y-2 pl-12">
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Vulnerability prioritization</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>False positive identification</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Configuration review</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Patch level assessment</span>
            </li>
          </ul>
        </div>
        
        <div className="card">
          <div className="flex items-center gap-3 mb-4">
            <div className="bg-cybr-primary/10 p-3 rounded-full">
              <span className="text-xl font-bold text-cybr-primary">4</span>
            </div>
            <h3 className="text-xl font-bold">Exploitation</h3>
          </div>
          <ul className="space-y-2 pl-12">
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Initial access exploitation</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Privilege escalation</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Lateral movement techniques</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Password attacks</span>
            </li>
          </ul>
        </div>
        
        <div className="card">
          <div className="flex items-center gap-3 mb-4">
            <div className="bg-cybr-primary/10 p-3 rounded-full">
              <span className="text-xl font-bold text-cybr-primary">5</span>
            </div>
            <h3 className="text-xl font-bold">Post Exploitation</h3>
          </div>
          <ul className="space-y-2 pl-12">
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Data exfiltration testing</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Persistence establishment</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Defense evasion testing</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Evidence collection</span>
            </li>
          </ul>
        </div>
        
        <div className="card">
          <div className="flex items-center gap-3 mb-4">
            <div className="bg-cybr-primary/10 p-3 rounded-full">
              <span className="text-xl font-bold text-cybr-primary">6</span>
            </div>
            <h3 className="text-xl font-bold">Reporting</h3>
          </div>
          <ul className="space-y-2 pl-12">
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Vulnerability documentation</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Impact assessment</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Remediation recommendations</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cybr-primary">•</span>
              <span>Risk prioritization</span>
            </li>
          </ul>
        </div>
      </div>
      
      <div className="card mt-10">
        <h3 className="text-2xl font-bold mb-6">Infrastructure Testing Frameworks</h3>
        
        <div className="space-y-6">
          <div className="mb-6">
            <h4 className="text-xl font-semibold mb-2 flex items-center gap-2">
              <Server className="text-cybr-primary h-5 w-5" />
              MITRE ATT&CK Framework
            </h4>
            <p className="mb-2">
              A comprehensive matrix of tactics and techniques used by threat actors, providing a common language
              for infrastructure penetration testing:
            </p>
            <ul className="list-disc pl-6 space-y-1">
              <li>Initial Access tactics</li>
              <li>Execution methods</li>
              <li>Persistence mechanisms</li>
              <li>Privilege Escalation techniques</li>
              <li>Defense Evasion strategies</li>
              <li>Credential Access methods</li>
              <li>Discovery techniques</li>
              <li>Lateral Movement approaches</li>
              <li>Collection methods</li>
              <li>Data exfiltration techniques</li>
            </ul>
          </div>
          
          <div className="mb-6">
            <h4 className="text-xl font-semibold mb-2 flex items-center gap-2">
              <Network className="text-cybr-primary h-5 w-5" />
              Infrastructure Testing Standards
            </h4>
            <p className="mb-2">
              Several industry standards guide infrastructure penetration testing approaches:
            </p>
            <ul className="list-disc pl-6 space-y-1">
              <li><strong>PTES (Penetration Testing Execution Standard)</strong> - Comprehensive framework covering pre-engagement, intelligence gathering, threat modeling, vulnerability analysis, exploitation, post-exploitation, and reporting</li>
              <li><strong>OSSTMM (Open Source Security Testing Methodology Manual)</strong> - Scientific methodology for security testing across multiple channels including physical, human, wireless, telecommunications, and networks</li>
              <li><strong>NIST SP 800-115</strong> - Technical guide for planning and conducting information security testing and assessments</li>
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
};

export default InfraMethodologySection;
