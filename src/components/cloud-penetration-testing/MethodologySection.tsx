
import React from 'react';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';

const MethodologySection: React.FC = () => {
  return (
    <section className="space-y-12">
      <div>
        <h2 className="text-3xl font-bold mb-6">Cloud Penetration Testing Methodology</h2>
        <p className="mb-8">
          A structured approach to testing cloud environments is essential for comprehensive security assessment.
          Below is a methodology that can be applied across different cloud service providers.
        </p>

        <div className="space-y-8">
          <div className="card">
            <h3 className="text-2xl font-bold mb-4">1. Reconnaissance & Information Gathering</h3>
            <p className="mb-4">The initial phase focuses on collecting information about the target cloud environment.</p>
            
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>External Footprinting:</strong> Identify domains, subdomains, IP ranges, and publicly exposed cloud resources</li>
              <li><strong>Service Enumeration:</strong> Determine which cloud services are in use (storage, compute, serverless, etc.)</li>
              <li><strong>OSINT:</strong> Gather information from job listings, code repositories, and other public sources</li>
              <li><strong>Technical Footprinting:</strong> Identify cloud-specific technologies, frameworks, and dependencies</li>
              <li><strong>Resource Mapping:</strong> Create a map of discovered resources and their relationships</li>
            </ul>
          </div>
          
          <div className="card">
            <h3 className="text-2xl font-bold mb-4">2. Configuration Analysis</h3>
            <p className="mb-4">Assess the security configuration of cloud resources to identify potential vulnerabilities.</p>
            
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>IAM Review:</strong> Analyze identity and access management policies, roles, and permissions</li>
              <li><strong>Network Configuration:</strong> Review security groups, NACLs, and network segmentation</li>
              <li><strong>Storage Security:</strong> Check for public buckets, container registries, and access controls</li>
              <li><strong>Encryption Settings:</strong> Verify encryption at rest and in transit for sensitive resources</li>
              <li><strong>Logging & Monitoring:</strong> Assess the adequacy of audit logging and monitoring controls</li>
            </ul>
          </div>
          
          <div className="card">
            <h3 className="text-2xl font-bold mb-4">3. Vulnerability Assessment</h3>
            <p className="mb-4">Identify security vulnerabilities in cloud infrastructure and application components.</p>
            
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>Infrastructure Scanning:</strong> Use cloud-specific vulnerability scanners</li>
              <li><strong>Application Security Testing:</strong> Perform DAST/SAST on cloud-deployed applications</li>
              <li><strong>Container Security:</strong> Scan container images and Kubernetes configurations</li>
              <li><strong>Serverless Security:</strong> Evaluate serverless function security</li>
              <li><strong>Database Security:</strong> Check for misconfigurations in cloud databases</li>
            </ul>
          </div>
          
          <div className="card">
            <h3 className="text-2xl font-bold mb-4">4. Exploitation & Privilege Escalation</h3>
            <p className="mb-4">Attempt to exploit identified vulnerabilities to assess their real-world impact.</p>
            
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>Exploitation:</strong> Exploit identified vulnerabilities in a controlled manner</li>
              <li><strong>Privilege Escalation:</strong> Attempt to escalate privileges within the cloud environment</li>
              <li><strong>Lateral Movement:</strong> Move between different resources and services</li>
              <li><strong>Data Exfiltration Testing:</strong> Test controls preventing unauthorized data access</li>
              <li><strong>Persistence:</strong> Assess ability to maintain unauthorized access</li>
            </ul>
          </div>
          
          <div className="card">
            <h3 className="text-2xl font-bold mb-4">5. Post-Exploitation</h3>
            <p className="mb-4">Analyze the impact of successful exploits and identify further attack paths.</p>
            
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>Access Analysis:</strong> Document the level of access obtained</li>
              <li><strong>Data Sensitivity:</strong> Identify sensitive data that could be accessed</li>
              <li><strong>Attack Path Mapping:</strong> Document the chain of vulnerabilities exploited</li>
              <li><strong>Business Impact Assessment:</strong> Evaluate the potential business impact</li>
              <li><strong>Evidence Collection:</strong> Collect evidence for reporting purposes</li>
            </ul>
          </div>
          
          <div className="card">
            <h3 className="text-2xl font-bold mb-4">6. Reporting & Remediation</h3>
            <p className="mb-4">Document findings and provide actionable recommendations for remediation.</p>
            
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>Comprehensive Documentation:</strong> Detail all findings with evidence</li>
              <li><strong>Risk Classification:</strong> Assign severity ratings to vulnerabilities</li>
              <li><strong>Remediation Guidance:</strong> Provide specific, cloud-appropriate remediation steps</li>
              <li><strong>Recommendations:</strong> Suggest security improvements specific to the cloud environment</li>
              <li><strong>Executive Summary:</strong> Provide a business-focused overview of findings</li>
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
};

export default MethodologySection;
