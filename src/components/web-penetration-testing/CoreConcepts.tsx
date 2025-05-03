
import React from 'react';
import { Shield } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import SecurityCard from '@/components/SecurityCard';

const CoreConcepts: React.FC = () => {
  return (
    <div className="space-y-10">
      <div>
        <h2 className="section-title">Core Web Penetration Testing Concepts</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mt-8">
          <Card>
            <CardHeader>
              <CardTitle>What is Web Penetration Testing?</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="mb-4">
                Web penetration testing is a security assessment approach that evaluates web applications 
                for vulnerabilities from an attacker's perspective. It involves systematically testing 
                all aspects of a web application including its infrastructure, design, and implementation.
              </p>
              <p>
                Unlike automated scanning, penetration testing requires actively exploiting discovered 
                vulnerabilities to determine their real-world risk and impact. This process helps organizations 
                identify and remediate security issues before they can be exploited by malicious actors.
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>The Penetration Testing Lifecycle</CardTitle>
            </CardHeader>
            <CardContent>
              <ol className="list-decimal list-inside space-y-2">
                <li><strong>Planning & Reconnaissance</strong> - Defining scope and gathering information</li>
                <li><strong>Scanning</strong> - Analyzing the application for potential vulnerabilities</li>
                <li><strong>Exploitation</strong> - Attempting to exploit discovered vulnerabilities</li>
                <li><strong>Post-Exploitation</strong> - Determining attack impact and potential pivots</li>
                <li><strong>Reporting</strong> - Documenting findings and providing remediation steps</li>
              </ol>
            </CardContent>
          </Card>

          <Card className="md:col-span-2">
            <CardHeader>
              <CardTitle>The OWASP Top 10</CardTitle>
              <CardDescription>
                The industry standard awareness document for web application security
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
                {[
                  { label: "A01:2021", title: "Broken Access Control" },
                  { label: "A02:2021", title: "Cryptographic Failures" },
                  { label: "A03:2021", title: "Injection" },
                  { label: "A04:2021", title: "Insecure Design" },
                  { label: "A05:2021", title: "Security Misconfiguration" },
                  { label: "A06:2021", title: "Vulnerable & Outdated Components" },
                  { label: "A07:2021", title: "Identification & Authentication Failures" },
                  { label: "A08:2021", title: "Software & Data Integrity Failures" },
                  { label: "A09:2021", title: "Security Logging & Monitoring Failures" },
                  { label: "A10:2021", title: "Server-Side Request Forgery" },
                ].map((item, index) => (
                  <div 
                    key={index} 
                    className="p-4 border border-cybr-primary/20 rounded-lg bg-cybr-muted/30 hover:bg-cybr-muted/50 transition-all"
                  >
                    <div className="font-mono text-xs text-cybr-primary mb-2">{item.label}</div>
                    <div className="font-medium">{item.title}</div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      <div>
        <h3 className="text-2xl font-bold mb-4">Key Testing Methodologies</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <SecurityCard
            title="Black Box Testing"
            description="Simulates an external attack with no prior knowledge of the system. The tester has no access to internal systems and must discover vulnerabilities from the outside."
            icon={<Shield className="h-6 w-6" />}
          />
          <SecurityCard
            title="White Box Testing"
            description="The tester has complete knowledge of the system, including source code, architecture diagrams, and documentation. Focuses on finding vulnerabilities with complete information."
            icon={<Shield className="h-6 w-6" />}
          />
          <SecurityCard
            title="Gray Box Testing"
            description="A hybrid approach where testers have partial knowledge of the system. This simulates attacks from users with limited privileges or knowledge."
            icon={<Shield className="h-6 w-6" />}
          />
        </div>
      </div>
    </div>
  );
};

export default CoreConcepts;
