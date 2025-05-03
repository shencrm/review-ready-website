
import React from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Terminal, Cloud, Lock, Server } from 'lucide-react';

const ToolsSection: React.FC = () => {
  return (
    <section className="space-y-12">
      <div>
        <h2 className="text-3xl font-bold mb-6">Cloud Penetration Testing Tools</h2>
        <p className="mb-8">
          Specialized tools are essential for effective cloud penetration testing. This section covers multi-cloud 
          and platform-specific tools that can help security professionals assess cloud environments more effectively.
        </p>

        <Tabs defaultValue="multi-cloud">
          <TabsList>
            <TabsTrigger value="multi-cloud">Multi-Cloud Tools</TabsTrigger>
            <TabsTrigger value="frameworks">Testing Frameworks</TabsTrigger>
            <TabsTrigger value="methodology">Tool Selection Guide</TabsTrigger>
          </TabsList>
          
          <TabsContent value="multi-cloud" className="mt-6">
            <div className="card mb-8">
              <h3 className="text-2xl font-bold mb-4">Multi-Cloud Assessment Tools</h3>
              <p className="mb-6">
                These tools work across multiple cloud platforms, enabling consistent testing across hybrid and 
                multi-cloud environments.
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-cybr-muted/20 rounded-lg p-6">
                  <h4 className="text-xl font-bold flex items-center mb-3">
                    <Terminal className="mr-2 h-5 w-5" />
                    ScoutSuite
                  </h4>
                  <p className="text-sm mb-3">
                    A multi-cloud security auditing tool that provides security posture assessment across AWS, Azure, GCP, 
                    and others.
                  </p>
                  <h5 className="font-semibold text-sm text-cybr-secondary mb-2">KEY FEATURES</h5>
                  <ul className="list-disc list-inside pl-2 text-sm text-cybr-foreground/80">
                    <li>Support for AWS, Azure, GCP, and Oracle Cloud</li>
                    <li>Rules-based assessment engine</li>
                    <li>HTML reporting dashboard</li>
                    <li>Open-source and extensible</li>
                    <li>Minimal cloud API usage to avoid detection</li>
                  </ul>
                </div>
                
                <div className="bg-cybr-muted/20 rounded-lg p-6">
                  <h4 className="text-xl font-bold flex items-center mb-3">
                    <Terminal className="mr-2 h-5 w-5" />
                    Prowler
                  </h4>
                  <p className="text-sm mb-3">
                    Command line tool designed for AWS, Azure and GCP security assessment, auditing, hardening and incident response.
                  </p>
                  <h5 className="font-semibold text-sm text-cybr-secondary mb-2">KEY FEATURES</h5>
                  <ul className="list-disc list-inside pl-2 text-sm text-cybr-foreground/80">
                    <li>750+ security checks across platforms</li>
                    <li>Customizable security checks</li>
                    <li>CIS benchmark checks for AWS, Azure and GCP</li>
                    <li>Comprehensive findings with remediation</li>
                    <li>Multiple output formats including JSON, CSV, HTML</li>
                  </ul>
                </div>
                
                <div className="bg-cybr-muted/20 rounded-lg p-6">
                  <h4 className="text-xl font-bold flex items-center mb-3">
                    <Terminal className="mr-2 h-5 w-5" />
                    cs-suite
                  </h4>
                  <p className="text-sm mb-3">
                    Cloud Security Suite is a one-stop tool for auditing the security posture of AWS/GCP/Azure infrastructure.
                  </p>
                  <h5 className="font-semibold text-sm text-cybr-secondary mb-2">KEY FEATURES</h5>
                  <ul className="list-disc list-inside pl-2 text-sm text-cybr-foreground/80">
                    <li>Multi-cloud support in a single tool</li>
                    <li>Automated scanning capabilities</li>
                    <li>Security benchmarking</li>
                    <li>Easy integration into CI/CD pipelines</li>
                    <li>Comprehensive HTML reports</li>
                  </ul>
                </div>
                
                <div className="bg-cybr-muted/20 rounded-lg p-6">
                  <h4 className="text-xl font-bold flex items-center mb-3">
                    <Terminal className="mr-2 h-5 w-5" />
                    Nuclei
                  </h4>
                  <p className="text-sm mb-3">
                    Fast and customizable vulnerability scanner that can be adapted for cloud service testing.
                  </p>
                  <h5 className="font-semibold text-sm text-cybr-secondary mb-2">KEY FEATURES</h5>
                  <ul className="list-disc list-inside pl-2 text-sm text-cybr-foreground/80">
                    <li>Template-based scanning engine</li>
                    <li>Cloud API endpoint testing</li>
                    <li>Easily extensible for custom checks</li>
                    <li>Fast parallel scanning</li>
                    <li>Growing library of cloud-specific templates</li>
                  </ul>
                </div>
              </div>
            </div>
          </TabsContent>
          
          <TabsContent value="frameworks" className="mt-6">
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Cloud Penetration Testing Frameworks</h3>
              <p className="mb-6">
                Frameworks provide structured approaches and toolsets for comprehensive cloud penetration testing.
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-cybr-muted/20 rounded-lg p-6">
                  <h4 className="text-xl font-bold mb-3">Pacu</h4>
                  <p className="mb-3 text-sm">
                    An open-source AWS exploitation framework designed for simulating attack scenarios and testing security posture.
                  </p>
                  <h5 className="font-semibold text-sm text-cybr-secondary mb-2">CAPABILITIES</h5>
                  <ul className="list-disc list-inside pl-2 text-sm text-cybr-foreground/80">
                    <li>60+ modules for AWS service testing</li>
                    <li>Reconnaissance and enumeration</li>
                    <li>Privilege escalation techniques</li>
                    <li>Data exfiltration simulations</li>
                    <li>Cleanup functionality to revert changes</li>
                  </ul>
                </div>
                
                <div className="bg-cybr-muted/20 rounded-lg p-6">
                  <h4 className="text-xl font-bold mb-3">PowerZure</h4>
                  <p className="mb-3 text-sm">
                    PowerShell framework for assessing Azure environments with various attack modules.
                  </p>
                  <h5 className="font-semibold text-sm text-cybr-secondary mb-2">CAPABILITIES</h5>
                  <ul className="list-disc list-inside pl-2 text-sm text-cybr-foreground/80">
                    <li>Azure AD security assessment</li>
                    <li>Resource enumeration and discovery</li>
                    <li>Permission analysis and exploitation</li>
                    <li>Post-exploitation capabilities</li>
                    <li>Managed identity assessment</li>
                  </ul>
                </div>
                
                <div className="bg-cybr-muted/20 rounded-lg p-6">
                  <h4 className="text-xl font-bold mb-3">GCAT</h4>
                  <p className="mb-3 text-sm">
                    Google Cloud Attack Tool designed for testing GCP environments against common attack vectors.
                  </p>
                  <h5 className="font-semibold text-sm text-cybr-secondary mb-2">CAPABILITIES</h5>
                  <ul className="list-disc list-inside pl-2 text-sm text-cybr-foreground/80">
                    <li>GCP resource enumeration</li>
                    <li>IAM privilege escalation testing</li>
                    <li>Service account key exploitation</li>
                    <li>Metadata service attack simulations</li>
                    <li>Project-level permission analysis</li>
                  </ul>
                </div>
                
                <div className="bg-cybr-muted/20 rounded-lg p-6">
                  <h4 className="text-xl font-bold mb-3">Cloud-Katana</h4>
                  <p className="mb-3 text-sm">
                    Automated serverless tool for testing security controls in multi-cloud environments.
                  </p>
                  <h5 className="font-semibold text-sm text-cybr-secondary mb-2">CAPABILITIES</h5>
                  <ul className="list-disc list-inside pl-2 text-sm text-cybr-foreground/80">
                    <li>Simulated attack scenarios</li>
                    <li>Testing detection capabilities</li>
                    <li>Multi-cloud support</li>
                    <li>MITRE ATT&CK framework alignment</li>
                    <li>Customizable attack workflows</li>
                  </ul>
                </div>
              </div>
            </div>
            
            <div className="card mt-8">
              <h3 className="text-2xl font-bold mb-4">Specialized Testing Tools</h3>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-cybr-muted/20 rounded-lg p-4">
                  <h4 className="text-lg font-bold mb-2">CloudBrute</h4>
                  <p className="text-sm">Tool for finding cloud resources belonging to a target across AWS, Azure, and GCP.</p>
                </div>
                
                <div className="bg-cybr-muted/20 rounded-lg p-4">
                  <h4 className="text-lg font-bold mb-2">Cartography</h4>
                  <p className="text-sm">Tool that consolidates infrastructure assets and the relationships between them.</p>
                </div>
                
                <div className="bg-cybr-muted/20 rounded-lg p-4">
                  <h4 className="text-lg font-bold mb-2">CloudMapper</h4>
                  <p className="text-sm">Creates network diagrams of AWS environments for visual analysis of security issues.</p>
                </div>
                
                <div className="bg-cybr-muted/20 rounded-lg p-4">
                  <h4 className="text-lg font-bold mb-2">CloudSploit</h4>
                  <p className="text-sm">Security configuration scanner specifically designed for cloud infrastructure.</p>
                </div>
                
                <div className="bg-cybr-muted/20 rounded-lg p-4">
                  <h4 className="text-lg font-bold mb-2">Magellan</h4>
                  <p className="text-sm">Multi-cloud enumeration and vulnerability scanning tool.</p>
                </div>
                
                <div className="bg-cybr-muted/20 rounded-lg p-4">
                  <h4 className="text-lg font-bold mb-2">IAMFinder</h4>
                  <p className="text-sm">Discovers AWS IAM users, roles, and policies to find privilege escalation paths.</p>
                </div>
              </div>
            </div>
          </TabsContent>
          
          <TabsContent value="methodology" className="mt-6">
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Tool Selection Methodology</h3>
              <p className="mb-6">
                Selecting the right tools for cloud penetration testing depends on several factors including the target 
                environment, testing objectives, and specific requirements.
              </p>
              
              <div className="space-y-6">
                <div className="bg-cybr-muted/20 p-6 rounded-lg">
                  <h4 className="text-xl font-bold mb-3">Factors to Consider</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <h5 className="font-semibold mb-2">Cloud Environment</h5>
                      <ul className="list-disc list-inside pl-2 text-sm">
                        <li>Single cloud vs. multi-cloud</li>
                        <li>Specific services in use</li>
                        <li>Scale of deployment</li>
                        <li>Compliance requirements</li>
                      </ul>
                    </div>
                    
                    <div>
                      <h5 className="font-semibold mb-2">Testing Scope</h5>
                      <ul className="list-disc list-inside pl-2 text-sm">
                        <li>Infrastructure configuration assessment</li>
                        <li>Identity and access testing</li>
                        <li>Application security</li>
                        <li>Data security</li>
                      </ul>
                    </div>
                    
                    <div>
                      <h5 className="font-semibold mb-2">Tool Capabilities</h5>
                      <ul className="list-disc list-inside pl-2 text-sm">
                        <li>Detection avoidance capabilities</li>
                        <li>API rate limiting consideration</li>
                        <li>Documentation and support</li>
                        <li>Integration with other tools</li>
                      </ul>
                    </div>
                    
                    <div>
                      <h5 className="font-semibold mb-2">Operational Constraints</h5>
                      <ul className="list-disc list-inside pl-2 text-sm">
                        <li>Permission levels available</li>
                        <li>Testing timeframe</li>
                        <li>Allowed activities (ToE)</li>
                        <li>Reporting requirements</li>
                      </ul>
                    </div>
                  </div>
                </div>
                
                <div className="bg-cybr-muted/20 p-6 rounded-lg">
                  <h4 className="text-xl font-bold mb-4">Tool Selection Matrix</h4>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b">
                          <th className="text-left pb-2 font-bold">Tool Category</th>
                          <th className="text-left pb-2 font-bold">Best For</th>
                          <th className="text-left pb-2 font-bold">Example Tools</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y">
                        <tr>
                          <td className="py-3 pr-4 font-medium">Configuration Scanners</td>
                          <td className="py-3 pr-4">Identifying misconfigurations across large environments</td>
                          <td className="py-3">ScoutSuite, Prowler, CloudSploit</td>
                        </tr>
                        <tr>
                          <td className="py-3 pr-4 font-medium">Exploitation Frameworks</td>
                          <td className="py-3 pr-4">Actively testing attack vectors and privilege escalation</td>
                          <td className="py-3">Pacu, PowerZure, GCAT</td>
                        </tr>
                        <tr>
                          <td className="py-3 pr-4 font-medium">Reconnaissance Tools</td>
                          <td className="py-3 pr-4">External discovery of cloud assets and resources</td>
                          <td className="py-3">CloudBrute, S3Scanner, GCPBucketBrute</td>
                        </tr>
                        <tr>
                          <td className="py-3 pr-4 font-medium">Visualization Tools</td>
                          <td className="py-3 pr-4">Understanding relationships and attack paths</td>
                          <td className="py-3">CloudMapper, Cartography, AzureHound</td>
                        </tr>
                        <tr>
                          <td className="py-3 pr-4 font-medium">Vulnerability Scanners</td>
                          <td className="py-3 pr-4">Finding known vulnerabilities in cloud deployments</td>
                          <td className="py-3">Nuclei, Nessus, InsightVM</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
                
                <div className="bg-cybr-muted/20 p-6 rounded-lg">
                  <h4 className="text-xl font-bold mb-3">Building an Effective Tool Stack</h4>
                  <p className="mb-4">
                    For comprehensive cloud penetration testing, consider combining tools from different categories to cover 
                    all aspects of cloud security assessment.
                  </p>
                  
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="border border-cybr-muted rounded-md p-4">
                      <h5 className="font-bold mb-2 text-cybr-primary">Initial Assessment</h5>
                      <ul className="list-disc list-inside pl-2 text-sm space-y-1">
                        <li>Configuration scanners</li>
                        <li>Compliance benchmarking tools</li>
                        <li>Asset discovery tools</li>
                      </ul>
                    </div>
                    
                    <div className="border border-cybr-muted rounded-md p-4">
                      <h5 className="font-bold mb-2 text-cybr-primary">Deep Testing</h5>
                      <ul className="list-disc list-inside pl-2 text-sm space-y-1">
                        <li>Exploitation frameworks</li>
                        <li>Custom scripts for specific services</li>
                        <li>Specialized testing tools</li>
                      </ul>
                    </div>
                    
                    <div className="border border-cybr-muted rounded-md p-4">
                      <h5 className="font-bold mb-2 text-cybr-primary">Analysis & Reporting</h5>
                      <ul className="list-disc list-inside pl-2 text-sm space-y-1">
                        <li>Visualization tools</li>
                        <li>Impact assessment frameworks</li>
                        <li>Report generation tools</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </section>
  );
};

export default ToolsSection;
