
import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';

const Tools = () => {
  const staticTools = [
    {
      name: "SonarQube",
      description: "Open-source platform for continuous inspection of code quality and security vulnerabilities.",
      features: ["Multi-language support", "CI/CD integration", "Quality gates", "Security rules"]
    },
    {
      name: "Fortify",
      description: "Enterprise-grade static application security testing tool with comprehensive vulnerability detection.",
      features: ["Deep code analysis", "Integration API", "Vulnerability prioritization", "Custom rules"]
    },
    {
      name: "Checkmarx",
      description: "Static application security testing solution that identifies security vulnerabilities in source code.",
      features: ["Incremental scanning", "Best fix location", "DevOps integration", "Custom queries"]
    }
  ];

  const dynamicTools = [
    {
      name: "OWASP ZAP",
      description: "Free security tool for finding vulnerabilities in web applications during development and testing.",
      features: ["Active scanner", "Spider", "Fuzzer", "REST API"]
    },
    {
      name: "Burp Suite",
      description: "Integrated platform for security testing of web applications with various tools for different tasks.",
      features: ["Proxy", "Scanner", "Intruder", "Repeater", "Extensible with plugins"]
    },
    {
      name: "Acunetix",
      description: "Automated web vulnerability scanner that checks for XSS, SQL Injection and other vulnerabilities.",
      features: ["AcuSensor technology", "Malware detection", "Interactive dashboard", "API scanning"]
    }
  ];

  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      
      <main className="flex-grow py-12">
        <div className="container mx-auto px-4">
          <div className="mb-12">
            <h1 className="text-4xl font-bold mb-6">Tools and Automation</h1>
            <div className="h-1 w-24 bg-cybr-primary mb-6"></div>
            <p className="text-xl text-cybr-foreground/80">
              Leverage automated tools to enhance your secure code review process.
            </p>
          </div>
          
          <section className="mb-12">
            <h2 className="text-2xl font-bold mb-6">Static Analysis Tools</h2>
            <p className="mb-6">
              Static Application Security Testing (SAST) tools analyze source code without executing it, identifying potential 
              security vulnerabilities early in the development process.
            </p>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {staticTools.map((tool, index) => (
                <div key={index} className="card h-full">
                  <h3 className="text-xl font-bold mb-3">{tool.name}</h3>
                  <p className="mb-4 text-cybr-foreground/80">{tool.description}</p>
                  <h4 className="font-semibold text-sm text-cybr-secondary mb-2">KEY FEATURES</h4>
                  <ul className="list-disc list-inside pl-4 text-sm text-cybr-foreground/80">
                    {tool.features.map((feature, idx) => (
                      <li key={idx}>{feature}</li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </section>
          
          <section className="mb-12">
            <h2 className="text-2xl font-bold mb-6">Dynamic Analysis Tools</h2>
            <p className="mb-6">
              Dynamic Application Security Testing (DAST) tools analyze applications in their running state, 
              identifying vulnerabilities that might not be apparent in static code.
            </p>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {dynamicTools.map((tool, index) => (
                <div key={index} className="card h-full">
                  <h3 className="text-xl font-bold mb-3">{tool.name}</h3>
                  <p className="mb-4 text-cybr-foreground/80">{tool.description}</p>
                  <h4 className="font-semibold text-sm text-cybr-secondary mb-2">KEY FEATURES</h4>
                  <ul className="list-disc list-inside pl-4 text-sm text-cybr-foreground/80">
                    {tool.features.map((feature, idx) => (
                      <li key={idx}>{feature}</li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </section>
          
          <section className="mb-12">
            <h2 className="text-2xl font-bold mb-6">Integrating Tools into CI/CD</h2>
            <div className="card">
              <p className="mb-4">
                Integrating security tools into your Continuous Integration/Continuous Delivery pipeline 
                helps automate security testing and catch vulnerabilities early.
              </p>
              
              <div className="space-y-6 mt-6">
                <div>
                  <h3 className="text-xl font-bold mb-3">Benefits of CI/CD Integration</h3>
                  <ul className="list-disc list-inside space-y-2 pl-4 text-cybr-foreground/80">
                    <li><span className="font-semibold">Early Detection:</span> Find vulnerabilities during development, not production</li>
                    <li><span className="font-semibold">Consistent Testing:</span> Every code change undergoes the same security checks</li>
                    <li><span className="font-semibold">Feedback Loop:</span> Developers receive immediate security feedback</li>
                    <li><span className="font-semibold">Historical Tracking:</span> Monitor security improvements over time</li>
                  </ul>
                </div>
                
                <div>
                  <h3 className="text-xl font-bold mb-3">Implementation Steps</h3>
                  <ol className="list-decimal list-inside space-y-3 pl-4 text-cybr-foreground/80">
                    <li><span className="font-semibold">Select Appropriate Tools:</span> Choose tools that integrate well with your tech stack and CI/CD platform</li>
                    <li><span className="font-semibold">Configure Quality Gates:</span> Define security thresholds that must be met before deployment</li>
                    <li><span className="font-semibold">Prioritize Findings:</span> Focus on high-risk vulnerabilities first</li>
                    <li><span className="font-semibold">Automate Reporting:</span> Set up notifications and dashboards for visibility</li>
                    <li><span className="font-semibold">Continuous Improvement:</span> Regularly update rules and scan configurations</li>
                  </ol>
                </div>
                
                <div>
                  <h3 className="text-xl font-bold mb-3">Common Integration Points</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3">
                    <div className="bg-cybr-muted/50 p-4 rounded-md">
                      <h4 className="font-semibold text-cybr-secondary mb-2">Pre-Commit Hooks</h4>
                      <p className="text-sm text-cybr-foreground/80">
                        Run lightweight security checks before code is committed to version control.
                      </p>
                    </div>
                    
                    <div className="bg-cybr-muted/50 p-4 rounded-md">
                      <h4 className="font-semibold text-cybr-secondary mb-2">Pull Request Analysis</h4>
                      <p className="text-sm text-cybr-foreground/80">
                        Scan code changes when pull requests are created or updated.
                      </p>
                    </div>
                    
                    <div className="bg-cybr-muted/50 p-4 rounded-md">
                      <h4 className="font-semibold text-cybr-secondary mb-2">Build Pipeline</h4>
                      <p className="text-sm text-cybr-foreground/80">
                        Run comprehensive scans during the build process.
                      </p>
                    </div>
                    
                    <div className="bg-cybr-muted/50 p-4 rounded-md">
                      <h4 className="font-semibold text-cybr-secondary mb-2">Pre-Deployment</h4>
                      <p className="text-sm text-cybr-foreground/80">
                        Final security validations before code is deployed to production.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>
          
          <section>
            <h2 className="text-2xl font-bold mb-6">Tool Selection Strategy</h2>
            <div className="card">
              <p className="mb-6">
                Choosing the right security tools requires considering factors such as your tech stack, team expertise, 
                budget constraints, and specific security requirements.
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-cybr-muted/50 p-6 rounded-md">
                  <h3 className="text-xl font-bold mb-3">Technology Fit</h3>
                  <ul className="list-disc list-inside pl-4 text-cybr-foreground/80">
                    <li>Language and framework support</li>
                    <li>Integration capabilities</li>
                    <li>Deployment model compatibility</li>
                    <li>Performance impact</li>
                  </ul>
                </div>
                
                <div className="bg-cybr-muted/50 p-6 rounded-md">
                  <h3 className="text-xl font-bold mb-3">Organizational Needs</h3>
                  <ul className="list-disc list-inside pl-4 text-cybr-foreground/80">
                    <li>Compliance requirements</li>
                    <li>Team skill level</li>
                    <li>Budget considerations</li>
                    <li>Reporting requirements</li>
                  </ul>
                </div>
                
                <div className="bg-cybr-muted/50 p-6 rounded-md">
                  <h3 className="text-xl font-bold mb-3">Tool Effectiveness</h3>
                  <ul className="list-disc list-inside pl-4 text-cybr-foreground/80">
                    <li>False positive rate</li>
                    <li>Detection capability</li>
                    <li>Rule customization</li>
                    <li>Community/vendor support</li>
                  </ul>
                </div>
              </div>
            </div>
          </section>
        </div>
      </main>
      
      <Footer />
    </div>
  );
};

export default Tools;
