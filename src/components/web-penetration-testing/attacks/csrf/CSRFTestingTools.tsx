
import React from 'react';

const CSRFTestingTools: React.FC = () => {
  return (
    <div>
      <h4 className="text-xl font-semibold mb-4">CSRF Testing Tools and Resources</h4>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-4 bg-cybr-muted/50 rounded-md">
          <h5 className="font-semibold mb-2">Automated Scanning Tools</h5>
          <ul className="list-disc pl-6 space-y-1 text-sm">
            <li><strong>Burp Suite Professional:</strong> Advanced CSRF detection with PoC generation</li>
            <li><strong>OWASP ZAP:</strong> Active and passive CSRF vulnerability scanning</li>
            <li><strong>CSRFtester:</strong> Specialized tool for comprehensive CSRF testing</li>
            <li><strong>Nuclei:</strong> Template-based CSRF detection and exploitation</li>
            <li><strong>W3af:</strong> Web application scanner with CSRF detection capabilities</li>
            <li><strong>Acunetix:</strong> Commercial scanner with CSRF vulnerability detection</li>
          </ul>
        </div>
        
        <div className="p-4 bg-cybr-muted/50 rounded-md">
          <h5 className="font-semibold mb-2">Manual Testing and Development Tools</h5>
          <ul className="list-disc pl-6 space-y-1 text-sm">
            <li><strong>Browser DevTools:</strong> Network monitoring and request analysis</li>
            <li><strong>Postman/Insomnia:</strong> API testing and request crafting</li>
            <li><strong>curl:</strong> Command-line HTTP request testing</li>
            <li><strong>CSRF PoC Generator:</strong> Automated HTML form generation tools</li>
            <li><strong>HackBar:</strong> Browser extension for security testing</li>
            <li><strong>Custom Scripts:</strong> Python, JavaScript automation for testing</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default CSRFTestingTools;
