
import React from 'react';
import LDAPInjection from './other-injection/LDAPInjection';
import NoSQLInjection from './other-injection/NoSQLInjection';
import SSTInjection from './other-injection/SSTInjection';
import XPathInjection from './other-injection/XPathInjection';

const OtherInjectionFlaws: React.FC = () => {
  return (
    <section id="other-injection" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Other Injection Flaws</h3>
      
      <div className="mb-8">
        <p className="mb-4">
          Beyond SQL injection, command injection, and XSS, there are various other injection vulnerabilities that can affect
          web applications. These occur when untrusted data is processed without proper validation or sanitization,
          allowing attackers to inject malicious content or commands into different interpreters and processing engines.
        </p>
        <p className="mb-4">
          These injection flaws exploit the fundamental weakness where user input is trusted and directly incorporated
          into queries, commands, or templates without proper bounds checking or escaping. Each type targets different
          backend systems and processing mechanisms, but they all share the common vulnerability pattern of insufficient
          input validation and output encoding.
        </p>
      </div>

      <LDAPInjection />
      <NoSQLInjection />
      <SSTInjection />
      <XPathInjection />

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Cross-Attack Prevention Strategy</h4>
        <p className="mb-4">
          All injection vulnerabilities share common prevention principles that can be applied across different attack types:
        </p>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>Input Validation:</strong> Validate all user inputs at application boundaries</li>
          <li><strong>Output Encoding:</strong> Properly encode data when incorporating it into queries or templates</li>
          <li><strong>Parameterized Queries:</strong> Use prepared statements and parameterized queries when available</li>
          <li><strong>Principle of Least Privilege:</strong> Limit application and database permissions</li>
          <li><strong>Security Testing:</strong> Implement automated testing for injection vulnerabilities</li>
          <li><strong>Error Handling:</strong> Never expose system details in error messages</li>
          <li><strong>Security Headers:</strong> Implement appropriate security headers like Content Security Policy</li>
          <li><strong>Regular Updates:</strong> Keep all frameworks, libraries, and systems updated</li>
        </ul>
      </div>
    </section>
  );
};

export default OtherInjectionFlaws;
