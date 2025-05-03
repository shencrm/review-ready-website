
import React from 'react';
import { File } from 'lucide-react';

const InterviewQuestionsSection: React.FC = () => {
  const questions = [
    {
      q: "What is the difference between authentication and authorization?",
      a: "Authentication verifies who a user is (identity), while authorization determines what resources a user has permission to access (permissions)."
    },
    {
      q: "Explain the concept of Cross-Site Scripting (XSS) and how to prevent it.",
      a: "XSS is a vulnerability that allows attackers to inject client-side scripts into web pages viewed by other users. Prevention includes proper output encoding, Content Security Policy (CSP), and using frameworks that automatically escape output."
    },
    {
      q: "What is SQL Injection and how can it be prevented?",
      a: "SQL Injection occurs when untrusted data is sent to an interpreter as part of a command or query. Prevention methods include using parameterized queries, stored procedures, ORM frameworks, and input validation."
    },
    {
      q: "Explain the difference between Black Box, White Box, and Gray Box testing.",
      a: "Black Box testing is performed without knowledge of internal structures. White Box testing is done with full knowledge of the system's internals. Gray Box testing is a hybrid approach with partial knowledge of the system."
    },
    {
      q: "What tools do you typically use for web penetration testing?",
      a: "Common tools include Burp Suite, OWASP ZAP, Nmap, SQLmap, Metasploit, Nikto, and browser developer tools. Each serves different purposes in the testing process."
    },
    {
      q: "What is CSRF and how would you prevent it?",
      a: "Cross-Site Request Forgery tricks users into performing unwanted actions on sites they're authenticated to. Prevention includes using anti-CSRF tokens, SameSite cookies, checking Referer headers, and requiring re-authentication for sensitive operations."
    },
    {
      q: "How would you test for broken access controls?",
      a: "Test by attempting horizontal and vertical privilege escalation, modifying URL parameters, attempting to access unauthorized resources, testing API endpoints directly, and checking if client-side restrictions can be bypassed."
    },
    {
      q: "Explain the OWASP Top 10 and its importance.",
      a: "The OWASP Top 10 is a standard awareness document for web application security risks. It represents a broad consensus about the most critical security risks to web applications and helps organizations focus their security efforts on the most common threats."
    },
    {
      q: "What is the difference between a vulnerability and a risk?",
      a: "A vulnerability is a weakness that can be exploited by threats. Risk is the potential for loss or damage when a threat exploits a vulnerability. Risk takes into account both the likelihood and impact of a vulnerability being exploited."
    },
    {
      q: "How would you secure a REST API?",
      a: "Secure REST APIs by implementing proper authentication (OAuth, API keys, JWT), using HTTPS, implementing rate limiting, validating inputs, applying proper access controls, using secure headers, and logging and monitoring API usage."
    }
  ];

  return (
    <div className="space-y-8">
      <h2 className="section-title">Interview Questions</h2>
      
      <div className="space-y-6">
        {questions.map((item, index) => (
          <div key={index} className="card">
            <div className="flex gap-3 mb-3">
              <File className="h-5 w-5 text-cybr-primary flex-shrink-0 mt-1" />
              <h4 className="text-lg font-bold">{item.q}</h4>
            </div>
            <p className="pl-8">{item.a}</p>
          </div>
        ))}
      </div>

      <div className="card">
        <h3 className="text-xl font-bold mb-4">Interview Preparation Tips</h3>
        <ul className="list-disc pl-6 space-y-2">
          <li>Stay updated on the latest vulnerabilities and attack vectors</li>
          <li>Practice with CTF (Capture The Flag) challenges and vulnerable applications</li>
          <li>Be able to explain concepts in both technical and non-technical terms</li>
          <li>Prepare examples from your experience for common security scenarios</li>
          <li>Understand the business impact of security vulnerabilities</li>
          <li>Be familiar with compliance standards relevant to the industry (PCI DSS, HIPAA, GDPR, etc.)</li>
        </ul>
      </div>
    </div>
  );
};

export default InterviewQuestionsSection;
