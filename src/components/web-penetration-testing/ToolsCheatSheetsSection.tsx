
import React from 'react';
import { KeyRound, Code } from 'lucide-react';

const ToolsCheatSheetsSection: React.FC = () => {
  return (
    <div className="space-y-8">
      <h2 className="section-title">Tools & Cheat Sheets</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <div>
          <h3 className="text-xl font-bold mb-4">Penetration Testing Tools</h3>
          
          <div className="space-y-4">
            <div className="card">
              <h4 className="font-semibold mb-2">Web Proxies</h4>
              <ul className="list-disc pl-6 space-y-1">
                <li><strong>Burp Suite</strong> - Intercepting proxy with scanning capabilities</li>
                <li><strong>OWASP ZAP</strong> - Free alternative to Burp with automation features</li>
                <li><strong>Mitmproxy</strong> - Command-line based HTTP proxy</li>
              </ul>
            </div>
            
            <div className="card">
              <h4 className="font-semibold mb-2">Scanning & Enumeration</h4>
              <ul className="list-disc pl-6 space-y-1">
                <li><strong>Nmap</strong> - Network discovery and security auditing</li>
                <li><strong>Nikto</strong> - Web server scanner</li>
                <li><strong>Amass</strong> - Network mapping of attack surfaces</li>
                <li><strong>ffuf</strong> - Fast web fuzzer for content discovery</li>
              </ul>
            </div>
            
            <div className="card">
              <h4 className="font-semibold mb-2">Exploitation Frameworks</h4>
              <ul className="list-disc pl-6 space-y-1">
                <li><strong>Metasploit</strong> - Advanced open source platform for exploit development</li>
                <li><strong>BeEF</strong> - Browser Exploitation Framework</li>
                <li><strong>SQLmap</strong> - Automated SQL injection tool</li>
              </ul>
            </div>
          </div>
        </div>
        
        <div>
          <h3 className="text-xl font-bold mb-4">Cheat Sheets & Reference Materials</h3>
          
          <div className="space-y-4">
            <div className="card">
              <h4 className="font-semibold mb-2">OWASP Resources</h4>
              <ul className="list-disc pl-6 space-y-1">
                <li><a href="https://cheatsheetseries.owasp.org/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP Cheat Sheet Series</a></li>
                <li><a href="https://owasp.org/www-project-web-security-testing-guide/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP Web Security Testing Guide</a></li>
                <li><a href="https://owasp.org/www-project-api-security/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP API Security Top 10</a></li>
              </ul>
            </div>
            
            <div className="card">
              <h4 className="font-semibold mb-2">Payload Collections</h4>
              <ul className="list-disc pl-6 space-y-1">
                <li><a href="https://github.com/swisskyrepo/PayloadsAllTheThings" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">PayloadsAllTheThings</a> - Collection of useful payloads</li>
                <li><a href="https://github.com/OWASP/CheatSheetSeries" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP CheatSheetSeries GitHub</a></li>
                <li><a href="https://portswigger.net/web-security/cross-site-scripting/cheat-sheet" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">PortSwigger XSS Cheat Sheet</a></li>
              </ul>
            </div>
            
            <div className="card">
              <h4 className="font-semibold mb-2">Vulnerable Practice Applications</h4>
              <ul className="list-disc pl-6 space-y-1">
                <li><strong>OWASP Juice Shop</strong> - Modern vulnerable web application</li>
                <li><strong>WebGoat</strong> - Deliberately insecure application</li>
                <li><strong>DVWA</strong> - Damn Vulnerable Web Application</li>
                <li><strong>bWAPP</strong> - Buggy web application for learning</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
      
      <div className="card">
        <h3 className="text-xl font-bold mb-4">Command References</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="font-semibold mb-2">Reconnaissance</h4>
            <pre className="bg-cybr-muted p-3 rounded text-sm overflow-x-auto">
              <code># Find subdomains
amass enum -d example.com

# Port scanning
nmap -sV -p- example.com

# Content discovery
ffuf -w wordlist.txt -u https://example.com/FUZZ
              </code>
            </pre>
          </div>
          
          <div>
            <h4 className="font-semibold mb-2">SQL Injection</h4>
            <pre className="bg-cybr-muted p-3 rounded text-sm overflow-x-auto">
              <code># Basic tests
' OR 1=1 --
" OR 1=1 --
' UNION SELECT 1,2,3 --

# SQLMap
sqlmap -u "http://example.com/?id=1" --dbs
              </code>
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ToolsCheatSheetsSection;
