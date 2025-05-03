
import React from 'react';
import { Code } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';

const XSS: React.FC = () => {
  return (
    <section id="xss" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Cross-Site Scripting (XSS)</h3>
      <p className="mb-6">
        XSS attacks occur when an application includes untrusted data in a new web page without proper validation or escaping,
        allowing attackers to execute scripts in the victim's browser. This can lead to session hijacking, credential theft,
        malicious redirects, and website defacement. XSS is consistently ranked among the top web application vulnerabilities.
      </p>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <SecurityCard
          title="Reflected XSS"
          description="Non-persistent attack where malicious script is reflected off a web server, typically through URLs, search results, or error messages. The attacker tricks victims into clicking malicious links."
          severity="medium"
        />
        <SecurityCard
          title="Stored XSS"
          description="Malicious script is permanently stored on the target server (e.g., in a database, comment field, forum post) and later retrieved by victims during normal browsing. Most dangerous form of XSS."
          severity="high"
        />
        <SecurityCard
          title="DOM-based XSS"
          description="Vulnerability exists in client-side code rather than server-side code. JavaScript modifies the DOM in an unsafe way based on attacker-controllable data sources like URL fragments or localStorage."
          severity="medium"
        />
      </div>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Impact of XSS Attacks</h4>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li><strong>Session Hijacking:</strong> Stealing session cookies to impersonate users</li>
        <li><strong>Credential Harvesting:</strong> Creating fake login forms to steal passwords</li>
        <li><strong>Keylogging:</strong> Recording user keypresses to capture sensitive information</li>
        <li><strong>Phishing:</strong> Injecting convincing phishing content into trusted sites</li>
        <li><strong>Web Application Defacement:</strong> Modifying the appearance of websites</li>
        <li><strong>Malware Distribution:</strong> Redirecting users to malware downloads</li>
      </ul>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Example Attack</h4>
      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable Code" 
        code={`// Directly inserting user input into HTML
document.getElementById("output").innerHTML = 
  "Search results for: " + userInput;

// Attacker input: <script>sendCookiesToAttacker(document.cookie)</script>
// This executes the script in the victim's browser

// Server-side example (PHP)
<?php
echo '<div>Welcome, ' . $_GET['name'] . '!</div>';
?>
// Attacker request: /page.php?name=<script>alert(document.cookie)</script>

// React example with dangerouslySetInnerHTML
function Comment({ userComment }) {
  return <div dangerouslySetInnerHTML={{ __html: userComment }} />;
}
// This renders userComment as HTML without sanitization`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure Implementation" 
        code={`// Using safe methods to add text content
document.getElementById("output").textContent = 
  "Search results for: " + userInput;

// Or properly escaping HTML on the server side
const escapeHtml = (unsafe) => {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

// Safe server-side rendering (PHP)
<?php
echo '<div>Welcome, ' . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') . '!</div>';
?>

// Safe React component using proper encoding
function Comment({ userComment }) {
  // userComment is automatically encoded when used as text content
  return <div>{userComment}</div>;
}

// Additional protections:
// 1. Implement Content-Security-Policy headers
// 2. Use frameworks that escape output by default (React, Vue, Angular)
// 3. Apply input validation with allowlists
// 4. Use HttpOnly cookies to prevent JavaScript access to sensitive cookies
// 5. Use X-XSS-Protection header for older browsers`} 
      />
    </section>
  );
};

export default XSS;
