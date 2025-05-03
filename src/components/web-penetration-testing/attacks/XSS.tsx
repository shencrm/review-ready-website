
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
        and defacement.
      </p>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <SecurityCard
          title="Reflected XSS"
          description="Non-persistent attack where malicious script is reflected off a web server, such as in search results or error messages."
          severity="medium"
        />
        <SecurityCard
          title="Stored XSS"
          description="Malicious script is stored on the target server (e.g., in a database) and later retrieved by victims when they access the affected content."
          severity="high"
        />
        <SecurityCard
          title="DOM-based XSS"
          description="Vulnerability exists in client-side code rather than server-side code, where JavaScript modifies the DOM in an unsafe way."
          severity="medium"
        />
      </div>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Example Attack</h4>
      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable Code" 
        code={`// Directly inserting user input into HTML
document.getElementById("output").innerHTML = 
  "Search results for: " + userInput;

// Attacker input: <script>sendCookiesToAttacker(document.cookie)</script>
// This executes the script in the victim's browser`} 
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
};`} 
      />
    </section>
  );
};

export default XSS;
