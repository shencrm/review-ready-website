
import React from 'react';
import { ShieldAlert } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const CSRF: React.FC = () => {
  return (
    <section id="csrf" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Cross-Site Request Forgery (CSRF)</h3>
      <p className="mb-6">
        CSRF attacks trick authenticated users into executing unwanted actions on a web application where they're currently authenticated.
        This exploits the trust a website has in a user's browser, making the victim perform state-changing requests like fund transfers,
        password changes, or account modifications without their knowledge or consent.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">How CSRF Works</h4>
      <p className="mb-4">
        CSRF attacks typically follow these steps:
      </p>
      <ol className="list-decimal pl-6 space-y-2 mb-4">
        <li>The victim logs into a vulnerable website (e.g., banking site) and receives a session cookie</li>
        <li>Without logging out, the victim visits a malicious website controlled by the attacker</li>
        <li>The malicious site contains code that automatically submits a form or sends a request to the vulnerable site</li>
        <li>The victim's browser automatically includes the session cookies when making the request</li>
        <li>The vulnerable site processes the request as if the victim intentionally submitted it</li>
      </ol>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Example Attack</h4>
      <CodeExample 
        language="html" 
        isVulnerable={true}
        title="Malicious Website Code" 
        code={`<!-- Attacker's website contains this hidden form -->
<form action="https://bank.example/transfer" method="POST" id="exploit-form">
  <input type="hidden" name="recipient" value="attacker">
  <input type="hidden" name="amount" value="10000">
</form>
<script>
  document.getElementById("exploit-form").submit();
</script>

<!-- When victim visits the attacker's site while logged into their bank,
     this form automatically submits, sending money to the attacker -->

<!-- Alternative methods include:
  - Using an image tag: <img src="https://bank.example/transfer?to=attacker&amount=1000">
  - Using XMLHttpRequest or fetch with simple GET requests
  - Embedding malicious actions in legitimate-looking content -->

<!-- The vulnerable bank site has no protection against cross-site requests -->
`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="CSRF Protection Implementation" 
        code={`// Server-side code (Express.js example)
const express = require('express');
const csrf = require('csurf');
const app = express();

// Setup CSRF protection
const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);

app.get('/transfer-form', (req, res) => {
  // Include CSRF token in form
  res.render('transfer', { csrfToken: req.csrfToken() });
});

app.post('/transfer', (req, res) => {
  // The csurf middleware will automatically validate the token
  // and reject the request if invalid
  
  // Process the transfer if token is valid
  processTransfer(req.body);
  res.send('Transfer complete');
});

// SameSite cookie attribute for additional protection
app.use((req, res, next) => {
  res.cookie('session', 'value', {
    httpOnly: true,
    secure: true,
    sameSite: 'strict' // Prevents the cookie from being sent in cross-site requests
  });
  next();
});

// Custom token verification logic (example)
function validateCsrfToken(req, res, next) {
  // Get token from request header or form body
  const token = req.headers['x-csrf-token'] || req.body._csrf;
  
  // Get stored token from user's session
  const storedToken = req.session.csrfToken;
  
  if (!token || token !== storedToken) {
    return res.status(403).send('Invalid CSRF token');
  }
  
  next();
}`} 
      />
      
      <CodeExample 
        language="html" 
        isVulnerable={false}
        title="Protected Form" 
        code={`<!-- Form with CSRF token -->
<form action="/transfer" method="POST">
  <input type="hidden" name="_csrf" value="{{csrfToken}}">
  <input type="text" name="recipient" placeholder="Recipient">
  <input type="number" name="amount" placeholder="Amount">
  <button type="submit">Transfer</button>
</form>

<!-- Using CSRF token in JavaScript fetch request -->
<script>
  async function sendRequest() {
    const response = await fetch('/api/action', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
      },
      body: JSON.stringify({ data: 'value' })
    });
    return response.json();
  }
</script>`} 
      />
      
      <h4 className="text-xl font-semibold mt-6 mb-3">CSRF Prevention Methods</h4>
      <ul className="list-disc pl-6 space-y-2">
        <li><strong>CSRF Tokens:</strong> Unique, unpredictable values in forms that must be verified server-side</li>
        <li><strong>SameSite Cookie Attribute:</strong> Setting cookies as SameSite=Strict or SameSite=Lax</li>
        <li><strong>Custom Request Headers:</strong> For AJAX requests, requiring custom headers that simple forms can't add</li>
        <li><strong>Double Submit Cookie:</strong> Sending the same random token in both a cookie and request parameter</li>
        <li><strong>Requiring Re-authentication:</strong> For sensitive operations like changing passwords or making payments</li>
      </ul>
    </section>
  );
};

export default CSRF;
