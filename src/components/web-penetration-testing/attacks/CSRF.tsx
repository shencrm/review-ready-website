
import React from 'react';
import { ShieldAlert } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const CSRF: React.FC = () => {
  return (
    <section id="csrf" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Cross-Site Request Forgery (CSRF)</h3>
      <p className="mb-6">
        CSRF attacks trick authenticated users into executing unwanted actions on a web application where they're currently authenticated.
        This exploits the trust a website has in a user's browser, making the victim perform state-changing requests like fund transfers
        or password changes without their knowledge.
      </p>
      
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
     this form automatically submits, sending money to the attacker -->`} 
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
});`} 
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
</form>`} 
      />
    </section>
  );
};

export default CSRF;
