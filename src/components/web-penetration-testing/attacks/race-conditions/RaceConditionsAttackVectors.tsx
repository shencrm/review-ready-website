
import React from 'react';

const RaceConditionsAttackVectors: React.FC = () => {
  return (
    <div className="mb-8">
      <h4 className="text-xl font-semibold mb-4">Common Race Condition Attack Vectors</h4>
      
      <h5 className="text-lg font-medium mb-3">1. Banking/Financial Race Conditions</h5>
      <p className="mb-4">
        Exploiting timing windows in financial transactions to withdraw more funds than available.
      </p>
      <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
        <p className="font-semibold mb-2">Attack Scenario:</p>
        <pre className="text-sm bg-cybr-muted p-2 rounded">
{`1. Attacker has $100 in account
2. Sends 10 simultaneous withdrawal requests for $100 each
3. All requests pass balance check before any updates balance
4. Attacker successfully withdraws $1000 from $100 account`}
        </pre>
      </div>

      <h5 className="text-lg font-medium mb-3">2. File Upload Race Conditions</h5>
      <p className="mb-4">
        Exploiting timing between file upload and validation to bypass security checks.
      </p>
      <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
        <p className="font-semibold mb-2">Attack Process:</p>
        <pre className="text-sm bg-cybr-muted p-2 rounded">
{`1. Upload malicious file (e.g., shell.php)
2. Quickly access file before validation completes
3. Execute malicious code before file is removed
4. Gain system access or execute arbitrary commands`}
        </pre>
      </div>

      <h5 className="text-lg font-medium mb-3">3. Session Fixation Race Conditions</h5>
      <p className="mb-4">
        Exploiting timing in session management to hijack or elevate privileges.
      </p>
      <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
        <p className="font-semibold mb-2">Exploitation Steps:</p>
        <pre className="text-sm bg-cybr-muted p-2 rounded">
{`1. Login with valid credentials
2. Simultaneously send privilege escalation requests
3. Exploit timing between authentication and authorization
4. Gain elevated privileges before session is properly established`}
        </pre>
      </div>
    </div>
  );
};

export default RaceConditionsAttackVectors;
