
import React from 'react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { InfoIcon } from 'lucide-react';
import SecurityCard from '@/components/SecurityCard';

const CSRFIntroduction: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Introduction */}
      <div>
        <p className="mb-4">
          CSRF attacks trick authenticated users into executing unwanted actions on a web application where they are currently authenticated.
          This exploits the trust a website has in a user's browser, making the victim perform state-changing requests like fund transfers,
          password changes, or account modifications without their knowledge or consent. CSRF is particularly dangerous because it leverages
          the victim's existing authenticated session to perform malicious actions.
        </p>
        
        <Alert className="mb-4 text-amber-900 dark:text-amber-200 bg-slate-50">
          <InfoIcon className="h-4 w-4" />
          <AlertTitle>Attacker's Goal</AlertTitle>
          <AlertDescription>
            Force authenticated users to perform unintended actions such as changing passwords, transferring funds, 
            modifying account settings, or performing administrative functions without their knowledge.
          </AlertDescription>
        </Alert>
      </div>

      {/* Attack Mechanics */}
      <div>
        <h4 className="text-xl font-semibold mb-4">How CSRF Attacks Work</h4>
        <div className="p-4 bg-cybr-muted/50 rounded-md mb-4">
          <h5 className="font-semibold mb-2">Attack Flow:</h5>
          <ol className="list-decimal pl-6 space-y-2">
            <li><strong>User Authentication:</strong> The victim logs into a vulnerable website (e.g., banking site) and receives a session cookie</li>
            <li><strong>Session Persistence:</strong> Without logging out, the victim visits a malicious website controlled by the attacker</li>
            <li><strong>Malicious Request:</strong> The malicious site contains code that automatically submits a form or sends a request to the vulnerable site</li>
            <li><strong>Automatic Cookie Inclusion:</strong> The victim's browser automatically includes the session cookies when making the request</li>
            <li><strong>Server Processing:</strong> The vulnerable site processes the request as if the victim intentionally submitted it</li>
            <li><strong>Action Execution:</strong> The malicious action is completed using the victim's authenticated session</li>
          </ol>
        </div>
      </div>

      {/* Vulnerable Components */}
      <div>
        <h4 className="text-xl font-semibold mb-4">Commonly Vulnerable Components</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
          <SecurityCard
            title="State-Changing Forms"
            description="Any form that performs actions like password changes, profile updates, money transfers, or administrative functions without CSRF protection."
            severity="high"
          />
          <SecurityCard
            title="RESTful APIs"
            description="API endpoints that rely solely on cookies for authentication and perform state-changing operations via GET/POST requests."
            severity="high"
          />
          <SecurityCard
            title="Single Page Applications"
            description="SPAs that make AJAX requests without including CSRF tokens or relying only on cookie-based authentication."
            severity="medium"
          />
          <SecurityCard
            title="Administrative Interfaces"
            description="Admin panels and management interfaces that perform privileged operations without proper CSRF protection."
            severity="high"
          />
        </div>
      </div>
    </div>
  );
};

export default CSRFIntroduction;
