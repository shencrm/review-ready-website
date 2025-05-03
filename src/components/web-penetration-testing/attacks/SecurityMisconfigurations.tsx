
import React from 'react';
import { ShieldX } from 'lucide-react';
import SecurityCard from '@/components/SecurityCard';

const SecurityMisconfigurations: React.FC = () => {
  return (
    <section id="misconfig" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Security Misconfigurations</h3>
      <p className="mb-6">
        Security misconfigurations include improperly configured permissions, unnecessary features enabled, 
        default accounts/passwords, overly informative error messages, and missing security hardening. 
        These are often the result of insecure default configurations, incomplete configurations, or ad hoc changes.
      </p>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <SecurityCard
          title="Default Configurations"
          description="Using default settings from sample applications, cloud services, or pre-configured development environments."
          severity="high"
        />
        <SecurityCard
          title="Unnecessary Features"
          description="Unused features and frameworks that expand attack surface without providing value."
          severity="medium"
        />
        <SecurityCard
          title="Missing Updates"
          description="Unpatched flaws in the application stack, including OS, web server, DBMS, and libraries."
          severity="high"
        />
      </div>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Common Misconfigurations</h4>
      <ul className="list-disc pl-6 space-y-2">
        <li>Directory listing enabled on the server</li>
        <li>Default or weak credentials for administrative interfaces</li>
        <li>Application servers with debug mode enabled in production</li>
        <li>Missing HTTP security headers or improper CORS settings</li>
        <li>Error messages revealing stack traces or sensitive information</li>
        <li>Outdated or vulnerable system components</li>
        <li>Unnecessary services running on the server</li>
      </ul>
    </section>
  );
};

export default SecurityMisconfigurations;
