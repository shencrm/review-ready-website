
import React from 'react';
import SecurityCard from '@/components/SecurityCard';
import { Smartphone, Shield, Bug, Database, Lock, Code, Terminal } from 'lucide-react';

const MobileCommonAttacksSection: React.FC = () => {
  return (
    <section className="space-y-12">
      <div>
        <h2 className="text-3xl font-bold mb-6">Common Mobile Security Attacks</h2>
        <p className="mb-8">
          Mobile applications face a variety of security threats, from insecure data storage to code injection.
          Understanding these attack vectors is crucial for effective mobile penetration testing.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <SecurityCard
            title="Insecure Data Storage"
            description="Mobile apps often store sensitive data insecurely in local databases, configuration files, or shared preferences, making it accessible to attackers with physical access or through malware."
            icon={<Database />}
            severity="high"
          />
          
          <SecurityCard
            title="Improper Certificate Validation"
            description="Many apps fail to properly validate SSL/TLS certificates, enabling MITM attacks where attackers can intercept and modify network traffic between the app and backend servers."
            icon={<Shield />}
            severity="high"
          />
          
          <SecurityCard
            title="Insecure Communication"
            description="Transmitting sensitive data over unencrypted channels or using weak encryption protocols exposes user information to interception and compromise."
            icon={<Lock />}
            severity="high"
          />
          
          <SecurityCard
            title="Client-Side Injection"
            description="Mobile apps may be vulnerable to injection attacks, including SQL injection, JavaScript injection, or WebView-based attacks that can compromise the app's data or functionality."
            icon={<Code />}
            severity="high"
          />
          
          <SecurityCard
            title="Insecure Authentication"
            description="Weak authentication mechanisms, such as persistent device identifiers or easily bypassed biometric implementations, can allow unauthorized access to user accounts."
            icon={<Lock />}
            severity="medium"
          />
          
          <SecurityCard
            title="Reverse Engineering"
            description="Mobile applications can be decompiled and analyzed, potentially exposing sensitive logic, hardcoded credentials, or proprietary algorithms."
            icon={<Bug />}
            severity="medium"
          />
          
          <SecurityCard
            title="Sensitive Data in Runtime"
            description="Critical data like encryption keys or session tokens may be exposed in memory dumps or through runtime analysis of the application."
            icon={<Terminal />}
            severity="medium"
          />
          
          <SecurityCard
            title="Broken Cryptography"
            description="Using custom or deprecated cryptographic implementations instead of standard, well-tested algorithms can lead to data exposure even when encryption is attempted."
            icon={<Shield />}
            severity="high"
          />
        </div>
      </div>
    </section>
  );
};

export default MobileCommonAttacksSection;
