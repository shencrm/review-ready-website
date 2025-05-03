
import React from 'react';
import SecurityCard from '@/components/SecurityCard';
import { Cloud, Shield, Bug, Database, Server, Key, Lock, Code } from 'lucide-react';

const CommonAttacksSection: React.FC = () => {
  return (
    <section className="space-y-12">
      <div>
        <h2 className="text-3xl font-bold mb-6">Common Cloud Security Attacks</h2>
        <p className="mb-8">
          Cloud environments present unique security challenges compared to traditional on-premises infrastructure.
          Understanding common attack vectors is essential for effective cloud penetration testing.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <SecurityCard
            title="Misconfiguration Exploits"
            description="Exploiting improperly configured cloud resources, such as public S3 buckets, open security groups, or excessive IAM permissions, is one of the most common attack vectors in cloud environments."
            icon={<Cloud />}
            severity="high"
          />
          
          <SecurityCard
            title="Account Hijacking"
            description="Attackers target cloud service accounts through phishing, credential stuffing, or exploiting weak authentication mechanisms to gain unauthorized access to cloud resources."
            icon={<Key />}
            severity="high"
          />
          
          <SecurityCard
            title="Insecure APIs"
            description="Cloud services expose APIs that may contain vulnerabilities, lack proper authentication, or have insufficient rate limiting, allowing attackers to abuse functionality."
            icon={<Code />}
            severity="high"
          />
          
          <SecurityCard
            title="Privilege Escalation"
            description="Attackers exploit IAM misconfigurations, service roles, or vulnerabilities to elevate privileges and gain broader access to cloud resources."
            icon={<Lock />}
            severity="high"
          />
          
          <SecurityCard
            title="Metadata Service Attacks"
            description="Cloud instance metadata services can be exploited through SSRF or other vulnerabilities to access sensitive information including authentication credentials."
            icon={<Database />}
            severity="medium"
          />
          
          <SecurityCard
            title="Container Escape"
            description="Attackers break out of containerized environments to access the underlying host or other containers in the same cluster."
            icon={<Server />}
            severity="medium"
          />
          
          <SecurityCard
            title="Serverless Function Attacks"
            description="Vulnerabilities in serverless functions can lead to unauthorized execution, data exposure, or dependency-based attacks."
            icon={<Code />}
            severity="medium"
          />
          
          <SecurityCard
            title="Cross-Tenant Attacks"
            description="Exploiting vulnerabilities in cloud infrastructure to breach isolation boundaries between different customer environments."
            icon={<Shield />}
            severity="high"
          />
        </div>
      </div>
    </section>
  );
};

export default CommonAttacksSection;
