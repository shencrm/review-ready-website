
import React, { useState } from 'react';
import SecurityCard from '@/components/SecurityCard';
import { Cloud, Shield, Bug, Database, Server, Key, Lock, Code } from 'lucide-react';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import { ScrollArea } from '@/components/ui/scroll-area';

interface AttackSection {
  id: string;
  title: string;
  icon: React.ReactNode;
  content: React.ReactNode;
}

const CommonAttacksSection: React.FC = () => {
  const [selectedSection, setSelectedSection] = useState<string>('misconfiguration');

  const attackSections: AttackSection[] = [
    {
      id: 'misconfiguration',
      title: 'Misconfiguration Exploits',
      icon: <Cloud className="h-5 w-5" />,
      content: (
        <SecurityCard
          title="Misconfiguration Exploits"
          description="Exploiting improperly configured cloud resources, such as public S3 buckets, open security groups, or excessive IAM permissions, is one of the most common attack vectors in cloud environments."
          icon={<Cloud />}
          severity="high"
        />
      )
    },
    {
      id: 'account-hijacking',
      title: 'Account Hijacking',
      icon: <Key className="h-5 w-5" />,
      content: (
        <SecurityCard
          title="Account Hijacking"
          description="Attackers target cloud service accounts through phishing, credential stuffing, or exploiting weak authentication mechanisms to gain unauthorized access to cloud resources."
          icon={<Key />}
          severity="high"
        />
      )
    },
    {
      id: 'insecure-apis',
      title: 'Insecure APIs',
      icon: <Code className="h-5 w-5" />,
      content: (
        <SecurityCard
          title="Insecure APIs"
          description="Cloud services expose APIs that may contain vulnerabilities, lack proper authentication, or have insufficient rate limiting, allowing attackers to abuse functionality."
          icon={<Code />}
          severity="high"
        />
      )
    },
    {
      id: 'privilege-escalation',
      title: 'Privilege Escalation',
      icon: <Lock className="h-5 w-5" />,
      content: (
        <SecurityCard
          title="Privilege Escalation"
          description="Attackers exploit IAM misconfigurations, service roles, or vulnerabilities to elevate privileges and gain broader access to cloud resources."
          icon={<Lock />}
          severity="high"
        />
      )
    },
    {
      id: 'metadata-service',
      title: 'Metadata Service Attacks',
      icon: <Database className="h-5 w-5" />,
      content: (
        <SecurityCard
          title="Metadata Service Attacks"
          description="Cloud instance metadata services can be exploited through SSRF or other vulnerabilities to access sensitive information including authentication credentials."
          icon={<Database />}
          severity="medium"
        />
      )
    },
    {
      id: 'container-escape',
      title: 'Container Escape',
      icon: <Server className="h-5 w-5" />,
      content: (
        <SecurityCard
          title="Container Escape"
          description="Attackers break out of containerized environments to access the underlying host or other containers in the same cluster."
          icon={<Server />}
          severity="medium"
        />
      )
    },
    {
      id: 'serverless-attacks',
      title: 'Serverless Function Attacks',
      icon: <Code className="h-5 w-5" />,
      content: (
        <SecurityCard
          title="Serverless Function Attacks"
          description="Vulnerabilities in serverless functions can lead to unauthorized execution, data exposure, or dependency-based attacks."
          icon={<Code />}
          severity="medium"
        />
      )
    },
    {
      id: 'cross-tenant',
      title: 'Cross-Tenant Attacks',
      icon: <Shield className="h-5 w-5" />,
      content: (
        <SecurityCard
          title="Cross-Tenant Attacks"
          description="Exploiting vulnerabilities in cloud infrastructure to breach isolation boundaries between different customer environments."
          icon={<Shield />}
          severity="high"
        />
      )
    },
  ];

  return (
    <section className="space-y-12">
      <div>
        <h2 className="text-3xl font-bold mb-6">Common Cloud Security Attacks</h2>
        <p className="mb-8">
          Cloud environments present unique security challenges compared to traditional on-premises infrastructure.
          Understanding common attack vectors is essential for effective cloud penetration testing.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          {/* Left sidebar with attack types */}
          <div className="md:col-span-1">
            <div className="sticky top-20">
              <div className="bg-cybr-muted/20 rounded-lg p-4">
                <h3 className="text-lg font-semibold mb-4 text-cybr-primary">Attack Types</h3>
                
                <ScrollArea className="h-[calc(100vh-200px)] pr-4">
                  <ul className="space-y-1">
                    {attackSections.map(section => (
                      <li key={section.id}>
                        <button 
                          className={`flex w-full items-center gap-2 p-2 rounded-md hover:bg-cybr-muted/30 transition-colors ${selectedSection === section.id ? 'bg-cybr-muted/40 text-cybr-primary font-medium' : ''}`}
                          onClick={() => setSelectedSection(section.id)}
                        >
                          {section.icon}
                          <span>{section.title}</span>
                        </button>
                      </li>
                    ))}
                  </ul>
                </ScrollArea>
              </div>
            </div>
          </div>
          
          {/* Right content area */}
          <div className="md:col-span-3">
            {attackSections.find(section => section.id === selectedSection)?.content}
          </div>
        </div>
      </div>
    </section>
  );
};

export default CommonAttacksSection;
