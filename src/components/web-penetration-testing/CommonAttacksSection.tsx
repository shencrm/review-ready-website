import React from 'react';
import SecurityCard from '@/components/SecurityCard';
import SQLInjection from './attacks/SQLInjection';
import XSS from './attacks/XSS';
import CSRF from './attacks/CSRF';
import BrokenAuthentication from './attacks/BrokenAuthentication';
import BrokenAccessControl from './attacks/BrokenAccessControl';
import InsecureDeserialization from './attacks/InsecureDeserialization';
import CommandInjection from './attacks/CommandInjection';
import OtherInjectionFlaws from './attacks/OtherInjectionFlaws';
import JWTAttacks from './attacks/JWTAttacks';
import OAuthVulnerabilities from './attacks/OAuthVulnerabilities';
import APIVulnerabilities from './attacks/APIVulnerabilities';
import GraphQLVulnerabilities from './attacks/GraphQLVulnerabilities';
import CORSMisconfigurations from './attacks/CORSMisconfigurations';
import CSPBypass from './attacks/CSPBypass';
import HTTPRequestSmuggling from './attacks/HTTPRequestSmuggling';
import XXE from './attacks/XXE';
import SSTI from './attacks/SSTI';

const CommonAttacksSection: React.FC = () => {
  return (
    <div className="space-y-8">
      <div className="text-center mb-8">
        <h2 className="text-3xl font-bold mb-4">Common Web Application Attacks</h2>
        <p className="text-lg opacity-80 max-w-3xl mx-auto">
          Explore detailed explanations, examples, and mitigation strategies for the most prevalent 
          web application security vulnerabilities and attack vectors.
        </p>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
        <SecurityCard
          title="SQL Injection"
          description="Database manipulation through malicious SQL commands in user input fields."
          severity="high"
        />
        <SecurityCard
          title="Cross-Site Scripting (XSS)"
          description="Injection of malicious scripts into web pages viewed by other users."
          severity="high"
        />
        <SecurityCard
          title="Cross-Site Request Forgery (CSRF)"
          description="Unauthorized commands transmitted from a user that the web application trusts."
          severity="medium"
        />
        <SecurityCard
          title="XXE Injection"
          description="Exploitation of XML processors to access local files and internal systems."
          severity="high"
        />
        <SecurityCard
          title="Template Injection (SSTI)"
          description="Server-side template injection leading to remote code execution."
          severity="high"
        />
        <SecurityCard
          title="Broken Authentication"
          description="Flaws in authentication mechanisms allowing attackers to compromise accounts."
          severity="high"
        />
      </div>

      <div className="space-y-12">
        <SQLInjection />
        <XSS />
        <CSRF />
        <XXE />
        <SSTI />
        <BrokenAuthentication />
        <BrokenAccessControl />
        <InsecureDeserialization />
        <CommandInjection />
        <OtherInjectionFlaws />
        <JWTAttacks />
        <OAuthVulnerabilities />
        <APIVulnerabilities />
        <GraphQLVulnerabilities />
        <CORSMisconfigurations />
        <CSPBypass />
        <HTTPRequestSmuggling />
      </div>
    </div>
  );
};

export default CommonAttacksSection;
