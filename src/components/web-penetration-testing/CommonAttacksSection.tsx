
import React from 'react';
import { Database, ShieldAlert, Code, Bug, KeyRound, File, Lock, ShieldX } from 'lucide-react';
import SQLInjection from './attacks/SQLInjection';
import XSS from './attacks/XSS';
import CSRF from './attacks/CSRF';
import BrokenAuthentication from './attacks/BrokenAuthentication';
import BrokenAccessControl from './attacks/BrokenAccessControl';
import XXE from './attacks/XXE';
import InsecureDeserialization from './attacks/InsecureDeserialization';
import CommandInjection from './attacks/CommandInjection';
import SecurityMisconfigurations from './attacks/SecurityMisconfigurations';
import PathTraversal from './attacks/PathTraversal';

interface AttackType {
  id: string;
  title: string;
  icon: React.ReactNode;
}

const CommonAttacksSection: React.FC = () => {
  const attackTypes: AttackType[] = [
    { id: 'sql-injection', title: 'SQL Injection', icon: <Database className="h-5 w-5" /> },
    { id: 'xss', title: 'Cross-Site Scripting', icon: <Code className="h-5 w-5" /> },
    { id: 'csrf', title: 'Cross-Site Request Forgery', icon: <ShieldAlert className="h-5 w-5" /> },
    { id: 'auth', title: 'Broken Authentication', icon: <Lock className="h-5 w-5" /> },
    { id: 'access', title: 'Broken Access Control', icon: <KeyRound className="h-5 w-5" /> },
    { id: 'xxe', title: 'XML External Entity', icon: <File className="h-5 w-5" /> },
    { id: 'deserial', title: 'Insecure Deserialization', icon: <Bug className="h-5 w-5" /> },
    { id: 'cmd-injection', title: 'Command Injection', icon: <Code className="h-5 w-5" /> },
    { id: 'misconfig', title: 'Security Misconfigurations', icon: <ShieldX className="h-5 w-5" /> },
    { id: 'file-traversal', title: 'File Inclusion/Path Traversal', icon: <File className="h-5 w-5" /> },
    { id: 'ssrf', title: 'Server-Side Request Forgery', icon: <ShieldAlert className="h-5 w-5" /> },
    { id: 'http-smuggling', title: 'HTTP Request Smuggling', icon: <Bug className="h-5 w-5" /> },
    { id: 'jwt', title: 'JWT Attacks', icon: <KeyRound className="h-5 w-5" /> },
    { id: 'api', title: 'API Vulnerabilities', icon: <Code className="h-5 w-5" /> },
    { id: 'race', title: 'Race Conditions', icon: <Bug className="h-5 w-5" /> },
    { id: 'cors', title: 'CORS Misconfigurations', icon: <ShieldX className="h-5 w-5" /> },
    { id: 'websocket', title: 'WebSocket Vulnerabilities', icon: <Bug className="h-5 w-5" /> },
    { id: 'prototype', title: 'Prototype Pollution', icon: <Code className="h-5 w-5" /> },
    { id: 'graphql', title: 'GraphQL Vulnerabilities', icon: <Database className="h-5 w-5" /> },
    { id: 'oauth', title: 'OAuth Vulnerabilities', icon: <Lock className="h-5 w-5" /> },
    { id: 'cache', title: 'Web Cache Poisoning', icon: <Bug className="h-5 w-5" /> },
    { id: 'csp', title: 'CSP Bypass', icon: <ShieldX className="h-5 w-5" /> },
    { id: 'other-injection', title: 'Other Injection Flaws', icon: <Code className="h-5 w-5" /> },
  ];

  return (
    <>
      <h2 className="section-title">Common Web Attacks</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mt-8">
        {/* Left sidebar with attack types */}
        <div className="md:col-span-1 bg-cybr-muted/20 rounded-lg p-4 self-start sticky top-20">
          <h3 className="text-lg font-semibold mb-4 text-cybr-primary">Attack Types</h3>
          <ul className="space-y-1">
            {attackTypes.map(attack => (
              <li key={attack.id}>
                <a 
                  href={`#${attack.id}`}
                  className="flex items-center gap-2 p-2 rounded-md hover:bg-cybr-muted/30 transition-colors"
                  onClick={(e) => {
                    e.preventDefault();
                    document.getElementById(attack.id)?.scrollIntoView({ behavior: 'smooth' });
                  }}
                >
                  {attack.icon}
                  <span>{attack.title}</span>
                </a>
              </li>
            ))}
          </ul>
        </div>
        
        {/* Right content area */}
        <div className="md:col-span-3 space-y-16">
          <SQLInjection />
          <XSS />
          <CSRF />
          <BrokenAuthentication />
          <BrokenAccessControl />
          <XXE />
          <InsecureDeserialization />
          <CommandInjection />
          <SecurityMisconfigurations />
          <PathTraversal />
          {/* Additional attack components would be added here */}
        </div>
      </div>
    </>
  );
};

export default CommonAttacksSection;
