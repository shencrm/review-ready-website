
import React, { useState, useEffect } from 'react';
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
import SSRF from './attacks/SSRF';
import HTTPRequestSmuggling from './attacks/HTTPRequestSmuggling';
import JWTAttacks from './attacks/JWTAttacks';
import APIVulnerabilities from './attacks/APIVulnerabilities';
import RaceConditions from './attacks/RaceConditions';
import CORSMisconfigurations from './attacks/CORSMisconfigurations';
import WebSocketVulnerabilities from './attacks/WebSocketVulnerabilities';
import PrototypePollution from './attacks/PrototypePollution';
import GraphQLVulnerabilities from './attacks/GraphQLVulnerabilities';
import OAuthVulnerabilities from './attacks/OAuthVulnerabilities';
import WebCachePoisoning from './attacks/WebCachePoisoning';
import CSPBypass from './attacks/CSPBypass';
import OtherInjectionFlaws from './attacks/OtherInjectionFlaws';
import SSTI from './attacks/SSTI';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';

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
    { id: 'ssti', title: 'Server-Side Template Injection', icon: <Code className="h-5 w-5" /> },
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

  const [selectedAttack, setSelectedAttack] = useState<string>('sql-injection');

  // Get attack component based on selected ID
  const renderAttackComponent = () => {
    switch (selectedAttack) {
      case 'sql-injection': return <SQLInjection />;
      case 'xss': return <XSS />;
      case 'csrf': return <CSRF />;
      case 'auth': return <BrokenAuthentication />;
      case 'access': return <BrokenAccessControl />;
      case 'xxe': return <XXE />;
      case 'ssti': return <SSTI />;
      case 'deserial': return <InsecureDeserialization />;
      case 'cmd-injection': return <CommandInjection />;
      case 'misconfig': return <SecurityMisconfigurations />;
      case 'file-traversal': return <PathTraversal />;
      case 'ssrf': return <SSRF />;
      case 'http-smuggling': return <HTTPRequestSmuggling />;
      case 'jwt': return <JWTAttacks />;
      case 'api': return <APIVulnerabilities />;
      case 'race': return <RaceConditions />;
      case 'cors': return <CORSMisconfigurations />;
      case 'websocket': return <WebSocketVulnerabilities />;
      case 'prototype': return <PrototypePollution />;
      case 'graphql': return <GraphQLVulnerabilities />;
      case 'oauth': return <OAuthVulnerabilities />;
      case 'cache': return <WebCachePoisoning />;
      case 'csp': return <CSPBypass />;
      case 'other-injection': return <OtherInjectionFlaws />;
      default: return <SQLInjection />;
    }
  };

  // Scroll to top when selected attack changes
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [selectedAttack]);

  return (
    <>
      <h2 className="section-title">Common Web Attacks</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mt-8">
        {/* Left sidebar with attack types - now using ScrollArea */}
        <div className="md:col-span-1">
          <div className="sticky top-20">
            <div className="bg-cybr-muted/20 rounded-lg p-4">
              <h3 className="text-lg font-semibold mb-4 text-cybr-primary">Attack Types</h3>
              
              <ScrollArea className="h-[calc(100vh-200px)] pr-4">
                <ul className="space-y-1">
                  {attackTypes.map(attack => (
                    <li key={attack.id}>
                      <button 
                        className={`flex w-full items-center gap-2 p-2 rounded-md hover:bg-cybr-muted/30 transition-colors ${selectedAttack === attack.id ? 'bg-cybr-muted/40 text-cybr-primary font-medium' : ''}`}
                        onClick={() => setSelectedAttack(attack.id)}
                      >
                        {attack.icon}
                        <span>{attack.title}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              </ScrollArea>
            </div>
          </div>
        </div>
        
        {/* Right content area - showing only selected attack */}
        <div className="md:col-span-3">
          {renderAttackComponent()}
        </div>
      </div>
    </>
  );
};

export default CommonAttacksSection;
