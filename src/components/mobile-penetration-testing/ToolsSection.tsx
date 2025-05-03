
import React from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Terminal, Smartphone, Lock, Bug } from 'lucide-react';

const ToolsSection: React.FC = () => {
  return (
    <section className="space-y-12">
      <div className="mb-8">
        <h2 className="text-3xl font-bold mb-6">Mobile Penetration Testing Tools</h2>
        <p className="mb-4">
          Effective mobile penetration testing requires a comprehensive toolkit for static analysis,
          dynamic analysis, network interception, and reverse engineering.
        </p>
      </div>
      
      <Tabs defaultValue="static">
        <TabsList className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-8">
          <TabsTrigger value="static" className="flex items-center gap-2">
            <Bug className="h-4 w-4" />
            Static Analysis
          </TabsTrigger>
          <TabsTrigger value="dynamic" className="flex items-center gap-2">
            <Terminal className="h-4 w-4" />
            Dynamic Analysis
          </TabsTrigger>
          <TabsTrigger value="network" className="flex items-center gap-2">
            <Lock className="h-4 w-4" />
            Network Analysis
          </TabsTrigger>
          <TabsTrigger value="frameworks" className="flex items-center gap-2">
            <Smartphone className="h-4 w-4" />
            Testing Frameworks
          </TabsTrigger>
        </TabsList>
        
        <TabsContent value="static">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-cybr-muted/20 rounded-lg p-6">
              <h4 className="text-xl font-bold flex items-center mb-3">
                <Terminal className="mr-2 h-5 w-5" />
                MobSF (Mobile Security Framework)
              </h4>
              <p className="text-sm mb-3">
                An automated, all-in-one mobile application security testing framework capable of performing static and dynamic analysis.
              </p>
              <ul className="text-sm list-disc pl-5 mb-3">
                <li>Supports Android and iOS applications</li>
                <li>Source code analysis and decompilation</li>
                <li>Comprehensive security report generation</li>
                <li>API vulnerability assessment</li>
              </ul>
              <a href="https://github.com/MobSF/Mobile-Security-Framework-MobSF" className="text-cybr-primary text-sm hover:underline" target="_blank" rel="noreferrer">
                Visit MobSF Repository →
              </a>
            </div>
            
            <div className="bg-cybr-muted/20 rounded-lg p-6">
              <h4 className="text-xl font-bold flex items-center mb-3">
                <Terminal className="mr-2 h-5 w-5" />
                JADX
              </h4>
              <p className="text-sm mb-3">
                A powerful decompiler for Android APKs that produces Java source code from Android DEX and APK files.
              </p>
              <ul className="text-sm list-disc pl-5 mb-3">
                <li>Decompiles DEX to Java</li>
                <li>Command-line and GUI versions</li>
                <li>Export as Gradle project</li>
                <li>Save decompiled sources as Java files</li>
              </ul>
              <a href="https://github.com/skylot/jadx" className="text-cybr-primary text-sm hover:underline" target="_blank" rel="noreferrer">
                Visit JADX Repository →
              </a>
            </div>
            
            <div className="bg-cybr-muted/20 rounded-lg p-6">
              <h4 className="text-xl font-bold flex items-center mb-3">
                <Terminal className="mr-2 h-5 w-5" />
                Hopper Disassembler
              </h4>
              <p className="text-sm mb-3">
                A reverse engineering tool for macOS and Linux that lets you disassemble, decompile, and debug iOS applications.
              </p>
              <ul className="text-sm list-disc pl-5 mb-3">
                <li>Disassembles iOS binaries</li>
                <li>Generates pseudo-code from assembly</li>
                <li>Advanced control flow analysis</li>
                <li>Debugging capabilities</li>
              </ul>
              <a href="https://www.hopperapp.com/" className="text-cybr-primary text-sm hover:underline" target="_blank" rel="noreferrer">
                Visit Hopper Website →
              </a>
            </div>
            
            <div className="bg-cybr-muted/20 rounded-lg p-6">
              <h4 className="text-xl font-bold flex items-center mb-3">
                <Terminal className="mr-2 h-5 w-5" />
                APKTool
              </h4>
              <p className="text-sm mb-3">
                A tool for reverse engineering Android APK files to nearly original form, with the ability to debug smali code.
              </p>
              <ul className="text-sm list-disc pl-5 mb-3">
                <li>Decodes resources to nearly original form</li>
                <li>Rebuilds decoded resources back to binary APK</li>
                <li>Handles APK signing</li>
                <li>Debugging capabilities with breakpoints</li>
              </ul>
              <a href="https://ibotpeaches.github.io/Apktool/" className="text-cybr-primary text-sm hover:underline" target="_blank" rel="noreferrer">
                Visit APKTool Website →
              </a>
            </div>
          </div>
        </TabsContent>
        
        <TabsContent value="dynamic">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-cybr-muted/20 rounded-lg p-6">
              <h4 className="text-xl font-bold flex items-center mb-3">
                <Terminal className="mr-2 h-5 w-5" />
                Frida
              </h4>
              <p className="text-sm mb-3">
                A dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers to hook into running processes.
              </p>
              <ul className="text-sm list-disc pl-5 mb-3">
                <li>Runtime manipulation</li>
                <li>Hook functions and modify behavior</li>
                <li>Access to memory</li>
                <li>Cross-platform (Android and iOS)</li>
              </ul>
              <a href="https://frida.re/" className="text-cybr-primary text-sm hover:underline" target="_blank" rel="noreferrer">
                Visit Frida Website →
              </a>
            </div>
            
            <div className="bg-cybr-muted/20 rounded-lg p-6">
              <h4 className="text-xl font-bold flex items-center mb-3">
                <Terminal className="mr-2 h-5 w-5" />
                Objection
              </h4>
              <p className="text-sm mb-3">
                A runtime mobile exploration toolkit, powered by Frida, built to help assess mobile applications without requiring a jailbreak.
              </p>
              <ul className="text-sm list-disc pl-5 mb-3">
                <li>Memory dumping</li>
                <li>Root detection bypassing</li>
                <li>SSL pinning bypass</li>
                <li>Exploration of app data directories</li>
              </ul>
              <a href="https://github.com/sensepost/objection" className="text-cybr-primary text-sm hover:underline" target="_blank" rel="noreferrer">
                Visit Objection Repository →
              </a>
            </div>
            
            <div className="bg-cybr-muted/20 rounded-lg p-6">
              <h4 className="text-xl font-bold flex items-center mb-3">
                <Terminal className="mr-2 h-5 w-5" />
                drozer
              </h4>
              <p className="text-sm mb-3">
                A comprehensive security and attack framework for Android, allowing you to interact with app components.
              </p>
              <ul className="text-sm list-disc pl-5 mb-3">
                <li>Interact with IPC endpoints</li>
                <li>Identify app attack surfaces</li>
                <li>Exploit vulnerabilities</li>
                <li>Test content providers and activities</li>
              </ul>
              <a href="https://github.com/FSecureLABS/drozer" className="text-cybr-primary text-sm hover:underline" target="_blank" rel="noreferrer">
                Visit drozer Repository →
              </a>
            </div>
            
            <div className="bg-cybr-muted/20 rounded-lg p-6">
              <h4 className="text-xl font-bold flex items-center mb-3">
                <Terminal className="mr-2 h-5 w-5" />
                iOS-Security-Suite
              </h4>
              <p className="text-sm mb-3">
                A collection of security tools for iOS applications to protect against reverse engineering.
              </p>
              <ul className="text-sm list-disc pl-5 mb-3">
                <li>Jailbreak detection</li>
                <li>Debugger detection</li>
                <li>Reverse engineering tool detection</li>
                <li>Runtime integrity checks</li>
              </ul>
              <a href="https://github.com/securing/IOSSecuritySuite" className="text-cybr-primary text-sm hover:underline" target="_blank" rel="noreferrer">
                Visit iOS-Security-Suite Repository →
              </a>
            </div>
          </div>
        </TabsContent>
        
        <TabsContent value="network">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-cybr-muted/20 rounded-lg p-6">
              <h4 className="text-xl font-bold flex items-center mb-3">
                <Terminal className="mr-2 h-5 w-5" />
                Burp Suite
              </h4>
              <p className="text-sm mb-3">
                An integrated platform for performing security testing of web and mobile applications, with specific features for mobile testing.
              </p>
              <ul className="text-sm list-disc pl-5 mb-3">
                <li>HTTP request interception and modification</li>
                <li>Mobile certificate installation</li>
                <li>API testing capabilities</li>
                <li>Automatic vulnerability scanning</li>
              </ul>
              <a href="https://portswigger.net/burp" className="text-cybr-primary text-sm hover:underline" target="_blank" rel="noreferrer">
                Visit Burp Suite Website →
              </a>
            </div>
            
            <div className="bg-cybr-muted/20 rounded-lg p-6">
              <h4 className="text-xl font-bold flex items-center mb-3">
                <Terminal className="mr-2 h-5 w-5" />
                Charles Proxy
              </h4>
              <p className="text-sm mb-3">
                A web debugging proxy application that enables a developer to view HTTP/HTTPS traffic between their machine and the internet.
              </p>
              <ul className="text-sm list-disc pl-5 mb-3">
                <li>TLS/SSL proxying</li>
                <li>Bandwidth throttling</li>
                <li>AJAX debugging</li>
                <li>AMF support for Flash</li>
              </ul>
              <a href="https://www.charlesproxy.com/" className="text-cybr-primary text-sm hover:underline" target="_blank" rel="noreferrer">
                Visit Charles Proxy Website →
              </a>
            </div>
            
            <div className="bg-cybr-muted/20 rounded-lg p-6">
              <h4 className="text-xl font-bold flex items-center mb-3">
                <Terminal className="mr-2 h-5 w-5" />
                MITM Proxy
              </h4>
              <p className="text-sm mb-3">
                An interactive TLS-capable intercepting proxy for HTTP/1, HTTP/2, and WebSockets with a console interface and Python API.
              </p>
              <ul className="text-sm list-disc pl-5 mb-3">
                <li>Intercept and modify requests/responses</li>
                <li>Save complete HTTP exchanges for later analysis</li>
                <li>Python scriptability</li>
                <li>Command-line interface</li>
              </ul>
              <a href="https://mitmproxy.org/" className="text-cybr-primary text-sm hover:underline" target="_blank" rel="noreferrer">
                Visit MITM Proxy Website →
              </a>
            </div>
            
            <div className="bg-cybr-muted/20 rounded-lg p-6">
              <h4 className="text-xl font-bold flex items-center mb-3">
                <Terminal className="mr-2 h-5 w-5" />
                SSL Kill Switch
              </h4>
              <p className="text-sm mb-3">
                A tool designed to bypass SSL certificate pinning in iOS and macOS applications.
              </p>
              <ul className="text-sm list-disc pl-5 mb-3">
                <li>Disables SSL validation</li>
                <li>Bypasses certificate pinning</li>
                <li>Works with most iOS applications</li>
                <li>Compatible with jailbroken devices</li>
              </ul>
              <a href="https://github.com/nabla-c0d3/ssl-kill-switch2" className="text-cybr-primary text-sm hover:underline" target="_blank" rel="noreferrer">
                Visit SSL Kill Switch Repository →
              </a>
            </div>
          </div>
        </TabsContent>
        
        <TabsContent value="frameworks">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-cybr-muted/20 rounded-lg p-6">
              <h4 className="text-xl font-bold flex items-center mb-3">
                <Terminal className="mr-2 h-5 w-5" />
                OWASP Mobile Security Testing Guide
              </h4>
              <p className="text-sm mb-3">
                A comprehensive manual for mobile app security testing and reverse engineering for both iOS and Android.
              </p>
              <ul className="text-sm list-disc pl-5 mb-3">
                <li>Testing methodologies</li>
                <li>Platform-specific guidance</li>
                <li>Case studies</li>
                <li>Tools recommendations</li>
              </ul>
              <a href="https://owasp.org/www-project-mobile-security-testing-guide/" className="text-cybr-primary text-sm hover:underline" target="_blank" rel="noreferrer">
                Visit MSTG Website →
              </a>
            </div>
            
            <div className="bg-cybr-muted/20 rounded-lg p-6">
              <h4 className="text-xl font-bold flex items-center mb-3">
                <Terminal className="mr-2 h-5 w-5" />
                OWASP MASVS
              </h4>
              <p className="text-sm mb-3">
                The Mobile Application Security Verification Standard provides a baseline of security requirements for mobile apps.
              </p>
              <ul className="text-sm list-disc pl-5 mb-3">
                <li>Security requirements framework</li>
                <li>Testing checklist</li>
                <li>Risk assessment guidelines</li>
                <li>Security level categorization</li>
              </ul>
              <a href="https://owasp.org/www-project-mobile-security-verification-standard/" className="text-cybr-primary text-sm hover:underline" target="_blank" rel="noreferrer">
                Visit MASVS Website →
              </a>
            </div>
            
            <div className="bg-cybr-muted/20 rounded-lg p-6">
              <h4 className="text-xl font-bold flex items-center mb-3">
                <Terminal className="mr-2 h-5 w-5" />
                iMAS (iOS Mobile Application Security)
              </h4>
              <p className="text-sm mb-3">
                A security framework for iOS applications with built-in security controls.
              </p>
              <ul className="text-sm list-disc pl-5 mb-3">
                <li>Secure storage</li>
                <li>Anti-debugging features</li>
                <li>Device integrity checks</li>
                <li>Secure authentication</li>
              </ul>
              <a href="https://github.com/project-imas/security-check" className="text-cybr-primary text-sm hover:underline" target="_blank" rel="noreferrer">
                Visit iMAS Repository →
              </a>
            </div>
            
            <div className="bg-cybr-muted/20 rounded-lg p-6">
              <h4 className="text-xl font-bold flex items-center mb-3">
                <Terminal className="mr-2 h-5 w-5" />
                QARK (Quick Android Review Kit)
              </h4>
              <p className="text-sm mb-3">
                A tool designed to look for security vulnerabilities in Android applications.
              </p>
              <ul className="text-sm list-disc pl-5 mb-3">
                <li>Static code analysis</li>
                <li>Vulnerability reporting</li>
                <li>APK decompilation</li>
                <li>Manifest analysis</li>
              </ul>
              <a href="https://github.com/linkedin/qark" className="text-cybr-primary text-sm hover:underline" target="_blank" rel="noreferrer">
                Visit QARK Repository →
              </a>
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </section>
  );
};

export default ToolsSection;
