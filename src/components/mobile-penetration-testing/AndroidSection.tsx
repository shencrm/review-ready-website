
import React, { useState } from 'react';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Smartphone, Settings, CheckCircle, Code, Shield, Database, Network, Key, Bug, Terminal, FileText, Search } from 'lucide-react';
import { useActiveSection } from '@/hooks/useActiveSection';
import SectionNavigation from '@/components/web-penetration-testing/advanced/SectionNavigation';

// Import the detailed components
import AndroidEnvironmentSetup from './android/AndroidEnvironmentSetup';
import AndroidMethodology from './android/AndroidMethodology';
import AndroidStaticAnalysis from './android/AndroidStaticAnalysis';
import AndroidDynamicAnalysis from './android/AndroidDynamicAnalysis';
import AndroidNetworkAnalysis from './android/AndroidNetworkAnalysis';

const AndroidSection: React.FC = () => {
  const [activeTab, setActiveTab] = useState('environment-setup');
  
  // Navigation items for the sidebar
  const navigationItems = [
    { id: 'environment-setup', title: 'Environment Setup', icon: <Settings className="h-4 w-4" /> },
    { id: 'methodology', title: 'Testing Methodology', icon: <CheckCircle className="h-4 w-4" /> },
    { id: 'static-analysis', title: 'Static Analysis', icon: <Code className="h-4 w-4" /> },
    { id: 'dynamic-analysis', title: 'Dynamic Analysis', icon: <Terminal className="h-4 w-4" /> },
    { id: 'network-analysis', title: 'Network Analysis', icon: <Network className="h-4 w-4" /> },
    { id: 'storage-analysis', title: 'Storage Analysis', icon: <Database className="h-4 w-4" /> },
    { id: 'ipc-analysis', title: 'IPC Analysis', icon: <Shield className="h-4 w-4" /> },
    { id: 'auth-testing', title: 'Authentication Testing', icon: <Key className="h-4 w-4" /> },
    { id: 'crypto-analysis', title: 'Cryptography Analysis', icon: <Key className="h-4 w-4" /> },
    { id: 'anti-analysis', title: 'Anti-Analysis Bypass', icon: <Bug className="h-4 w-4" /> },
    { id: 'privilege-escalation', title: 'Privilege Escalation', icon: <Shield className="h-4 w-4" /> },
    { id: 'exploitation', title: 'Exploitation Techniques', icon: <Bug className="h-4 w-4" /> },
    { id: 'post-exploitation', title: 'Post-Exploitation', icon: <Terminal className="h-4 w-4" /> },
    { id: 'reporting', title: 'Reporting', icon: <FileText className="h-4 w-4" /> }
  ];

  const { activeSection, setActiveSection } = useActiveSection(navigationItems.map(item => item.id));

  return (
    <div className="flex gap-6">
      {/* Navigation Sidebar */}
      <div className="w-64 flex-shrink-0">
        <SectionNavigation
          items={navigationItems}
          activeSection={activeSection}
          onSectionChange={(sectionId) => {
            setActiveSection(sectionId);
            setActiveTab(sectionId);
          }}
        />
      </div>

      {/* Main Content */}
      <div className="flex-1">
        <div className="mb-8">
          <h2 className="text-3xl font-bold mb-6 flex items-center gap-2">
            <Smartphone className="text-cybr-primary" />
            Android Penetration Testing - Comprehensive Guide
          </h2>
          <p className="text-xl mb-6 text-cybr-foreground/80">
            A comprehensive and detailed guide to Android application security testing, including environment setup, 
            methodology, code analysis, dynamic testing, and advanced exploitation techniques.
          </p>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-8">
          <TabsList className="grid grid-cols-4 md:grid-cols-6 gap-1 h-auto p-1">
            <TabsTrigger value="environment-setup" className="flex items-center gap-1 py-2 text-xs">
              <Settings className="h-3 w-3" />
              <span className="hidden md:inline">Environment</span>
            </TabsTrigger>
            <TabsTrigger value="methodology" className="flex items-center gap-1 py-2 text-xs">
              <CheckCircle className="h-3 w-3" />
              <span className="hidden md:inline">Methodology</span>
            </TabsTrigger>
            <TabsTrigger value="static-analysis" className="flex items-center gap-1 py-2 text-xs">
              <Code className="h-3 w-3" />
              <span className="hidden md:inline">Static</span>
            </TabsTrigger>
            <TabsTrigger value="dynamic-analysis" className="flex items-center gap-1 py-2 text-xs">
              <Terminal className="h-3 w-3" />
              <span className="hidden md:inline">Dynamic</span>
            </TabsTrigger>
            <TabsTrigger value="network-analysis" className="flex items-center gap-1 py-2 text-xs">
              <Network className="h-3 w-3" />
              <span className="hidden md:inline">Network</span>
            </TabsTrigger>
            <TabsTrigger value="exploitation" className="flex items-center gap-1 py-2 text-xs">
              <Bug className="h-3 w-3" />
              <span className="hidden md:inline">Exploitation</span>
            </TabsTrigger>
          </TabsList>

          <TabsContent value="environment-setup" id="environment-setup" className="scroll-mt-20">
            <AndroidEnvironmentSetup />
          </TabsContent>

          <TabsContent value="methodology" id="methodology" className="scroll-mt-20">
            <AndroidMethodology />
          </TabsContent>

          <TabsContent value="static-analysis" id="static-analysis" className="scroll-mt-20">
            <AndroidStaticAnalysis />
          </TabsContent>

          <TabsContent value="dynamic-analysis" id="dynamic-analysis" className="scroll-mt-20">
            <AndroidDynamicAnalysis />
          </TabsContent>

          <TabsContent value="network-analysis" id="network-analysis" className="scroll-mt-20">
            <AndroidNetworkAnalysis />
          </TabsContent>

          <TabsContent value="storage-analysis" id="storage-analysis" className="scroll-mt-20">
            <div className="text-center py-12">
              <Database className="h-16 w-16 text-cybr-primary mx-auto mb-4" />
              <h3 className="text-2xl font-bold mb-2">Storage Analysis</h3>
              <p className="text-cybr-foreground/70">This section is under development</p>
            </div>
          </TabsContent>

          <TabsContent value="ipc-analysis" id="ipc-analysis" className="scroll-mt-20">
            <div className="text-center py-12">
              <Shield className="h-16 w-16 text-cybr-primary mx-auto mb-4" />
              <h3 className="text-2xl font-bold mb-2">IPC Analysis</h3>
              <p className="text-cybr-foreground/70">This section is under development</p>
            </div>
          </TabsContent>

          <TabsContent value="auth-testing" id="auth-testing" className="scroll-mt-20">
            <div className="text-center py-12">
              <Key className="h-16 w-16 text-cybr-primary mx-auto mb-4" />
              <h3 className="text-2xl font-bold mb-2">Authentication Testing</h3>
              <p className="text-cybr-foreground/70">This section is under development</p>
            </div>
          </TabsContent>

          <TabsContent value="crypto-analysis" id="crypto-analysis" className="scroll-mt-20">
            <div className="text-center py-12">
              <Key className="h-16 w-16 text-cybr-primary mx-auto mb-4" />
              <h3 className="text-2xl font-bold mb-2">Cryptography Analysis</h3>
              <p className="text-cybr-foreground/70">This section is under development</p>
            </div>
          </TabsContent>

          <TabsContent value="anti-analysis" id="anti-analysis" className="scroll-mt-20">
            <div className="text-center py-12">
              <Bug className="h-16 w-16 text-cybr-primary mx-auto mb-4" />
              <h3 className="text-2xl font-bold mb-2">Anti-Analysis Bypass</h3>
              <p className="text-cybr-foreground/70">This section is under development</p>
            </div>
          </TabsContent>

          <TabsContent value="privilege-escalation" id="privilege-escalation" className="scroll-mt-20">
            <div className="text-center py-12">
              <Shield className="h-16 w-16 text-cybr-primary mx-auto mb-4" />
              <h3 className="text-2xl font-bold mb-2">Privilege Escalation</h3>
              <p className="text-cybr-foreground/70">This section is under development</p>
            </div>
          </TabsContent>

          <TabsContent value="exploitation" id="exploitation" className="scroll-mt-20">
            <div className="text-center py-12">
              <Bug className="h-16 w-16 text-cybr-primary mx-auto mb-4" />
              <h3 className="text-2xl font-bold mb-2">Exploitation Techniques</h3>
              <p className="text-cybr-foreground/70">This section is under development</p>
            </div>
          </TabsContent>

          <TabsContent value="post-exploitation" id="post-exploitation" className="scroll-mt-20">
            <div className="text-center py-12">
              <Terminal className="h-16 w-16 text-cybr-primary mx-auto mb-4" />
              <h3 className="text-2xl font-bold mb-2">Post-Exploitation</h3>
              <p className="text-cybr-foreground/70">This section is under development</p>
            </div>
          </TabsContent>

          <TabsContent value="reporting" id="reporting" className="scroll-mt-20">
            <div className="text-center py-12">
              <FileText className="h-16 w-16 text-cybr-primary mx-auto mb-4" />
              <h3 className="text-2xl font-bold mb-2">Reporting</h3>
              <p className="text-cybr-foreground/70">This section is under development</p>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default AndroidSection;
