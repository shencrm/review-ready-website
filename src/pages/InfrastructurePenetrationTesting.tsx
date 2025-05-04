
import React, { useState } from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Server, Shield, Monitor, Terminal, Network, Bug, Lock } from 'lucide-react';
import WindowsSection from '@/components/infrastructure-penetration-testing/WindowsSection';
import LinuxSection from '@/components/infrastructure-penetration-testing/LinuxSection';
import ActiveDirectorySection from '@/components/infrastructure-penetration-testing/ActiveDirectorySection';
import InfraMethodologySection from '@/components/infrastructure-penetration-testing/MethodologySection';
import InfraToolsSection from '@/components/infrastructure-penetration-testing/ToolsSection';
import InfraCommonAttacksSection from '@/components/infrastructure-penetration-testing/CommonAttacksSection';

const InfrastructurePenetrationTesting: React.FC = () => {
  const [activeTab, setActiveTab] = useState('common-attacks');

  const sections = [
    { id: 'common-attacks', title: 'Common Attacks', icon: <Bug className="h-6 w-6" /> },
    { id: 'methodology', title: 'Methodology', icon: <Shield className="h-6 w-6" /> },
    { id: 'windows', title: 'Windows', icon: <Monitor className="h-6 w-6" /> },
    { id: 'linux', title: 'Linux', icon: <Terminal className="h-6 w-6" /> },
    { id: 'active-directory', title: 'Active Directory', icon: <Network className="h-6 w-6" /> },
    { id: 'tools', title: 'Tools', icon: <Terminal className="h-6 w-6" /> },
  ];

  return (
    <div className="flex flex-col min-h-screen">
      <NavBar />
      <main className="flex-1">
        <div className="container mx-auto px-4 py-12">
          <div className="flex items-center gap-4 mb-8">
            <Server className="h-8 w-8 text-cybr-primary" />
            <h1 className="text-4xl font-bold">Infrastructure Penetration Testing</h1>
          </div>
          
          <p className="text-xl mb-12 text-cybr-foreground/80">
            A comprehensive guide to security testing infrastructure components including Windows, Linux, 
            and Active Directory environments. Learn about common vulnerabilities, methodologies, 
            and tools used in infrastructure penetration testing.
          </p>
          
          <Tabs
            value={activeTab}
            onValueChange={(value) => setActiveTab(value)}
            className="space-y-8"
          >
            <TabsList className="grid grid-cols-2 md:grid-cols-6 gap-2">
              {sections.map((section) => (
                <TabsTrigger 
                  key={section.id} 
                  value={section.id}
                  className="flex items-center gap-2 py-2"
                >
                  {section.icon}
                  <span className="hidden md:inline">{section.title}</span>
                </TabsTrigger>
              ))}
            </TabsList>
            <TabsContent value="common-attacks" className="mt-8">
              <InfraCommonAttacksSection />
            </TabsContent>
            <TabsContent value="methodology" className="mt-8">
              <InfraMethodologySection />
            </TabsContent>
            <TabsContent value="windows" className="mt-8">
              <WindowsSection />
            </TabsContent>
            <TabsContent value="linux" className="mt-8">
              <LinuxSection />
            </TabsContent>
            <TabsContent value="active-directory" className="mt-8">
              <ActiveDirectorySection />
            </TabsContent>
            <TabsContent value="tools" className="mt-8">
              <InfraToolsSection />
            </TabsContent>
          </Tabs>
        </div>
      </main>
      <Footer />
    </div>
  );
};

export default InfrastructurePenetrationTesting;
