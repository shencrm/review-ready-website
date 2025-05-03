
import React, { useState } from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Smartphone, Shield, Bug, Code, Terminal, Lock } from 'lucide-react';
import AndroidSection from '@/components/mobile-penetration-testing/AndroidSection';
import IOSSection from '@/components/mobile-penetration-testing/IOSSection';
import MobileMethodologySection from '@/components/mobile-penetration-testing/MethodologySection';
import MobileToolsSection from '@/components/mobile-penetration-testing/ToolsSection';
import MobileCommonAttacksSection from '@/components/mobile-penetration-testing/CommonAttacksSection';

const MobilePenetrationTesting: React.FC = () => {
  const [activeTab, setActiveTab] = useState('common-attacks');

  const sections = [
    { id: 'common-attacks', title: 'Common Attacks', icon: <Bug className="h-6 w-6" /> },
    { id: 'methodology', title: 'Methodology', icon: <Shield className="h-6 w-6" /> },
    { id: 'android', title: 'Android', icon: <Smartphone className="h-6 w-6" /> },
    { id: 'ios', title: 'iOS', icon: <Smartphone className="h-6 w-6" /> },
    { id: 'tools', title: 'Tools', icon: <Terminal className="h-6 w-6" /> },
  ];

  return (
    <div className="flex flex-col min-h-screen">
      <NavBar />
      <main className="flex-1">
        <div className="container mx-auto px-4 py-12">
          <div className="flex items-center gap-4 mb-8">
            <Smartphone className="h-8 w-8 text-cybr-primary" />
            <h1 className="text-4xl font-bold">Mobile Penetration Testing</h1>
          </div>
          
          <p className="text-xl mb-12 text-cybr-foreground/80">
            A comprehensive guide to security testing mobile applications on Android and iOS platforms.
            Learn about common vulnerabilities, methodologies, platform-specific attack vectors, and tools.
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
              <MobileCommonAttacksSection />
            </TabsContent>
            <TabsContent value="methodology" className="mt-8">
              <MobileMethodologySection />
            </TabsContent>
            <TabsContent value="android" className="mt-8">
              <AndroidSection />
            </TabsContent>
            <TabsContent value="ios" className="mt-8">
              <IOSSection />
            </TabsContent>
            <TabsContent value="tools" className="mt-8">
              <MobileToolsSection />
            </TabsContent>
          </Tabs>
        </div>
      </main>
      <Footer />
    </div>
  );
};

export default MobilePenetrationTesting;
