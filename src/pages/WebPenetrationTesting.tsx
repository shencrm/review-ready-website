
import React, { useState } from 'react';
import NavBar from '@/components/NavBar';
import { Shield, ShieldAlert, Code, Bug, Database, Lock, KeyRound, File, FileSearch, ShieldX } from 'lucide-react';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import CoreConcepts from '@/components/web-penetration-testing/CoreConcepts';
import CommonAttacksSection from '@/components/web-penetration-testing/CommonAttacksSection';
import TestingTechniquesSection from '@/components/web-penetration-testing/TestingTechniquesSection';
import MitigationStrategiesSection from '@/components/web-penetration-testing/MitigationStrategiesSection';
import ToolsCheatSheetsSection from '@/components/web-penetration-testing/ToolsCheatSheetsSection';
import InterviewQuestionsSection from '@/components/web-penetration-testing/InterviewQuestionsSection';
import { cn } from '@/lib/utils';

const WebPenetrationTesting: React.FC = () => {
  const [activeSection, setActiveSection] = useState('core-concepts');

  const sections = [
    { id: 'core-concepts', title: 'Core Concepts', icon: <Shield className="h-6 w-6" /> },
    { id: 'common-attacks', title: 'Common Attacks', icon: <ShieldAlert className="h-6 w-6" /> },
    { id: 'testing-techniques', title: 'Testing Techniques', icon: <FileSearch className="h-6 w-6" /> },
    { id: 'mitigation-strategies', title: 'Mitigation Strategies', icon: <ShieldX className="h-6 w-6" /> },
    { id: 'tools-cheatsheets', title: 'Tools & Cheat Sheets', icon: <KeyRound className="h-6 w-6" /> },
    { id: 'interview-questions', title: 'Interview Questions', icon: <File className="h-6 w-6" /> },
  ];

  return (
    <div className="min-h-screen flex flex-col bg-cybr-background text-cybr-foreground">
      <NavBar />
      
      <main className="flex-1">
        <div className="container mx-auto px-4 py-8">
          <header className="mb-12 text-center">
            <h1 className="text-4xl md:text-5xl font-bold mb-4 text-cybr-primary">
              Web Penetration Testing
            </h1>
            <p className="text-xl opacity-80 max-w-3xl mx-auto">
              A comprehensive guide to web application security testing techniques, common vulnerabilities, 
              and mitigation strategies for securing web applications.
            </p>
          </header>

          {/* Main Navigation Tabs */}
          <div className="mb-10">
            <Tabs 
              defaultValue={activeSection} 
              onValueChange={setActiveSection} 
              className="w-full"
            >
              <TabsList className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 w-full bg-cybr-muted/30 p-1">
                {sections.map(section => (
                  <TabsTrigger 
                    key={section.id}
                    value={section.id}
                    className="flex items-center gap-2"
                  >
                    {section.icon}
                    <span className="hidden sm:inline">{section.title}</span>
                  </TabsTrigger>
                ))}
              </TabsList>

              {/* Core Concepts Section */}
              <TabsContent value="core-concepts" className="mt-6">
                <CoreConcepts />
              </TabsContent>

              {/* Common Attacks Section */}
              <TabsContent value="common-attacks" className="mt-6">
                <CommonAttacksSection />
              </TabsContent>
              
              {/* Testing Techniques Section */}
              <TabsContent value="testing-techniques" className="mt-6">
                <TestingTechniquesSection />
              </TabsContent>
              
              {/* Mitigation Strategies Section */}
              <TabsContent value="mitigation-strategies" className="mt-6">
                <MitigationStrategiesSection />
              </TabsContent>
              
              {/* Tools & Cheat Sheets Section */}
              <TabsContent value="tools-cheatsheets" className="mt-6">
                <ToolsCheatSheetsSection />
              </TabsContent>
              
              {/* Interview Questions Section */}
              <TabsContent value="interview-questions" className="mt-6">
                <InterviewQuestionsSection />
              </TabsContent>
            </Tabs>
          </div>
        </div>
      </main>
    </div>
  );
};

export default WebPenetrationTesting;
