
import React, { useState } from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { cloud, shield, aws, azure, gcp, database, bug, code, terminal, server } from 'lucide-react';
import AWSSection from '@/components/cloud-penetration-testing/AWSSection';
import AzureSection from '@/components/cloud-penetration-testing/AzureSection';
import GCPSection from '@/components/cloud-penetration-testing/GCPSection';
import CommonAttacksSection from '@/components/cloud-penetration-testing/CommonAttacksSection';
import MethodologySection from '@/components/cloud-penetration-testing/MethodologySection';
import ToolsSection from '@/components/cloud-penetration-testing/ToolsSection';

const CloudPenetrationTesting: React.FC = () => {
  const [activeTab, setActiveTab] = useState('common-attacks');

  const sections = [
    { id: 'common-attacks', title: 'Common Attacks', icon: <bug className="h-6 w-6" /> },
    { id: 'methodology', title: 'Methodology', icon: <shield className="h-6 w-6" /> },
    { id: 'aws', title: 'AWS', icon: <aws className="h-6 w-6" /> },
    { id: 'azure', title: 'Azure', icon: <azure className="h-6 w-6" /> },
    { id: 'gcp', title: 'GCP', icon: <gcp className="h-6 w-6" /> },
    { id: 'tools', title: 'Tools', icon: <terminal className="h-6 w-6" /> },
  ];

  return (
    <div className="min-h-screen flex flex-col bg-cybr-background text-cybr-foreground">
      <NavBar />
      
      <main className="flex-1">
        <div className="container mx-auto px-4 py-8">
          <header className="mb-12 text-center">
            <h1 className="text-4xl md:text-5xl font-bold mb-4 text-cybr-primary">
              Cloud Penetration Testing
            </h1>
            <p className="text-xl opacity-80 max-w-3xl mx-auto">
              A comprehensive guide to security testing methodologies, common vulnerabilities,
              and mitigation strategies across AWS, Azure, and GCP cloud environments.
            </p>
          </header>

          {/* Main Navigation Tabs */}
          <div className="mb-10">
            <Tabs 
              defaultValue={activeTab} 
              onValueChange={setActiveTab} 
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

              <TabsContent value="common-attacks" className="mt-6">
                <CommonAttacksSection />
              </TabsContent>

              <TabsContent value="methodology" className="mt-6">
                <MethodologySection />
              </TabsContent>

              <TabsContent value="aws" className="mt-6">
                <AWSSection />
              </TabsContent>
              
              <TabsContent value="azure" className="mt-6">
                <AzureSection />
              </TabsContent>
              
              <TabsContent value="gcp" className="mt-6">
                <GCPSection />
              </TabsContent>
              
              <TabsContent value="tools" className="mt-6">
                <ToolsSection />
              </TabsContent>
            </Tabs>
          </div>
        </div>
      </main>
      
      <Footer />
    </div>
  );
};

export default CloudPenetrationTesting;
