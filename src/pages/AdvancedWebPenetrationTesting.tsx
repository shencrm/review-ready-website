
import React from 'react';
import NavBar from '@/components/NavBar';
import { Zap } from 'lucide-react';
import AdvancedContentSection from '@/components/web-penetration-testing/AdvancedContentSection';

const AdvancedWebPenetrationTesting: React.FC = () => {
  return (
    <div className="min-h-screen flex flex-col bg-cybr-background text-cybr-foreground">
      <NavBar />
      
      <main className="flex-1">
        <div className="container mx-auto px-4 py-8">
          <header className="mb-12 text-center">
            <div className="flex items-center justify-center gap-3 mb-4">
              <Zap className="h-12 w-12 text-cybr-primary" />
              <h1 className="text-4xl md:text-5xl font-bold text-cybr-primary">
                Advanced Web Penetration Testing
              </h1>
            </div>
            <p className="text-xl opacity-80 max-w-4xl mx-auto">
              Master advanced techniques, cutting-edge methodologies, and expert-level exploitation 
              strategies for comprehensive web application security assessment.
            </p>
          </header>

          <AdvancedContentSection />
        </div>
      </main>
    </div>
  );
};

export default AdvancedWebPenetrationTesting;
