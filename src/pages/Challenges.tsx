
import React, { useState, useEffect } from 'react';
import NavBar from '@/components/NavBar';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Shield, Code, Check, AlertTriangle, FileCode } from 'lucide-react';
import ChallengeExplorer from '@/components/challenges/ChallengeExplorer';
import WelcomeSection from '@/components/challenges/WelcomeSection';
import { ChallengeProvider } from '@/components/challenges/ChallengeContext';

const Challenges: React.FC = () => {
  const [activeSection, setActiveSection] = useState('welcome');

  const sections = [
    { id: 'welcome', title: 'Welcome', icon: <Shield className="h-5 w-5" /> },
    { id: 'challenges', title: 'Challenge Explorer', icon: <FileCode className="h-5 w-5" /> },
    { id: 'leaderboard', title: 'Leaderboard', icon: <Code className="h-5 w-5" /> },
    { id: 'resources', title: 'Learning Resources', icon: <AlertTriangle className="h-5 w-5" /> },
  ];
  
  // Scroll to top when changing sections
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [activeSection]);

  return (
    <div className="min-h-screen flex flex-col bg-cybr-background text-cybr-foreground">
      <NavBar />
      
      <main className="flex-1">
        <div className="container mx-auto px-4 py-8">
          <header className="mb-12 text-center">
            <h1 className="text-4xl md:text-5xl font-bold mb-4 text-cybr-primary">
              Secure Code Review Challenges
            </h1>
            <p className="text-xl opacity-80 max-w-3xl mx-auto">
              Test your security knowledge with interactive code review exercises. Identify vulnerabilities, 
              compare secure and insecure implementations, and improve your secure coding skills.
            </p>
          </header>

          <ChallengeProvider>
            <div className="mb-10">
              <Tabs 
                defaultValue={activeSection} 
                onValueChange={setActiveSection} 
                className="w-full"
              >
                <TabsList className="grid grid-cols-2 md:grid-cols-4 w-full bg-cybr-muted/30 p-1">
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

                <TabsContent value="welcome" className="mt-6">
                  <WelcomeSection />
                </TabsContent>

                <TabsContent value="challenges" className="mt-6">
                  <ChallengeExplorer />
                </TabsContent>
                
                <TabsContent value="leaderboard" className="mt-6">
                  <div className="card p-6">
                    <h2 className="section-title">Leaderboard</h2>
                    <p className="mb-4">Track your progress and compare your results with other participants.</p>
                    <div className="p-8 text-center text-cybr-foreground/70">
                      <p>The leaderboard feature is coming soon!</p>
                      <p className="text-sm mt-2">Complete challenges to earn points and see your name here.</p>
                    </div>
                  </div>
                </TabsContent>
                
                <TabsContent value="resources" className="mt-6">
                  <div className="card p-6">
                    <h2 className="section-title">Learning Resources</h2>
                    <p className="mb-6">Additional materials to improve your secure coding skills:</p>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="border border-cybr-primary/20 p-4 rounded-lg bg-cybr-muted/30">
                        <h3 className="text-xl font-bold mb-2 text-cybr-primary">OWASP Resources</h3>
                        <ul className="list-disc pl-6 space-y-2">
                          <li><a href="https://owasp.org/www-project-top-ten/" className="text-cybr-primary hover:underline" target="_blank" rel="noopener noreferrer">OWASP Top 10</a></li>
                          <li><a href="https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/" className="text-cybr-primary hover:underline" target="_blank" rel="noopener noreferrer">Secure Coding Practices</a></li>
                          <li><a href="https://owasp.org/www-project-cheat-sheets/" className="text-cybr-primary hover:underline" target="_blank" rel="noopener noreferrer">OWASP Cheat Sheets</a></li>
                        </ul>
                      </div>
                      
                      <div className="border border-cybr-primary/20 p-4 rounded-lg bg-cybr-muted/30">
                        <h3 className="text-xl font-bold mb-2 text-cybr-primary">Books & Guides</h3>
                        <ul className="list-disc pl-6 space-y-2">
                          <li>The Art of Software Security Assessment</li>
                          <li>Secure Coding in C and C++</li>
                          <li>Web Application Security: A Beginner's Guide</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </TabsContent>
              </Tabs>
            </div>
          </ChallengeProvider>
        </div>
      </main>
    </div>
  );
};

export default Challenges;
