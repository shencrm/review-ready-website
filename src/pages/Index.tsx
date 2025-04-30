
import React from 'react';
import Hero from '@/components/Hero';
import SecurityCard from '@/components/SecurityCard';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import { Link } from 'react-router-dom';

const Index = () => {
  const securityTopics = [
    {
      title: "Methodology",
      description: "Learn step-by-step approaches for conducting effective security code reviews across various project types.",
      path: "/methodology"
    },
    {
      title: "Language Guides",
      description: "Explore language-specific security vulnerabilities and best practices for major programming languages.",
      path: "/languages"
    },
    {
      title: "Database Security",
      description: "Master techniques to identify and prevent SQL injection and other database security issues.",
      path: "/database-security"
    },
    {
      title: "Tools & Automation",
      description: "Discover tools and automation strategies to enhance your secure code review process.",
      path: "/tools"
    },
  ];

  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      
      <main className="flex-grow">
        <Hero />
        
        <section className="py-16">
          <div className="container mx-auto px-4">
            <div className="mb-12 text-center">
              <h2 className="text-3xl md:text-4xl font-bold mb-6">Why Secure Code Review Matters</h2>
              <p className="max-w-3xl mx-auto text-lg text-cybr-foreground/80">
                Security vulnerabilities cost businesses millions each year and damage user trust. 
                Proactive code reviews identify issues before they become exploitable weaknesses.
              </p>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
              <div className="card">
                <div className="w-12 h-12 flex items-center justify-center bg-cybr-primary/10 rounded-full mb-6">
                  <span className="text-2xl text-cybr-primary">🔍</span>
                </div>
                <h3 className="text-xl font-bold mb-3">Early Detection</h3>
                <p className="text-cybr-foreground/80">
                  Find security flaws during development when they're easier and less costly to fix.
                </p>
              </div>
              
              <div className="card">
                <div className="w-12 h-12 flex items-center justify-center bg-cybr-secondary/10 rounded-full mb-6">
                  <span className="text-2xl text-cybr-secondary">🛡️</span>
                </div>
                <h3 className="text-xl font-bold mb-3">Risk Mitigation</h3>
                <p className="text-cybr-foreground/80">
                  Systematically reduce the attack surface and protect sensitive data.
                </p>
              </div>
              
              <div className="card">
                <div className="w-12 h-12 flex items-center justify-center bg-cybr-accent/10 rounded-full mb-6">
                  <span className="text-2xl text-cybr-accent">💡</span>
                </div>
                <h3 className="text-xl font-bold mb-3">Knowledge Sharing</h3>
                <p className="text-cybr-foreground/80">
                  Build security awareness across development teams through collaborative review.
                </p>
              </div>
            </div>
          </div>
        </section>
        
        <section className="py-16 bg-cybr-muted/30">
          <div className="container mx-auto px-4">
            <div className="mb-12">
              <h2 className="section-title">Explore Our Security Topics</h2>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              {securityTopics.map((topic, index) => (
                <Link to={topic.path} key={index} className="block">
                  <SecurityCard 
                    title={topic.title}
                    description={topic.description}
                    className="h-full hover:-translate-y-1 transition-transform duration-300"
                  />
                </Link>
              ))}
            </div>
          </div>
        </section>
        
        <section className="py-16">
          <div className="container mx-auto px-4">
            <div className="mb-12 text-center">
              <h2 className="text-3xl md:text-4xl font-bold mb-6">Getting Started Is Easy</h2>
              <p className="max-w-3xl mx-auto text-lg text-cybr-foreground/80">
                Begin your journey to becoming proficient in secure code review with our structured learning path.
              </p>
            </div>
            
            <div className="max-w-4xl mx-auto">
              <div className="relative">
                <div className="absolute left-4 inset-y-0 w-0.5 bg-gradient-to-b from-cybr-primary via-cybr-secondary to-cybr-accent"></div>
                
                <div className="relative pl-12 pb-12">
                  <div className="absolute left-0 w-8 h-8 bg-cybr-primary rounded-full flex items-center justify-center">
                    <span className="text-cybr-background font-bold">1</span>
                  </div>
                  <h3 className="text-xl font-bold mb-2">Learn the Prerequisites</h3>
                  <p className="text-cybr-foreground/80">
                    Familiarize yourself with basic programming concepts and security fundamentals.
                  </p>
                </div>
                
                <div className="relative pl-12 pb-12">
                  <div className="absolute left-0 w-8 h-8 bg-cybr-secondary rounded-full flex items-center justify-center">
                    <span className="text-cybr-background font-bold">2</span>
                  </div>
                  <h3 className="text-xl font-bold mb-2">Study the Methodology</h3>
                  <p className="text-cybr-foreground/80">
                    Understand the systematic approach to reviewing code for security vulnerabilities.
                  </p>
                </div>
                
                <div className="relative pl-12 pb-12">
                  <div className="absolute left-0 w-8 h-8 bg-cybr-accent rounded-full flex items-center justify-center">
                    <span className="text-cybr-background font-bold">3</span>
                  </div>
                  <h3 className="text-xl font-bold mb-2">Practice with Examples</h3>
                  <p className="text-cybr-foreground/80">
                    Apply your knowledge with real-world code snippets and vulnerability examples.
                  </p>
                </div>
                
                <div className="relative pl-12">
                  <div className="absolute left-0 w-8 h-8 bg-cybr-primary rounded-full flex items-center justify-center">
                    <span className="text-cybr-background font-bold">4</span>
                  </div>
                  <h3 className="text-xl font-bold mb-2">Master Advanced Techniques</h3>
                  <p className="text-cybr-foreground/80">
                    Deepen your expertise with specialized topics and automation tools.
                  </p>
                </div>
              </div>
            </div>
            
            <div className="text-center mt-12">
              <Link to="/getting-started" className="cybr-btn">
                Begin Your Journey
              </Link>
            </div>
          </div>
        </section>
      </main>
      
      <Footer />
    </div>
  );
};

export default Index;
