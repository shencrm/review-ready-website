
import React from 'react';
import { Link } from 'react-router-dom';

const Hero: React.FC = () => {
  return (
    <div className="relative py-20 overflow-hidden grid-pattern">
      {/* Background Elements */}
      <div className="absolute -top-24 -left-24 w-64 h-64 bg-cybr-primary/5 rounded-full blur-3xl"></div>
      <div className="absolute -bottom-32 -right-32 w-96 h-96 bg-cybr-secondary/5 rounded-full blur-3xl"></div>
      
      <div className="container mx-auto px-4 relative">
        <div className="max-w-4xl mx-auto text-center">
          <h1 className="text-4xl md:text-6xl font-bold mb-6">
            Master <span className="text-cybr-primary">Secure Code Review</span>
          </h1>
          
          <div className="h-1 w-32 mx-auto my-8 animated-gradient rounded-full"></div>
          
          <p className="text-xl md:text-2xl mb-10 text-cybr-foreground/90">
            A comprehensive guide to identifying vulnerabilities, 
            implementing best practices, and building secure applications.
          </p>
          
          <div className="flex flex-col sm:flex-row justify-center gap-4 mb-12">
            <Link to="/getting-started" className="cybr-btn">
              Get Started
            </Link>
            <Link to="/methodology" className="cybr-btn">
              Learn Methodology
            </Link>
          </div>
          
          <div className="text-sm text-cybr-foreground/60">
            Based on <span className="text-cybr-secondary">OWASP</span> standards and industry best practices
          </div>
        </div>
      </div>
    </div>
  );
};

export default Hero;
