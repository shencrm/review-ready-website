
import React from 'react';
import { Link } from 'react-router-dom';

const Footer: React.FC = () => {
  return (
    <footer className="mt-20 py-12 bg-cybr-muted/50 border-t border-cybr-muted">
      <div className="container mx-auto px-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div className="col-span-1 md:col-span-2">
            <Link to="/" className="flex items-center space-x-2 mb-4">
              <div className="w-8 h-8 rounded-full bg-cybr-primary"></div>
              <span className="text-xl font-bold text-cybr-foreground">
                Secure<span className="text-cybr-primary">CodeReview</span>
              </span>
            </Link>
            <p className="text-cybr-foreground/80 mb-6">
              A comprehensive guide for aspiring Application Security Engineers, covering methodologies, 
              best practices, language-specific vulnerabilities, and more.
            </p>
          </div>
          
          <div>
            <h3 className="text-lg font-semibold mb-4 text-cybr-foreground">Sections</h3>
            <ul className="space-y-2">
              <li><Link to="/" className="text-cybr-foreground/70 hover:text-cybr-primary">Home</Link></li>
              <li><Link to="/getting-started" className="text-cybr-foreground/70 hover:text-cybr-primary">Getting Started</Link></li>
              <li><Link to="/methodology" className="text-cybr-foreground/70 hover:text-cybr-primary">Methodology</Link></li>
              <li><Link to="/languages" className="text-cybr-foreground/70 hover:text-cybr-primary">Languages</Link></li>
              <li><Link to="/database-security" className="text-cybr-foreground/70 hover:text-cybr-primary">Database Security</Link></li>
            </ul>
          </div>
          
          <div>
            <h3 className="text-lg font-semibold mb-4 text-cybr-foreground">Resources</h3>
            <ul className="space-y-2">
              <li><Link to="/tools" className="text-cybr-foreground/70 hover:text-cybr-primary">Tools</Link></li>
              <li><Link to="/checklists" className="text-cybr-foreground/70 hover:text-cybr-primary">Checklists</Link></li>
              <li><Link to="/resources" className="text-cybr-foreground/70 hover:text-cybr-primary">Resources</Link></li>
              <li><Link to="/contact" className="text-cybr-foreground/70 hover:text-cybr-primary">Contact</Link></li>
            </ul>
          </div>
        </div>
        
        <div className="mt-8 pt-8 border-t border-cybr-muted text-center text-cybr-foreground/60">
          <p>© {new Date().getFullYear()} SecureCodeReview. All rights reserved.</p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
