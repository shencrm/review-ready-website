
import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';

const Resources = () => {
  const officialResources = [
    {
      name: "OWASP Top 10",
      description: "The standard awareness document for developers and web application security focusing on the most critical security risks.",
      link: "https://owasp.org/www-project-top-ten/"
    },
    {
      name: "NIST Secure Software Development Framework (SSDF)",
      description: "Recommendations for mitigating the risk of software vulnerabilities throughout the development lifecycle.",
      link: "https://csrc.nist.gov/Projects/ssdf"
    },
    {
      name: "CWE/SANS Top 25",
      description: "List of the most dangerous software weaknesses that can lead to serious vulnerabilities in software.",
      link: "https://cwe.mitre.org/top25/"
    }
  ];

  const booksResources = [
    {
      name: "The Art of Software Security Assessment",
      author: "Mark Dowd, John McDonald, and Justin Schuh",
      description: "Comprehensive guide to software security assessment, covering everything from code auditing to exploitation techniques."
    },
    {
      name: "Secure Coding in C and C++",
      author: "Robert C. Seacord",
      description: "In-depth look at common programming errors in C/C++ and how to avoid security problems."
    },
    {
      name: "Web Application Security: A Beginner's Guide",
      author: "Bryan Sullivan and Vincent Liu",
      description: "Practical introduction to web application security, covering major vulnerabilities and defenses."
    }
  ];

  const tools = [
    {
      name: "OWASP ZAP",
      description: "Free security tool for finding vulnerabilities in web applications during development and testing.",
      link: "https://www.zaproxy.org/"
    },
    {
      name: "SonarQube",
      description: "Open-source platform for continuous inspection of code quality and security vulnerabilities.",
      link: "https://www.sonarqube.org/"
    },
    {
      name: "Dependency Check",
      description: "Software composition analysis tool that identifies project dependencies with known vulnerabilities.",
      link: "https://owasp.org/www-project-dependency-check/"
    }
  ];

  const communities = [
    {
      name: "OWASP Community",
      description: "Global community focused on improving software security with chapters worldwide.",
      link: "https://owasp.org/community/"
    },
    {
      name: "r/netsec on Reddit",
      description: "Active community discussing network security, web application security, and more.",
      link: "https://www.reddit.com/r/netsec/"
    },
    {
      name: "Security Stack Exchange",
      description: "Q&A forum for information security professionals.",
      link: "https://security.stackexchange.com/"
    }
  ];

  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      
      <main className="flex-grow py-12">
        <div className="container mx-auto px-4">
          <div className="mb-12">
            <h1 className="text-4xl font-bold mb-6">Resources</h1>
            <div className="h-1 w-24 bg-cybr-primary mb-6"></div>
            <p className="text-xl text-cybr-foreground/80">
              Additional materials to expand your secure code review knowledge.
            </p>
          </div>
          
          <section className="mb-12">
            <h2 className="text-2xl font-bold mb-6">Official Documentation & Standards</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {officialResources.map((resource, index) => (
                <div key={index} className="card">
                  <h3 className="text-xl font-bold mb-3">{resource.name}</h3>
                  <p className="mb-4 text-cybr-foreground/80">{resource.description}</p>
                  <a 
                    href={resource.link} 
                    target="_blank" 
                    rel="noreferrer"
                    className="text-cybr-primary hover:underline inline-flex items-center"
                  >
                    Visit Resource
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                    </svg>
                  </a>
                </div>
              ))}
            </div>
          </section>
          
          <section className="mb-12">
            <h2 className="text-2xl font-bold mb-6">Recommended Books</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {booksResources.map((book, index) => (
                <div key={index} className="card">
                  <h3 className="text-xl font-bold mb-2">{book.name}</h3>
                  <p className="text-sm text-cybr-secondary mb-3">by {book.author}</p>
                  <p className="text-cybr-foreground/80">{book.description}</p>
                </div>
              ))}
            </div>
          </section>
          
          <section className="mb-12">
            <h2 className="text-2xl font-bold mb-6">Tools & Utilities</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {tools.map((tool, index) => (
                <div key={index} className="card">
                  <h3 className="text-xl font-bold mb-3">{tool.name}</h3>
                  <p className="mb-4 text-cybr-foreground/80">{tool.description}</p>
                  <a 
                    href={tool.link} 
                    target="_blank" 
                    rel="noreferrer"
                    className="text-cybr-primary hover:underline inline-flex items-center"
                  >
                    View Tool
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                    </svg>
                  </a>
                </div>
              ))}
            </div>
          </section>
          
          <section className="mb-12">
            <h2 className="text-2xl font-bold mb-6">Communities & Forums</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {communities.map((community, index) => (
                <div key={index} className="card">
                  <h3 className="text-xl font-bold mb-3">{community.name}</h3>
                  <p className="mb-4 text-cybr-foreground/80">{community.description}</p>
                  <a 
                    href={community.link} 
                    target="_blank" 
                    rel="noreferrer"
                    className="text-cybr-primary hover:underline inline-flex items-center"
                  >
                    Join Community
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                    </svg>
                  </a>
                </div>
              ))}
            </div>
          </section>
          
          <section>
            <h2 className="text-2xl font-bold mb-6">Training & Certifications</h2>
            <div className="card">
              <h3 className="text-xl font-bold mb-4">Security Certifications</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="font-semibold text-cybr-secondary mb-2">Certified Secure Software Lifecycle Professional (CSSLP)</h4>
                  <p className="text-cybr-foreground/80 text-sm mb-3">
                    Demonstrates security expertise across the entire software development lifecycle.
                  </p>
                  <a 
                    href="https://www.isc2.org/Certifications/CSSLP" 
                    target="_blank" 
                    rel="noreferrer"
                    className="text-cybr-primary hover:underline text-sm"
                  >
                    Learn more
                  </a>
                </div>
                
                <div>
                  <h4 className="font-semibold text-cybr-secondary mb-2">Certified Ethical Hacker (CEH)</h4>
                  <p className="text-cybr-foreground/80 text-sm mb-3">
                    Focused on penetration testing methodologies and identifying security vulnerabilities.
                  </p>
                  <a 
                    href="https://www.eccouncil.org/train-certify/certified-ethical-hacker-ceh/" 
                    target="_blank" 
                    rel="noreferrer"
                    className="text-cybr-primary hover:underline text-sm"
                  >
                    Learn more
                  </a>
                </div>
                
                <div>
                  <h4 className="font-semibold text-cybr-secondary mb-2">GIAC Web Application Penetration Tester (GWAPT)</h4>
                  <p className="text-cybr-foreground/80 text-sm mb-3">
                    Specialized in web application security assessment and penetration testing.
                  </p>
                  <a 
                    href="https://www.giac.org/certification/web-application-penetration-tester-gwapt" 
                    target="_blank" 
                    rel="noreferrer"
                    className="text-cybr-primary hover:underline text-sm"
                  >
                    Learn more
                  </a>
                </div>
                
                <div>
                  <h4 className="font-semibold text-cybr-secondary mb-2">Offensive Security Web Expert (OSWE)</h4>
                  <p className="text-cybr-foreground/80 text-sm mb-3">
                    Advanced certification focused on white box web application security testing.
                  </p>
                  <a 
                    href="https://www.offensive-security.com/awae-oswe/" 
                    target="_blank" 
                    rel="noreferrer"
                    className="text-cybr-primary hover:underline text-sm"
                  >
                    Learn more
                  </a>
                </div>
              </div>
              
              <div className="mt-8">
                <h3 className="text-xl font-bold mb-4">Online Courses & Practice Environments</h3>
                <ul className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <li className="flex items-start">
                    <span className="inline-block w-4 h-4 bg-cybr-primary rounded-full mr-2 mt-1 flex-shrink-0"></span>
                    <a 
                      href="https://portswigger.net/web-security" 
                      target="_blank" 
                      rel="noreferrer" 
                      className="text-cybr-primary hover:underline"
                    >
                      PortSwigger Web Security Academy
                    </a>
                  </li>
                  <li className="flex items-start">
                    <span className="inline-block w-4 h-4 bg-cybr-primary rounded-full mr-2 mt-1 flex-shrink-0"></span>
                    <a 
                      href="https://www.hacksplaining.com/" 
                      target="_blank" 
                      rel="noreferrer" 
                      className="text-cybr-primary hover:underline"
                    >
                      Hacksplaining
                    </a>
                  </li>
                  <li className="flex items-start">
                    <span className="inline-block w-4 h-4 bg-cybr-primary rounded-full mr-2 mt-1 flex-shrink-0"></span>
                    <a 
                      href="https://owasp.org/www-project-webgoat/" 
                      target="_blank" 
                      rel="noreferrer" 
                      className="text-cybr-primary hover:underline"
                    >
                      OWASP WebGoat
                    </a>
                  </li>
                  <li className="flex items-start">
                    <span className="inline-block w-4 h-4 bg-cybr-primary rounded-full mr-2 mt-1 flex-shrink-0"></span>
                    <a 
                      href="https://www.securecodewarrior.com/" 
                      target="_blank" 
                      rel="noreferrer" 
                      className="text-cybr-primary hover:underline"
                    >
                      Secure Code Warrior
                    </a>
                  </li>
                  <li className="flex items-start">
                    <span className="inline-block w-4 h-4 bg-cybr-primary rounded-full mr-2 mt-1 flex-shrink-0"></span>
                    <a 
                      href="https://www.pentesteracademy.com/" 
                      target="_blank" 
                      rel="noreferrer" 
                      className="text-cybr-primary hover:underline"
                    >
                      Pentester Academy
                    </a>
                  </li>
                  <li className="flex items-start">
                    <span className="inline-block w-4 h-4 bg-cybr-primary rounded-full mr-2 mt-1 flex-shrink-0"></span>
                    <a 
                      href="https://tryhackme.com/" 
                      target="_blank" 
                      rel="noreferrer" 
                      className="text-cybr-primary hover:underline"
                    >
                      TryHackMe
                    </a>
                  </li>
                </ul>
              </div>
            </div>
          </section>
        </div>
      </main>
      
      <Footer />
    </div>
  );
};

export default Resources;
