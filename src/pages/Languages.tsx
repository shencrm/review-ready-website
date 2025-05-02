
import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import { Link } from 'react-router-dom';

const Languages = () => {
  const languages = [
    {
      name: "JavaScript",
      description: "Learn about XSS, prototype pollution, insecure dependencies, and other common JavaScript vulnerabilities.",
      path: "/languages/javascript",
      icon: "JS"
    },
    {
      name: "Python",
      description: "Discover vulnerabilities in Python code, from insecure deserialization to command injection risks.",
      path: "/languages/python",
      icon: "PY"
    },
    {
      name: "Java",
      description: "Explore common security flaws in Java including improper validation, CSRF, and XXE vulnerabilities.",
      path: "/languages/java",
      icon: "JV"
    },
    {
      name: "C#",
      description: "Understand security issues in .NET including LINQ injection, insecure deserialization, and access control problems.",
      path: "/languages/csharp",
      icon: "C#"
    },
    {
      name: "PHP",
      description: "Learn about typical PHP vulnerabilities like remote code execution, file inclusion, and session security.",
      path: "/languages/php",
      icon: "PHP"
    },
    {
      name: "React",
      description: "Understand security vulnerabilities in React, secure state management, and XSS risks unique to React applications.",
      path: "/languages/react",
      icon: "RE"
    },
    {
      name: "Node.js",
      description: "Learn about server-side security, module vulnerabilities, and command injection in the Node.js environment.",
      path: "/languages/nodejs",
      icon: "ND"
    },
    {
      name: "Golang",
      description: "Explore the security of Go applications, error handling, and protection against common security threats in this modern language.",
      path: "/languages/golang",
      icon: "GO"
    }
  ];

  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      
      <main className="flex-grow py-12">
        <div className="container mx-auto px-4">
          <div className="mb-12">
            <h1 className="text-4xl font-bold mb-6">Programming Language-Specific Security Guides</h1>
            <div className="h-1 w-24 bg-cybr-primary mb-6"></div>
            <p className="text-xl text-cybr-foreground/80">
              Explore security vulnerabilities and best practices for different programming languages.
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {languages.map((language, index) => (
              <Link key={index} to={language.path} className="block group">
                <div className="card h-full group-hover:-translate-y-1 transition-transform duration-300">
                  <div className="flex items-start">
                    <div className="w-12 h-12 bg-cybr-muted rounded-md flex items-center justify-center text-cybr-primary font-mono text-xl font-bold mr-4">
                      {language.icon}
                    </div>
                    <div className="flex-1">
                      <h2 className="text-2xl font-bold mb-2 group-hover:text-cybr-primary transition-colors">
                        {language.name}
                      </h2>
                      <p className="text-cybr-foreground/80">
                        {language.description}
                      </p>
                    </div>
                  </div>
                </div>
              </Link>
            ))}
          </div>
          
          <div className="mt-16">
            <h2 className="text-2xl font-bold mb-6">Why Language-Specific Security Is Important</h2>
            <div className="card">
              <p className="mb-4">
                Each programming language has its own unique challenges and vulnerabilities. Understanding these language-specific issues is critical for conducting effective secure code reviews.
              </p>
              
              <p className="mb-4">
                While general security principles apply to all languages, the implementation details and common pitfalls vary significantly. For example:
              </p>
              
              <ul className="list-disc list-inside space-y-3 pl-4 text-cybr-foreground/80">
                <li>JavaScript faces unique challenges with prototype-based inheritance and browser DOM interactions</li>
                <li>Python with its dynamic typing can lead to unexpected security issues related to types</li>
                <li>Java's complex class structure and serialization mechanisms present specific attack vectors</li>
                <li>C# applications have vulnerabilities specific to the .NET framework</li>
                <li>PHP has historically been prone to inclusion vulnerabilities and injection flaws</li>
                <li>React requires an understanding of unique security risks in SPAs and state management</li>
                <li>Node.js requires special attention to server-side security in a JavaScript environment</li>
                <li>Golang, despite being relatively modern, can still be vulnerable if not implemented correctly</li>
              </ul>
              
              <p className="mt-4">
                By understanding language-specific issues, you can perform more focused and effective security reviews.
              </p>
            </div>
          </div>
          
          <div className="mt-16">
            <h2 className="text-2xl font-bold mb-6">Cross-Language Security Principles</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="card">
                <h3 className="text-xl font-bold mb-3">Input Validation</h3>
                <p className="text-cybr-foreground/80">
                  Always validate, sanitize, and encode user input regardless of language. Never trust external data.
                </p>
              </div>
              
              <div className="card">
                <h3 className="text-xl font-bold mb-3">Authentication & Authorization</h3>
                <p className="text-cybr-foreground/80">
                  Implement strong identity verification and proper access controls using language-specific best practices.
                </p>
              </div>
              
              <div className="card">
                <h3 className="text-xl font-bold mb-3">Data Protection</h3>
                <p className="text-cybr-foreground/80">
                  Use appropriate encryption, secure storage mechanisms, and careful handling of sensitive information.
                </p>
              </div>
            </div>
          </div>
        </div>
      </main>
      
      <Footer />
    </div>
  );
};

export default Languages;
