import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CodeExample from '@/components/CodeExample';
import { Link } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';

const ReactPage = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      
      <main className="flex-grow py-12">
        <div className="container mx-auto px-4">
          <div className="mb-12">
            <h1 className="text-4xl font-bold mb-6">React Security</h1>
            <div className="h-1 w-24 bg-cybr-primary mb-6"></div>
            <p className="text-xl text-cybr-foreground/80">
              Secure coding practices and vulnerability prevention for React applications.
            </p>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 space-y-8">
              <section>
                <h2 className="text-2xl font-bold mb-4">XSS in React Applications</h2>
                <p className="mb-4">
                  While React's design protects against most XSS vulnerabilities through automatic escaping,
                  there are several ways developers can inadvertently create security holes.
                </p>
                
                <CodeExample
                  language="jsx"
                  title="Dangerous Use of dangerouslySetInnerHTML"
                  code={`// VULNERABLE: Improper use of dangerouslySetInnerHTML
function UserProfile({ userProvidedHtml }) {
  return (
    <div className="profile-bio">
      <div dangerouslySetInnerHTML={{ __html: userProvidedHtml }} />
    </div>
  );
}

// If userProvidedHtml contains malicious script tags, they will execute`}
                />
                
                <CodeExample
                  language="jsx"
                  title="Secure Content Rendering"
                  code={`// SECURE: Using a sanitization library
import DOMPurify from 'dompurify';

function UserProfile({ userProvidedHtml }) {
  const sanitizedHtml = DOMPurify.sanitize(userProvidedHtml);
  
  return (
    <div className="profile-bio">
      <div dangerouslySetInnerHTML={{ __html: sanitizedHtml }} />
    </div>
  );
}

// ALTERNATIVE: Avoid HTML parsing entirely
function SaferUserProfile({ userProvidedText }) {
  return (
    <div className="profile-bio">
      {userProvidedText}
    </div>
  );
}`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">URL-Based Vulnerabilities</h2>
                <p className="mb-4">
                  React applications often use user-controlled URL parameters which can introduce security risks.
                </p>
                
                <CodeExample
                  language="jsx"
                  title="Insecure URL Handling"
                  code={`// VULNERABLE: Using user-provided URLs without validation
function ExternalLink({ url, children }) {
  return (
    <a href={url}>
      {children}
    </a>
  );
}

// Could be used like: <ExternalLink url="javascript:alert('XSS')">Click me</ExternalLink>
// Which creates a JavaScript protocol link that executes code`}
                />
                
                <CodeExample
                  language="jsx"
                  title="Secure URL Handling"
                  code={`// SECURE: URL validation and sanitization
function ExternalLink({ url, children }) {
  // Validate URLs - only allow http and https
  const isSafeUrl = /^https?:\\/\\//.test(url);
  
  // Use a fallback for unsafe URLs
  const safeUrl = isSafeUrl ? url : '#';
  
  return (
    <a 
      href={safeUrl} 
      target="_blank"
      rel="noopener noreferrer"
    >
      {children}
      {!isSafeUrl && <span> (invalid URL)</span>}
    </a>
  );
}`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Server-Side Rendering (SSR) Security</h2>
                <p className="mb-4">
                  React SSR introduces specific security concerns that aren't present in client-side only apps.
                </p>
                
                <CodeExample
                  language="jsx"
                  title="SSR Data Leakage"
                  code={`// VULNERABLE: Exposing sensitive data in initial state
function ServerComponent({ user }) {
  // Server renders this with all user data
  return (
    <div>
      <script
        dangerouslySetInnerHTML={{
          __html: \`window.__INITIAL_STATE__ = \${JSON.stringify({
            currentUser: user // Might include sensitive data!
          })}\`
        }}
      />
      <UserProfile user={user} />
    </div>
  );
}

// Even private fields in the user object get exposed to the client`}
                />
                
                <CodeExample
                  language="jsx"
                  title="Secure Initial State Handling"
                  code={`// SECURE: Filtering sensitive data before exposure
function sanitizeUserData(user) {
  // Only include safe fields for client exposure
  const { id, name, publicProfile } = user;
  return { id, name, publicProfile };
}

function ServerComponent({ user }) {
  const safeUserData = sanitizeUserData(user);
  
  return (
    <div>
      <script
        dangerouslySetInnerHTML={{
          __html: \`window.__INITIAL_STATE__ = \${JSON.stringify({
            currentUser: safeUserData
          })}\`
        }}
      />
      <UserProfile user={safeUserData} />
    </div>
  );
}`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">React State Management Security</h2>
                <p className="mb-4">
                  Common pitfalls when managing state in React applications that can lead to security vulnerabilities.
                </p>
                
                <CodeExample
                  language="jsx"
                  title="Insecure Storage of Sensitive Data"
                  code={`// VULNERABLE: Storing sensitive data in localStorage
function LoginForm() {
  const handleLogin = async (credentials) => {
    const response = await api.login(credentials);
    
    // Don't store sensitive information in localStorage
    localStorage.setItem('authToken', response.token);
    localStorage.setItem('userDetails', JSON.stringify(response.user));
  };
  
  // Rest of component...
}

// localStorage is vulnerable to XSS attacks - any script can access it`}
                />
                
                <CodeExample
                  language="jsx"
                  title="Secure Authentication State"
                  code={`// SECURE: Using memory state and HttpOnly cookies
function LoginForm() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [user, setUser] = useState(null);
  
  const handleLogin = async (credentials) => {
    // Backend sets HttpOnly, Secure cookies
    const response = await api.login(credentials);
    
    // Only store non-sensitive data in state
    setIsLoggedIn(true);
    setUser({
      id: response.user.id,
      name: response.user.name,
      role: response.user.role
    });
    
    // Sensitive authentication details remain in HttpOnly cookies
    // managed by the browser, inaccessible to JavaScript
  };
  
  // Rest of component...
}`}
                />
              </section>
            </div>
            
            <div className="lg:col-span-1">
              <div className="sticky top-24">
                <div className="card">
                  <h3 className="text-xl font-bold mb-4">React Security Concerns</h3>
                  <ul className="space-y-2 pl-4 text-cybr-foreground/80">
                    <li>Improper use of dangerouslySetInnerHTML</li>
                    <li>Unvalidated URLs in links</li>
                    <li>Sensitive data exposure in SSR</li>
                    <li>Insecure state management</li>
                    <li>Insufficient input validation</li>
                    <li>Unsafe dependency inclusion</li>
                    <li>Cross-Site Request Forgery</li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">React Security Tools</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://github.com/cure53/DOMPurify" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">DOMPurify</a></li>
                    <li><a href="https://github.com/snyk/snyk" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Snyk</a></li>
                    <li><a href="https://reactjs.org/docs/dom-elements.html" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">React DOM Elements</a></li>
                    <li><a href="https://eslint.org/docs/latest/rules/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">ESLint Rules</a></li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Related Technologies</h3>
                  <div className="space-y-3">
                    <Link to="/languages/javascript" className="block text-cybr-primary hover:underline">JavaScript Security</Link>
                    <Link to="/languages/nodejs" className="block text-cybr-primary hover:underline">Node.js Security</Link>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
      
      <Footer />
    </div>
  );
};

export default ReactPage;
