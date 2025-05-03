
import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CodeExample from '@/components/CodeExample';
import { Link } from 'react-router-dom';
import { Shield, Code, AlertTriangle, FileWarning } from 'lucide-react';

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
              Security vulnerabilities and best practices for React applications.
            </p>
          </div>
          
          <div className="card mb-8">
            <h2 className="text-2xl font-bold mb-4">About React</h2>
            <p className="mb-4">
              React is an open-source JavaScript library for building user interfaces, particularly for single-page applications.
              Developed and maintained by Facebook (now Meta) and released in 2013, React has revolutionized front-end development
              with its component-based architecture and virtual DOM implementation for efficient UI updates.
            </p>
            <p className="mb-4">
              Unlike traditional frameworks, React focuses only on the view layer of an application, making it easy to integrate
              with other libraries or frameworks for routing, state management, and other functionalities. Its declarative
              approach allows developers to design simple views for each state in their application, and React efficiently
              updates and renders just the right components when data changes.
            </p>
            <p className="mb-4">
              React has become one of the most popular front-end technologies due to its performance, flexibility, and strong
              community support. It's used by major companies worldwide, including Facebook, Instagram, Netflix, Airbnb, and
              many others. The ecosystem has expanded to include React Native for mobile development and frameworks like Next.js
              and Gatsby that build upon React's foundation.
            </p>
            <p>
              From a security perspective, React provides some built-in protections against common web vulnerabilities like XSS
              through features such as JSX escaping. However, React applications can still be vulnerable to various security issues
              depending on how they're implemented, especially when integrating with APIs, managing authentication, handling user
              input, or incorporating third-party dependencies. Understanding these security considerations is crucial for React
              developers.
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
                  code={`// VULNERABLE: Incorrect use of dangerouslySetInnerHTML
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
                  title="Secure Content Display"
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

// ALTERNATIVE: Avoid HTML parsing altogether
function SaferUserProfile({ userProvidedText }) {
  return (
    <div className="profile-bio">
      {userProvidedText}
    </div>
  );
}`}
                />

                <CodeExample
                  language="jsx"
                  title="Advanced XSS Protection Example in React"
                  code={`// Most comprehensive approach - full sanitization with allowlisted tags
import DOMPurify from 'dompurify';
import React, { useState, useEffect } from 'react';

function SecureContentRenderer({ content, allowedTags = ['b', 'i', 'em', 'strong', 'a', 'p', 'br'] }) {
  const [sanitizedContent, setSanitizedContent] = useState('');
  
  useEffect(() => {
    // Configure DOMPurify to restrict allowed tags and attributes
    DOMPurify.setConfig({
      ALLOWED_TAGS: allowedTags,
      ALLOWED_ATTR: ['href', 'target', 'rel', 'title', 'class'],
      ALLOW_DATA_ATTR: false,
      ADD_ATTR: ['target'], // Add target="_blank" to links
      FORBID_TAGS: ['script', 'style', 'iframe', 'form', 'object', 'embed'],
      FORBID_ATTR: ['onerror', 'onload', 'onclick']
    });
    
    // Clean the content
    const cleaned = DOMPurify.sanitize(content, {
      USE_PROFILES: { html: true }
    });
    
    // Add rel="noopener noreferrer" to all links
    const parser = new DOMParser();
    const doc = parser.parseFromString(cleaned, 'text/html');
    
    const links = doc.querySelectorAll('a');
    links.forEach(link => {
      link.setAttribute('rel', 'noopener noreferrer');
      link.setAttribute('target', '_blank');
    });
    
    // Convert back to string
    const safeContent = doc.body.innerHTML;
    setSanitizedContent(safeContent);
  }, [content, allowedTags]);
  
  return (
    <div className="secure-content">
      {sanitizedContent ? (
        <div dangerouslySetInnerHTML={{ __html: sanitizedContent }} />
      ) : (
        <p>Loading secure content...</p>
      )}
    </div>
  );
}

function UserContentExample() {
  // Example usage
  const userContent = \`
    <h2>My Heading</h2>
    <p>Paragraph with <strong>bold</strong> <em>formatting</em></p>
    <script>alert('XSS attempt');</script>
    <a href="https://example.com" onclick="alert('XSS')">Example Link</a>
    <iframe src="https://malicious-site.com"></iframe>
    <div data-custom="exploit">Allowed tag but with forbidden attribute</div>
  \`;
  
  return (
    <div className="user-content-container">
      <h1>Secure User Content</h1>
      <SecureContentRenderer 
        content={userContent}
        allowedTags={['h2', 'h3', 'p', 'strong', 'em', 'a', 'ul', 'ol', 'li']}
      />
      
      <div className="mt-4 p-3 bg-yellow-100 border border-yellow-300 rounded">
        <p>Note: The content has been filtered and all forbidden tags like script, iframe and event attributes have been removed.</p>
      </div>
    </div>
  );
}`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">URL-based Vulnerabilities</h2>
                <p className="mb-4">
                  React applications often use URL parameters controlled by users, which can introduce security risks.
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
                  code={`// SECURE: Validate and sanitize URLs
function ExternalLink({ url, children }) {
  // Validate URLs - only allow http and https
  const isSafeUrl = /^https?:\\/\\//.test(url);
  
  // Use default for unsafe URLs
  const safeUrl = isSafeUrl ? url : '#';
  
  return (
    <a 
      href={safeUrl} 
      target="_blank"
      rel="noopener noreferrer"
    >
      {children}
      {!isSafeUrl && <span> (Invalid URL)</span>}
    </a>
  );
}`}
                />

                <CodeExample
                  language="jsx"
                  title="More Comprehensive URL Management"
                  code={`// Advanced solution for URL validation and filtering
import { useState, useEffect } from 'react';

// Custom hook for URL safety validation
function useSafeUrl(initialUrl) {
  const [url, setUrl] = useState('');
  const [isValid, setIsValid] = useState(false);
  const [error, setError] = useState('');
  
  useEffect(() => {
    if (!initialUrl) {
      setUrl('#');
      setIsValid(false);
      setError('No URL provided');
      return;
    }
    
    try {
      // Try to parse the URL
      const parsedUrl = new URL(initialUrl);
      
      // Check protocol
      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        setUrl('#');
        setIsValid(false);
        setError(\`Unauthorized protocol: \${parsedUrl.protocol}\`);
        return;
      }
      
      // Blacklist of known malicious domains
      const blacklistedDomains = ['evil.com', 'malware.site', 'phishing.example'];
      if (blacklistedDomains.includes(parsedUrl.hostname)) {
        setUrl('#');
        setIsValid(false);
        setError('Suspicious domain detected');
        return;
      }
      
      // Additional checks as needed (e.g., URL length)
      if (initialUrl.length > 2000) {
        setUrl('#');
        setIsValid(false);
        setError('URL too long');
        return;
      }
      
      // URL is safe
      setUrl(initialUrl);
      setIsValid(true);
      setError('');
    } catch (error) {
      // Invalid URL that couldn't be parsed
      setUrl('#');
      setIsValid(false);
      setError('Invalid URL format');
    }
  }, [initialUrl]);
  
  return { url, isValid, error };
}

// Wrapper component for safe external links
function SafeExternalLink({ url, children, className = '' }) {
  const { url: safeUrl, isValid, error } = useSafeUrl(url);
  
  return (
    <div className="safe-link-wrapper">
      <a 
        href={safeUrl} 
        target={isValid ? "_blank" : "_self"}
        rel={isValid ? "noopener noreferrer" : undefined}
        className={\`\${className} \${!isValid ? 'cursor-not-allowed opacity-70' : ''}\`}
      >
        {children}
      </a>
      {!isValid && (
        <div className="text-red-500 text-xs mt-1" title={error}>
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          <span className="ml-1">Unsafe link</span>
        </div>
      )}
    </div>
  );
}

// Example usage
function LinkDemo() {
  return (
    <div className="space-y-4">
      <h2>Link Examples:</h2>
      
      <div>
        <h3>Valid Link:</h3>
        <SafeExternalLink url="https://example.com">Example Site</SafeExternalLink>
      </div>
      
      <div>
        <h3>JavaScript Protocol Link (will be blocked):</h3>
        <SafeExternalLink url="javascript:alert('XSS')">Malicious JavaScript Link</SafeExternalLink>
      </div>
      
      <div>
        <h3>Suspicious Domain Link (will be blocked):</h3>
        <SafeExternalLink url="https://evil.com">Suspicious Site</SafeExternalLink>
      </div>
      
      <div>
        <h3>Invalid Link (will be blocked):</h3>
        <SafeExternalLink url="not-a-valid-url">Invalid Link</SafeExternalLink>
      </div>
    </div>
  );
}`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Server-Side Rendering (SSR) Security</h2>
                <p className="mb-4">
                  Server-side rendering in React introduces specific security concerns not present in client-side only applications.
                </p>
                
                <CodeExample
                  language="jsx"
                  title="SSR Data Leakage"
                  code={`// VULNERABLE: Exposing sensitive information in initial state
function ServerComponent({ user }) {
  // Server renders this with all user data
  return (
    <div>
      <script
        dangerouslySetInnerHTML={{
          __html: \`window.__INITIAL_STATE__ = \${JSON.stringify({
            currentUser: user // May include sensitive info!
          })}\`
        }}
      />
      <UserProfile user={user} />
    </div>
  );
}

// Even private fields in user object are exposed to client`}
                />
                
                <CodeExample
                  language="jsx"
                  title="Secure Initial State Handling"
                  code={`// SECURE: Filter sensitive information before exposure
function sanitizeUserData(user) {
  // Include only client-safe fields
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

                <CodeExample
                  language="jsx"
                  title="Advanced SSR Security Approach"
                  code={`// Comprehensive approach to SSR security in Next.js
import { useEffect } from 'react';
import { GetServerSideProps } from 'next';
import { serialize } from 'cookie';

// Comprehensive sanitization function
function sanitizeDataForClient(data) {
  // Recursive function to filter sensitive info from any data structure
  function sanitizeObject(obj) {
    if (obj === null || typeof obj !== 'object') {
      return obj;
    }
    
    // Handle arrays
    if (Array.isArray(obj)) {
      return obj.map(item => sanitizeObject(item));
    }
    
    // Handle objects
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      // Skip sensitive fields
      if (['password', 'token', 'secret', 'apiKey', 'ssn', 'creditCard'].includes(key)) {
        continue;
      }
      
      // If it's an object, apply sanitization recursively
      sanitized[key] = sanitizeObject(value);
    }
    
    return sanitized;
  }
  
  return sanitizeObject(data);
}

// Safe initial state hydration
function SafeStateHydration({ pageProps }) {
  return (
    <>
      {/* Pass sanitized data to initial state */}
      <script
        id="__NEXT_DATA_SANITIZED__"
        type="application/json"
        dangerouslySetInnerHTML={{
          __html: JSON.stringify({
            props: sanitizeDataForClient(pageProps),
          })
        }}
      />
    </>
  );
}

// Example Next.js page with SSR security
function UserDashboard({ user, privateData, publicData }) {
  // Instead of relying on server data, make an additional API request for sensitive info after client-side authentication
  useEffect(() => {
    // This will only run on the client after initial render
    const fetchSensitiveData = async () => {
      if (user && user.isAuthenticated) {
        try {
          const response = await fetch('/api/user/sensitive-data', {
            credentials: 'include' // Send cookies
          });
          if (response.ok) {
            const sensitiveData = await response.json();
            // Update state with sensitive info
            // Used only on Client Side and not transmitted in SSR
          }
        } catch (error) {
          console.error('Error loading sensitive data:', error);
        }
      }
    };
    
    fetchSensitiveData();
  }, [user]);

  return (
    <div>
      <SafeStateHydration pageProps={{ user, publicData }} />
      <h1>Dashboard for {user.name}</h1>
      <div className="public-data">
        {/* Display public data from SSR */}
        <PublicProfile data={publicData} />
      </div>
      
      {/* Sensitive components only rendered client-side after additional verification */}
      <ClientSideSecureComponent userId={user.id} />
    </div>
  );
}

// Example of GetServerSideProps with security
export const getServerSideProps: GetServerSideProps = async (context) => {
  // Authenticate user with secure HttpOnly cookies
  const authCookie = context.req.cookies.authToken;
  
  // If no authentication, redirect to login
  if (!authCookie) {
    return {
      redirect: {
        destination: '/login',
        permanent: false,
      }
    };
  }
  
  try {
    // Validate and fetch user data server-side
    const user = await validateUserSession(authCookie);
    
    // Set a new auth cookie with short expiry
    context.res.setHeader('Set-Cookie', [
      serialize('authToken', refreshedToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 3600, // One hour
        path: '/',
      })
    ]);
    
    // Fetch public and private data
    const publicData = await fetchPublicUserData(user.id);
    const privateData = await fetchPrivateUserData(user.id);
    
    // Return filtered data after sanitization
    return {
      props: {
        user: sanitizeDataForClient(user),
        publicData,
        // Not returning privateData intentionally - will be fetched client-side with API call
      }
    };
  } catch (error) {
    console.error('SSR error:', error);
    
    // On auth error, clear the cookie and send to login
    context.res.setHeader('Set-Cookie', [
      serialize('authToken', '', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        expires: new Date(0),
        path: '/',
      })
    ]);
    
    return {
      redirect: {
        destination: '/login?error=session_expired',
        permanent: false,
      }
    };
  }
};

export default UserDashboard;`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">React State Management Security</h2>
                <p className="mb-4">
                  Common pitfalls in state management for React applications that can lead to security vulnerabilities.
                </p>
                
                <CodeExample
                  language="jsx"
                  title="Insecure Storage of Sensitive Information"
                  code={`// VULNERABLE: Storing sensitive information in localStorage
function LoginForm() {
  const handleLogin = async (credentials) => {
    const response = await api.login(credentials);
    
    // Don't store sensitive info in localStorage
    localStorage.setItem('authToken', response.token);
    localStorage.setItem('userDetails', JSON.stringify(response.user));
  };
  
  // Rest of component...
}

// localStorage is exposed to XSS attacks - any script can access it`}
                />
                
                <CodeExample
                  language="jsx"
                  title="Secure Authentication State"
                  code={`// SECURE: Using memory state and HttpOnly cookies
function LoginForm() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [user, setUser] = useState(null);
  
  const handleLogin = async (credentials) => {
    // HttpOnly, Secure cookies are set by the backend
    const response = await api.login(credentials);
    
    // Store only non-sensitive info in state
    setIsLoggedIn(true);
    setUser({
      id: response.user.id,
      name: response.user.name,
      role: response.user.role
    });
    
    // Sensitive auth details remain in HttpOnly cookies
    // Managed by browser, not accessible to JavaScript
  };
  
  // Rest of component...
}`}
                />

                <CodeExample
                  language="jsx"
                  title="Full Implementation of Secure State with React Context API"
                  code={`// auth-context.js - Comprehensive authentication security implementation in React
import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import jwtDecode from 'jwt-decode';

// Create context
const AuthContext = createContext(null);

// Hook to use the auth context
export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

// Auth provider
export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // Check auth status when app loads
  const checkAuthStatus = useCallback(async () => {
    try {
      setLoading(true);
      
      // Make API call to verify auth based on HttpOnly cookies
      // Cookies sent automatically with credentials: 'include'
      const response = await fetch('/api/auth/verify', {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json'
        }
      });
      
      if (!response.ok) {
        throw new Error('Session expired');
      }
      
      const data = await response.json();
      
      // Store only non-sensitive info in state
      setUser({
        id: data.id,
        name: data.name,
        email: data.email,
        role: data.role,
        permissions: data.permissions
      });
      
      setError(null);
      
    } catch (err) {
      setUser(null);
      setError('Not logged in');
      console.error('Authentication error:', err);
    } finally {
      setLoading(false);
    }
  }, []);
  
  // Check auth status when component loads
  useEffect(() => {
    checkAuthStatus();
    
    // Optional: refresh auth at regular intervals
    const refreshInterval = setInterval(() => {
      if (user) { // Only refresh if user is logged in
        checkAuthStatus();
      }
    }, 10 * 60 * 1000); // Every 10 minutes
    
    return () => clearInterval(refreshInterval);
  }, [checkAuthStatus, user]);
  
  // Login function
  const login = async (credentials) => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        credentials: 'include', // Required to receive HttpOnly cookies
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(credentials)
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Login error');
      }
      
      const data = await response.json();
      
      // Store only non-sensitive info in state
      setUser({
        id: data.user.id,
        name: data.user.name,
        email: data.user.email,
        role: data.user.role,
        permissions: data.user.permissions
      });
      
      return true;
    } catch (err) {
      setError(err.message);
      return false;
    } finally {
      setLoading(false);
    }
  };
  
  // Logout function
  const logout = async () => {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json'
        }
      });
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      // Even if server call fails, update local state
      setUser(null);
    }
  };
  
  // Check if user has a specific permission
  const hasPermission = (permission) => {
    if (!user || !user.permissions) return false;
    return user.permissions.includes(permission);
  };
  
  // Check if user has a specific role
  const hasRole = (role) => {
    if (!user) return false;
    return user.role === role;
  };
  
  // Value provided to context consumers
  const contextValue = {
    user,
    isAuthenticated: !!user,
    loading,
    error,
    login,
    logout,
    checkAuthStatus,
    hasPermission,
    hasRole
  };
  
  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
}

// Secure route component that requires authentication
export function ProtectedRoute({ children, requiredPermissions = [], requiredRoles = [] }) {
  const { isAuthenticated, user, hasPermission, hasRole, loading } = useAuth();
  
  if (loading) {
    return <div>Loading...</div>;
  }
  
  // Check if user is logged in
  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  
  // Check permissions if specified
  if (requiredPermissions.length > 0) {
    const hasAllPermissions = requiredPermissions.every(perm => hasPermission(perm));
    if (!hasAllPermissions) {
      return <AccessDenied message="You don't have the required permissions to view this page" />;
    }
  }
  
  // Check roles if specified
  if (requiredRoles.length > 0) {
    const hasRequiredRole = requiredRoles.some(role => hasRole(role));
    if (!hasRequiredRole) {
      return <AccessDenied message="A higher role is required to access this page" />;
    }
  }
  
  return <>{children}</>;
}

// Example login page
function LoginPage() {
  const { login, error, isAuthenticated } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();
  const location = useLocation();
  
  const from = location.state?.from || '/dashboard';
  
  useEffect(() => {
    if (isAuthenticated) {
      navigate(from, { replace: true });
    }
  }, [isAuthenticated, navigate, from]);
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    const success = await login({ email, password });
    if (success) {
      navigate(from, { replace: true });
    }
  };
  
  return (
    <div className="login-page">
      <h1>Login</h1>
      <form onSubmit={handleSubmit}>
        {error && <div className="error-message">{error}</div>}
        <div>
          <label htmlFor="email">Email:</label>
          <input
            id="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>
        <div>
          <label htmlFor="password">Password:</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        <button type="submit">Login</button>
      </form>
    </div>
  );
}

// Using auth system in application
function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/dashboard" element={
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        } />
        <Route path="/admin" element={
          <ProtectedRoute requiredRoles={['admin']}>
            <AdminPanel />
          </ProtectedRoute>
        } />
        <Route path="/reports" element={
          <ProtectedRoute requiredPermissions={['view:reports']}>
            <ReportsPage />
          </ProtectedRoute>
        } />
      </Routes>
    </AuthProvider>
  );
}`}
                />
              </section>
            </div>
            
            <div className="lg:col-span-1">
              <div className="sticky top-24">
                <div className="card">
                  <h3 className="text-xl font-bold mb-4">React Security Issues</h3>
                  <ul className="space-y-2 pl-4 text-cybr-foreground/80">
                    <li>Improper use of dangerouslySetInnerHTML</li>
                    <li>Unvalidated URLs in links</li>
                    <li>Sensitive data exposure in SSR</li>
                    <li>Insecure state management</li>
                    <li>Insufficient input validation</li>
                    <li>Including unsafe dependencies</li>
                    <li>Cross-Site Request Forgery (CSRF)</li>
                    <li>DOM-based vector vulnerabilities</li>
                    <li>Sensitive data leakage</li>
                    <li>Lack of component access control</li>
                    <li>Insecure token management</li>
                    <li>Unsafe third-party components</li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">React Security Tools</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://github.com/cure53/DOMPurify" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">DOMPurify</a></li>
                    <li><a href="https://github.com/snyk/snyk" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Snyk</a></li>
                    <li><a href="https://reactjs.org/docs/dom-elements.html" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">React DOM Elements</a></li>
                    <li><a href="https://eslint.org/docs/latest/rules/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">ESLint Rules</a></li>
                    <li><a href="https://www.npmjs.com/package/js-xss" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">js-xss</a></li>
                    <li><a href="https://www.npmjs.com/package/serialize-javascript" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">serialize-javascript</a></li>
                    <li><a href="https://www.npmjs.com/package/@hapi/joi" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">joi (validation)</a></li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">React Security Resources</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://reactjs.org/docs/security.html" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">React Security Docs</a></li>
                    <li><a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP Top 10</a></li>
                    <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/React_Security_Cheat_Sheet.html" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP React Cheatsheet</a></li>
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
