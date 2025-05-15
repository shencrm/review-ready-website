
import { Challenge } from './challenge-types';

export const clientSideSecurityChallenges: Challenge[] = [
  {
    id: 'client-security-1',
    title: 'React Authentication State Management',
    description: 'This React code manages user authentication. Does it handle authentication securely?',
    difficulty: 'medium',
    category: 'Client-Side Security',
    languages: ['JavaScript', 'React'],
    type: 'single',
    vulnerabilityType: 'Insecure Authentication Storage',
    code: `import React, { useState, useEffect } from 'react';

function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check if user is already logged in
    const token = localStorage.getItem('auth_token');
    const userData = localStorage.getItem('user_data');
    
    if (token && userData) {
      setUser(JSON.parse(userData));
    }
    
    setLoading(false);
  }, []);

  const login = async (email, password) => {
    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      
      const data = await response.json();
      
      if (response.ok) {
        localStorage.setItem('auth_token', data.token);
        localStorage.setItem('user_data', JSON.stringify(data.user));
        setUser(data.user);
        return { success: true };
      } else {
        return { success: false, error: data.error };
      }
    } catch (error) {
      return { success: false, error: 'Network error' };
    }
  };

  const logout = () => {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user_data');
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
}`,
    answer: false,
    explanation: "This implementation has security issues: 1) It stores sensitive user data and tokens in localStorage, which is accessible to any JavaScript running on the domain and vulnerable to XSS attacks, 2) There's no token validation or expiration checking, 3) No CSRF protection when making API calls, 4) No secure handling of the token (e.g., HttpOnly cookies would be more secure). A better approach would use HttpOnly cookies for the token and avoid storing sensitive user data on the client side."
  },
  {
    id: 'client-security-2',
    title: 'React Router Authorization',
    description: 'Review this React protected route implementation. Is it securely implemented?',
    difficulty: 'easy',
    category: 'Client-Side Security',
    languages: ['JavaScript', 'React'],
    type: 'single',
    vulnerabilityType: 'Broken Access Control',
    code: `import React from 'react';
import { Route, Redirect } from 'react-router-dom';

function ProtectedRoute({ component: Component, ...rest }) {
  const isAuthenticated = localStorage.getItem('auth_token') !== null;

  return (
    <Route
      {...rest}
      render={(props) =>
        isAuthenticated ? (
          <Component {...props} />
        ) : (
          <Redirect to="/login" />
        )
      }
    />
  );
}

// Usage in routes configuration
function AppRoutes() {
  return (
    <Switch>
      <Route exact path="/" component={Home} />
      <Route path="/login" component={Login} />
      <ProtectedRoute path="/dashboard" component={Dashboard} />
      <ProtectedRoute path="/admin" component={AdminPanel} />
    </Switch>
  );
}`,
    answer: false,
    explanation: "This implementation is not secure because: 1) It only checks for the presence of an auth_token in localStorage without validating it, 2) localStorage can be easily manipulated by users in the browser, 3) There's no role-based access control - all protected routes use the same check, meaning any authenticated user could access the admin panel, 4) Client-side route protection is easily bypassed and should always be complemented by server-side authorization checks. A better approach would verify the token on the server and implement proper role-based access control."
  }
];
