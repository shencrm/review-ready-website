import { Challenge } from './challenge-types';

export const frontEndVulnerabilitiesChallenges: Challenge[] = [
  {
    id: 'frontend-vuln-1',
    title: 'Insecure Storage in Browser',
    description: 'This React code stores user authentication data. What security issue does it have?',
    difficulty: 'easy',
    category: 'Client-Side Security',
    languages: ['JavaScript', 'React'],
    type: 'single',
    vulnerabilityType: 'Insecure Client Storage',
    code: `import React, { useState, useEffect } from 'react';
import axios from 'axios';

function UserProfile() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check if we have user data in localStorage
    const savedUserData = localStorage.getItem('user_data');
    
    if (savedUserData) {
      // Parse the saved user data including auth token
      const userData = JSON.parse(savedUserData);
      setUser(userData);
      setLoading(false);
    } else {
      // Fetch user data from API
      fetchUserData();
    }
  }, []);

  const fetchUserData = async () => {
    try {
      const response = await axios.post('/api/auth/login', {
        username: 'demo_user',
        password: 'demo_password'
      });
      
      // Save the entire response including token to localStorage
      localStorage.setItem('user_data', JSON.stringify(response.data));
      
      setUser(response.data);
    } catch (error) {
      console.error('Login failed', error);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('user_data');
    setUser(null);
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      {user ? (
        <>
          <h2>Welcome, {user.name}!</h2>
          <p>Email: {user.email}</p>
          <button onClick={handleLogout}>Logout</button>
        </>
      ) : (
        <button onClick={fetchUserData}>Login</button>
      )}
    </div>
  );
}

export default UserProfile;`,
    answer: false,
    explanation: "This code has several security issues related to client-side storage: 1) It stores sensitive authentication data including the auth token in localStorage, which is accessible to any JavaScript code running on the same domain (including XSS attacks), 2) It stores credentials ('demo_user'/'demo_password') directly in the code, 3) It doesn't expire or refresh the token, allowing it to be used indefinitely if stolen, 4) Full response data is stored, which may include sensitive user information beyond what's needed for authentication. A better approach would be to use HTTP-only cookies for token storage (inaccessible to JavaScript), implement token expiration, and store only essential data in memory during the session."
  },
  {
    id: 'frontend-vuln-2',
    title: 'Prototype Pollution in JavaScript',
    description: 'This utility function merges objects. What security vulnerability is present?',
    difficulty: 'hard',
    category: 'Client-Side Security',
    languages: ['JavaScript'],
    type: 'multiple-choice',
    vulnerabilityType: 'Prototype Pollution',
    code: `/**
 * Deep merge two objects recursively
 * @param {Object} target - Target object to merge into
 * @param {Object} source - Source object to merge from
 * @return {Object} Merged object
 */
function deepMerge(target, source) {
  // Handle edge cases
  if (!source) return target;
  if (!target) return source;
  
  // Iterate through source properties
  for (const key in source) {
    // If property exists in target and both are objects
    if (typeof source[key] === 'object' && source[key] !== null &&
        typeof target[key] === 'object' && target[key] !== null) {
      // Recursively merge nested objects
      deepMerge(target[key], source[key]);
    } else {
      // Otherwise assign source value to target
      target[key] = source[key];
    }
  }
  
  return target;
}

// Usage example:
const userDefaults = {
  theme: 'light',
  notifications: {
    email: true,
    push: false
  }
};

// User preferences from API/localStorage
const userPreferences = JSON.parse(userInput);

// Merge defaults with user preferences
const config = deepMerge(userDefaults, userPreferences);`,
    options: [
      'The function doesn\'t handle circular references',
      'Race condition when merging objects',
      'Prototype pollution allowing modification of Object.prototype',
      'Memory leak due to recursive function calls without proper cleanup'
    ],
    answer: 2,
    explanation: "This code is vulnerable to prototype pollution because it doesn't check if the property keys being merged are '__proto__', 'constructor', or 'prototype'. An attacker could supply input like {'__proto__': {malicious: 'value'}} which would modify the Object prototype, affecting all JavaScript objects in the application. For example, if userInput contains {'__proto__': {'isAdmin': true}}, then every object would have isAdmin=true, potentially bypassing authorization checks. To fix this, either use Object.create(null) to create objects without a prototype, explicitly check and reject reserved property names, or use a library with prototype pollution protection."
  }
];
