
import { Challenge } from './challenge-types';

export const browserSecurityChallenges: Challenge[] = [
  {
    id: 'browser-sec-1',
    title: 'Cross-Origin Resource Policy',
    description: 'This JavaScript code loads a third-party script. What security issue is present?',
    difficulty: 'medium',
    category: 'Client-Side Security',
    languages: ['JavaScript', 'HTML'],
    type: 'multiple-choice',
    vulnerabilityType: 'Supply Chain Attack',
    code: `// script.js - Main application script

// Configuration
const config = {
  apiEndpoint: 'https://api.example.com/v1',
  analyticsToken: 'a1b2c3d4e5f6',
  debug: false
};

// Initialize application
function initApp() {
  console.log('Initializing application...');
  
  // Load authentication module
  loadAuthModule();
  
  // Load third-party analytics
  loadAnalytics();
  
  // Set up event handlers
  document.getElementById('login-form').addEventListener('submit', handleLogin);
  
  console.log('Application initialized');
}

// Load authentication module
function loadAuthModule() {
  const script = document.createElement('script');
  script.src = '/assets/js/auth.js';
  document.head.appendChild(script);
}

// Load third-party analytics script
function loadAnalytics() {
  const script = document.createElement('script');
  script.src = 'https://analytics.example.org/tracker.js?token=' + config.analyticsToken;
  document.head.appendChild(script);
}

// Handle login form submission
function handleLogin(event) {
  event.preventDefault();
  
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  
  // Authenticate user
  authenticateUser(username, password)
    .then(response => {
      if (response.success) {
        window.location.href = '/dashboard';
      } else {
        showError('Invalid username or password');
      }
    })
    .catch(error => {
      showError('Authentication failed: ' + error.message);
    });
}

// Document ready
document.addEventListener('DOMContentLoaded', initApp);`,
    options: [
      'Missing subresource integrity (SRI) check',
      'Using createElement instead of a static script tag',
      'Not setting crossorigin attribute',
      'Loading scripts after DOMContentLoaded'
    ],
    answer: 0,
    explanation: "The code is vulnerable to supply chain attacks because it lacks Subresource Integrity (SRI) checks when loading the third-party analytics script. Without SRI, if the third-party script is compromised or modified on the server, the application would load and execute the malicious version without detection. This could lead to data theft, session hijacking, or other attacks. To fix this, the script should include integrity and crossorigin attributes: `script.integrity = 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC'` and `script.crossOrigin = 'anonymous'`. The integrity attribute contains a cryptographic hash of the expected file, and the browser will only execute the script if it matches this hash, protecting against modified or malicious scripts. This is especially important for third-party resources hosted on external domains."
  },
  {
    id: 'browser-sec-2',
    title: 'Local Storage Security',
    description: 'Review this React component that stores user data. What security issue is present?',
    difficulty: 'easy',
    category: 'Client-Side Security',
    languages: ['JavaScript', 'React'],
    type: 'single',
    vulnerabilityType: 'Client-Side Storage',
    code: `import React, { useState, useEffect } from 'react';
import axios from 'axios';

const UserProfile = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  useEffect(() => {
    // Check if we have cached user data
    const cachedUser = localStorage.getItem('user_data');
    
    if (cachedUser) {
      // Use cached data
      setUser(JSON.parse(cachedUser));
      setLoading(false);
    } else {
      // Fetch user data from API
      fetchUserData();
    }
  }, []);
  
  const fetchUserData = async () => {
    try {
      const token = localStorage.getItem('auth_token');
      
      if (!token) {
        throw new Error('Not authenticated');
      }
      
      const response = await axios.get('/api/user/profile', {
        headers: { Authorization: \`Bearer \${token}\` }
      });
      
      // Cache user data in localStorage for future use
      localStorage.setItem('user_data', JSON.stringify(response.data));
      
      setUser(response.data);
      setLoading(false);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  };
  
  const handleLogout = () => {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user_data');
    window.location.href = '/login';
  };
  
  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;
  
  return (
    <div className="user-profile">
      <h1>User Profile</h1>
      
      {user && (
        <div>
          <p><strong>Name:</strong> {user.name}</p>
          <p><strong>Email:</strong> {user.email}</p>
          <p><strong>Role:</strong> {user.role}</p>
          <p><strong>Account Number:</strong> {user.accountNumber}</p>
          <p><strong>SSN (Last 4):</strong> {user.ssnLast4}</p>
          <p><strong>Address:</strong> {user.address}</p>
          
          <button onClick={handleLogout}>Logout</button>
        </div>
      )}
    </div>
  );
};

export default UserProfile;`,
    answer: false,
    explanation: "This code stores sensitive user data in localStorage, which is a significant security issue. Unlike cookies, localStorage has no expiration mechanism, no HTTP-only flag, and is accessible to any JavaScript running on the page, making it vulnerable to XSS attacks. The sensitive data stored includes the user's full name, email, account number, SSN digits, and address - all of which should be protected. Additionally, the auth_token is also stored in localStorage, which could lead to authentication vulnerabilities. If an attacker can execute JavaScript on the site (via XSS), they can steal both the user's personal information and their authentication token. A more secure approach would be to: 1) Only store non-sensitive data client-side; 2) Use httpOnly and secure cookies for authentication tokens; 3) Fetch sensitive data from the API when needed rather than caching it; and 4) Implement proper session management with server-side controls."
  },
  {
    id: 'browser-sec-3',
    title: 'DOM-based Security',
    description: 'Compare these two React components that render user comments. Which one is protected against XSS?',
    difficulty: 'medium',
    category: 'Client-Side Security',
    languages: ['JavaScript', 'React'],
    type: 'comparison',
    vulnerabilityType: 'DOM-based XSS',
    secureCode: `import React from 'react';
import DOMPurify from 'dompurify';

const CommentList = ({ comments }) => {
  // Function to sanitize HTML content
  const sanitizeContent = (html) => {
    // Configure DOMPurify to allow certain tags but no scripts
    const config = {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
      ALLOWED_ATTR: ['href']
    };
    
    return DOMPurify.sanitize(html, config);
  };

  return (
    <div className="comments-section">
      <h2>User Comments</h2>
      
      {comments.length === 0 ? (
        <p>No comments yet. Be the first to comment!</p>
      ) : (
        <ul className="comment-list">
          {comments.map((comment) => (
            <li key={comment.id} className="comment-item">
              <div className="comment-header">
                <span className="comment-author">{comment.author}</span>
                <span className="comment-date">
                  {new Date(comment.timestamp).toLocaleDateString()}
                </span>
              </div>
              
              {/* Render sanitized content */}
              <div 
                className="comment-content"
                dangerouslySetInnerHTML={{ __html: sanitizeContent(comment.content) }}
              />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

export default CommentList;`,
    vulnerableCode: `import React from 'react';

const CommentList = ({ comments }) => {
  // Function to create HTML from comment content
  const renderContent = (content) => {
    // Replace URLs with actual links
    const withLinks = content.replace(
      /(https?:\\/\\/[^\\s]+)/g, 
      '<a href="$1" target="_blank">$1</a>'
    );
    
    // Replace newlines with <br>
    const withLineBreaks = withLinks.replace(/\\n/g, '<br>');
    
    return withLineBreaks;
  };

  return (
    <div className="comments-section">
      <h2>User Comments</h2>
      
      {comments.length === 0 ? (
        <p>No comments yet. Be the first to comment!</p>
      ) : (
        <ul className="comment-list">
          {comments.map((comment) => (
            <li key={comment.id} className="comment-item">
              <div className="comment-header">
                <span className="comment-author">{comment.author}</span>
                <span className="comment-date">
                  {new Date(comment.timestamp).toLocaleDateString()}
                </span>
              </div>
              
              {/* Render HTML content */}
              <div 
                className="comment-content"
                dangerouslySetInnerHTML={{ __html: renderContent(comment.content) }}
              />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

export default CommentList;`,
    answer: 'secure',
    explanation: "The secure implementation uses DOMPurify to sanitize HTML content before rendering it with dangerouslySetInnerHTML. It explicitly configures allowed tags and attributes, preventing the execution of malicious scripts while still allowing basic formatting. This approach protects against XSS attacks even when rendering user-generated content that might contain HTML. In contrast, the vulnerable implementation has a critical security flaw: it processes user-generated content with simple string replacements and then renders it as HTML without any sanitization. An attacker could craft a comment containing malicious script tags or event handlers (like onclick attributes) that would be inserted directly into the page and executed. For example, a comment containing '<img src=x onerror=\"alert(document.cookie)\">' would steal cookies in the vulnerable implementation but would be safely neutralized in the secure one."
  }
];
