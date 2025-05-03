
import React from 'react';
import { Lock } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const OAuthVulnerabilities: React.FC = () => {
  return (
    <section id="oauth" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">OAuth Vulnerabilities</h3>
      <p className="mb-6">
        OAuth is a widely used authorization protocol that allows applications to access resources on behalf of users
        without exposing their credentials. However, OAuth implementations can contain vulnerabilities that compromise
        the security of the authentication process and expose sensitive user data.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Common OAuth Vulnerabilities</h4>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li><strong>Improper Implementation of PKCE</strong>: Not using Proof Key for Code Exchange in mobile/SPA apps</li>
        <li><strong>Insufficient Redirect URI Validation</strong>: Accepting unvalidated or partial redirect URIs</li>
        <li><strong>Missing State Parameter</strong>: Not using or validating the state parameter against CSRF</li>
        <li><strong>Improper Scope Validation</strong>: Failing to validate or restrict requested scopes</li>
        <li><strong>Using Implicit Flow</strong>: Using the less secure implicit flow instead of authorization code flow</li>
      </ul>
      
      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable OAuth Implementation" 
        code={`// Client-side OAuth flow with vulnerabilities
function initiateOAuthLogin() {
  // Missing state parameter (vulnerable to CSRF)
  const authUrl = 'https://oauth-provider.com/auth'
    + '?response_type=token' // Using implicit flow (less secure)
    + '&client_id=CLIENT_ID'
    + '&redirect_uri=https://myapp.com/callback';
    
  window.location.href = authUrl;
}

// Callback handler with vulnerabilities
function handleOAuthCallback() {
  // Directly extracting token from hash without validation
  const hash = window.location.hash.substring(1);
  const params = new URLSearchParams(hash);
  const accessToken = params.get('access_token');
  
  if (accessToken) {
    // No validation of token before use
    // No verification that this is the same authorization flow that was initiated
    // Store token and authenticate user
    localStorage.setItem('access_token', accessToken);
    fetchUserProfile(accessToken);
  }
}

// Server endpoint with loose redirect validation
app.get('/oauth/authorize', (req, res) => {
  const clientId = req.query.client_id;
  const redirectUri = req.query.redirect_uri;
  
  // Vulnerable: Only checking if the redirect_uri starts with an allowed domain
  if (redirectUri.startsWith('https://myapp.com')) {
    // Proceed with authorization flow
    // This could allow redirects to malicious subdomains or paths
  } else {
    res.status(400).send('Invalid redirect URI');
  }
});`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure OAuth Implementation" 
        code={`// Client-side secure OAuth implementation
function initiateOAuthLogin() {
  // Generate a random state for CSRF protection
  const state = generateRandomString(32);
  
  // Store state in sessionStorage for verification later
  sessionStorage.setItem('oauth_state', state);
  
  // For public clients (SPA, mobile), generate PKCE challenge
  const codeVerifier = generateRandomString(64);
  const codeChallenge = base64UrlEncode(sha256(codeVerifier));
  sessionStorage.setItem('code_verifier', codeVerifier);
  
  // Use authorization code flow with PKCE (more secure than implicit)
  const authUrl = 'https://oauth-provider.com/auth'
    + '?response_type=code'
    + '&client_id=CLIENT_ID'
    + '&redirect_uri=' + encodeURIComponent('https://myapp.com/callback')
    + '&scope=' + encodeURIComponent('profile email')
    + '&state=' + state
    + '&code_challenge=' + codeChallenge
    + '&code_challenge_method=S256';
    
  window.location.href = authUrl;
}

// Secure callback handler
function handleOAuthCallback() {
  const urlParams = new URLSearchParams(window.location.search);
  const code = urlParams.get('code');
  const state = urlParams.get('state');
  const storedState = sessionStorage.getItem('oauth_state');
  const codeVerifier = sessionStorage.getItem('code_verifier');
  
  // Clear stored state
  sessionStorage.removeItem('oauth_state');
  sessionStorage.removeItem('code_verifier');
  
  // Validate state to prevent CSRF
  if (!state || state !== storedState) {
    return showError('Invalid state parameter. Authentication failed.');
  }
  
  if (code) {
    // Exchange code for token using PKCE verifier
    exchangeCodeForToken(code, codeVerifier);
  }
}

// Exchange code for token securely
async function exchangeCodeForToken(code, codeVerifier) {
  try {
    const response = await fetch('https://myapp.com/api/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        code,
        code_verifier: codeVerifier,
        client_id: 'CLIENT_ID',
        redirect_uri: 'https://myapp.com/callback'
      })
    });
    
    const data = await response.json();
    if (data.access_token) {
      // Store token securely (HttpOnly cookie set by server)
      // Then redirect to protected area
      window.location.href = '/dashboard';
    }
  } catch (error) {
    showError('Failed to exchange code for token');
  }
}

// Server-side token endpoint with secure handling
app.post('/api/token', async (req, res) => {
  const { code, code_verifier, client_id, redirect_uri } = req.body;
  
  // Validate client_id
  if (client_id !== process.env.CLIENT_ID) {
    return res.status(400).json({ error: 'Invalid client' });
  }
  
  // Validate redirect_uri with exact matching
  if (redirect_uri !== process.env.ALLOWED_REDIRECT_URI) {
    return res.status(400).json({ error: 'Invalid redirect URI' });
  }
  
  try {
    // Exchange code for token with OAuth provider
    const tokenResponse = await fetch('https://oauth-provider.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri,
        client_id,
        client_secret: process.env.CLIENT_SECRET, // Keep secret server-side
        code_verifier
      })
    });
    
    const tokenData = await tokenResponse.json();
    
    // Set access token in HttpOnly cookie
    res.cookie('access_token', tokenData.access_token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: tokenData.expires_in * 1000
    });
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to exchange token' });
  }
});`} 
      />
    </section>
  );
};

export default OAuthVulnerabilities;
