
import { Challenge } from './challenge-types';

export const webSecurityChallenges: Challenge[] = [
  {
    id: 'web-sec-1',
    title: 'HTTP Security Headers',
    description: 'Which security header helps prevent Clickjacking attacks?',
    difficulty: 'medium',
    category: 'Web Security',
    languages: ['HTML'],
    type: 'multiple-choice',
    vulnerabilityType: 'Header Configuration',
    options: [
      'Content-Security-Policy',
      'X-XSS-Protection',
      'X-Frame-Options',
      'Strict-Transport-Security'
    ],
    answer: 2,
    explanation: "The X-Frame-Options header controls whether a browser should be allowed to render a page in a <frame>, <iframe>, <embed> or <object>. By ensuring the page cannot be embedded in a frame, this header prevents clickjacking attacks where attackers trick users into clicking on buttons or links on a hidden website layered underneath the visible content the user expects to be interacting with."
  },
  {
    id: 'web-sec-2',
    title: 'DOM-Based XSS',
    description: 'Which of the following is a safe way to insert user input into the DOM?',
    difficulty: 'hard',
    category: 'Web Security',
    languages: ['JavaScript'],
    type: 'multiple-choice',
    vulnerabilityType: 'Cross-Site Scripting',
    options: [
      'element.innerHTML = userInput;',
      'element.innerText = userInput;',
      'eval("var userMessage = " + userInput);',
      'document.write(userInput);'
    ],
    answer: 1,
    explanation: "Using element.innerText is the safest option among these choices because it treats the input as plain text rather than HTML or JavaScript. This prevents the browser from interpreting any HTML tags or JavaScript code that might be included in the user input. In contrast, innerHTML, eval(), and document.write() all can execute JavaScript if it's included in the input, making them vulnerable to XSS attacks."
  },
  {
    id: 'web-sec-3',
    title: 'CORS Security Configuration',
    description: 'Which CORS header configuration presents the highest security risk?',
    difficulty: 'medium',
    category: 'Web Security',
    languages: ['JavaScript'],
    type: 'multiple-choice',
    vulnerabilityType: 'CORS Misconfiguration',
    options: [
      'Access-Control-Allow-Origin: https://trusted-site.com',
      'Access-Control-Allow-Origin: null',
      'Access-Control-Allow-Origin: *',
      'Access-Control-Allow-Origin: https://*.company.com'
    ],
    answer: 2,
    explanation: "Setting 'Access-Control-Allow-Origin: *' presents the highest security risk because it allows any domain to make cross-origin requests to your site. This wildcard configuration effectively disables the Same-Origin Policy protection and could allow malicious websites to access sensitive data from your site if used with 'Access-Control-Allow-Credentials: true'. For sensitive operations, it's best to explicitly list trusted origins rather than using the wildcard."
  },
  {
    id: 'web-sec-4',
    title: 'GraphQL Security',
    description: 'Which of the following is NOT a common security issue in GraphQL APIs?',
    difficulty: 'hard',
    category: 'Web Security',
    languages: ['GraphQL'],
    type: 'multiple-choice',
    vulnerabilityType: 'API Security',
    options: [
      'Introspection attacks',
      'Resource exhaustion via complex queries',
      'Automatic input sanitization',
      'Improper access control'
    ],
    answer: 2,
    explanation: "GraphQL does NOT automatically sanitize inputs - this is a misconception. Developers must implement proper validation and sanitization for all inputs, just as with REST APIs. The other options are genuine GraphQL security concerns: introspection can reveal API structure, complex nested queries can cause DoS issues, and improper access controls can lead to unauthorized data access. Disabling introspection in production, implementing query complexity analysis, and proper authorization are essential security measures for GraphQL APIs."
  },
  {
    id: 'web-sec-5',
    title: 'Web Cache Poisoning',
    description: 'Which component is most directly exploited in a web cache poisoning attack?',
    difficulty: 'hard',
    category: 'Web Security',
    languages: ['HTTP'],
    type: 'multiple-choice',
    vulnerabilityType: 'Cache Poisoning',
    options: [
      'The user\'s local browser cache',
      'CDN or reverse proxy caches',
      'DNS cache',
      'Database query cache'
    ],
    answer: 1,
    explanation: "Web cache poisoning primarily exploits CDN or reverse proxy caches. In these attacks, an attacker sends specially crafted requests that cause the cache to store a malicious response which is then served to other users. The attack works by exploiting how caches key their entries and how they handle unusual or unkeyed headers. When successful, this turns a single-user attack into one affecting all users who receive content from the same cache, making it particularly dangerous."
  },
  {
    id: 'web-sec-6',
    title: 'Web Application Firewall Bypass',
    description: 'Which technique is commonly used to bypass Web Application Firewalls (WAF) protection against SQL injection?',
    difficulty: 'hard',
    category: 'Web Security',
    languages: ['HTTP', 'SQL'],
    type: 'multiple-choice',
    vulnerabilityType: 'WAF Bypass',
    options: [
      'Using HTTPS instead of HTTP',
      'Encoding payloads using alternative representations like hex or URL encoding',
      'Increasing the frequency of requests',
      'Adding random parameters to the URL'
    ],
    answer: 1,
    explanation: "Encoding SQL injection payloads using alternative representations like hexadecimal, URL encoding, or Unicode encoding is a common technique to bypass Web Application Firewalls. Many WAFs look for specific attack signatures in their plain text form, so encoding these payloads can help attackers evade detection. For example, converting 'SELECT' to hex '0x53454c454354' or using double URL encoding on special characters. Sophisticated WAFs implement multiple layers of decoding before analysis, but attackers continuously find new encoding combinations that security tools might not properly decode before inspection."
  },
  {
    id: 'web-sec-7',
    title: 'SameSite Cookie Attribute',
    description: 'Which SameSite cookie setting provides the best protection against CSRF attacks?',
    difficulty: 'medium',
    category: 'Web Security',
    languages: ['HTTP'],
    type: 'multiple-choice',
    vulnerabilityType: 'Cookie Security',
    options: [
      'SameSite=None',
      'SameSite=Lax',
      'SameSite=Strict',
      'SameSite=Default'
    ],
    answer: 2,
    explanation: "SameSite=Strict provides the strongest protection against CSRF attacks by preventing the browser from sending the cookie in any cross-site requests. This means the cookie is only sent when the site for the cookie matches the site currently shown in the browser's URL bar. While this setting provides maximum security, it can impact user experience as even legitimate actions like clicking a link to your site from an external site won't include the cookie. SameSite=Lax is a more balanced option, allowing cookies on GET requests initiated from other sites but blocking them on POST requests, which is why many sites use it as a practical compromise. SameSite=None allows cookies in all cross-site requests but requires the Secure flag, while Default typically falls back to Lax in modern browsers."
  },
  {
    id: 'web-sec-8',
    title: 'Content Security Policy Effectiveness',
    description: 'Which Content Security Policy (CSP) directive is most effective against DOM-based XSS attacks?',
    difficulty: 'hard',
    category: 'Web Security',
    languages: ['HTML'],
    type: 'multiple-choice',
    vulnerabilityType: 'XSS Prevention',
    options: [
      'default-src \'self\'',
      'script-src \'self\'',
      'script-src \'nonce-[random]\'',
      'script-src \'unsafe-inline\''
    ],
    answer: 2,
    explanation: "The script-src directive with a nonce-based approach provides the strongest protection against DOM-based XSS attacks. Nonces are cryptographically strong random values generated on each page load that must be included in script tags to allow them to execute. This approach prevents injected scripts (which wouldn't have the correct nonce) from running, even if an attacker manages to insert script content into the DOM. While 'self' restrictions limit scripts to the same origin, they wouldn't prevent exploitation if the attacker can inject scripts that appear to come from the same domain. The 'unsafe-inline' directive actually weakens security by allowing inline scripts to execute without restriction."
  },
  {
    id: 'web-sec-9',
    title: 'JWT Security Best Practice',
    description: 'Which practice provides the strongest security for JWT implementation?',
    difficulty: 'medium',
    category: 'Web Security',
    languages: ['JavaScript'],
    type: 'multiple-choice',
    vulnerabilityType: 'Authentication',
    options: [
      'Using the "none" algorithm for performance',
      'Storing sensitive user data in JWT claims',
      'Using short-lived tokens with a refresh token mechanism',
      'Relying solely on client-side JWT validation'
    ],
    answer: 2,
    explanation: "Using short-lived access tokens with a refresh token mechanism is the strongest security practice for JWT implementation. This approach limits the window of opportunity for attackers if a token is compromised, as access tokens expire quickly (typically in minutes). The refresh token, which should be stored securely and with httpOnly and secure flags, can be used to obtain new access tokens without requiring the user to reauthenticate. The 'none' algorithm provides no security and should never be used. Storing sensitive data in JWT claims is risky because JWTs are only encoded, not encrypted by default. Relying solely on client-side validation is insecure because a malicious client could simply bypass or modify the validation."
  },
  {
    id: 'web-sec-10',
    title: 'OAuth 2.0 Security',
    description: 'Which OAuth 2.0 attack is mitigated by implementing the PKCE extension?',
    difficulty: 'hard',
    category: 'Web Security',
    languages: ['JavaScript'],
    type: 'multiple-choice',
    vulnerabilityType: 'Authentication',
    options: [
      'Token substitution attack',
      'Authorization code interception attack',
      'Open redirect attack',
      'Cross-site request forgery'
    ],
    answer: 1,
    explanation: "Proof Key for Code Exchange (PKCE) was specifically designed to mitigate authorization code interception attacks in OAuth 2.0, particularly for public clients like mobile and single-page applications that cannot securely store a client secret. In the standard OAuth flow, if an attacker intercepts the authorization code, they could potentially exchange it for an access token. PKCE prevents this by requiring the client to create a secret verifier and a derived challenge. The challenge is sent with the authorization request, and the original verifier must be presented when exchanging the code for tokens, ensuring that only the legitimate client who initiated the flow can complete it. Since the verifier never travels over the network in the initial request, an attacker who intercepts the authorization code cannot exchange it without knowing the verifier."
  }
];

