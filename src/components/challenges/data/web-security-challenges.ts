
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
  }
];
