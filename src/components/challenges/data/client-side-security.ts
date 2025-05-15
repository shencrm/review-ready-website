
import { Challenge } from './challenge-types';

export const clientSideSecurityChallenges: Challenge[] = [
  {
    id: 'client-side-security-1',
    title: 'DOM-based XSS',
    description: 'Compare these two JavaScript functions that update page content based on URL parameters. Which one is protected against DOM-based XSS?',
    difficulty: 'easy',
    category: 'Client-Side Security',
    languages: ['JavaScript'],
    type: 'comparison',
    vulnerabilityType: 'DOM-based XSS',
    secureCode: `function displayWelcomeMessage() {
  // Get URL parameters
  const urlParams = new URLSearchParams(window.location.search);
  const username = urlParams.get('username');
  
  // Get the welcome element
  const welcomeElement = document.getElementById('welcome-message');
  
  if (username) {
    // Create a text node (safe from XSS)
    const textNode = document.createTextNode('Welcome, ' + username + '!');
    welcomeElement.appendChild(textNode);
    
    // Alternative safe approach using textContent
    // welcomeElement.textContent = 'Welcome, ' + username + '!';
  } else {
    welcomeElement.textContent = 'Welcome, guest!';
  }
}

// Call the function when the page loads
document.addEventListener('DOMContentLoaded', displayWelcomeMessage);`,
    vulnerableCode: `function displayWelcomeMessage() {
  // Get URL parameters
  const urlParams = new URLSearchParams(window.location.search);
  const username = urlParams.get('username');
  
  // Get the welcome element
  const welcomeElement = document.getElementById('welcome-message');
  
  if (username) {
    // Update the HTML (vulnerable to XSS)
    welcomeElement.innerHTML = 'Welcome, ' + username + '!';
  } else {
    welcomeElement.innerHTML = 'Welcome, guest!';
  }
}

// Call the function when the page loads
document.addEventListener('DOMContentLoaded', displayWelcomeMessage);`,
    answer: 'secure',
    explanation: "The secure implementation prevents DOM-based XSS by using document.createTextNode() or textContent instead of innerHTML. These methods treat the content as plain text rather than HTML, ensuring that any HTML or JavaScript in the username parameter is displayed as text rather than being executed. The vulnerable implementation uses innerHTML which parses and executes any HTML or JavaScript in the username parameter, allowing attackers to execute arbitrary code by crafting a malicious URL like '?username=<script>alert(document.cookie)</script>'."
  },
  {
    id: 'client-side-security-2',
    title: 'Content Security Policy Implementation',
    description: 'Review this HTML file with Content Security Policy (CSP) headers. Is it properly configured for security?',
    difficulty: 'hard',
    category: 'Client-Side Security',
    languages: ['HTML'],
    type: 'single',
    vulnerabilityType: 'CSP Configuration',
    code: `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Application</title>
    
    <!-- Content Security Policy -->
    <meta http-equiv="Content-Security-Policy" 
          content="default-src 'self'; 
                   script-src 'self' https://trusted-cdn.com; 
                   style-src 'self' https://trusted-cdn.com;
                   img-src 'self' data: https:;
                   connect-src 'self' https://api.example.com;
                   font-src 'self' https://trusted-cdn.com;
                   object-src 'none';
                   media-src 'self';
                   frame-src 'self';
                   form-action 'self';
                   base-uri 'self';
                   frame-ancestors 'self';
                   upgrade-insecure-requests;
                   report-uri https://example.com/csp-report">
    
    <link rel="stylesheet" href="styles.css">
    <script src="app.js" defer></script>
</head>
<body>
    <header>
        <h1>Secure Application</h1>
        <nav>
            <ul>
                <li><a href="/">Home</a></li>
                <li><a href="/about">About</a></li>
                <li><a href="/contact">Contact</a></li>
            </ul>
        </nav>
    </header>
    
    <main>
        <section id="content">
            <h2>Welcome to our secure application!</h2>
            <p>This application implements various security best practices.</p>
            
            <div id="dynamic-content"></div>
            
            <form action="/submit" method="post">
                <input type="text" name="name" placeholder="Your name">
                <input type="email" name="email" placeholder="Your email">
                <button type="submit">Submit</button>
            </form>
        </section>
    </main>
    
    <footer>
        <p>&copy; 2023 Secure Application. All rights reserved.</p>
    </footer>
</body>
</html>`,
    answer: true,
    explanation: "This CSP configuration is well-implemented with multiple security features: 1) It uses default-src 'self' as a fallback restricting resources to the same origin, 2) It explicitly defines trusted sources for scripts, styles, images, and connections, 3) It blocks object-src completely with 'none', preventing plugin-based attacks, 4) It restricts form submissions to same origin with form-action 'self', 5) It prevents clickjacking with frame-ancestors 'self', 6) It automatically upgrades HTTP to HTTPS with upgrade-insecure-requests, 7) It includes reporting with report-uri, and 8) It sets base-uri to prevent base tag hijacking. Overall, this is a strong policy that follows defense-in-depth principles without using unsafe-inline or unsafe-eval, which are common CSP weaknesses."
  }
];
