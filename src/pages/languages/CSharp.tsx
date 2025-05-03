
import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Link } from 'react-router-dom';
import { ShieldAlert, Database, Key, FileWarning, Bug, Lock } from 'lucide-react';

const CSharp = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      
      <main className="flex-grow py-12">
        <div className="container mx-auto px-4">
          <div className="mb-12">
            <h1 className="text-4xl font-bold mb-6">C# Security</h1>
            <div className="h-1 w-24 bg-cybr-primary mb-6"></div>
            <p className="text-xl text-cybr-foreground/80">
              Security vulnerabilities and best practices for C# applications.
            </p>
          </div>
          
          <div className="card mb-8">
            <h2 className="text-2xl font-bold mb-4">About C#</h2>
            <p className="mb-4">
              C# (pronounced "C sharp") is a modern, object-oriented programming language developed by Microsoft in 2000 as part of
              its .NET initiative. Created by Anders Hejlsberg, C# was designed to be a simple, modern, general-purpose,
              object-oriented programming language that combines the high productivity of rapid application development languages
              with the raw power of C and C++.
            </p>
            <p className="mb-4">
              As a statically-typed language, C# helps developers catch errors at compile time rather than runtime, while still
              offering features like type inference to reduce verbosity. It runs on the .NET platform, which provides a rich
              standard library and powerful runtime services including automatic memory management through garbage collection,
              exception handling, and thread management.
            </p>
            <p className="mb-4">
              C# is widely used for developing Windows desktop applications, web applications using ASP.NET, games with Unity,
              and increasingly for cross-platform mobile development through frameworks like Xamarin and MAUI. It's also
              becoming more popular for cloud services and microservices with .NET Core and now .NET 6+.
            </p>
            <p>
              From a security perspective, C# benefits from .NET's managed runtime environment, which provides protection against
              common vulnerabilities like buffer overflows. However, C# applications can still be vulnerable to injection attacks,
              insecure deserialization, authentication flaws, and other security issues, particularly in web applications built with
              ASP.NET. Understanding these risks and following secure coding practices remains essential for C# developers.
            </p>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 space-y-8">
              <section>
                <h2 className="text-2xl font-bold mb-4">LINQ Injection</h2>
                <p className="mb-4">
                  LINQ injection occurs when untrusted input is directly incorporated into dynamically constructed LINQ queries.
                  Similar to SQL injection, attackers can manipulate the query logic to access unauthorized data or bypass security controls.
                </p>
                
                <SecurityCard
                  title="What is LINQ Injection?"
                  description="LINQ injection is a vulnerability that occurs when untrusted user input is used directly in dynamic LINQ queries. This allows attackers to modify the intended query logic and potentially access unauthorized data."
                  icon={<Database className="w-6 h-6" />}
                  severity="high"
                />
                
                <CodeExample
                  language="csharp"
                  title="LINQ Injection Vulnerability"
                  code={`// VULNERABLE: Dynamic LINQ with string concatenation
using System;
using System.Linq;
using System.Linq.Dynamic.Core;

public IQueryable<User> GetUsersByRole(string role)
{
    // User input directly incorporated into the query string
    string query = $"Role == \\"{role}\\"";
    
    // VULNERABLE: Dynamic LINQ using untrusted input
    return dbContext.Users.Where(query);
}

// Attacker could input: Role == "admin" || true
// Query becomes: Role == "admin" || true
// Returns all users regardless of role`}
                  isVulnerable={true}
                />
                
                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>The vulnerability above occurs because the user-supplied <code>role</code> parameter is directly incorporated into a dynamic LINQ query string. An attacker could inject additional query logic by providing a string like <code>admin" || true</code>, which would cause the query to return all users regardless of their role, effectively bypassing authorization controls.</p>
                </div>
                
                <CodeExample
                  language="csharp"
                  title="Secure LINQ Usage"
                  code={`// SECURE: Using parameterized LINQ expressions
using System;
using System.Linq;
using System.Linq.Expressions;

public IQueryable<User> GetUsersByRoleSafely(string role)
{
    // SECURE: Using strongly-typed LINQ with parameters
    return dbContext.Users.Where(u => u.Role == role);
}

// ALTERNATIVE: If dynamic queries are needed
using System.Linq.Dynamic.Core;

public IQueryable<User> GetUsersByRoleDynamicSafely(string role)
{
    // SECURE: Using parameters in Dynamic LINQ
    return dbContext.Users.Where("Role == @0", role);
}`}
                  isVulnerable={false}
                />

                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>The secure solution uses parameterized LINQ expressions instead of string concatenation. The first approach uses a strongly-typed lambda expression where the parameter is safely bound. The second approach shows how to use Dynamic LINQ safely by passing the role parameter separately, which prevents the attacker from modifying the query structure.</p>
                </div>
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">SQL Injection</h2>
                <p className="mb-4">
                  Despite ORM tools, SQL injection remains a risk in C# applications, especially with raw SQL queries.
                  This allows attackers to execute arbitrary SQL commands against your database.
                </p>
                
                <SecurityCard
                  title="SQL Injection in C# Applications"
                  description="SQL injection in C# occurs when developers use string concatenation to build SQL queries rather than using parameterized queries or stored procedures. This can lead to data theft, corruption, or complete database compromise."
                  icon={<Database className="w-6 h-6" />}
                  severity="high"
                />
                
                <CodeExample
                  language="csharp"
                  title="SQL Injection Vulnerability"
                  code={`// VULNERABLE: String concatenation in SQL
using System.Data.SqlClient;

public User GetUser(string username)
{
    using (SqlConnection connection = new SqlConnection(_connectionString))
    {
        connection.Open();
        
        // VULNERABLE: Direct string concatenation
        string sql = "SELECT * FROM Users WHERE Username = '" + username + "'";
        
        using (SqlCommand command = new SqlCommand(sql, connection))
        {
            using (SqlDataReader reader = command.ExecuteReader())
            {
                if (reader.Read())
                {
                    return new User
                    {
                        Id = (int)reader["Id"],
                        Username = (string)reader["Username"]
                    };
                }
            }
        }
    }
    
    return null;
}

// Attacker could input: admin' OR 1=1--`}
                  isVulnerable={true}
                />
                
                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>This vulnerable code directly concatenates user input into an SQL query. If an attacker inputs <code>admin' OR 1=1--</code>, the resulting query becomes <code>SELECT * FROM Users WHERE Username = 'admin' OR 1=1--'</code>. The <code>OR 1=1</code> always evaluates to true, causing the query to return all users, and the <code>--</code> comments out the rest of the query, bypassing any additional conditions.</p>
                </div>
                
                <CodeExample
                  language="csharp"
                  title="Secure SQL Query"
                  code={`// SECURE: Using parameterized queries
using System.Data.SqlClient;

public User GetUserSafely(string username)
{
    using (SqlConnection connection = new SqlConnection(_connectionString))
    {
        connection.Open();
        
        // SECURE: Using parameters
        string sql = "SELECT * FROM Users WHERE Username = @Username";
        
        using (SqlCommand command = new SqlCommand(sql, connection))
        {
            // Add parameter
            command.Parameters.AddWithValue("@Username", username);
            
            using (SqlDataReader reader = command.ExecuteReader())
            {
                if (reader.Read())
                {
                    return new User
                    {
                        Id = (int)reader["Id"],
                        Username = (string)reader["Username"]
                    };
                }
            }
        }
    }
    
    return null;
}

// ALTERNATIVE: Using Entity Framework
public User GetUserEF(string username)
{
    // Entity Framework handles parameterization automatically
    return _dbContext.Users.FirstOrDefault(u => u.Username == username);
}`}
                  isVulnerable={false}
                />

                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>The secure code uses parameterized queries by defining placeholders (like <code>@Username</code>) in the SQL string and then providing values separately through the Parameters collection. This ensures the database treats the input as data rather than executable code. The second example shows how Entity Framework automatically parameterizes queries, making them safe from SQL injection.</p>
                </div>
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Insecure Deserialization</h2>
                <p className="mb-4">
                  .NET's binary formatters can lead to remote code execution when deserializing untrusted data.
                  This can allow attackers to execute arbitrary code on your system.
                </p>
                
                <SecurityCard
                  title="Insecure Deserialization Risks"
                  description="Using BinaryFormatter to deserialize untrusted data can lead to remote code execution. Attackers can craft malicious serialized objects that execute code when deserialized."
                  icon={<FileWarning className="w-6 h-6" />}
                  severity="high"
                />
                
                <CodeExample
                  language="csharp"
                  title="Insecure Deserialization"
                  code={`// VULNERABLE: Using BinaryFormatter with untrusted data
using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

[Serializable]
public class UserSettings
{
    public string Theme { get; set; }
    public Dictionary<string, string> Preferences { get; set; }
}

public UserSettings DeserializeSettings(byte[] data)
{
    BinaryFormatter formatter = new BinaryFormatter();
    
    using (MemoryStream stream = new MemoryStream(data))
    {
        // VULNERABLE: BinaryFormatter can deserialize arbitrary types
        return (UserSettings)formatter.Deserialize(stream);
    }
}

// In ASP.NET MVC controller
[HttpPost]
public IActionResult RestoreSettings([FromBody] byte[] serializedSettings)
{
    var settings = DeserializeSettings(serializedSettings);
    // Use settings...
    return Ok();
}

// BinaryFormatter can execute code during deserialization
// through specially crafted payloads`}
                  isVulnerable={true}
                />
                
                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>This vulnerable code uses <code>BinaryFormatter</code> to deserialize data from an untrusted source. The danger is that <code>BinaryFormatter</code> can deserialize any serializable type, including types that execute code during deserialization. An attacker can craft a malicious serialized object that, when deserialized, executes arbitrary code on the server with the application's privileges. This could lead to complete system compromise.</p>
                </div>
                
                <CodeExample
                  language="csharp"
                  title="Secure Deserialization"
                  code={`// SECURE: Using JSON serialization instead of BinaryFormatter
using System.Text.Json;
using System.Text.Json.Serialization;

public class UserSettings
{
    public string Theme { get; set; }
    public Dictionary<string, string> Preferences { get; set; }
}

public UserSettings DeserializeSettingsSafely(string jsonData)
{
    // SECURE: JSON deserialization doesn't execute code
    var options = new JsonSerializerOptions
    {
        PropertyNameCaseInsensitive = true
    };
    
    return JsonSerializer.Deserialize<UserSettings>(jsonData, options);
}

// In ASP.NET Core controller
[HttpPost]
public IActionResult RestoreSettings([FromBody] UserSettings settings)
{
    // ASP.NET Core model binding uses secure JSON deserialization
    // Use settings...
    return Ok();
}

// IMPORTANT: In .NET Core, BinaryFormatter is marked as insecure
// and will be deprecated in future versions`}
                  isVulnerable={false}
                />

                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>The secure approach uses JSON serialization instead of <code>BinaryFormatter</code>. JSON deserialization is safer because it doesn't execute code during the process. Additionally, the ASP.NET Core model binding system handles JSON deserialization securely by default. Microsoft has acknowledged the security risks of <code>BinaryFormatter</code> and has marked it for deprecation in future .NET versions.</p>
                </div>
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Cross-Site Request Forgery (CSRF)</h2>
                <p className="mb-4">
                  CSRF protection in ASP.NET Core applications requires explicit configuration.
                  Without it, attackers can trick users into making unwanted state-changing requests.
                </p>
                
                <SecurityCard
                  title="CSRF Vulnerabilities in ASP.NET"
                  description="Without proper anti-forgery tokens, attackers can trick authenticated users into performing unwanted actions on your website by having them visit a malicious site."
                  icon={<Bug className="w-6 h-6" />}
                  severity="medium"
                />
                
                <CodeExample
                  language="csharp"
                  title="Enabling CSRF Protection"
                  code={`// SECURE: Enabling Anti-Forgery tokens in ASP.NET Core
// In Startup.cs
public void ConfigureServices(IServiceCollection services)
{
    services.AddControllersWithViews(options =>
    {
        // SECURE: Enable automatic CSRF validation for all POST/PUT/DELETE actions
        options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
    });
    
    // SECURE: Configure anti-forgery options if needed
    services.AddAntiforgery(options =>
    {
        options.HeaderName = "X-XSRF-TOKEN"; // For JavaScript clients
        options.Cookie.Name = "XSRF-TOKEN";
        options.Cookie.HttpOnly = false; // Allow JavaScript to read the cookie
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    });
}

// In controller actions
[HttpPost]
[ValidateAntiForgeryToken] // Explicitly validate token for this action
public IActionResult UpdateProfile(ProfileViewModel model)
{
    // Process the update...
    return RedirectToAction("Index");
}`}
                  isVulnerable={false}
                />
                
                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>This code demonstrates how to enable CSRF protection in ASP.NET Core applications. The <code>AutoValidateAntiforgeryTokenAttribute</code> is applied globally to automatically validate anti-forgery tokens for all POST, PUT, and DELETE actions. The code also configures specific anti-forgery options like cookie properties and custom header names. For individual controller actions, the <code>[ValidateAntiForgeryToken]</code> attribute ensures that a valid anti-forgery token must be present in the request.</p>
                </div>
                
                <CodeExample
                  language="csharp"
                  title="Using Anti-Forgery Tokens in Razor Views"
                  code={`<!-- SECURE: Using anti-forgery tokens in form -->
@using Microsoft.AspNetCore.Mvc.Rendering
@using Microsoft.AspNetCore.Antiforgery

@inject IAntiforgery Antiforgery

<!-- Form with automatic token -->
<form asp-controller="Account" asp-action="UpdateProfile" method="post">
    <!-- Form fields -->
    <input type="text" asp-for="Name" />
    
    <!-- Anti-forgery token automatically included by tag helpers -->
    <button type="submit">Update</button>
</form>

<!-- For AJAX requests -->
<script>
    const token = document.querySelector('input[name="__RequestVerificationToken"]').value;

    fetch('/api/users/update', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-XSRF-TOKEN': token
        },
        body: JSON.stringify({ name: 'New Name' })
    });
</script>`}
                  isVulnerable={false}
                />

                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>This example shows how to use anti-forgery tokens in Razor views and AJAX requests. In forms, the ASP.NET Core tag helpers automatically generate and include the anti-forgery token. For AJAX requests, the code extracts the token value from the form and includes it in a custom header. This ensures that the server can verify that the request came from your site and not a malicious third-party site.</p>
                </div>
              </section>

              <section>
                <h2 className="text-2xl font-bold mb-4">XML External Entity (XXE) Injection</h2>
                <p className="mb-4">
                  XXE vulnerabilities occur when improperly configured XML parsers process external entity references within XML documents,
                  potentially leading to sensitive data disclosure, denial of service, or server-side request forgery.
                </p>
                
                <SecurityCard
                  title="XML External Entity (XXE) Injection"
                  description="XXE attacks exploit vulnerable XML parsers to access files on the application server, perform server-side request forgery, or execute denial of service attacks through resource exhaustion."
                  icon={<FileWarning className="w-6 h-6" />}
                  severity="high"
                />
                
                <CodeExample
                  language="csharp"
                  title="Vulnerable XML Processing"
                  code={`// VULNERABLE: Insecure XML parsing
using System;
using System.Xml;

public string ProcessXmlDocument(string xmlData)
{
    XmlDocument doc = new XmlDocument();
    
    // VULNERABLE: Default settings allow XXE
    doc.LoadXml(xmlData);
    
    // Process the XML...
    XmlNode node = doc.SelectSingleNode("//data");
    return node?.InnerText;
}

// Attacker could submit this malicious XML:
/*
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
*/
// This would return the contents of /etc/passwd file`}
                  isVulnerable={true}
                />
                
                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>This vulnerable code uses <code>XmlDocument</code> with default settings, which allows XML external entity (XXE) processing. An attacker can submit XML containing a DOCTYPE declaration with an external entity that references a local file (e.g., <code>/etc/passwd</code>). When the XML is processed, the parser will replace the entity reference with the contents of that file, potentially exposing sensitive information. The attacker could also use this to perform server-side request forgery or denial of service attacks.</p>
                </div>
                
                <CodeExample
                  language="csharp"
                  title="Secure XML Processing"
                  code={`// SECURE: XML parsing with external entities disabled
using System;
using System.Xml;

public string ProcessXmlDocumentSafely(string xmlData)
{
    // Create secure XML reader settings
    XmlReaderSettings settings = new XmlReaderSettings
    {
        DtdProcessing = DtdProcessing.Prohibit, // Prohibit DTD processing
        ValidationType = ValidationType.None,
        XmlResolver = null // Prevent resolution of external entities
    };
    
    // Create secure XML document
    XmlDocument doc = new XmlDocument();
    doc.XmlResolver = null; // Disable external entity resolution
    
    using (XmlReader reader = XmlReader.Create(new StringReader(xmlData), settings))
    {
        doc.Load(reader);
    }
    
    // Process the XML...
    XmlNode node = doc.SelectSingleNode("//data");
    return node?.InnerText;
}

// ALTERNATIVE: Using XDocument (LINQ to XML)
using System.Xml.Linq;

public string ProcessXDocumentSafely(string xmlData)
{
    // XDocument from string with secure options
    XDocument doc = XDocument.Parse(xmlData, LoadOptions.PreserveWhitespace);
    
    // XDocument doesn't resolve external entities by default
    return doc.Root.Element("data")?.Value;
}`}
                  isVulnerable={false}
                />

                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>The secure version configures the XML parser to prevent XXE attacks in two ways. First, it creates an <code>XmlReaderSettings</code> object with <code>DtdProcessing.Prohibit</code> to disable DTD processing, which blocks DOCTYPE declarations. Second, it sets <code>XmlResolver</code> to <code>null</code> to prevent the resolution of external entities. The alternative approach uses <code>XDocument</code> (LINQ to XML), which doesn't resolve external entities by default, making it inherently safer against XXE attacks.</p>
                </div>
              </section>

              <section>
                <h2 className="text-2xl font-bold mb-4">Improper Certificate Validation</h2>
                <p className="mb-4">
                  Bypassing SSL/TLS certificate validation can lead to man-in-the-middle attacks.
                  Ensure proper validation is always enforced in production code.
                </p>
                
                <SecurityCard
                  title="Improper Certificate Validation"
                  description="Bypassing SSL/TLS certificate validation makes your application vulnerable to man-in-the-middle attacks where attackers can intercept and modify network traffic."
                  icon={<Lock className="w-6 h-6" />}
                  severity="high"
                />
                
                <CodeExample
                  language="csharp"
                  title="Dangerous Certificate Validation Bypass"
                  code={`// VULNERABLE: Bypassing certificate validation
using System;
using System.Net;
using System.Net.Http;

public class InsecureHttpClient
{
    public HttpClient CreateInsecureClient()
    {
        // DANGEROUS: Bypassing SSL certificate validation
        ServicePointManager.ServerCertificateValidationCallback = 
            (sender, certificate, chain, sslPolicyErrors) => true;
        
        return new HttpClient();
    }
}

// ALTERNATIVE VULNERABLE APPROACH with HttpClientHandler
public HttpClient CreateAnotherInsecureClient()
{
    var handler = new HttpClientHandler
    {
        // DANGEROUS: Don't ever do this in production
        ServerCertificateCustomValidationCallback = 
            (message, cert, chain, errors) => true
    };
    
    return new HttpClient(handler);
}

// This code disables certificate validation entirely,
// making all HTTPS connections vulnerable to interception`}
                  isVulnerable={true}
                />
                
                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>This dangerous code bypasses SSL/TLS certificate validation by setting callbacks that always return <code>true</code> regardless of certificate errors. This effectively disables all security checks for HTTPS connections. An attacker who can intercept network traffic (e.g., on a public Wi-Fi network) could present a fake certificate and the code would accept it, allowing the attacker to view and modify all traffic between the application and the server without detection.</p>
                </div>
                
                <CodeExample
                  language="csharp"
                  title="Secure Certificate Validation"
                  code={`// SECURE: Proper certificate validation
using System;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;

public class SecureHttpClient
{
    // SECURE: Default HttpClient with proper validation
    public HttpClient CreateSecureClient()
    {
        return new HttpClient();
        // Default behavior validates certificates properly
    }
    
    // For specific certificate pinning (advanced security)
    public HttpClient CreateClientWithCertificatePinning()
    {
        var handler = new HttpClientHandler();
        
        // Add custom validation to implement certificate pinning
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
        {
            // Only accept if no errors OR if it's expected self-signed cert
            if (errors == System.Net.Security.SslPolicyErrors.None)
            {
                return true; // Certificate is valid according to the system
            }
            
            // Optionally implement certificate pinning by validating
            // the certificate thumbprint or public key
            if (cert != null)
            {
                // Example: Check against known thumbprint
                string thumbprint = cert.GetCertHashString();
                bool isPinnedCert = thumbprint == "EXPECTED_THUMBPRINT_HERE";
                
                if (isPinnedCert)
                {
                    return true; // This is our pinned certificate
                }
            }
            
            return false; // Reject all other certificates
        };
        
        return new HttpClient(handler);
    }
}`}
                  isVulnerable={false}
                />

                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md mb-4">
                  <h4 className="font-semibold mb-2">Explanation:</h4>
                  <p>The secure code demonstrates two approaches. First, using the default <code>HttpClient</code> constructor, which performs proper certificate validation using the operating system's certificate store. Second, implementing certificate pinning for advanced security. With certificate pinning, the application validates that the server's certificate matches an expected value (e.g., a specific thumbprint), providing protection even if an attacker has compromised a certificate authority. This ensures connections are only established with legitimate servers.</p>
                </div>
              </section>
            </div>
            
            <div className="lg:col-span-1">
              <div className="sticky top-24">
                <div className="card">
                  <h3 className="text-xl font-bold mb-4">C# Security Vulnerabilities</h3>
                  <ul className="space-y-2 pl-4 text-cybr-foreground/80">
                    <li>LINQ Injection</li>
                    <li>SQL Injection</li>
                    <li>Insecure Deserialization</li>
                    <li>Cross-Site Request Forgery</li>
                    <li>XML External Entity (XXE)</li>
                    <li>Open Redirect</li>
                    <li>Improper Certificate Validation</li>
                    <li>Weak Cryptography</li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">.NET Security Tools</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://security-code-scan.github.io/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Security Code Scan</a></li>
                    <li><a href="https://owasp.org/www-project-dependency-check/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP Dependency Check</a></li>
                    <li><a href="https://www.nuget.org/packages/Microsoft.NetCore.Analyzers" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Microsoft .NET Core Analyzers</a></li>
                    <li><a href="https://github.com/Sonarr/Sonarr" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">SonarQube for .NET</a></li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Resources</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://docs.microsoft.com/en-us/aspnet/core/security/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">ASP.NET Core Security Documentation</a></li>
                    <li><a href="https://owasp.org/www-project-cheat-sheets/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP Cheat Sheets</a></li>
                    <li><a href="https://docs.microsoft.com/en-us/dotnet/standard/security/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">.NET Security Guidelines</a></li>
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

export default CSharp;
