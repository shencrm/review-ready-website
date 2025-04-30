
import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CodeExample from '@/components/CodeExample';
import { Link } from 'react-router-dom';

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
              Security vulnerabilities and best practices for C# and .NET applications.
            </p>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 space-y-8">
              <section>
                <h2 className="text-2xl font-bold mb-4">LINQ Injection</h2>
                <p className="mb-4">
                  LINQ injection occurs when untrusted input is directly incorporated into dynamically constructed LINQ queries.
                </p>
                
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
                />
                
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
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">SQL Injection</h2>
                <p className="mb-4">
                  Despite ORM tools, SQL injection remains a risk in C# applications, especially with raw SQL queries.
                </p>
                
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
                />
                
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
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Insecure Deserialization</h2>
                <p className="mb-4">
                  .NET's binary formatters can lead to remote code execution when deserializing untrusted data.
                </p>
                
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
                />
                
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
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Cross-Site Request Forgery (CSRF)</h2>
                <p className="mb-4">
                  CSRF protection in ASP.NET Core applications requires explicit configuration.
                </p>
                
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
                />
                
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
                />
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
