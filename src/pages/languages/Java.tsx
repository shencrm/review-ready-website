import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CodeExample from '@/components/CodeExample';
import { Link } from 'react-router-dom';

const Java = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      
      <main className="flex-grow py-12">
        <div className="container mx-auto px-4">
          <div className="mb-12">
            <h1 className="text-4xl font-bold mb-6">Java Security</h1>
            <div className="h-1 w-24 bg-cybr-primary mb-6"></div>
            <p className="text-xl text-cybr-foreground/80">
              Common vulnerabilities and security best practices for Java applications.
            </p>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 space-y-8">
              <section>
                <h2 className="text-2xl font-bold mb-4">XML External Entity (XXE) Injection</h2>
                <p className="mb-4">
                  XXE vulnerabilities occur when XML parsers are configured to process external entity references within XML documents.
                </p>
                
                <CodeExample
                  language="java"
                  title="XXE Vulnerability"
                  code={`// VULNERABLE: Default XML parser configuration
import org.w3c.dom.Document;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;

public void parseXml(String xml) {
    try {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        
        // VULNERABLE: Parser will process XXE
        Document doc = builder.parse(new ByteArrayInputStream(xml.getBytes()));
        
        // Process document...
    } catch (Exception e) {
        e.printStackTrace();
    }
}

/* Malicious XML:
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>
*/`}
                />
                
                <CodeExample
                  language="java"
                  title="XXE Prevention"
                  code={`// SECURE: Disabling XXE processing
import org.w3c.dom.Document;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;

public void parseXmlSafely(String xml) {
    try {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        
        // SECURE: Disable XXE
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(xml.getBytes()));
        
        // Process document...
    } catch (Exception e) {
        e.printStackTrace();
    }
}`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Insecure Deserialization</h2>
                <p className="mb-4">
                  Java's deserialization mechanism can lead to remote code execution if untrusted data is deserialized.
                </p>
                
                <CodeExample
                  language="java"
                  title="Insecure Deserialization"
                  code={`// VULNERABLE: Deserializing untrusted data
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;

public Object deserializeObject(String serializedData) {
    try {
        byte[] data = Base64.getDecoder().decode(serializedData);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        
        // VULNERABLE: Deserializing untrusted data can lead to RCE
        return ois.readObject();
    } catch (Exception e) {
        e.printStackTrace();
        return null;
    }
}

// Routes that accept serialized data are vulnerable
@PostMapping("/api/restore-state")
public ResponseEntity<?> restoreState(@RequestBody String serializedState) {
    Object restoredState = deserializeObject(serializedState);
    // Use restoredState...
}`}
                />
                
                <CodeExample
                  language="java"
                  title="Secure Alternatives to Java Deserialization"
                  code={`// SECURE: Using safer alternatives like JSON
import com.fasterxml.jackson.databind.ObjectMapper;

public Object deserializeObjectSafely(String jsonData, Class<?> valueType) {
    try {
        ObjectMapper mapper = new ObjectMapper();
        
        // SECURE: Using JSON instead of Java serialization
        return mapper.readValue(jsonData, valueType);
    } catch (Exception e) {
        e.printStackTrace();
        return null;
    }
}

// ALTERNATIVE: If Java deserialization is required, use a filter
import java.io.ObjectInputStream;
import java.io.ByteArrayInputStream;
import java.io.InvalidClassException;

public Object deserializeWithFilter(byte[] serializedData) 
        throws IOException, ClassNotFoundException {
    
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedData)) {
        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            String className = desc.getName();
            // Only allow specific classes
            if (!className.startsWith("com.myapp.model.") && 
                !className.startsWith("java.util.ArrayList")) {
                throw new InvalidClassException("Unauthorized deserialization attempt", className);
            }
            return super.resolveClass(desc);
        }
    };
    
    return ois.readObject();
}`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">SQL Injection</h2>
                <p className="mb-4">
                  SQL injection in Java applications occurs when user input is directly incorporated into SQL queries.
                </p>
                
                <CodeExample
                  language="java"
                  title="SQL Injection Vulnerability"
                  code={`// VULNERABLE: String concatenation in SQL
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public User getUserByUsername(Connection conn, String username) {
    try {
        Statement stmt = conn.createStatement();
        
        // VULNERABLE: Direct string concatenation
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        ResultSet rs = stmt.executeQuery(sql);
        
        if (rs.next()) {
            // Extract user data...
            return new User(rs.getInt("id"), rs.getString("username"));
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
    return null;
}

// Attacker could input: admin' OR '1'='1`}
                />
                
                <CodeExample
                  language="java"
                  title="Secure SQL Queries with PreparedStatement"
                  code={`// SECURE: Using parameterized queries
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public User getUserByUsernameSafely(Connection conn, String username) {
    try {
        // SECURE: Using PreparedStatement with parameters
        String sql = "SELECT * FROM users WHERE username = ?";
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setString(1, username);
        
        ResultSet rs = pstmt.executeQuery();
        
        if (rs.next()) {
            // Extract user data...
            return new User(rs.getInt("id"), rs.getString("username"));
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
    return null;
}

// ALTERNATIVE: Using ORM like Hibernate
public User getUserWithHibernate(String username) {
    Session session = sessionFactory.openSession();
    try {
        // Hibernate automatically uses prepared statements
        return session.createQuery("from User where username = :username", User.class)
            .setParameter("username", username)
            .uniqueResult();
    } finally {
        session.close();
    }
}`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Cross-Site Request Forgery (CSRF)</h2>
                <p className="mb-4">
                  CSRF vulnerabilities allow attackers to perform actions on behalf of authenticated users.
                </p>
                
                <CodeExample
                  language="java"
                  title="CSRF Vulnerability in Spring"
                  code={`// VULNERABLE: No CSRF protection
@Controller
public class UserController {
    
    @PostMapping("/user/update-email")
    public String updateEmail(@RequestParam String email, HttpSession session) {
        // Get current user
        User user = (User) session.getAttribute("user");
        
        // Update user's email
        userService.updateEmail(user.getId(), email);
        
        return "redirect:/profile";
    }
    
    // Any website can make a form that submits to this endpoint
    // if the user is logged in
}

<!-- Malicious form on attacker site -->
<form action="https://vulnerable-site.com/user/update-email" method="post">
    <input type="hidden" name="email" value="attacker@evil.com" />
    <input type="submit" value="Win Free Prize!" />
</form>`}
                />
                
                <CodeExample
                  language="java"
                  title="CSRF Protection in Spring"
                  code={`// SECURE: CSRF protection in Spring Security
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            // SECURE: Enable CSRF protection
            .csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
            // ... other configuration
    }
}

// In Thymeleaf template:
// <input type="hidden" th:name="${_csrf.parameterName}" th:value="${_csrf.token}"/>

// In JSP:
// <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />

// In AJAX:
// const token = document.querySelector('meta[name="_csrf"]').content;
// const header = document.querySelector('meta[name="_csrf_header"]').content;
// xhr.setRequestHeader(header, token);`}
                />
              </section>
            </div>
            
            <div className="lg:col-span-1">
              <div className="sticky top-24">
                <div className="card">
                  <h3 className="text-xl font-bold mb-4">Common Java Vulnerabilities</h3>
                  <ul className="space-y-2 pl-4 text-cybr-foreground/80">
                    <li>XML External Entity (XXE)</li>
                    <li>Insecure Deserialization</li>
                    <li>SQL Injection</li>
                    <li>Cross-Site Request Forgery (CSRF)</li>
                    <li>Path Traversal</li>
                    <li>Unsafe Reflection</li>
                    <li>Server-Side Request Forgery</li>
                    <li>Weak Authentication</li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Java Security Tools</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://github.com/find-sec-bugs/find-sec-bugs" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Find Security Bugs</a></li>
                    <li><a href="https://owasp.org/www-project-dependency-check/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP Dependency Check</a></li>
                    <li><a href="https://spotbugs.github.io/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">SpotBugs</a></li>
                    <li><a href="https://www.sonarqube.org/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">SonarQube</a></li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Best Practices</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li>Use parameterized queries</li>
                    <li>Implement proper input validation</li>
                    <li>Apply the principle of least privilege</li>
                    <li>Keep dependencies updated</li>
                    <li>Use secure coding guidelines</li>
                    <li>Implement proper logging and monitoring</li>
                    <li>Use security frameworks like Spring Security</li>
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

export default Java;
