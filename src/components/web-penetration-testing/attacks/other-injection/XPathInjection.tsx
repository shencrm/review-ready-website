
import React from 'react';
import { Code } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const XPathInjection: React.FC = () => {
  return (
    <div className="mb-12">
      <h4 className="text-xl font-semibold mb-6 flex items-center gap-2">
        <Code className="h-6 w-6 text-cybr-primary" />
        XPath Injection
      </h4>
      
      <div className="mb-6">
        <h5 className="text-lg font-semibold mb-3">What is XPath Injection?</h5>
        <p className="mb-4">
          XPath injection occurs when user input is used to construct XPath queries to navigate XML documents,
          potentially allowing attackers to access unauthorized data or bypass authentication. XPath is used to
          navigate through elements and attributes in XML documents, and injection vulnerabilities arise when
          user input is directly incorporated into XPath expressions.
        </p>
        <p className="mb-4">
          This vulnerability is particularly dangerous in applications that use XML databases, configuration files,
          or authentication systems based on XML data structures. XPath injection can lead to authentication bypass,
          data extraction, and information disclosure.
        </p>
      </div>

      <div className="mb-6">
        <h5 className="text-lg font-semibold mb-3">Attacker Goals</h5>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>Authentication Bypass:</strong> Circumvent XML-based authentication mechanisms</li>
          <li><strong>Data Extraction:</strong> Access sensitive information stored in XML documents</li>
          <li><strong>Node Enumeration:</strong> Discover XML document structure and content</li>
          <li><strong>Privilege Escalation:</strong> Access higher-privilege data or user accounts</li>
          <li><strong>Configuration Disclosure:</strong> Extract application configuration from XML files</li>
          <li><strong>Blind Data Extraction:</strong> Extract data when direct output is not visible</li>
        </ul>
      </div>

      <CodeExample 
        language="java" 
        isVulnerable={true}
        title="Vulnerable Java XPath Implementation" 
        code={`// Java application vulnerable to XPath injection
import javax.xml.xpath.*;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class VulnerableXPathAuth {
    private Document xmlDoc;
    private XPath xpath;
    
    public boolean authenticateUser(String username, String password) {
        try {
            // Vulnerable: Direct string concatenation in XPath
            String xpathQuery = "//user[username='" + username + 
                               "' and password='" + password + "']";
            
            System.out.println("XPath Query: " + xpathQuery); // Debug - reveals injection
            
            XPathExpression expr = xpath.compile(xpathQuery);
            NodeList result = (NodeList) expr.evaluate(xmlDoc, XPathConstants.NODESET);
            
            return result.getLength() > 0;
            
        } catch (Exception e) {
            // Vulnerable: Exposing XPath errors
            System.err.println("XPath Error: " + e.getMessage());
            return false;
        }
    }
}

/*
ATTACK PAYLOADS:

1. Authentication Bypass:
   Username: admin' or '1'='1
   Password: anything
   XPath: //user[username='admin' or '1'='1' and password='anything']
   Result: Always returns true due to '1'='1'

2. Password Extraction (Blind):
   Username: admin' and substring(password,1,1)='s
   Password: anything
   Tests if first character of admin's password is 's'

3. All Users Extraction:
   Username: '] | //user/* | //user[username='
   Password: anything
   Returns all user data from the XML
*/`} 
      />

      <CodeExample 
        language="java" 
        isVulnerable={false}
        title="Secure XPath Implementation" 
        code={`// Secure Java XPath implementation
import javax.xml.xpath.*;
import java.util.regex.Pattern;

public class SecureXPathAuth {
    private Document xmlDoc;
    private XPath xpath;
    private static final Pattern VALID_USERNAME = Pattern.compile("^[a-zA-Z0-9._-]{3,30}$");
    
    public boolean authenticateUser(String username, String password) {
        // 1. Input validation
        if (!isValidInput(username, VALID_USERNAME) || 
            password == null || password.length() > 128) {
            return false;
        }
        
        try {
            // 2. Hash the password before comparison
            String hashedPassword = hashPassword(password);
            
            // 3. Use parameterized XPath with variable resolver
            String xpathQuery = "//user[username=$username and password=$password]";
            XPathExpression expr = xpath.compile(xpathQuery);
            
            // 4. Set variables securely
            Map<String, String> variables = new HashMap<>();
            variables.put("username", username);
            variables.put("password", hashedPassword);
            
            ((SecureVariableResolver) xpath.getXPathVariableResolver()).setVariables(variables);
            
            NodeList result = (NodeList) expr.evaluate(xmlDoc, XPathConstants.NODESET);
            return result.getLength() > 0;
            
        } catch (Exception e) {
            // 5. Secure error handling - don't expose XPath details
            logSecurityEvent("Authentication attempt failed for user: " + 
                            sanitizeForLogging(username));
            return false;
        }
    }
    
    private boolean isValidInput(String input, Pattern pattern) {
        return input != null && pattern.matcher(input).matches();
    }
}`} 
      />

      <div className="mb-6">
        <h5 className="text-lg font-semibold mb-3">Prevention Best Practices</h5>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>Input Validation:</strong> Validate all user inputs against strict patterns and length limits</li>
          <li><strong>Parameterized Queries:</strong> Use XPath variable resolvers instead of string concatenation</li>
          <li><strong>Character Escaping:</strong> Properly escape XPath special characters in user input</li>
          <li><strong>Least Privilege:</strong> Limit XPath query scope and accessible document sections</li>
          <li><strong>Error Handling:</strong> Never expose XPath errors or document structure to users</li>
          <li><strong>Alternative Technologies:</strong> Consider using relational databases instead of XML for sensitive data</li>
        </ul>
      </div>
    </div>
  );
};

export default XPathInjection;
