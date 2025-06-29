
import React from 'react';
import { Database } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const LDAPInjection: React.FC = () => {
  return (
    <div className="mb-12">
      <h4 className="text-xl font-semibold mb-6 flex items-center gap-2">
        <Database className="h-6 w-6 text-cybr-primary" />
        LDAP Injection
      </h4>
      
      <div className="mb-6">
        <h5 className="text-lg font-semibold mb-3">What is LDAP Injection?</h5>
        <p className="mb-4">
          LDAP (Lightweight Directory Access Protocol) injection occurs when user input is incorrectly filtered or 
          sanitized before being used in LDAP queries. This vulnerability allows attackers to manipulate LDAP queries
          to access unauthorized information, bypass authentication mechanisms, or modify directory data.
        </p>
        <p className="mb-4">
          LDAP injection is particularly dangerous in enterprise environments where LDAP directories store critical
          user authentication data, organizational structure, and access control information. A successful attack
          can lead to complete compromise of the directory service and all dependent applications.
        </p>
      </div>

      <div className="mb-6">
        <h5 className="text-lg font-semibold mb-3">Attacker Goals</h5>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>Authentication Bypass:</strong> Circumvent login mechanisms by manipulating authentication queries</li>
          <li><strong>Data Enumeration:</strong> Extract sensitive user information, group memberships, and organizational data</li>
          <li><strong>Privilege Escalation:</strong> Gain access to higher-privilege accounts or administrative functions</li>
          <li><strong>Directory Manipulation:</strong> Modify user attributes, passwords, or group memberships</li>
          <li><strong>Information Disclosure:</strong> Access confidential directory information like email addresses, phone numbers</li>
          <li><strong>Lateral Movement:</strong> Use directory information to identify and attack other systems</li>
        </ul>
      </div>

      <div className="mb-6">
        <h5 className="text-lg font-semibold mb-3">Vulnerable Components</h5>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>Authentication Systems:</strong> Login forms using LDAP for user verification</li>
          <li><strong>User Search Functions:</strong> Directory search and user lookup features</li>
          <li><strong>Group Management:</strong> Systems managing user groups and organizational units</li>
          <li><strong>Single Sign-On (SSO):</strong> LDAP-based SSO implementations</li>
          <li><strong>Enterprise Applications:</strong> HR systems, email clients, and corporate portals</li>
          <li><strong>Web Applications:</strong> Any application using LDAP for authentication or data retrieval</li>
        </ul>
      </div>

      <div className="mb-6">
        <h5 className="text-lg font-semibold mb-3">Why LDAP Injection Works</h5>
        <div className="bg-cybr-muted/30 p-6 rounded-lg mb-4">
          <p className="mb-3">
            LDAP injection exploits the way LDAP queries are constructed using string concatenation without proper
            input validation. LDAP uses special characters for logical operations (* & | ! = &lt; &gt; ( ) \ / , + " ;)
            that can be manipulated to alter query logic.
          </p>
          <p className="mb-3">
            The vulnerability occurs when user input containing these special characters is directly embedded into
            LDAP search filters, allowing attackers to inject additional conditions or completely change the query structure.
          </p>
        </div>
      </div>

      <div className="mb-6">
        <h5 className="text-lg font-semibold mb-3">Step-by-Step Exploitation Process</h5>
        <div className="space-y-4">
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h6 className="font-semibold text-cybr-primary mb-2">Phase 1: Target Identification</h6>
            <ol className="list-decimal pl-6 space-y-1">
              <li>Identify applications using LDAP authentication or directory services</li>
              <li>Locate login forms, search functions, or user management interfaces</li>
              <li>Test for LDAP error messages that reveal directory structure</li>
              <li>Analyze application responses for LDAP-specific behavior patterns</li>
            </ol>
          </div>
          
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h6 className="font-semibold text-cybr-primary mb-2">Phase 2: LDAP Query Structure Discovery</h6>
            <ol className="list-decimal pl-6 space-y-1">
              <li>Test input fields with LDAP special characters to trigger errors</li>
              <li>Analyze error messages to understand query structure</li>
              <li>Identify which user inputs are incorporated into LDAP queries</li>
              <li>Determine the LDAP attributes being searched (uid, cn, mail, etc.)</li>
            </ol>
          </div>
          
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h6 className="font-semibold text-cybr-primary mb-2">Phase 3: Injection Testing</h6>
            <ol className="list-decimal pl-6 space-y-1">
              <li>Craft payloads to modify query logic (using * | & operators)</li>
              <li>Test authentication bypass techniques</li>
              <li>Attempt to extract additional user attributes</li>
              <li>Try to enumerate directory structure and user accounts</li>
            </ol>
          </div>
          
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h6 className="font-semibold text-cybr-primary mb-2">Phase 4: Data Extraction</h6>
            <ol className="list-decimal pl-6 space-y-1">
              <li>Use wildcard characters to enumerate all users or groups</li>
              <li>Extract sensitive attributes like passwords, email addresses</li>
              <li>Map organizational structure and user relationships</li>
              <li>Identify high-privilege accounts for further targeting</li>
            </ol>
          </div>
        </div>
      </div>

      <CodeExample 
        language="java" 
        isVulnerable={true}
        title="Vulnerable LDAP Authentication Code" 
        code={`// Java LDAP authentication with injection vulnerability
public class LDAPAuthenticator {
    private DirContext ctx;
    
    public boolean authenticate(String username, String password) {
        try {
            // Vulnerable: Direct string concatenation without sanitization
            String searchFilter = "(&(objectClass=user)(uid=" + username + ")(userPassword=" + password + "))";
            
            SearchControls searchCtls = new SearchControls();
            searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            // Execute the vulnerable query
            NamingEnumeration<SearchResult> results = 
                ctx.search("ou=users,dc=company,dc=com", searchFilter, searchCtls);
            
            return results.hasMore(); // True if user found
            
        } catch (Exception e) {
            // Error messages might leak directory structure
            System.err.println("LDAP Error: " + e.getMessage());
            return false;
        }
    }
    
    public List<User> searchUsers(String searchTerm) {
        List<User> users = new ArrayList<>();
        try {
            // Vulnerable: User input directly in search filter
            String filter = "(|(cn=*" + searchTerm + "*)(mail=*" + searchTerm + "*))";
            
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[]{"cn", "mail", "department"});
            
            NamingEnumeration<SearchResult> results = 
                ctx.search("ou=users,dc=company,dc=com", filter, controls);
            
            while (results.hasMore()) {
                SearchResult result = results.next();
                // Process results...
                users.add(createUserFromResult(result));
            }
        } catch (Exception e) {
            logger.error("Search failed: " + e.getMessage());
        }
        return users;
    }
}

/* 
ATTACK PAYLOADS:

1. Authentication Bypass:
   Username: admin)(&(objectClass=*
   Password: anything
   Resulting query: (&(objectClass=user)(uid=admin)(&(objectClass=*)(userPassword=anything))
   This always returns true due to (objectClass=*) matching everything

2. Information Extraction:
   Username: *))(|(uid=*
   Password: ignored  
   This transforms the query to return all users

3. Wildcard Enumeration:
   Search term: *))(objectClass=*
   This returns all directory entries, not just users
*/`} 
      />

      <CodeExample 
        language="java" 
        isVulnerable={false}
        title="Secure LDAP Implementation" 
        code={`import javax.naming.directory.*;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import java.util.Hashtable;
import java.util.regex.Pattern;

public class SecureLDAPAuthenticator {
    private DirContext ctx;
    private static final Pattern VALID_USERNAME = Pattern.compile("^[a-zA-Z0-9._-]+$");
    private static final String[] LDAP_SPECIAL_CHARS = {"*", "(", ")", "\\\\", "/", "\\0"};
    
    public boolean authenticate(String username, String password) {
        // 1. Input validation
        if (!isValidUsername(username) || password == null || password.isEmpty()) {
            return false;
        }
        
        try {
            // 2. Use parameterized queries with proper escaping
            String escapedUsername = escapeLDAPFilter(username);
            String searchFilter = "(&(objectClass=user)(uid={0}))";
            
            // 3. Use SearchControls with limits
            SearchControls searchCtls = new SearchControls();
            searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            searchCtls.setCountLimit(1); // Limit results
            searchCtls.setTimeLimit(5000); // 5 second timeout
            searchCtls.setReturningAttributes(new String[]{"dn"}); // Only return what we need
            
            // 4. Execute search with parameter substitution
            NamingEnumeration<SearchResult> results = ctx.search(
                "ou=users,dc=company,dc=com", 
                searchFilter, 
                new Object[]{escapedUsername},
                searchCtls
            );
            
            if (!results.hasMore()) {
                return false;
            }
            
            SearchResult result = results.next();
            String userDN = result.getNameInNamespace();
            
            // 5. Authenticate by binding with user credentials
            return bindUser(userDN, password);
            
        } catch (NamingException e) {
            // 6. Log securely without exposing sensitive information
            logger.warn("Authentication failed for user: " + username.replaceAll("[^a-zA-Z0-9]", ""));
            return false;
        }
    }
    
    private String escapeLDAPFilter(String input) {
        if (input == null) return null;
        
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            switch (c) {
                case '*':  sb.append("\\2a"); break;
                case '(':  sb.append("\\28"); break;
                case ')':  sb.append("\\29"); break;
                case '\\': sb.append("\\5c"); break;
                case '/':  sb.append("\\2f"); break;
                case '\0': sb.append("\\00"); break;
                default:   sb.append(c); break;
            }
        }
        return sb.toString();
    }
}`} 
      />

      <div className="mb-6">
        <h5 className="text-lg font-semibold mb-3">Detection and Testing Methods</h5>
        <div className="space-y-4">
          <div>
            <h6 className="font-semibold mb-2">Manual Testing Steps</h6>
            <ol className="list-decimal pl-6 space-y-2">
              <li><strong>Input Field Analysis:</strong> Test login forms and search fields with LDAP special characters</li>
              <li><strong>Error Message Analysis:</strong> Submit malformed inputs to trigger LDAP errors</li>
              <li><strong>Authentication Bypass Testing:</strong> Try payloads like *)(&(objectClass=*) in username fields</li>
              <li><strong>Wildcard Testing:</strong> Use * characters to test for information disclosure</li>
              <li><strong>Logical Operator Testing:</strong> Test &, |, ! operators in various input fields</li>
            </ol>
          </div>
          
          <div>
            <h6 className="font-semibold mb-2">Automated Testing Tools</h6>
            <ul className="list-disc pl-6 space-y-1">
              <li><strong>LDAPExplorer:</strong> Specialized LDAP injection testing tool</li>
              <li><strong>Burp Suite LDAP Extensions:</strong> Automated LDAP injection detection</li>
              <li><strong>Custom Python Scripts:</strong> Using python-ldap library for testing</li>
              <li><strong>OWASP ZAP:</strong> With LDAP injection detection plugins</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LDAPInjection;
