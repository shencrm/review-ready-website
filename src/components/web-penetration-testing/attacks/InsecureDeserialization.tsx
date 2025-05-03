
import React from 'react';
import { Bug } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';

const InsecureDeserialization: React.FC = () => {
  return (
    <section id="deserial" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Insecure Deserialization</h3>
      <p className="mb-6">
        Insecure deserialization occurs when an application deserializes untrusted data without sufficient verification,
        allowing attackers to manipulate serialized objects to achieve harmful results, including remote code execution.
        This vulnerability can lead to serious attacks like authentication bypass, privilege escalation, and injection attacks.
        It's often difficult to detect and can have devastating consequences on application security.
      </p>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        <SecurityCard
          title="Immediate Impact"
          description="Remote code execution, application crashes, and complex replay attacks that bypass authentication and authorization. In worst cases, an attacker can gain complete control of the application server."
          severity="high"
        />
        <SecurityCard
          title="Vulnerable Languages"
          description="Java, PHP, Python, and .NET are commonly affected due to their powerful serialization frameworks. Each language has its own serialization mechanisms and associated vulnerabilities."
          severity="high"
        />
      </div>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">How Insecure Deserialization Works</h4>
      <p className="mb-4">
        Deserialization vulnerabilities exploit the process of converting serialized data back into objects:
      </p>
      <ol className="list-decimal pl-6 space-y-2 mb-4">
        <li>An application deserializes user-controllable data</li>
        <li>The attacker crafts malicious serialized objects</li>
        <li>When deserialized, these objects can trigger unexpected code paths</li>
        <li>The application executes harmful code during the deserialization process</li>
        <li>This often happens through "magic methods" that are automatically called during deserialization</li>
      </ol>
      
      <CodeExample 
        language="php" 
        isVulnerable={true}
        title="Vulnerable PHP Deserialization" 
        code={`<?php
// Vulnerable code accepts serialized object from user
$userData = unserialize($_COOKIE['user_data']);

// Attacker-controlled cookie might contain:
// O:8:"UserInfo":2:{s:8:"username";s:5:"admin";s:5:"admin";b:1;}
// This could create an object with unauthorized admin privileges

// More dangerous example with PHP object injection
class CustomTemplate {
  private $template_file_path;
  private $logout_file;
  
  function __construct($template_file_path) {
    $this->template_file_path = $template_file_path;
  }
  
  function __destruct() {
    // This method is automatically called during garbage collection
    if (isset($this->logout_file)) {
      // Vulnerable file operation triggered during deserialization
      file_put_contents($this->logout_file, "Logged out");
    }
  }
}

// Attacker creates a serialized object:
// O:14:"CustomTemplate":2:{s:18:"template_file_path";s:9:"irrelevant";s:11:"logout_file";s:11:"/etc/passwd";}
// When deserialized, this could overwrite system files!
?>`} 
      />
      
      <CodeExample 
        language="java" 
        isVulnerable={true}
        title="Vulnerable Java Deserialization" 
        code={`// Vulnerable Java code accepting serialized data over network
try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
    // Vulnerable: Deserializing untrusted data
    Object obj = ois.readObject();
    Command command = (Command) obj;
    command.execute();
} catch (Exception e) {
    e.printStackTrace();
}

// Attacker could send a serialized object using gadget chains like:
// Apache Commons Collections + InvokerTransformer
// This could lead to remote code execution!`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Safe Alternative" 
        code={`// Use JSON instead of serialized objects
const userData = JSON.parse(cookie);

// Explicitly validate data after parsing
if (!isValidUserData(userData)) {
  throw new Error("Invalid user data");
}

// Explicitly set properties from the validated data
const user = {
  username: userData.username,
  // Don't directly copy admin flag from user input
};

// Check permissions through proper authorization system
const isAdmin = authorizationService.isAdmin(user.username);

// For Java applications, use serialization filtering
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;

ObjectInputStream ois = new ObjectInputStream(inputStream);
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "java.base/*;java.util.*;!*");
ois.setObjectInputFilter(filter);
Object obj = ois.readObject();

// For PHP, prefer safer alternatives
<?php
// Instead of direct unserialization, use JSON
$userData = json_decode($_COOKIE['user_data'], true);

// Or if serialization is necessary, use HMAC to verify integrity
$hmac = hash_hmac('sha256', $serializedData, SECRET_KEY);
if (hash_equals($hmac, $_COOKIE['data_hmac'])) {
    $data = unserialize($serializedData);
} else {
    // Invalid HMAC - potential tampering
    throw new Exception("Invalid data integrity");
}
?>`} 
      />
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Prevention Strategies</h4>
      <ul className="list-disc pl-6 space-y-2">
        <li><strong>Avoid Serialization of Sensitive Data:</strong> Use simpler data formats like JSON for untrusted data</li>
        <li><strong>Integrity Checking:</strong> Use cryptographic signatures to detect tampering</li>
        <li><strong>Type Constraints:</strong> Enforce strict type constraints when deserializing</li>
        <li><strong>Deserialization Filtering:</strong> Use language-specific filters to restrict which classes can be deserialized</li>
        <li><strong>Monitoring:</strong> Monitor deserialization processes for unusual behavior</li>
        <li><strong>Principle of Least Privilege:</strong> Run applications with minimal necessary permissions</li>
        <li><strong>Sanitize and Validate:</strong> Always validate deserialized data before use</li>
      </ul>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Language-Specific Guidance</h4>
      <ul className="list-disc pl-6 space-y-2">
        <li><strong>Java:</strong> Use ObjectInputFilter (Java 9+), or look into RASP solutions</li>
        <li><strong>PHP:</strong> Use JSON instead of serialize/unserialize, or implement cryptographic integrity checks</li>
        <li><strong>.NET:</strong> Use DataContractSerializer or JSON.NET instead of BinaryFormatter</li>
        <li><strong>Python:</strong> Avoid pickle for untrusted data; use alternatives like JSON or YAML</li>
        <li><strong>Ruby:</strong> Avoid Marshal.load for untrusted data; use JSON instead</li>
      </ul>
    </section>
  );
};

export default InsecureDeserialization;
