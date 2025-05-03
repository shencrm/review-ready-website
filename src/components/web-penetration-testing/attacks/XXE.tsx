
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
        local files, perform server-side request forgery, internal port scanning, or remote code execution.
      </p>
      
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
     in the lastName field, potentially revealing sensitive system information -->`} 
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

// Disable XXE in PHP
libxml_disable_entity_loader(true);

// Disable XXE in .NET
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;`} 
      />
    </section>
  );
};

export default XXE;
