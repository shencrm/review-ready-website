
import { Challenge } from './challenge-types';

export const xxeChallenges: Challenge[] = [
  {
    id: 'xxe-1',
    title: 'XML External Entity (XXE) Vulnerability',
    description: 'Compare these two C# methods that parse XML data. Which one is protected against XXE attacks?',
    difficulty: 'hard',
    category: 'XXE',
    languages: ['C#'],
    type: 'comparison',
    vulnerabilityType: 'XXE',
    secureCode: `using System;
using System.IO;
using System.Xml;

public class XmlProcessor
{
    public XmlDocument ParseXmlSecurely(string xmlData)
    {
        XmlDocument xmlDoc = new XmlDocument();
        
        // Disable external entity processing
        xmlDoc.XmlResolver = null;
        
        // Load the XML with external entities disabled
        xmlDoc.LoadXml(xmlData);
        
        return xmlDoc;
    }
    
    public void ProcessXmlDocument(string xmlData)
    {
        try
        {
            XmlDocument doc = ParseXmlSecurely(xmlData);
            
            // Process the XML document...
            Console.WriteLine("XML processed successfully");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error processing XML: {ex.Message}");
        }
    }
}`,
    vulnerableCode: `using System;
using System.IO;
using System.Xml;

public class XmlProcessor
{
    public XmlDocument ParseXml(string xmlData)
    {
        XmlDocument xmlDoc = new XmlDocument();
        
        // Load the XML with default settings
        xmlDoc.LoadXml(xmlData);
        
        return xmlDoc;
    }
    
    public void ProcessXmlDocument(string xmlData)
    {
        try
        {
            XmlDocument doc = ParseXml(xmlData);
            
            // Process the XML document...
            Console.WriteLine("XML processed successfully");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error processing XML: {ex.Message}");
        }
    }
}`,
    answer: 'secure',
    explanation: "The secure version prevents XXE attacks by explicitly setting xmlDoc.XmlResolver = null, which disables the processing of external entities in the XML document. The vulnerable version uses default settings which allow external entity processing, making it vulnerable to XXE attacks where an attacker could include external entities that access local files or make network requests to internal services."
  }
];
