
import React from 'react';
import CodeExample from '@/components/CodeExample';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';

const AzureSection: React.FC = () => {
  return (
    <section className="space-y-12">
      <div>
        <h2 className="text-3xl font-bold mb-6">Azure Penetration Testing</h2>
        <p className="mb-8">
          Microsoft Azure is a comprehensive cloud platform with unique security considerations.
          Testing Azure environments requires understanding specific services, authentication mechanisms,
          and potential attack vectors.
        </p>
        
        <Tabs defaultValue="common-vulnerabilities">
          <TabsList>
            <TabsTrigger value="common-vulnerabilities">Common Vulnerabilities</TabsTrigger>
            <TabsTrigger value="testing-approach">Testing Approach</TabsTrigger>
            <TabsTrigger value="tools">Tools</TabsTrigger>
          </TabsList>
          
          <TabsContent value="common-vulnerabilities" className="space-y-6 mt-6">
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Azure Active Directory Vulnerabilities</h3>
              <p className="mb-4">
                Azure AD is the core identity service for Azure and often contains security issues:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Weak password policies and legacy authentication</li>
                <li>Excessive role assignments and privilege issues</li>
                <li>Misconfigured conditional access policies</li>
                <li>Dangerous consent grants to applications</li>
                <li>MFA bypass opportunities</li>
              </ul>
              
              <h4 className="text-xl font-bold mt-4 mb-2">Testing Azure AD Security</h4>
              <CodeExample 
                language="bash"
                title="Azure AD Assessment"
                code={`# Using AzureHound to collect data
./azurehound -c All -o azure_data.json

# Using AzureAD module in PowerShell
Connect-AzureAD
Get-AzureADUser
Get-AzureADDirectoryRole
Get-AzureADServicePrincipal

# Examining applications and service principals
Get-AzureADApplication
Get-AzureADServicePrincipal | Where-Object {$_.DisplayName -eq "Target App"}`}
              />
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Storage Account Issues</h3>
              <p className="mb-4">
                Azure Storage accounts can have multiple security problems:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Public blob containers with sensitive data</li>
                <li>Shared access signature (SAS) misconfigurations</li>
                <li>Insecure storage account keys management</li>
                <li>Missing encryption for sensitive data</li>
                <li>Improper network access controls</li>
              </ul>
              
              <h4 className="text-xl font-bold mt-4 mb-2">Testing Storage Security</h4>
              <CodeExample 
                language="bash"
                title="Storage Account Assessment"
                code={`# Using Azure CLI to check storage account properties
az storage account list

# Check for public access level on blob containers
az storage container list --account-name target-account-name

# List blobs in a container
az storage blob list --container-name container-name --account-name target-account-name

# Using tools like MicroBurst for Azure storage enumeration
Import-Module MicroBurst.psm1
Invoke-EnumerateAzureBlobs -Base target-name`}
              />
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Key Vault Security Issues</h3>
              <p className="mb-4">
                Azure Key Vault may have security misconfigurations:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Overly permissive access policies</li>
                <li>Lack of proper RBAC implementation</li>
                <li>Network security controls misconfiguration</li>
                <li>Logging and monitoring deficiencies</li>
                <li>Insecure secret rotation practices</li>
              </ul>
              
              <h4 className="text-xl font-bold mt-4 mb-2">Testing Key Vault Security</h4>
              <CodeExample 
                language="bash"
                title="Key Vault Assessment"
                code={`# List Key Vaults
az keyvault list

# Check access policies
az keyvault show --name target-vault-name

# List keys, secrets, and certificates
az keyvault key list --vault-name target-vault-name
az keyvault secret list --vault-name target-vault-name
az keyvault certificate list --vault-name target-vault-name`}
              />
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Azure Function Vulnerabilities</h3>
              <p className="mb-4">
                Serverless Azure Functions can contain security issues:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Insecure authentication and authorization</li>
                <li>Vulnerable dependencies in code</li>
                <li>Excessive managed identity permissions</li>
                <li>Insecure handling of secrets</li>
                <li>Code injection vulnerabilities</li>
              </ul>
              
              <h4 className="text-xl font-bold mt-4 mb-2">Testing Azure Functions</h4>
              <CodeExample 
                language="bash"
                title="Azure Function Assessment"
                code={`# List function apps
az functionapp list

# Get function app settings
az functionapp config appsettings list --name target-function-app --resource-group target-rg

# Check assigned managed identity
az functionapp identity show --name target-function-app --resource-group target-rg

# Review function code (if accessible)
az functionapp deployment source show --name target-function-app --resource-group target-rg`}
              />
            </div>
          </TabsContent>
          
          <TabsContent value="testing-approach" className="space-y-6 mt-6">
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Step-by-Step Azure Penetration Testing</h3>
              
              <div className="space-y-4">
                <div>
                  <h4 className="text-xl font-bold mb-2">1. Reconnaissance</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Identify Azure resources using tools like DNSx, Shodan</li>
                    <li>Look for Azure Storage, App Services, Function Apps</li>
                    <li>Identify Azure AD tenant information</li>
                    <li>Map out the Azure architecture based on discovered resources</li>
                    <li>Search for exposed Azure credentials in public repositories</li>
                  </ul>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">2. Initial Access Vector Identification</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Test for public blob containers with read/write access</li>
                    <li>Check for weak authentication in Azure AD</li>
                    <li>Look for exposed App Services with vulnerabilities</li>
                    <li>Test for SSRF vulnerabilities that could access IMDS</li>
                    <li>Check for poorly configured Function Apps</li>
                  </ul>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">3. Privilege Escalation</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Enumerate Azure RBAC permissions</li>
                    <li>Check for overly permissive role assignments</li>
                    <li>Test for privilege escalation using managed identities</li>
                    <li>Look for dangerous app consent grants</li>
                    <li>Test service principal credential abuse</li>
                  </ul>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">4. Lateral Movement</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Move between Azure subscriptions using role assignments</li>
                    <li>Exploit trust relationships between resources</li>
                    <li>Use managed identities to access other Azure services</li>
                    <li>Pivot through VNet peering connections</li>
                    <li>Abuse Azure AD integrated authentication</li>
                  </ul>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">5. Data Exfiltration Testing</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Test for unencrypted data in Storage accounts</li>
                    <li>Check SQL Database access controls and encryption</li>
                    <li>Test for sensitive data in Key Vault</li>
                    <li>Assess Azure Monitor and Log Analytics evasion</li>
                    <li>Test data exfiltration prevention controls</li>
                  </ul>
                </div>
              </div>
            </div>
          </TabsContent>
          
          <TabsContent value="tools" className="space-y-6 mt-6">
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Essential Azure Penetration Testing Tools</h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-xl font-bold mb-2">MicroBurst</h4>
                  <p className="mb-2">A collection of PowerShell scripts for Azure security assessment and exploitation.</p>
                  <div className="bg-cybr-muted/50 p-3 rounded">
                    <h5 className="font-semibold mb-1">Key Features:</h5>
                    <ul className="list-disc list-inside text-sm">
                      <li>Storage account enumeration</li>
                      <li>Key Vault scanning</li>
                      <li>Azure resource scanning</li>
                      <li>Service principal enumeration</li>
                    </ul>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">AzureHound</h4>
                  <p className="mb-2">Data collector for BloodHound, focused on Azure AD security assessment.</p>
                  <div className="bg-cybr-muted/50 p-3 rounded">
                    <h5 className="font-semibold mb-1">Key Features:</h5>
                    <ul className="list-disc list-inside text-sm">
                      <li>Visual mapping of Azure AD attack paths</li>
                      <li>Discovery of privilege escalation opportunities</li>
                      <li>Analysis of permission relationships</li>
                      <li>Identification of tenant-wide security issues</li>
                    </ul>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">ScoutSuite</h4>
                  <p className="mb-2">Multi-cloud security auditing tool with Azure support.</p>
                  <div className="bg-cybr-muted/50 p-3 rounded">
                    <h5 className="font-semibold mb-1">Key Features:</h5>
                    <ul className="list-disc list-inside text-sm">
                      <li>Comprehensive Azure service coverage</li>
                      <li>Rules-based assessment approach</li>
                      <li>Detailed security findings</li>
                      <li>Web-based reporting dashboard</li>
                    </ul>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">ROADtools</h4>
                  <p className="mb-2">Azure AD exploration framework for security assessments.</p>
                  <div className="bg-cybr-muted/50 p-3 rounded">
                    <h5 className="font-semibold mb-1">Key Features:</h5>
                    <ul className="list-disc list-inside text-sm">
                      <li>Azure AD data collection and analysis</li>
                      <li>Graphical interface for exploring relationships</li>
                      <li>Permission analysis capabilities</li>
                      <li>Authentication method assessment</li>
                    </ul>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">PowerZure</h4>
                  <p className="mb-2">PowerShell framework for assessing and exploiting Azure resources.</p>
                  <div className="bg-cybr-muted/50 p-3 rounded">
                    <h5 className="font-semibold mb-1">Key Features:</h5>
                    <ul className="list-disc list-inside text-sm">
                      <li>Reconnaissance functions</li>
                      <li>Privilege escalation techniques</li>
                      <li>Post-exploitation capabilities</li>
                      <li>Object manipulation in Azure</li>
                    </ul>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">Azure CLI</h4>
                  <p className="mb-2">Official command-line interface for Azure, essential for penetration testing.</p>
                  <div className="bg-cybr-muted/50 p-3 rounded">
                    <h5 className="font-semibold mb-1">Key Features:</h5>
                    <ul className="list-disc list-inside text-sm">
                      <li>Complete API coverage for Azure services</li>
                      <li>Scriptable for automated testing</li>
                      <li>Cross-platform compatibility</li>
                      <li>JSON output for programmatic processing</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </section>
  );
};

export default AzureSection;
