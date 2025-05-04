
import React from 'react';
import { Network, Shield, Bug, Terminal } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';

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
        <h3 className="text-2xl font-bold mb-4">Key Areas to Focus</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <Bug className="text-cybr-primary h-5 w-5" />
              Domain Enumeration
            </h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>User enumeration</li>
              <li>Group membership</li>
              <li>Trust relationships</li>
              <li>Domain controller identification</li>
              <li>LDAP queries</li>
            </ul>
            <p className="mt-2 text-sm">
              Understanding the AD structure is the first step in identifying security weaknesses.
            </p>
          </div>
          
          <div>
            <h4 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <Bug className="text-cybr-primary h-5 w-5" />
              Authentication Attacks
            </h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>Kerberoasting</li>
              <li>AS-REP Roasting</li>
              <li>Pass-the-Hash</li>
              <li>Pass-the-Ticket</li>
              <li>Password spraying</li>
            </ul>
            <p className="mt-2 text-sm">
              Various techniques exist to exploit authentication protocols in Active Directory.
            </p>
          </div>
          
          <div>
            <h4 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <Bug className="text-cybr-primary h-5 w-5" />
              Permission Models
            </h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>ACL misconfigurations</li>
              <li>Delegation issues</li>
              <li>Group Policy Objects</li>
              <li>AdminSDHolder</li>
              <li>Shadow admins</li>
            </ul>
            <p className="mt-2 text-sm">
              Permission models in Active Directory are complex and often lead to unintended privilege paths.
            </p>
          </div>
          
          <div>
            <h4 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <Bug className="text-cybr-primary h-5 w-5" />
              Lateral Movement
            </h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>Overpass-the-Hash</li>
              <li>Token impersonation</li>
              <li>DCOM</li>
              <li>PowerShell Remoting</li>
              <li>WMI techniques</li>
            </ul>
            <p className="mt-2 text-sm">
              Once a foothold is established, lateral movement techniques allow traversal across the domain.
            </p>
          </div>
        </div>
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
