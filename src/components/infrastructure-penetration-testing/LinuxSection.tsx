
import React from 'react';
import { Linux, Shield, Bug, Terminal } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';

const LinuxSection: React.FC = () => {
  return (
    <section className="space-y-12">
      <div className="mb-8">
        <h2 className="text-3xl font-bold mb-6 flex items-center gap-2">
          <Linux className="text-cybr-primary" />
          Linux Penetration Testing
        </h2>
        <p className="mb-4">
          Linux systems form the backbone of most server infrastructure and require specialized penetration testing approaches.
          Understanding Linux security models and common misconfigurations is essential for comprehensive security assessments.
        </p>
      </div>
      
      <div className="card mb-10">
        <h3 className="text-2xl font-bold mb-4">Key Areas to Focus</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <Bug className="text-cybr-primary h-5 w-5" />
              Privilege Escalation Vectors
            </h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>SUID/SGID binaries</li>
              <li>Sudo misconfigurations</li>
              <li>Cron jobs</li>
              <li>Kernel exploits</li>
              <li>Weak file permissions</li>
            </ul>
            <p className="mt-2 text-sm">
              Linux privilege escalation techniques allow attackers to gain root access from limited user accounts.
            </p>
          </div>
          
          <div>
            <h4 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <Bug className="text-cybr-primary h-5 w-5" />
              Service Vulnerabilities
            </h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>SSH misconfiguration</li>
              <li>Web servers (Apache, Nginx)</li>
              <li>Database services</li>
              <li>Containerization issues</li>
              <li>Legacy services</li>
            </ul>
            <p className="mt-2 text-sm">
              Services running on Linux systems often introduce vulnerabilities due to misconfigurations.
            </p>
          </div>
          
          <div>
            <h4 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <Bug className="text-cybr-primary h-5 w-5" />
              File System Security
            </h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>Permission models</li>
              <li>Symbolic links</li>
              <li>Hard links</li>
              <li>Sensitive file disclosure</li>
              <li>Temporary file handling</li>
            </ul>
            <p className="mt-2 text-sm">
              Linux file system permission issues can lead to unauthorized access to sensitive data.
            </p>
          </div>
          
          <div>
            <h4 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <Bug className="text-cybr-primary h-5 w-5" />
              Network Services
            </h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>Open ports</li>
              <li>Firewall configurations</li>
              <li>Network interfaces</li>
              <li>NFS/SMB shares</li>
              <li>Service discovery</li>
            </ul>
            <p className="mt-2 text-sm">
              Network configurations on Linux systems require careful security assessment.
            </p>
          </div>
        </div>
      </div>
      
      <div className="mb-10">
        <h3 className="text-2xl font-bold mb-6">Linux Penetration Testing Techniques</h3>
        
        <div className="space-y-6">
          <SecurityCard
            title="LinPEAS"
            description="Script for searching common Linux privilege escalation vectors, automating many checks that would otherwise be performed manually."
            icon={<Terminal className="h-6 w-6" />}
            severity="medium"
          />
          
          <div className="card">
            <h4 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <Terminal className="text-cybr-primary h-5 w-5" />
              Common Linux Enumeration Commands
            </h4>
            <p className="mb-3">
              Basic commands for initial system enumeration:
            </p>
            
            <CodeExample
              language="bash"
              code={`# System information
uname -a
cat /etc/os-release
hostname
whoami
id

# Network information
ifconfig -a || ip a
netstat -tuln || ss -tuln
cat /etc/hosts

# Find SUID binaries
find / -type f -perm -u=s 2>/dev/null

# List cron jobs
ls -la /etc/cron*
cat /etc/crontab

# Check sudo permissions
sudo -l`}
              title="Basic Linux Enumeration"
            />
          </div>
          
          <div className="card">
            <h4 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <Terminal className="text-cybr-primary h-5 w-5" />
              GTFOBins Techniques
            </h4>
            <p className="mb-3">GTFOBins is a curated list of Unix binaries that can be used to bypass local security restrictions:</p>
            
            <CodeExample
              language="bash"
              code={`# Example: Using find for privilege escalation
find . -exec /bin/sh -p \\; -quit

# Example: Using vim for privilege escalation
vim -c ':!/bin/sh'

# Example: Using python for privilege escalation
python -c 'import os; os.system("/bin/sh")'`}
              title="GTFOBins Examples"
              isVulnerable={true}
            />
          </div>
        </div>
      </div>
      
      <div className="card">
        <h3 className="text-2xl font-bold mb-4">Defensive Measures</h3>
        <div className="space-y-4">
          <div>
            <h4 className="text-lg font-semibold">Securing Linux Systems</h4>
            <CodeExample
              language="bash"
              code={`# Restrict SUID/SGID binaries
chmod u-s /usr/bin/vulnerable_binary

# Configure sudoers properly
visudo # Edit with caution

# Set up AppArmor profiles
aa-enforce /etc/apparmor.d/usr.sbin.service

# Enable auditd for logging
systemctl enable auditd
systemctl start auditd

# Configure SSH properly
# Edit /etc/ssh/sshd_config
# PermitRootLogin no
# PasswordAuthentication no
# X11Forwarding no`}
              title="Linux Hardening Best Practices"
              isVulnerable={false}
            />
          </div>
        </div>
      </div>
    </section>
  );
};

export default LinuxSection;
