
import { Challenge } from './challenge-types';

export const infrastructureSecurityChallenges: Challenge[] = [
  {
    id: 'infra-sec-1',
    title: 'Secure Network Architecture',
    description: 'Which network segmentation approach provides the strongest security for critical infrastructure?',
    difficulty: 'hard',
    category: 'Infrastructure Security',
    languages: ['Networking'],
    type: 'multiple-choice',
    vulnerabilityType: 'Network Segmentation',
    options: [
      'Using VLANs for logical separation only',
      'Implementing defense in depth with multiple DMZs and zero trust principles',
      'Applying network access controls at the edge only',
      'Using a flat network with strong perimeter security'
    ],
    answer: 1,
    explanation: "Defense in depth with multiple DMZs and zero trust principles provides the strongest security approach for critical infrastructure. This architecture implements multiple layers of security controls, with progressively stricter controls for more sensitive systems. Zero trust principles ensure that nothing is trusted by default, and every access requires verification regardless of source location. In contrast, VLANs alone provide only logical separation but don't prevent lateral movement if one segment is compromised. Edge-only access controls create a hard shell but soft interior, and flat networks with perimeter security offer minimal protection against lateral movement once the perimeter is breached."
  },
  {
    id: 'infra-sec-2',
    title: 'Hypervisor Security',
    description: 'Which hypervisor vulnerability presents the highest risk to cloud infrastructure?',
    difficulty: 'hard',
    category: 'Infrastructure Security',
    languages: ['Virtualization'],
    type: 'multiple-choice',
    vulnerabilityType: 'VM Escape',
    options: [
      'Resource exhaustion by a guest VM',
      'Guest-to-host VM escape vulnerability',
      'Unpatched guest operating systems',
      'Snapshot data exposure'
    ],
    answer: 1,
    explanation: "A guest-to-host VM escape vulnerability represents the most severe hypervisor security risk as it allows an attacker to break out of the virtual machine isolation and access the underlying host system. This effectively bypasses all security boundaries that virtualization is designed to enforce. Once attackers gain access to the hypervisor, they can potentially access all other VMs running on the same host, compromising the entire infrastructure. VM escapes are particularly dangerous in multi-tenant environments like public clouds, where they could allow one customer to access another customer's data and resources."
  },
  {
    id: 'infra-sec-3',
    title: 'Active Directory Security',
    description: 'Which Active Directory attack technique allows an attacker to forge authentication credentials for any user?',
    difficulty: 'hard',
    category: 'Infrastructure Security',
    languages: ['Windows'],
    type: 'multiple-choice',
    vulnerabilityType: 'Privilege Escalation',
    options: [
      'Pass-the-Hash',
      'Kerberoasting',
      'Golden Ticket',
      'DCShadow'
    ],
    answer: 2,
    explanation: "A Golden Ticket attack is one of the most severe Active Directory attacks because it allows an attacker to forge authentication credentials for any user in the domain. This attack works by compromising the krbtgt account's NTLM hash, which is used to encrypt and sign all Kerberos tickets in the domain. With this hash, attackers can create valid Kerberos TGTs (Ticket Granting Tickets) for any account, including administrators and those that don't exist, with any privileges and group memberships. These tickets typically have long validity periods (up to 10 years) and are extremely difficult to detect without specialized monitoring. The attack essentially gives attackers persistent and virtually unlimited access to the entire domain."
  },
  {
    id: 'infra-sec-4',
    title: 'Linux Privilege Escalation',
    description: 'Which Linux misconfiguration most directly enables local privilege escalation?',
    difficulty: 'medium',
    category: 'Infrastructure Security',
    languages: ['Linux'],
    type: 'multiple-choice',
    vulnerabilityType: 'Privilege Escalation',
    options: [
      'Weak firewall rules',
      'SUID binaries owned by root',
      'Unencrypted network traffic',
      'Default SSH server configuration'
    ],
    answer: 1,
    explanation: "SUID (Set User ID) binaries owned by root represent one of the most direct paths to privilege escalation on Linux systems. When the SUID bit is set on an executable file, it runs with the permissions of the file owner rather than the user executing it. If the binary is owned by root and contains vulnerabilities or allows command execution, a regular user can exploit this to run commands as root. Common examples include misconfigured binaries like nano, vim, or custom applications with the SUID bit unnecessarily set. Attackers often look for these misconfigured binaries using commands like 'find / -perm -4000' as one of their first steps after gaining initial access to a system."
  },
  {
    id: 'infra-sec-5',
    title: 'Windows Service Security',
    description: 'Which Windows service configuration issue commonly leads to privilege escalation?',
    difficulty: 'medium',
    category: 'Infrastructure Security',
    languages: ['Windows'],
    type: 'multiple-choice',
    vulnerabilityType: 'Privilege Escalation',
    options: [
      'Services running as Local Service account',
      'Services with improper path permissions allowing executable replacement',
      'Services configured to start manually',
      'Services using named pipes for communication'
    ],
    answer: 1,
    explanation: "Services with improper path permissions commonly lead to privilege escalation in Windows environments. If a service executes a binary from a location that a regular user can modify, the user can replace the legitimate binary with a malicious one. When the service starts (or restarts), it will execute the malicious code with the service account's privileges—often SYSTEM. This is known as a 'DLL hijacking' or 'binary planting' attack when it involves DLLs, or more generally as an 'Unquoted Service Path' vulnerability when Windows resolves ambiguous paths. To prevent this, service executable paths should be properly quoted if they contain spaces, and both the service executable and its directory should have proper access controls that prevent modification by non-administrative users."
  },
  {
    id: 'infra-sec-6',
    title: 'Network Protocol Security',
    description: 'Which network protocol is most vulnerable to MITM attacks when used without additional security measures?',
    difficulty: 'medium',
    category: 'Infrastructure Security',
    languages: ['Networking'],
    type: 'multiple-choice',
    vulnerabilityType: 'Man-in-the-Middle',
    options: [
      'SSH',
      'ARP',
      'DNS over HTTPS',
      'HTTPS with certificate pinning'
    ],
    answer: 1,
    explanation: "ARP (Address Resolution Protocol) is highly vulnerable to Man-in-the-Middle attacks because it lacks any authentication mechanism. In an ARP spoofing attack, a malicious actor can send fake ARP messages to associate their MAC address with the IP address of a legitimate server or gateway. This causes other devices on the network to send traffic intended for the legitimate device to the attacker instead. Unlike SSH, DNS over HTTPS, or HTTPS with certificate pinning, which all incorporate encryption and various forms of authentication, ARP operates at Layer 2 of the OSI model and was designed for functionality rather than security. Mitigations include using static ARP entries for critical systems, implementing ARP spoofing detection tools, or using more secure alternatives like Dynamic ARP Inspection (DAI) on managed switches."
  },
  {
    id: 'infra-sec-7',
    title: 'SSH Security Best Practice',
    description: 'Which SSH configuration setting provides the strongest security improvement?',
    difficulty: 'medium',
    category: 'Infrastructure Security',
    languages: ['Linux'],
    type: 'multiple-choice',
    vulnerabilityType: 'Authentication',
    options: [
      'Allowing root login with password',
      'Using default port 22',
      'Implementing key-based authentication only',
      'Setting an unlimited login grace time'
    ],
    answer: 2,
    explanation: "Implementing key-based authentication only (by disabling password authentication) significantly improves SSH security. Public key authentication is more resistant to brute force attacks than password authentication because private keys typically have much higher entropy than human-created passwords and are not transmitted across the network. By setting 'PasswordAuthentication no' in the SSH server configuration, you force all users to authenticate using SSH keys, which can also be protected with passphrases for additional security. This measure, combined with other hardening practices like disabling root login and restricting user access, establishes a much stronger security posture for SSH services than relying on password authentication."
  },
  {
    id: 'infra-sec-8',
    title: 'SIEM Log Security',
    description: 'What is the most significant security concern when implementing centralized logging with a SIEM?',
    difficulty: 'hard',
    category: 'Infrastructure Security',
    languages: ['Networking'],
    type: 'multiple-choice',
    vulnerabilityType: 'Log Management',
    options: [
      'Log retention policies',
      'Log transmission security',
      'Log file size limitations',
      'Log filtering rules'
    ],
    answer: 1,
    explanation: "Log transmission security is the most significant concern when implementing centralized logging with a SIEM (Security Information and Event Management) system. If logs are transmitted over the network unencrypted, they could be intercepted, exposing sensitive information or allowing attackers to modify logs to hide their activities. Additionally, unsecured log transport could allow attackers to disrupt the logging process entirely through denial-of-service attacks. While log retention policies, file size limitations, and filtering rules are important operational considerations, they don't present the same immediate security risk as insecure transmission. Best practices include using encrypted protocols like TLS or establishing secure VPN tunnels for log transmission, implementing mutual authentication between log sources and the SIEM, and ensuring integrity of logs through cryptographic methods."
  },
  {
    id: 'infra-sec-9',
    title: 'Server Hardening Technique',
    description: 'Which server hardening technique provides the most effective protection against zero-day vulnerabilities?',
    difficulty: 'hard',
    category: 'Infrastructure Security',
    languages: ['Linux'],
    type: 'multiple-choice',
    vulnerabilityType: 'System Hardening',
    options: [
      'Regular patching schedules',
      'Strong password policies',
      'Application whitelisting',
      'Antivirus software'
    ],
    answer: 2,
    explanation: "Application whitelisting provides the most effective protection against zero-day vulnerabilities because it enforces a 'deny by default' approach, allowing only specifically approved applications to run. Unlike regular patching, which can only address known vulnerabilities, application whitelisting can prevent the execution of malicious code even if it exploits previously unknown (zero-day) vulnerabilities. By preventing unauthorized applications and scripts from executing, it creates a proactive security barrier that doesn't rely on prior knowledge of specific threats. Strong password policies primarily protect against unauthorized access rather than exploitation of system vulnerabilities, and traditional antivirus software often fails to detect zero-day threats since it typically relies on signature-based detection of known malware."
  },
  {
    id: 'infra-sec-10',
    title: 'DNS Security Extensions',
    description: 'What is the primary security benefit of implementing DNSSEC?',
    difficulty: 'medium',
    category: 'Infrastructure Security',
    languages: ['Networking'],
    type: 'multiple-choice',
    vulnerabilityType: 'DNS Security',
    options: [
      'It encrypts DNS queries and responses',
      'It authenticates DNS responses through digital signatures',
      'It hides the source of DNS queries from ISPs',
      'It filters malicious domain requests'
    ],
    answer: 1,
    explanation: "DNSSEC (Domain Name System Security Extensions) primarily provides authentication of DNS responses through digital signatures, ensuring that DNS data hasn't been modified during transit. It creates a chain of trust from the root DNS servers down to the authoritative name servers for domains by using public-key cryptography to sign DNS records. This helps prevent DNS spoofing and cache poisoning attacks where an attacker might attempt to redirect users to malicious websites by providing fake DNS responses. Importantly, DNSSEC doesn't encrypt DNS traffic (that's what DNS over HTTPS or DNS over TLS provide), nor does it hide queries from ISPs or filter malicious domains. Its core purpose is to verify that DNS responses come from the legitimate authoritative source and haven't been tampered with."
  }
];

