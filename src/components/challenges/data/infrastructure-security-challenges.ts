
import { Challenge } from './challenge-types';

export const infrastructureSecurityChallenges: Challenge[] = [
  {
    id: 'infra-sec-1',
    title: 'Linux Privilege Escalation',
    description: 'Which of the following Linux file permissions is MOST concerning from a security perspective?',
    difficulty: 'hard',
    category: 'Operating System Security',
    languages: ['Bash'],
    type: 'multiple-choice',
    vulnerabilityType: 'Privilege Escalation',
    options: [
      'A world-readable /etc/shadow file',
      'A setuid (SUID) bit set on a user-writable script',
      'A world-readable SSH private key',
      'A world-readable /etc/passwd file'
    ],
    answer: 1,
    explanation: "A setuid (SUID) bit on a user-writable script is extremely dangerous because it allows the script to execute with the privileges of the file owner, rather than the user who runs it. If an attacker can modify the script's contents and it runs as root, they can gain complete control of the system. This is a common privilege escalation vector. While the other options are serious security issues that expose sensitive information, they don't directly grant elevated privileges to attackers."
  },
  {
    id: 'infra-sec-2',
    title: 'Active Directory Security',
    description: 'Which Active Directory attack technique involves extracting and reusing authentication tickets?',
    difficulty: 'hard',
    category: 'Operating System Security',
    languages: ['Windows'],
    type: 'multiple-choice',
    vulnerabilityType: 'Credential Theft',
    options: [
      'NTLM Relay',
      'Pass-the-Hash',
      'Kerberoasting',
      'Pass-the-Ticket'
    ],
    answer: 3,
    explanation: "Pass-the-Ticket is an attack technique where an attacker extracts Kerberos tickets (TGT or service tickets) from memory on a compromised system and reuses them to authenticate to other systems without needing the user's password. This allows lateral movement across the network while evading detection, as it uses legitimate authentication tickets. It's particularly dangerous in Active Directory environments because it can allow persistent access even after password changes if the ticket lifetime hasn't expired."
  },
  {
    id: 'infra-sec-3',
    title: 'Network Security Architecture',
    description: 'Which network segmentation approach provides the strongest security for critical assets?',
    difficulty: 'hard',
    category: 'Operating System Security',
    languages: ['Networking'],
    type: 'multiple-choice',
    vulnerabilityType: 'Network Design',
    options: [
      'Flat network with strong perimeter firewall',
      'VLAN-based segmentation only',
      'Micro-segmentation with zero trust principles',
      'DMZ with internal firewall'
    ],
    answer: 2,
    explanation: "Micro-segmentation with zero trust principles provides the strongest security because it implements fine-grained security controls down to the individual workload level. Unlike traditional network segmentation or perimeter defenses, zero trust assumes breach and verifies each request regardless of source. This approach limits lateral movement by treating all network traffic as untrusted and requiring authentication and authorization for all connections, even those inside the perimeter, significantly reducing the attack surface for critical assets."
  },
  {
    id: 'infra-sec-4',
    title: 'Container Escape Vulnerability',
    description: 'Which of the following Docker configurations creates the highest risk of container escape?',
    difficulty: 'hard',
    category: 'Container Security',
    languages: ['Docker'],
    type: 'multiple-choice',
    vulnerabilityType: 'Container Escape',
    options: [
      'Running a container with the default seccomp profile',
      'Running a container with --network=host',
      'Running a container with --privileged flag',
      'Running a container with a read-only filesystem'
    ],
    answer: 2,
    explanation: "The --privileged flag creates the highest risk of container escape because it gives the container nearly all the same capabilities as processes running on the host. This effectively disables most of the security mechanisms that isolate containers, including namespace restrictions and capability limitations. A privileged container can access host devices, modify kernel parameters, and potentially escape containment to affect the host system or other containers, representing a serious security risk."
  },
  {
    id: 'infra-sec-5',
    title: 'Certificate Authority Compromise',
    description: 'What is the most severe consequence of a Certificate Authority (CA) being compromised?',
    difficulty: 'medium',
    category: 'Infrastructure Security',
    languages: ['Networking'],
    type: 'multiple-choice',
    vulnerabilityType: 'PKI Security',
    options: [
      'Loss of confidentiality for specific TLS sessions',
      'Ability to issue fraudulent certificates for any domain',
      'Exposure of certificate private keys',
      'Temporary website downtime'
    ],
    answer: 1,
    explanation: "When a Certificate Authority is compromised, attackers can issue fraudulent certificates for any domain that would be trusted by browsers and operating systems. This allows attackers to conduct man-in-the-middle attacks against any website, creating convincing phishing sites, or intercepting encrypted communications without detection. This systemic breach of trust affects the entire web PKI ecosystem and can impact millions of users across all websites that rely on certificates from the compromised CA, not just specific TLS sessions."
  }
];
