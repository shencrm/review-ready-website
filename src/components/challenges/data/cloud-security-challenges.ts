
import { Challenge } from './challenge-types';

export const cloudSecurityChallenges: Challenge[] = [
  {
    id: 'cloud-sec-1',
    title: 'AWS S3 Security',
    description: 'Which S3 bucket policy presents the highest security risk?',
    difficulty: 'medium',
    category: 'Cloud Security',
    languages: ['AWS'],
    type: 'multiple-choice',
    vulnerabilityType: 'Misconfiguration',
    options: [
      'A policy that allows read access only to a specific IAM role',
      'A policy with "Principal": "*" and "Effect": "Allow"',
      'A policy that denies access to anonymous users',
      'A policy that requires MFA for delete operations'
    ],
    answer: 1,
    explanation: "A policy with 'Principal': '*' and 'Effect': 'Allow' presents the highest security risk because it grants access to anyone on the internet. This wildcard principal indicates that the permission applies to all AWS users, which effectively makes the S3 bucket publicly accessible. This configuration has been responsible for countless data breaches where sensitive information was exposed. Organizations should carefully restrict access by specifying exact principals (IAM users, roles, or services) that need access and follow the principle of least privilege. AWS also provides tools like S3 Block Public Access and IAM Access Analyzer to help identify and prevent such risky configurations."
  },
  {
    id: 'cloud-sec-2',
    title: 'Azure Key Vault Security',
    description: 'What is the most secure method for an Azure VM to access secrets in Azure Key Vault?',
    difficulty: 'hard',
    category: 'Cloud Security',
    languages: ['Azure'],
    type: 'multiple-choice',
    vulnerabilityType: 'Secret Management',
    options: [
      'Storing access keys in environment variables',
      'Using a service principal with a client secret',
      'Using Managed Identity with RBAC',
      'Embedding connection strings in application code'
    ],
    answer: 2,
    explanation: "Using Managed Identity with RBAC (Role-Based Access Control) is the most secure method for an Azure VM to access secrets in Azure Key Vault. Managed Identities eliminate the need to store credentials in code or configuration by providing an automatically managed identity in Azure AD for Azure resources. The VM can use this identity to request access tokens for services that support Azure AD authentication, like Key Vault. Combined with granular RBAC permissions, this approach follows the principle of least privilege and removes the risks associated with managing credentials manually. The other options all involve storing secrets somewhere (in environment variables, as a client secret, or in code), which creates potential exposure points and requires additional security measures for rotation and protection."
  },
  {
    id: 'cloud-sec-3',
    title: 'Serverless Security',
    description: 'Which security concern is unique to serverless architectures?',
    difficulty: 'medium',
    category: 'Cloud Security',
    languages: ['AWS', 'Azure', 'GCP'],
    type: 'multiple-choice',
    vulnerabilityType: 'Serverless',
    options: [
      'Patching operating systems',
      'Event-data injection',
      'Network firewall configuration',
      'Physical server access'
    ],
    answer: 1,
    explanation: "Event-data injection is a security concern unique to serverless architectures. In serverless environments, functions are triggered by various events (HTTP requests, queue messages, database changes, etc.), and attackers can manipulate these event data sources to inject malicious payloads. Unlike traditional applications where input validation might focus primarily on user interfaces and API endpoints, serverless functions must validate inputs from many different event sources, each with its own data format and security considerations. The other options are generally not concerns in serverless environments: cloud providers handle OS patching, traditional network firewall concepts are less relevant in the serverless model, and physical server access is entirely abstracted away by the cloud provider."
  },
  {
    id: 'cloud-sec-4',
    title: 'Kubernetes Security',
    description: 'Which Kubernetes security measure most effectively prevents container escape vulnerabilities?',
    difficulty: 'hard',
    category: 'Cloud Security',
    languages: ['Kubernetes'],
    type: 'multiple-choice',
    vulnerabilityType: 'Container Security',
    options: [
      'Using resource quotas',
      'Implementing network policies',
      'Enabling RBAC for API access',
      'Applying security contexts with strict Pod Security Standards'
    ],
    answer: 3,
    explanation: "Applying security contexts with strict Pod Security Standards most effectively prevents container escape vulnerabilities in Kubernetes. Security contexts define privilege and access control settings for Pods and containers, allowing you to restrict capabilities like preventing privilege escalation, using host namespaces, or mounting sensitive host paths. Pod Security Standards (PSS) provide predefined levels of security context restrictions, with the 'restricted' profile offering the strongest isolation by running containers as non-root users, preventing privilege escalation, and limiting capabilities. While resource quotas prevent resource exhaustion, network policies restrict pod-to-pod communication, and RBAC controls API access, these measures don't directly address the container boundary security that prevents a compromised container from escaping to the host system."
  },
  {
    id: 'cloud-sec-5',
    title: 'Cloud Identity Security',
    description: 'What is the most common attack vector for compromising cloud environments?',
    difficulty: 'medium',
    category: 'Cloud Security',
    languages: ['AWS', 'Azure', 'GCP'],
    type: 'multiple-choice',
    vulnerabilityType: 'Identity Security',
    options: [
      'Hypervisor vulnerabilities',
      'Cross-tenant data exposure',
      'Compromised access credentials',
      'Unpatched cloud provider infrastructure'
    ],
    answer: 2,
    explanation: "Compromised access credentials represent the most common attack vector for cloud environments. This includes stolen API keys, account passwords, session tokens, and OAuth tokens. According to multiple industry reports and breach analyses, identity-based attacks substantially outnumber all other cloud attack methods. Cloud environments rely heavily on identity and access management, and once an attacker obtains valid credentials, they can often access cloud resources without triggering security alerts since they're using legitimate authentication methods. These credentials can be compromised through phishing, password spraying, breach database reuse, client-side malware, or exposed secrets in code repositories. While the other options are potential concerns, cloud providers generally secure their infrastructure well, making credential theft the path of least resistance for attackers."
  },
  {
    id: 'cloud-sec-6',
    title: 'Container Registry Security',
    description: 'Which practice provides the strongest security for container images in a registry?',
    difficulty: 'medium',
    category: 'Cloud Security',
    languages: ['Docker', 'Kubernetes'],
    type: 'multiple-choice',
    vulnerabilityType: 'Supply Chain Security',
    options: [
      'Using official base images only',
      'Implementing automated vulnerability scanning with deployment blocking',
      'Limiting registry access to specific users',
      'Regularly updating container images'
    ],
    answer: 1,
    explanation: "Implementing automated vulnerability scanning with deployment blocking provides the strongest security for container images in a registry. This practice ensures that every image is automatically scanned for known vulnerabilities before deployment, and images that contain critical vulnerabilities are prevented from being deployed to production environments. By integrating this into the CI/CD pipeline, organizations create a security gate that catches vulnerable components early in the development lifecycle. While using official base images reduces the risk of malicious code, it doesn't address vulnerabilities in those images. Access controls are important but don't address the content security of the images themselves. Regular updates help but are ineffective without vulnerability detection mechanisms to identify which images need updating and verification that updates actually resolve security issues."
  },
  {
    id: 'cloud-sec-7',
    title: 'GCP IAM Best Practice',
    description: 'Which GCP IAM practice best implements the principle of least privilege?',
    difficulty: 'hard',
    category: 'Cloud Security',
    languages: ['GCP'],
    type: 'multiple-choice',
    vulnerabilityType: 'Access Control',
    options: [
      'Assigning the Owner role to all developers',
      'Using predefined roles exclusively',
      'Creating custom roles with only required permissions',
      'Implementing project-level permissions for all resources'
    ],
    answer: 2,
    explanation: "Creating custom roles with only required permissions best implements the principle of least privilege in Google Cloud Platform. Custom roles allow organizations to grant precisely the permissions needed for a specific job function and nothing more. While predefined roles offer convenience, they often include more permissions than necessary for a given task. For example, the predefined 'Editor' role grants broad modification permissions across many services. By creating custom roles that include only the exact permissions required, organizations reduce their attack surface and limit the potential impact of compromised credentials. This approach requires more initial configuration but provides stronger security boundaries and reduces the risk of privilege escalation."
  },
  {
    id: 'cloud-sec-8',
    title: 'Cloud Network Security',
    description: 'Which cloud network security control most effectively prevents data exfiltration?',
    difficulty: 'hard',
    category: 'Cloud Security',
    languages: ['Networking', 'AWS', 'Azure', 'GCP'],
    type: 'multiple-choice',
    vulnerabilityType: 'Data Exfiltration',
    options: [
      'VPC flow logs',
      'Inbound security groups',
      'DNS filtering',
      'Egress filtering with deep packet inspection'
    ],
    answer: 3,
    explanation: "Egress filtering with deep packet inspection (DPI) most effectively prevents data exfiltration from cloud environments. This combination allows organizations to not only restrict outbound connections based on destination and port (basic egress filtering) but also inspect the content of outbound traffic to identify and block sensitive data patterns, even when attackers attempt to hide them using permitted protocols or destinations. DPI can detect attempts to exfiltrate data through encrypted channels by analyzing traffic patterns or by performing TLS inspection when applicable. VPC flow logs provide visibility for detection but don't actively prevent exfiltration. Inbound security groups only restrict incoming traffic, not outgoing data. DNS filtering helps block connections to malicious domains but can't detect or prevent data being sent to legitimate but unauthorized destinations."
  },
  {
    id: 'cloud-sec-9',
    title: 'Terraform Security',
    description: 'Which practice most improves the security of Infrastructure as Code deployments?',
    difficulty: 'medium',
    category: 'Cloud Security',
    languages: ['Terraform'],
    type: 'multiple-choice',
    vulnerabilityType: 'IaC Security',
    options: [
      'Storing state files in version control',
      'Using variables for all resource names',
      'Automated security scanning of IaC templates',
      'Commenting all resource blocks'
    ],
    answer: 2,
    explanation: "Automated security scanning of Infrastructure as Code (IaC) templates most improves security by detecting misconfigurations, compliance violations, and security risks before infrastructure is deployed. Tools like Checkov, tfsec, and Terrascan can identify issues such as unencrypted storage, overly permissive network access, and IAM misconfigurations during the development process. This 'shift-left' approach catches security problems early when they're less expensive and risky to fix. In contrast, storing state files in version control is actually a security risk because they often contain sensitive information like credentials. Using variables for resource names is a good practice for maintainability but offers limited security benefits. Comments improve documentation but don't directly enhance security posture."
  },
  {
    id: 'cloud-sec-10',
    title: 'API Gateway Security',
    description: 'Which API Gateway security feature is most effective against API abuse?',
    difficulty: 'medium',
    category: 'Cloud Security',
    languages: ['AWS', 'Azure', 'GCP'],
    type: 'multiple-choice',
    vulnerabilityType: 'API Security',
    options: [
      'Basic authentication',
      'TLS encryption',
      'Rate limiting and throttling',
      'CORS configuration'
    ],
    answer: 2,
    explanation: "Rate limiting and throttling are the most effective API Gateway security features against API abuse. These mechanisms control the number of requests that can be made within a specified time period, protecting backend services from being overwhelmed by excessive traffic, whether malicious (DoS attacks) or unintentional (buggy clients). Rate limiting also helps prevent brute force attacks against authentication endpoints and can mitigate the impact of credential stuffing attacks. While basic authentication provides identity verification, TLS ensures data privacy during transit, and CORS prevents unauthorized cross-origin requests, none of these directly addresses the volume-based attacks and resource exhaustion that constitute API abuse. Properly implemented rate limiting should include different thresholds for different endpoints based on their sensitivity and resource requirements."
  }
];

