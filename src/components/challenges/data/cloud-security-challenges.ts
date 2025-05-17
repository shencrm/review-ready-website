
import { Challenge } from './challenge-types';

export const cloudSecurityChallenges: Challenge[] = [
  {
    id: 'cloud-sec-1',
    title: 'AWS S3 Security',
    description: 'Which AWS S3 bucket policy presents the highest security risk?',
    difficulty: 'medium',
    category: 'Cloud Security',
    languages: ['AWS'],
    type: 'multiple-choice',
    vulnerabilityType: 'Misconfigurations',
    options: [
      'A policy that denies all actions to the anonymous user',
      'A policy that allows specific actions to a specific IAM role',
      'A policy with Principal set to "*" and Effect set to "Allow"',
      'A policy that requires MFA for delete operations'
    ],
    answer: 2,
    explanation: "A policy with Principal set to '*' and Effect set to 'Allow' is extremely dangerous as it grants access to anyone on the internet. This overly permissive configuration is a common cause of data breaches involving S3 buckets. It essentially makes the bucket and its contents public, allowing anyone to perform the specified actions without authentication. Always follow the principle of least privilege by granting specific permissions only to authenticated and authorized principals who need them."
  },
  {
    id: 'cloud-sec-2',
    title: 'Azure RBAC Security',
    description: 'Which Azure role assignment practice represents the highest security risk?',
    difficulty: 'medium',
    category: 'Cloud Security',
    languages: ['Azure'],
    type: 'multiple-choice',
    vulnerabilityType: 'Access Control',
    options: [
      'Assigning a custom role with specific permissions needed for a task',
      'Assigning the Contributor role at the resource group level',
      'Assigning the Owner role at the subscription level to all DevOps team members',
      'Using managed identities for Azure resources'
    ],
    answer: 2,
    explanation: "Assigning the Owner role at the subscription level to all DevOps team members violates the principle of least privilege and creates a significant security risk. The Owner role grants full access to manage all resources and assign roles to others, essentially giving administrative control over the entire subscription. This increases the attack surface dramatically - if any DevOps team member's account is compromised, an attacker gains full control over all resources in the subscription. Instead, assign more limited roles at more specific resource scopes based on actual job requirements."
  },
  {
    id: 'cloud-sec-3',
    title: 'Kubernetes Security',
    description: 'Which of these Kubernetes configurations creates the most significant security vulnerability?',
    difficulty: 'hard',
    category: 'Cloud Security',
    languages: ['Kubernetes'],
    type: 'multiple-choice',
    vulnerabilityType: 'Container Orchestration',
    options: [
      'Using network policies to restrict pod communications',
      'Setting pod security contexts with non-root users',
      'Using cluster-admin ClusterRoleBindings for service accounts',
      'Implementing pod resource limits'
    ],
    answer: 2,
    explanation: "Using cluster-admin ClusterRoleBindings for service accounts is extremely dangerous as it grants full administrative access to the entire Kubernetes cluster. This configuration violates the principle of least privilege and could allow a compromised pod to manage any resource in the cluster, including creating privileged pods, accessing secrets, and modifying network policies. Even a minor vulnerability in a single application could lead to a total cluster compromise. Service accounts should always be assigned the minimum permissions required for their specific functions."
  },
  {
    id: 'cloud-sec-4',
    title: 'GCP Identity and Access Management',
    description: 'Which GCP IAM practice represents the poorest security posture?',
    difficulty: 'medium',
    category: 'Cloud Security',
    languages: ['GCP'],
    type: 'multiple-choice',
    vulnerabilityType: 'Access Management',
    options: [
      'Using service account keys stored in Secret Manager',
      'Granting the Basic Editor role to the allAuthenticatedUsers principal',
      'Implementing custom IAM roles with specific permissions',
      'Using short-lived OAuth access tokens'
    ],
    answer: 1,
    explanation: "Granting the Basic Editor role to 'allAuthenticatedUsers' is extremely risky because it gives edit permissions to anyone with a valid Google account - not just users in your organization. This dramatically increases the risk of unauthorized access, as billions of Google account holders would have editor privileges to your GCP resources. This misconfiguration could lead to data breaches, resource abuse, and potential financial impact from unauthorized resource usage. Instead, explicitly grant permissions only to specific user accounts or groups within your organization."
  },
  {
    id: 'cloud-sec-5',
    title: 'Cloud Network Security',
    description: 'Which cloud network security control is LEAST effective at preventing lateral movement attacks?',
    difficulty: 'hard',
    category: 'Cloud Security',
    languages: ['Networking'],
    type: 'multiple-choice',
    vulnerabilityType: 'Network Security',
    options: [
      'Microsegmentation with zero-trust network access',
      'Traditional security groups with default allow rules',
      'Cloud-native firewalls with IDS/IPS capabilities',
      'Private VPC endpoints for cloud services'
    ],
    answer: 1,
    explanation: "Traditional security groups with default allow rules are the least effective at preventing lateral movement because they typically operate on an allow-by-default model within a network segment. This approach permits free communication between resources in the same group, enabling attackers to move laterally once they've compromised a single resource. Modern approaches like microsegmentation implement zero-trust principles where all communications are denied by default and require explicit authorization, significantly limiting lateral movement even when a system is compromised."
  }
];
