
import { Challenge } from './challenge-types';

export const databaseSecurityChallenges: Challenge[] = [
  {
    id: 'db-sec-1',
    title: 'Database Authentication Security',
    description: 'Which database authentication method presents the highest security risk?',
    difficulty: 'medium',
    category: 'Database Security',
    languages: ['SQL'],
    type: 'multiple-choice',
    vulnerabilityType: 'Authentication',
    options: [
      'Using database-native role-based access control',
      'SQL authentication with credentials in plaintext configuration files',
      'Certificate-based authentication',
      'Multi-factor authentication for database access'
    ],
    answer: 1,
    explanation: "Storing SQL authentication credentials in plaintext configuration files is extremely risky. These files can be accessed by anyone with read permissions to the application server filesystem, exposing database credentials that provide direct access to data. This practice violates security principles and compliance requirements. Better approaches include using environment variables, secret management systems, key vaults, or identity-based authentication methods that don't require storing persistent credentials."
  },
  {
    id: 'db-sec-2',
    title: 'MongoDB Security Configuration',
    description: 'Which MongoDB configuration creates the most significant vulnerability?',
    difficulty: 'medium',
    category: 'Database Security',
    languages: ['MongoDB'],
    type: 'multiple-choice',
    vulnerabilityType: 'Configuration',
    options: [
      'Enabling authentication and authorization',
      'Binding MongoDB to localhost only',
      'Exposing MongoDB directly to the internet without authentication',
      'Using TLS/SSL for client connections'
    ],
    answer: 2,
    explanation: "Exposing MongoDB directly to the internet without authentication is a severe security risk that has led to thousands of data breaches and ransomware attacks. Without authentication, anyone who can reach the database port can access, modify, or delete all data. Attackers systematically scan the internet for exposed MongoDB instances. At minimum, databases should require authentication, use encryption, be bound only to necessary interfaces, and ideally be placed behind a firewall or VPN so they're not directly accessible from public networks."
  },
  {
    id: 'db-sec-3',
    title: 'SQL Injection Prevention',
    description: 'Which approach is MOST effective at preventing SQL injection attacks?',
    difficulty: 'medium',
    category: 'Database Security',
    languages: ['SQL'],
    type: 'multiple-choice',
    vulnerabilityType: 'Injection',
    options: [
      'Using prepared statements with parameterized queries',
      'Escaping user input by replacing quotes',
      'Filtering out SQL keywords from user input',
      'Encrypting the database contents'
    ],
    answer: 0,
    explanation: "Prepared statements with parameterized queries are the most effective defense against SQL injection because they enforce separation between code and data. When using prepared statements, the query structure is defined first with placeholders, then data is bound to these placeholders separately. The database treats the bound data strictly as values, not executable code, regardless of its content. Unlike input escaping or filtering which can be bypassed, prepared statements provide structural protection that prevents injection attacks at the architectural level."
  },
  {
    id: 'db-sec-4',
    title: 'Database Encryption',
    description: 'Which type of database encryption provides the LEAST protection against a compromised database administrator?',
    difficulty: 'hard',
    category: 'Database Security',
    languages: ['SQL'],
    type: 'multiple-choice',
    vulnerabilityType: 'Encryption',
    options: [
      'Client-side encryption',
      'Transparent Data Encryption (TDE)',
      'Column-level encryption with application-managed keys',
      'Always Encrypted with secure enclaves'
    ],
    answer: 1,
    explanation: "Transparent Data Encryption (TDE) provides the least protection against a compromised database administrator because it only encrypts data at rest (on disk), while the data is decrypted automatically when retrieved by the database engine. A database administrator with proper permissions can still query and view all the decrypted data. TDE primarily protects against theft of physical media or unauthorized file system access, but doesn't protect data from authorized database users. Client-side encryption or column-level encryption with application-managed keys provides better protection against insider threats."
  },
  {
    id: 'db-sec-5',
    title: 'Database Auditing Best Practices',
    description: 'Which database auditing practice is MOST important for detecting potential data breaches?',
    difficulty: 'medium',
    category: 'Database Security',
    languages: ['SQL'],
    type: 'multiple-choice',
    vulnerabilityType: 'Auditing',
    options: [
      'Logging successful authentication attempts',
      'Logging schema changes',
      'Logging all data access to sensitive tables',
      'Logging database backups'
    ],
    answer: 2,
    explanation: "Logging all data access to sensitive tables is most important for detecting potential data breaches. This practice enables security teams to identify unusual patterns of data retrieval that might indicate unauthorized access or data exfiltration. By monitoring who is accessing sensitive data, when, and how much data is being retrieved, organizations can detect anomalies that suggest compromise even when legitimate credentials are used. This is especially critical for detecting insider threats, compromised accounts, or situations where an attacker has bypassed perimeter defenses."
  }
];
