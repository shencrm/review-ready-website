
import { Challenge } from './challenge-types';

export const databaseSecurityChallenges: Challenge[] = [
  {
    id: 'db-sec-1',
    title: 'SQL Injection Prevention',
    description: 'Which technique is most effective for preventing SQL injection attacks?',
    difficulty: 'medium',
    category: 'Database Security',
    languages: ['SQL'],
    type: 'multiple-choice',
    vulnerabilityType: 'Injection',
    options: [
      'Input validation using regular expressions',
      'Parameterized queries (prepared statements)',
      'Escaping user input',
      'Encrypting database connections'
    ],
    answer: 1,
    explanation: "Parameterized queries (prepared statements) are the most effective defense against SQL injection because they enforce a separation between code and data. With prepared statements, the SQL command structure is defined first with placeholders, and user input is bound to these placeholders later. This ensures that user input can never change the structure of the query, even if it contains SQL syntax. Unlike input validation which might miss edge cases or escaping which can be bypassed in certain contexts, parameterized queries provide protection at the architectural level. Database connection encryption (TLS) is important for data protection in transit but doesn't prevent injection attacks."
  },
  {
    id: 'db-sec-2',
    title: 'Database Encryption Types',
    description: 'Which type of database encryption protects data from database administrators with system access?',
    difficulty: 'hard',
    category: 'Database Security',
    languages: ['SQL'],
    type: 'multiple-choice',
    vulnerabilityType: 'Data Protection',
    options: [
      'Transparent Data Encryption (TDE)',
      'Column-level encryption',
      'Client-side encryption',
      'Transport Layer Security (TLS)'
    ],
    answer: 2,
    explanation: "Client-side encryption protects data from database administrators with system access because data is encrypted before it reaches the database server. With client-side encryption, encryption/decryption happens within the application, and the keys are never available to the database system or its administrators. This ensures that even users with complete database access, including DBAs or attackers who have compromised the database server, can only see encrypted values without the means to decrypt them. In contrast, Transparent Data Encryption protects against storage media theft but data is decrypted when accessed through the database engine. Column-level encryption within the database still typically gives DBAs access to keys or encrypted data. TLS only protects data in transit between client and server."
  },
  {
    id: 'db-sec-3',
    title: 'MongoDB Security',
    description: 'Which MongoDB security measure most effectively prevents data breach from unauthorized access?',
    difficulty: 'medium',
    category: 'Database Security',
    languages: ['MongoDB'],
    type: 'multiple-choice',
    vulnerabilityType: 'Access Control',
    options: [
      'Enabling journaling',
      'Role-Based Access Control with field-level redaction',
      'Using WiredTiger storage engine',
      'Setting up replica sets'
    ],
    answer: 1,
    explanation: "Role-Based Access Control (RBAC) with field-level redaction provides the most effective protection against unauthorized access in MongoDB. RBAC allows administrators to define granular permissions for different users and roles, restricting access to specific databases, collections, or operations. When combined with field-level redaction, it can prevent unauthorized users from viewing sensitive fields within documents, even when they have access to the collection. This approach implements the principle of least privilege at both document and field levels. Journaling improves data durability but doesn't affect access control. The WiredTiger storage engine provides performance and compression benefits but minimal security advantages. Replica sets improve availability but don't directly enhance access controls."
  },
  {
    id: 'db-sec-4',
    title: 'Database Privilege Escalation',
    description: 'Which database permission most commonly leads to privilege escalation attacks?',
    difficulty: 'hard',
    category: 'Database Security',
    languages: ['SQL'],
    type: 'multiple-choice',
    vulnerabilityType: 'Privilege Escalation',
    options: [
      'SELECT permission on data tables',
      'EXECUTE permission on stored procedures',
      'CREATE/ALTER permission on database objects',
      'READ permission on log files'
    ],
    answer: 2,
    explanation: "CREATE/ALTER permissions on database objects most commonly lead to privilege escalation attacks because they allow users to create or modify database code that may execute with elevated privileges. For example, in many database systems, a user with CREATE PROCEDURE permission might be able to create a stored procedure that executes with the privileges of the procedure owner (often a more privileged account) due to ownership chaining or explicit EXECUTE AS clauses. Similarly, ALTER permissions can be used to modify existing trusted objects to perform malicious actions. This is particularly dangerous in systems using the definer's rights execution context rather than the caller's rights. The other permissions listed generally don't allow for changing the security context under which code executes."
  },
  {
    id: 'db-sec-5',
    title: 'PostgreSQL Security',
    description: 'Which PostgreSQL security feature provides the strongest isolation between database users?',
    difficulty: 'hard',
    category: 'Database Security',
    languages: ['SQL'],
    type: 'multiple-choice',
    vulnerabilityType: 'Multi-tenancy',
    options: [
      'Database roles with password authentication',
      'Row-Level Security (RLS) policies',
      'Schema separation',
      'SSL/TLS connection encryption'
    ],
    answer: 1,
    explanation: "Row-Level Security (RLS) policies provide the strongest isolation between database users in PostgreSQL. RLS allows database administrators to define security policies that restrict which rows a user can see or modify based on their identity or attributes, effectively implementing data-level segmentation within shared tables. This is particularly valuable in multi-tenant databases where different customers' data coexists in the same tables. Unlike schema separation which still allows users to potentially access other schemas if granted permissions, RLS enforces restrictions at the data level that cannot be bypassed even with elevated query privileges. RLS policies are transparent to applications and enforced consistently by the database engine itself. Password authentication establishes identity but doesn't control data access, and SSL/TLS secures connections but doesn't affect data access controls."
  },
  {
    id: 'db-sec-6',
    title: 'Oracle Database Security',
    description: 'Which Oracle security feature best addresses the risk of privileged user abuse?',
    difficulty: 'hard',
    category: 'Database Security',
    languages: ['SQL'],
    type: 'multiple-choice',
    vulnerabilityType: 'Insider Threat',
    options: [
      'Oracle Data Pump',
      'Database Vault',
      'Automatic Storage Management',
      'Flashback Query'
    ],
    answer: 1,
    explanation: "Oracle Database Vault best addresses the risk of privileged user abuse by creating security controls that restrict privileged database users (including DBAs) from accessing application data. It allows organizations to create realms around application schemas, tables, and other objects that prevent access even from accounts with powerful privileges like SYSDBA. Database Vault can also enforce separation of duties by controlling when privileged operations can be performed and by whom, preventing a single person from having unrestricted access. This protects against both malicious insiders and compromised privileged accounts. Oracle Data Pump is primarily a data movement utility, Automatic Storage Management manages storage, and Flashback Query is for data recovery—none of these directly addresses privileged user constraints."
  },
  {
    id: 'db-sec-7',
    title: 'Database Auditing',
    description: 'Which database auditing approach is most resistant to tampering by privileged users?',
    difficulty: 'hard',
    category: 'Database Security',
    languages: ['SQL'],
    type: 'multiple-choice',
    vulnerabilityType: 'Auditing',
    options: [
      'Storing audit logs in database tables',
      'Writing audit data to operating system files',
      'Sending audit events to a separate, dedicated audit server',
      'Using database triggers for custom audit logging'
    ],
    answer: 2,
    explanation: "Sending audit events to a separate, dedicated audit server provides the strongest resistance to tampering by privileged users. This approach uses database audit features to immediately stream audit data to an external system that database administrators don't have access to, creating proper separation of duties. Even users with complete control over the database server, including the ability to disable auditing or modify local audit trails, cannot alter or delete audit records that have already been transmitted to the separate system. For maximum security, this external audit system should implement write-once storage policies and strong access controls. Storing audit logs within the database or as OS files on the same server leaves them vulnerable to tampering by administrators with system access, and trigger-based auditing can be disabled by anyone with sufficient database privileges."
  },
  {
    id: 'db-sec-8',
    title: 'NoSQL Injection',
    description: 'Which statement about NoSQL injection is correct?',
    difficulty: 'medium',
    category: 'Database Security',
    languages: ['MongoDB', 'JavaScript'],
    type: 'multiple-choice',
    vulnerabilityType: 'Injection',
    options: [
      'NoSQL databases are inherently immune to injection attacks',
      'NoSQL injection typically exploits JavaScript execution contexts in document databases',
      'SQL and NoSQL injection mitigation techniques are identical',
      'NoSQL injection only affects graph databases'
    ],
    answer: 1,
    explanation: "NoSQL injection typically exploits JavaScript execution contexts in document databases, particularly in MongoDB's deprecated '$where' operator and similar constructs that allow JavaScript execution. In these contexts, attackers can inject malicious JavaScript code much like traditional SQL injection. For example, an attacker might inject code that always evaluates to true, bypassing authentication or authorization checks. While the syntax differs from SQL injection, the fundamental vulnerability remains the same: failure to properly separate code from data. NoSQL databases are not immune to injection; they simply have different injection vectors. Proper mitigation requires context-specific approaches, often including parameter binding libraries specific to the NoSQL system in use. The vulnerability affects many types of NoSQL databases, not just graph databases."
  },
  {
    id: 'db-sec-9',
    title: 'Database Backup Security',
    description: 'What is the most critical security measure for database backups containing sensitive data?',
    difficulty: 'medium',
    category: 'Database Security',
    languages: ['SQL'],
    type: 'multiple-choice',
    vulnerabilityType: 'Data Protection',
    options: [
      'Performing backups during off-peak hours',
      'Creating multiple backup copies',
      'Encrypting backup files with strong keys stored separately',
      'Using differential rather than full backups'
    ],
    answer: 2,
    explanation: "Encrypting backup files with strong keys stored separately is the most critical security measure for database backups containing sensitive data. Database backups often contain complete copies of sensitive production data but may be stored in less secure locations than the production environment, creating potential exposure points. Properly encrypted backups protect the data even if backup media or files are lost, stolen, or improperly accessed. It's essential that the encryption keys be stored separately from the backups themselves; otherwise, an attacker who gains access to the backup storage location could also obtain the means to decrypt the data. The other options primarily address availability and performance concerns rather than confidentiality of sensitive information."
  },
  {
    id: 'db-sec-10',
    title: 'Microsoft SQL Server Security',
    description: 'Which Microsoft SQL Server feature presents the highest security risk when misconfigured?',
    difficulty: 'hard',
    category: 'Database Security',
    languages: ['SQL'],
    type: 'multiple-choice',
    vulnerabilityType: 'Configuration',
    options: [
      'SQL Server Agent',
      'Extended stored procedures (xp_cmdshell)',
      'Database Mail',
      'SQL Server Reporting Services'
    ],
    answer: 1,
    explanation: "Extended stored procedures, particularly xp_cmdshell, present the highest security risk when misconfigured in Microsoft SQL Server. The xp_cmdshell procedure allows SQL Server to execute operating system commands with the privileges of the SQL Server service account, which is often a highly privileged account. If improperly secured, attackers who gain the ability to execute SQL commands (through SQL injection or compromised credentials) can leverage xp_cmdshell to run arbitrary commands on the operating system, potentially leading to complete server compromise. For this reason, xp_cmdshell is disabled by default in modern SQL Server installations. While the other options can pose security risks if misconfigured, none provide such direct and powerful access to the underlying operating system with minimal additional exploitation required."
  }
];

