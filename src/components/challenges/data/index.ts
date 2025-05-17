
import { sqlInjectionChallenges } from './sql-injection';
import { xssChallenges } from './xss';
import { csrfChallenges } from './csrf';
import { pathTraversalChallenges } from './path-traversal';
import { ssrfChallenges } from './ssrf';
import { commandInjectionChallenges } from './command-injection';
import { insecureDeserializationChallenges } from './insecure-deserialization';
import { brokenAuthChallenges } from './broken-auth';
import { dataExposureChallenges } from './data-exposure';
import { cryptoFailuresChallenges } from './crypto-failures';
import { accessControlChallenges } from './access-control';
import { xxeChallenges } from './xxe';
import { raceConditionChallenges } from './race-conditions';
import { apiSecurityChallenges } from './api-security';
import { webSecurityChallenges } from './web-security';
import { clientSideSecurityChallenges } from './client-side-security';
import { mobileSecurityChallenges } from './mobile-security';
import { containerSecurityChallenges } from './container-security';
import { cloudSecurityChallenges } from './cloud-security';
import { iotSecurityChallenges } from './iot-security';
import { securecodingChallenges } from './secure-coding';
import { binarySecurityChallenges } from './binary-security';
import { microserviceSecurityChallenges } from './microservice-security';

// Import previously added challenge categories
import { idorChallenges } from './idor';
import { jwtSecurityChallenges } from './jwt-security';
import { deserializationAttacksChallenges } from './deserialization-attacks';
import { serverSideTemplateInjectionChallenges } from './server-side-template-injection';
import { authorizationIssuesChallenges } from './authorization-issues';
import { cryptographyFailuresChallenges } from './cryptography-failures';
import { frontEndVulnerabilitiesChallenges } from './front-end-vulnerabilities';
import { securityHeadersChallenges } from './security-headers';
import { fileUploadVulnerabilitiesChallenges } from './file-upload-vulnerabilities';
import { graphqlSecurityChallenges } from './graphql-security';
import { devSecOpsChallenges } from './devsecops-challenges';
import { hostSecurityChallenges } from './host-security';
import { businessLogicFlawsChallenges } from './business-logic-flaws';

// Import the secure coding best practices challenges
import { securecodingBestPracticesChallenges } from './secure-coding-best-practices';
import { sessionManagementChallenges } from './session-management';
import { webSecurityMisconfigurationsChallenges } from './web-security-misconfigurations';
import { mobileSecurityIssuesChallenges } from './mobile-security-issues';
import { advancedWebAttacksChallenges } from './advanced-web-attacks';
import { secureArchitectureChallenges } from './secure-architecture';
import { defensiveCodingChallenges } from './defensive-coding';
import { browserSecurityChallenges } from './browser-security';
import { apiSecurityBestPracticesChallenges } from './api-security-best-practices';

// Import new security challenges categories
import { mobileSecurityChallenges as newMobileSecurityChallenges } from './mobile-security-challenges';
import { webSecurityChallenges as newWebSecurityChallenges } from './web-security-challenges';
import { infrastructureSecurityChallenges } from './infrastructure-security-challenges';
import { cloudSecurityChallenges as newCloudSecurityChallenges } from './cloud-security-challenges';
import { databaseSecurityChallenges } from './database-security-challenges';

// Combine all challenges into a single array
export const challenges = [
  ...sqlInjectionChallenges,
  ...xssChallenges,
  ...csrfChallenges,
  ...pathTraversalChallenges,
  ...ssrfChallenges,
  ...commandInjectionChallenges,
  ...insecureDeserializationChallenges,
  ...brokenAuthChallenges,
  ...dataExposureChallenges,
  ...cryptoFailuresChallenges,
  ...accessControlChallenges,
  ...xxeChallenges,
  ...raceConditionChallenges,
  ...apiSecurityChallenges,
  ...webSecurityChallenges,
  ...clientSideSecurityChallenges,
  ...mobileSecurityChallenges,
  ...containerSecurityChallenges,
  ...cloudSecurityChallenges,
  ...iotSecurityChallenges,
  ...securecodingChallenges,
  ...binarySecurityChallenges,
  ...microserviceSecurityChallenges,
  // Previously added challenge categories
  ...idorChallenges,
  ...jwtSecurityChallenges,
  ...deserializationAttacksChallenges,
  ...serverSideTemplateInjectionChallenges,
  ...authorizationIssuesChallenges,
  ...cryptographyFailuresChallenges,
  ...frontEndVulnerabilitiesChallenges,
  ...securityHeadersChallenges,
  ...fileUploadVulnerabilitiesChallenges,
  ...graphqlSecurityChallenges,
  ...devSecOpsChallenges,
  ...hostSecurityChallenges,
  ...businessLogicFlawsChallenges,
  // Secure coding best practices challenges
  ...securecodingBestPracticesChallenges,
  ...sessionManagementChallenges,
  ...webSecurityMisconfigurationsChallenges,
  ...mobileSecurityIssuesChallenges,
  ...advancedWebAttacksChallenges,
  ...secureArchitectureChallenges,
  ...defensiveCodingChallenges,
  ...browserSecurityChallenges,
  ...apiSecurityBestPracticesChallenges,
  // New security challenges
  ...newMobileSecurityChallenges,
  ...newWebSecurityChallenges,
  ...infrastructureSecurityChallenges,
  ...newCloudSecurityChallenges,
  ...databaseSecurityChallenges
];

// Export constants used in filters
export const categories = [
  'All', 
  'Injection Flaws', 
  'Cross-Site Scripting', 
  'CSRF', 
  'Path Traversal', 
  'SSRF', 
  'Insecure Deserialization', 
  'Broken Authentication', 
  'Sensitive Data Exposure', 
  'Cryptographic Failures', 
  'Broken Access Control', 
  'XXE', 
  'Race Conditions', 
  'API Security',
  'Web Security',
  'Client-Side Security',
  'Mobile Security',
  'Container Security',
  'Cloud Security',
  'IoT Security',
  'Secure Coding',
  'Binary Security',
  'Microservice Security',
  'DevSecOps',
  'Operating System Security',
  'Business Logic Flaws',
  'Security Misconfigurations',
  'Database Security',
  'Infrastructure Security'
];

export const languages = [
  'All', 
  'PHP', 
  'Java', 
  'JavaScript', 
  'Python', 
  'C#', 
  'React', 
  'Node.js', 
  'React Native',
  'C',
  'Docker',
  'Kubernetes',
  'YAML',
  'AWS',
  'Azure',
  'GCP',
  'JSON',
  'Android',
  'iOS',
  'HTML',
  'Bash',
  'GraphQL',
  'XML',
  'SQL',
  'MongoDB',
  'HTTP',
  'Networking',
  'Windows'
];

export const difficultyLevels = [
  'All', 
  'Easy', 
  'Medium', 
  'Hard'
];
