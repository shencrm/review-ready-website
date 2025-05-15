
// This file exports all challenge data and categorizations
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
  ...microserviceSecurityChallenges
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
  'Microservice Security'
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
  'JSON',
  'Android',
  'HTML'
];

export const difficultyLevels = [
  'All', 
  'Easy', 
  'Medium', 
  'Hard'
];
