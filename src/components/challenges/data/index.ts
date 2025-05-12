
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
  ...apiSecurityChallenges
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
  'API Security'
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
  'React Native'
];

export const difficultyLevels = [
  'All', 
  'Easy', 
  'Medium', 
  'Hard'
];
