
import { Challenge } from './challenge-types';

export const mobileSecurityChallenges: Challenge[] = [
  {
    id: 'mobile-sec-1',
    title: 'Android Deeplink Vulnerability',
    description: 'Which of the following describes a security risk with Android deeplinks?',
    difficulty: 'hard',
    category: 'Mobile Security',
    languages: ['Android'],
    type: 'multiple-choice',
    vulnerabilityType: 'Intent Redirection',
    options: [
      'Deeplinks always require user permission before launching',
      'Malicious apps can register for the same URI scheme and intercept sensitive data',
      'Deeplinks can only be used within the same application',
      'Android automatically encrypts all deeplink data'
    ],
    answer: 1,
    explanation: "Android's intent system allows multiple apps to register for the same URI scheme. If a malicious app registers for the same deeplink URI scheme as a legitimate app, it could intercept sensitive data when users click links meant for the legitimate application. This is known as a deeplink hijacking vulnerability. Always validate the source of deeplinks and avoid passing sensitive data through them."
  },
  {
    id: 'mobile-sec-2',
    title: 'iOS Data Protection',
    description: 'Which iOS data protection class provides the highest level of security for sensitive data?',
    difficulty: 'medium',
    category: 'Mobile Security',
    languages: ['iOS'],
    type: 'multiple-choice',
    vulnerabilityType: 'Data Storage',
    options: [
      'NSFileProtectionComplete',
      'NSFileProtectionCompleteUntilFirstUserAuthentication',
      'NSFileProtectionCompleteUnlessOpen',
      'NSFileProtectionNone'
    ],
    answer: 0,
    explanation: "NSFileProtectionComplete provides the highest level of security as it ensures data is only accessible when the device is unlocked. Files with this protection class are encrypted with a key derived from the user's passcode and the device's hardware key. When the device is locked, the decryption key is discarded, making the data inaccessible until the user unlocks the device again."
  },
  {
    id: 'mobile-sec-3',
    title: 'Secure Mobile Communication',
    description: 'Which of the following is NOT a recommended practice for secure API communication in mobile apps?',
    difficulty: 'medium',
    category: 'Mobile Security',
    languages: ['Android', 'iOS'],
    type: 'multiple-choice',
    vulnerabilityType: 'API Security',
    options: [
      'Certificate pinning',
      'Implementing proper TLS validation',
      'Storing API keys in the app binary',
      'Using mutual TLS authentication'
    ],
    answer: 2,
    explanation: "Storing API keys directly in the app binary is not recommended because mobile applications can be easily decompiled or analyzed, exposing these secrets. Attackers can extract API keys from the application code and misuse them. Instead, API keys should be stored securely using platform-specific secure storage mechanisms, retrieved from a backend service upon authentication, or protected through additional security layers."
  },
  {
    id: 'mobile-sec-4',
    title: 'Mobile App Code Obfuscation',
    description: 'What is the primary purpose of code obfuscation in mobile applications?',
    difficulty: 'medium',
    category: 'Mobile Security',
    languages: ['Android', 'iOS'],
    type: 'multiple-choice',
    vulnerabilityType: 'Reverse Engineering',
    options: [
      'To improve application performance',
      'To make the application size smaller',
      'To make reverse engineering and understanding the code more difficult',
      'To ensure compatibility across different device versions'
    ],
    answer: 2,
    explanation: "Code obfuscation is primarily used to make reverse engineering more difficult by transforming readable code into a form that's harder to understand while preserving its functionality. It renames variables and functions to meaningless names, removes metadata, and can modify the control flow to confuse analysts. While obfuscation isn't a complete security solution, it adds a layer of protection against casual inspection and makes it more time-consuming for attackers to understand the application's inner workings."
  },
  {
    id: 'mobile-sec-5',
    title: 'Biometric Authentication Security',
    description: 'Which statement about biometric authentication in mobile apps is correct?',
    difficulty: 'medium',
    category: 'Mobile Security',
    languages: ['Android', 'iOS'],
    type: 'multiple-choice',
    vulnerabilityType: 'Authentication',
    options: [
      'Biometric data is typically stored in the app\'s local storage',
      'Biometric authentication is immune to spoofing attacks',
      'Mobile OSes store biometric data in secure hardware and only provide pass/fail results to apps',
      'Applications can directly access the user\'s fingerprint data'
    ],
    answer: 2,
    explanation: "Modern mobile operating systems like iOS and Android store biometric data (fingerprints, face data) in secure hardware elements, and applications never have direct access to this data. When an app requests biometric authentication, the OS handles the verification and only returns a success or failure result to the application. This architecture ensures that sensitive biometric data remains protected in specialized hardware and isn't accessible even if the app is compromised."
  }
];
