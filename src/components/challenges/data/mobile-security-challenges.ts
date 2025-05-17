
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
  },
  {
    id: 'mobile-sec-6',
    title: 'Root Detection Bypass',
    description: 'Which technique is LEAST effective for detecting a rooted or jailbroken device?',
    difficulty: 'hard',
    category: 'Mobile Security',
    languages: ['Android', 'iOS'],
    type: 'multiple-choice',
    vulnerabilityType: 'Device Tampering',
    options: [
      'Checking for the presence of su binary or Cydia app',
      'Verifying file system permissions',
      'Examining app installation history',
      'Using Google SafetyNet or Apple DeviceCheck APIs'
    ],
    answer: 2,
    explanation: "Examining app installation history is the least effective method for detecting a rooted or jailbroken device because this information can be easily manipulated or cleared. More effective techniques include checking for the presence of root-related binaries (like 'su'), verifying file system permissions that should be read-only in non-rooted devices, and using platform-provided APIs like Google's SafetyNet or Apple's DeviceCheck which perform comprehensive integrity verification at multiple levels and are much harder to bypass."
  },
  {
    id: 'mobile-sec-7',
    title: 'Mobile App Dynamic Analysis',
    description: 'Which of the following tools is primarily used for dynamic analysis of iOS applications?',
    difficulty: 'hard',
    category: 'Mobile Security',
    languages: ['iOS'],
    type: 'multiple-choice',
    vulnerabilityType: 'Reverse Engineering',
    options: [
      'APKTool',
      'Frida',
      'Smali',
      'Androguard'
    ],
    answer: 1,
    explanation: "Frida is a dynamic instrumentation toolkit that can be used for both iOS and Android applications. It allows security researchers and developers to inject JavaScript into native apps, making it possible to hook functions, trace calls, and modify behavior at runtime. The other options are primarily Android-focused tools: APKTool is used for reverse engineering Android APK files, Smali is an assembler/disassembler for the dex format used by Android, and Androguard is a Python tool for working with Android apps."
  },
  {
    id: 'mobile-sec-8',
    title: 'Flutter App Security',
    description: 'What is a specific security vulnerability associated with Flutter mobile applications?',
    difficulty: 'hard',
    category: 'Mobile Security',
    languages: ['Android', 'iOS'],
    type: 'multiple-choice',
    vulnerabilityType: 'Cross-Platform Frameworks',
    options: [
      'Flutter apps cannot implement certificate pinning',
      'Dart code in Flutter is compiled to native code but can be reversed easily without obfuscation',
      'Flutter doesn\'t support secure storage mechanisms',
      'Flutter apps cannot use platform-specific biometric authentication'
    ],
    answer: 1,
    explanation: "A significant vulnerability in Flutter applications is that without proper obfuscation, the Dart code compiled to native code can be relatively easily reversed back to readable Dart code using tools like dart_deobfuscator. This makes it easier for attackers to understand the application logic, find security flaws, and extract sensitive information compared to some native applications. Flutter does support certificate pinning, secure storage (via plugins), and platform-specific biometric authentication, making the other options incorrect."
  },
  {
    id: 'mobile-sec-9',
    title: 'Android Runtime Permissions',
    description: 'Which Android permission model represents the best security practice?',
    difficulty: 'medium',
    category: 'Mobile Security',
    languages: ['Android'],
    type: 'multiple-choice',
    vulnerabilityType: 'Permission Management',
    options: [
      'Requesting all permissions during installation',
      'Using only normal permissions that don\'t require user consent',
      'Requesting permissions at runtime only when needed with clear context',
      'Using shared user IDs to inherit permissions from other trusted apps'
    ],
    answer: 2,
    explanation: "The most secure approach to Android permissions is requesting them at runtime when they're actually needed and with clear context about why the permission is necessary. This approach, known as runtime permissions (introduced in Android 6.0), gives users more control and visibility into what resources an app is accessing and why. It follows the principle of least privilege by ensuring the app only gets permissions when they're actually required for a specific function. Requesting all permissions at installation overwhelms users, using only normal permissions may limit functionality, and shared user IDs represent a potential security risk."
  },
  {
    id: 'mobile-sec-10',
    title: 'iOS App Transport Security',
    description: 'What is the primary purpose of App Transport Security (ATS) in iOS?',
    difficulty: 'medium',
    category: 'Mobile Security',
    languages: ['iOS'],
    type: 'multiple-choice',
    vulnerabilityType: 'Network Security',
    options: [
      'To encrypt local storage data',
      'To enforce secure connections using HTTPS with strong encryption',
      'To scan apps for malware before installation',
      'To restrict app data sharing between different applications'
    ],
    answer: 1,
    explanation: "App Transport Security (ATS) is an iOS feature designed to improve privacy and data integrity by ensuring that apps connect to web services using secure connection protocols. It enforces best practices for secure connections by requiring HTTPS connections with TLS 1.2 or higher and strong ciphers. ATS prevents apps from accidentally using insecure network connections that could expose sensitive user data to interception. By default, ATS blocks plaintext HTTP connections and connections using legacy SSL protocols or weak ciphers. While developers can add exceptions for specific domains, Apple requires justification during app review for any ATS exceptions."
  }
];

