
import { Challenge } from './challenge-types';

export const cryptographyFailuresChallenges: Challenge[] = [
  {
    id: 'crypto-failure-1',
    title: 'Weak Password Hashing',
    description: 'Compare these two password hashing implementations in PHP. Which one is secure?',
    difficulty: 'easy',
    category: 'Cryptographic Failures',
    languages: ['PHP'],
    type: 'comparison',
    vulnerabilityType: 'Weak Hashing',
    secureCode: `<?php
/**
 * Hash a password securely
 * 
 * @param string $password The password to hash
 * @return string The hashed password
 */
function hashPassword($password) {
    // Use PHP's built-in password hashing function with a strong algorithm
    $hashedPassword = password_hash($password, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536, // 64MB
        'time_cost' => 4,       // 4 iterations
        'threads' => 3          // 3 parallel threads
    ]);
    
    return $hashedPassword;
}

/**
 * Verify a password against a hash
 * 
 * @param string $password The password to verify
 * @param string $hash The hash to verify against
 * @return bool Whether the password is correct
 */
function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

// Usage example
$hashedPassword = hashPassword('user_password');
// Store $hashedPassword in database

// Later, when user tries to log in
if (verifyPassword('user_input_password', $hashedPassword)) {
    // Password is correct, log the user in
} else {
    // Password is incorrect
}
?>`,
    vulnerableCode: `<?php
/**
 * Hash a password
 * 
 * @param string $password The password to hash
 * @return string The hashed password
 */
function hashPassword($password) {
    // Add a static salt for "security"
    $salt = "s3cur1ty_s4lt";
    
    // Hash the password with MD5
    $hashedPassword = md5($salt . $password);
    
    return $hashedPassword;
}

/**
 * Verify a password against a hash
 * 
 * @param string $password The password to verify
 * @param string $hash The hash to verify against
 * @return bool Whether the password is correct
 */
function verifyPassword($password, $hash) {
    $salt = "s3cur1ty_s4lt";
    $hashedInput = md5($salt . $password);
    
    return $hashedInput === $hash;
}

// Usage example
$hashedPassword = hashPassword('user_password');
// Store $hashedPassword in database

// Later, when user tries to log in
if (verifyPassword('user_input_password', $hashedPassword)) {
    // Password is correct, log the user in
} else {
    // Password is incorrect
}
?>`,
    answer: 'secure',
    explanation: "The secure implementation uses PHP's password_hash() function with the modern Argon2id algorithm, which is designed specifically for password hashing. It automatically handles salting, includes work factors to slow down brute force attacks, and is tunable (memory cost, time cost, parallelism). The vulnerable implementation has multiple critical flaws: it uses MD5 which is cryptographically broken, it uses a static salt (rather than a unique salt per password), and it has no work factor to slow down brute force attacks. Additionally, the secure implementation automatically adapts to newer hashing algorithms through password_verify() when newer PHP versions are installed."
  },
  {
    id: 'crypto-failure-2',
    title: 'Insecure Random Number Generation',
    description: 'This Java code generates session IDs. What cryptographic vulnerability exists?',
    difficulty: 'medium',
    category: 'Cryptographic Failures',
    languages: ['Java'],
    type: 'single',
    vulnerabilityType: 'Predictable Randomness',
    code: `import java.util.Random;
import java.math.BigInteger;

public class SessionManager {
    
    // Random generator for session IDs
    private static final Random random = new Random();
    
    /**
     * Generate a new session ID for a user
     * 
     * @return String representing a unique session ID
     */
    public static String generateSessionId() {
        // Create a 16-byte (128-bit) random number
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        
        // Convert to a hexadecimal string
        String sessionId = new BigInteger(1, bytes).toString(16);
        
        return sessionId;
    }
    
    /**
     * Create a new user session
     * 
     * @param userId The ID of the user
     * @return The generated session token
     */
    public static String createSession(String userId) {
        // Generate session ID
        String sessionId = generateSessionId();
        
        // Log session creation (in a real app, save to database)
        System.out.println("Created session " + sessionId + " for user " + userId);
        
        return sessionId;
    }
}`,
    answer: false,
    explanation: "This code is vulnerable due to its use of java.util.Random which is not cryptographically secure. Random is a pseudorandom number generator that uses a deterministic algorithm - if an attacker can determine the seed (which can be derived from knowing some outputs), they can predict all future values. For security-sensitive applications like session ID generation, a cryptographically secure random number generator should be used. The code should use java.security.SecureRandom instead: 'private static final SecureRandom random = new SecureRandom();'. This ensures that session IDs are unpredictable even if an attacker observes a large number of previously generated IDs."
  }
];
