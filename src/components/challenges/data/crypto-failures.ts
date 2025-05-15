
import { Challenge } from './challenge-types';

export const cryptoFailuresChallenges: Challenge[] = [
  {
    id: 'crypto-failures-1',
    title: 'Password Hashing Security',
    description: 'Compare these two password hashing implementations in PHP. Which one is secure?',
    difficulty: 'easy',
    category: 'Cryptographic Failures',
    languages: ['PHP'],
    type: 'comparison',
    vulnerabilityType: 'Weak Cryptography',
    secureCode: `<?php
/**
 * Securely hash a password using modern algorithms
 * 
 * @param string $password The password to hash
 * @return string The hashed password
 */
function hashPassword($password) {
    // Using PHP's password_hash with bcrypt (default)
    // Cost parameter of 12 provides good security/performance balance
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    
    return $hashedPassword;
}

/**
 * Verify a password against a hash
 * 
 * @param string $password The password to verify
 * @param string $hashedPassword The stored hash to verify against
 * @return bool True if password is correct, false otherwise
 */
function verifyPassword($password, $hashedPassword) {
    // Using PHP's built-in verification function
    return password_verify($password, $hashedPassword);
}

// Example usage:
function registerUser($username, $password) {
    $hashedPassword = hashPassword($password);
    
    // Store username and hashed password in database
    storeInDatabase($username, $hashedPassword);
}

function loginUser($username, $password) {
    // Retrieve stored hash from database
    $storedHash = getHashFromDatabase($username);
    
    if ($storedHash && verifyPassword($password, $storedHash)) {
        // Password is correct
        return true;
    }
    
    // Password is incorrect
    return false;
}`,
    vulnerableCode: `<?php
/**
 * Hash a password
 * 
 * @param string $password The password to hash
 * @return string The hashed password
 */
function hashPassword($password) {
    // Add a simple salt
    $salt = "staticSalt123";
    
    // Use MD5 for hashing
    $hashedPassword = md5($salt . $password);
    
    return $hashedPassword;
}

/**
 * Verify a password against a hash
 * 
 * @param string $password The password to verify
 * @param string $hashedPassword The stored hash to verify against
 * @return bool True if password is correct, false otherwise
 */
function verifyPassword($password, $hashedPassword) {
    $salt = "staticSalt123";
    
    // Hash input password the same way
    $hashedInput = md5($salt . $password);
    
    // Compare the hashes
    return $hashedInput === $hashedPassword;
}

// Example usage:
function registerUser($username, $password) {
    $hashedPassword = hashPassword($password);
    
    // Store username and hashed password in database
    storeInDatabase($username, $hashedPassword);
}

function loginUser($username, $password) {
    // Retrieve stored hash from database
    $storedHash = getHashFromDatabase($username);
    
    if ($storedHash && verifyPassword($password, $storedHash)) {
        // Password is correct
        return true;
    }
    
    // Password is incorrect
    return false;
}`,
    answer: 'secure',
    explanation: "The secure implementation uses PHP's built-in password_hash() function with the PASSWORD_BCRYPT algorithm, which: 1) Automatically generates a random salt for each password, 2) Uses bcrypt, a strong adaptive hashing algorithm designed for passwords, 3) Supports a configurable 'cost' parameter to make the hashing computationally expensive and resistant to brute force attacks, and 4) Uses password_verify() which is timing-attack resistant. The vulnerable implementation has multiple issues: it uses MD5 which is cryptographically broken, uses a static hard-coded salt for all passwords, and doesn't implement any work factor to slow down brute force attacks."
  },
  {
    id: 'crypto-failures-2',
    title: 'Data Encryption Implementation',
    description: 'This Java code implements encryption for storing sensitive data. Is it securely implemented?',
    difficulty: 'medium',
    category: 'Cryptographic Failures',
    languages: ['Java'],
    type: 'single',
    vulnerabilityType: 'Weak Encryption',
    code: `import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class DataEncryptor {
    private static final String SECRET_KEY = "5up3rS3cr3tK3y!!"; // 16 bytes
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    /**
     * Encrypt sensitive data
     * 
     * @param plainText The text to encrypt
     * @return Base64 encoded encrypted string
     */
    public static String encrypt(String plainText) throws Exception {
        SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * Decrypt data
     * 
     * @param encryptedText Base64 encoded encrypted string
     * @return Decrypted string
     */
    public static String decrypt(String encryptedText) throws Exception {
        SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key);
        
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            String sensitiveData = "CCN:4111111111111111;CVV:123;EXP:12/25";
            
            // Encrypt data for storage
            String encrypted = encrypt(sensitiveData);
            System.out.println("Encrypted: " + encrypted);
            
            // Later, decrypt for use
            String decrypted = decrypt(encrypted);
            System.out.println("Decrypted: " + decrypted);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}`,
    answer: false,
    explanation: "This encryption implementation has several critical security issues: 1) It uses a hardcoded encryption key in the source code, which should never be done, 2) It uses AES in ECB mode, which does not provide semantic security and reveals patterns in the encrypted data, 3) It doesn't use an initialization vector (IV) which is required for secure modes like CBC, 4) It doesn't implement key rotation or versioning, 5) It converts strings directly to bytes without specifying character encoding, 6) It lacks integrity verification (no MAC or authenticated encryption), and 7) It doesn't protect the encryption key in memory. A secure implementation would use AES-GCM or AES-CBC with a random IV, derive keys from a secure source like a key management service, implement integrity checking, and properly handle key lifecycle."
  },
  {
    id: 'crypto-failures-3',
    title: 'TLS Implementation in Web Application',
    description: 'Review this Node.js HTTPS server setup. Is it configured securely?',
    difficulty: 'hard',
    category: 'Cryptographic Failures',
    languages: ['JavaScript', 'Node.js'],
    type: 'single',
    vulnerabilityType: 'TLS Configuration',
    code: `const https = require('https');
const fs = require('fs');
const express = require('express');
const app = express();

// SSL/TLS options
const options = {
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.cert'),
  ciphers: 'HIGH:!aNULL:!MD5',
  minVersion: 'TLSv1.2',
  secureOptions: require('constants').SSL_OP_NO_SSLv3 | require('constants').SSL_OP_NO_TLSv1
};

// Add security headers
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});

// Force HTTPS
app.use((req, res, next) => {
  if (!req.secure) {
    return res.redirect('https://' + req.headers.host + req.url);
  }
  next();
});

app.get('/', (req, res) => {
  res.send('Secure server running!');
});

// Create HTTPS server
const server = https.createServer(options, app);

server.listen(443, () => {
  console.log('Server listening on port 443');
});

// Also create an HTTP server to redirect to HTTPS
const http = require('http');
http.createServer((req, res) => {
  res.writeHead(301, { 'Location': 'https://' + req.headers.host + req.url });
  res.end();
}).listen(80);`,
    answer: true,
    explanation: "This TLS implementation follows several security best practices: 1) It enforces TLS 1.2 or higher by setting minVersion and explicitly disabling SSL 3.0 and TLS 1.0, 2) It specifies secure cipher suites by using the 'HIGH' keyword and excluding NULL and MD5 ciphers, 3) It implements HTTP Strict Transport Security (HSTS) with a long expiration and includeSubDomains flag, 4) It includes other important security headers like Content-Security-Policy, X-Content-Type-Options, and X-Frame-Options, 5) It properly redirects HTTP traffic to HTTPS, and 6) It separates the key and certificate files. While it's generally secure, it could be further improved by adding a preload directive to HSTS, implementing certificate pinning, and using OCSP stapling."
  }
];
