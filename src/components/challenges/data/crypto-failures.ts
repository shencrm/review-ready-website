
import { Challenge } from './challenge-types';

export const cryptoFailuresChallenges: Challenge[] = [
  {
    id: 'crypto-1',
    title: 'Secure Password Hashing',
    description: 'Compare these two Node.js password hashing implementations. Which one uses secure cryptographic practices?',
    difficulty: 'medium',
    category: 'Cryptographic Failures',
    languages: ['JavaScript', 'Node.js'],
    type: 'comparison',
    vulnerabilityType: 'Weak Password Storage',
    secureCode: `const crypto = require('crypto');

/**
 * Hash a password using a secure algorithm with salt
 * @param {string} password - The password to hash
 * @returns {Object} - The hash and salt
 */
function hashPassword(password) {
  // Generate a cryptographically secure random salt
  const salt = crypto.randomBytes(16).toString('hex');
  
  // Use PBKDF2 with many iterations
  const hash = crypto.pbkdf2Sync(
    password,
    salt,
    100000, // 100,000 iterations
    64,     // 64 bytes length
    'sha512'
  ).toString('hex');
  
  return {
    hash,
    salt
  };
}

/**
 * Verify a password against a stored hash
 * @param {string} password - The password to verify
 * @param {string} storedHash - The stored hash
 * @param {string} storedSalt - The stored salt
 * @returns {boolean} - Whether the password matches
 */
function verifyPassword(password, storedHash, storedSalt) {
  const hash = crypto.pbkdf2Sync(
    password,
    storedSalt,
    100000,
    64,
    'sha512'
  ).toString('hex');
  
  return hash === storedHash;
}

module.exports = {
  hashPassword,
  verifyPassword
};`,
    vulnerableCode: `const crypto = require('crypto');

/**
 * Hash a password with MD5
 * @param {string} password - The password to hash
 * @returns {string} - The hashed password
 */
function hashPassword(password) {
  // Use MD5 algorithm to hash the password
  return crypto.createHash('md5')
    .update(password)
    .digest('hex');
}

/**
 * Verify a password against a stored hash
 * @param {string} password - The password to verify
 * @param {string} storedHash - The stored hash
 * @returns {boolean} - Whether the password matches
 */
function verifyPassword(password, storedHash) {
  const hash = crypto.createHash('md5')
    .update(password)
    .digest('hex');
  
  return hash === storedHash;
}

module.exports = {
  hashPassword,
  verifyPassword
};`,
    answer: 'secure',
    explanation: "The secure version uses proper password hashing practices: 1) It uses PBKDF2, a secure key derivation function designed for passwords, 2) It applies 100,000 iterations to make brute-force attacks computationally expensive, 3) It uses a cryptographically secure random salt to prevent rainbow table attacks, and 4) It uses SHA-512 as the underlying hash function. The vulnerable version uses MD5, which is cryptographically broken and unsuitable for password hashing, and it doesn't use any salt, making it vulnerable to rainbow table attacks."
  }
];
