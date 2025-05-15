
import { Challenge } from './challenge-types';

export const securecodingChallenges: Challenge[] = [
  {
    id: 'secure-coding-1',
    title: 'Secure Random Number Generation',
    description: 'Compare these two methods for generating random tokens in C#. Which one is cryptographically secure?',
    difficulty: 'easy',
    category: 'Secure Coding',
    languages: ['C#'],
    type: 'comparison',
    vulnerabilityType: 'Weak Randomness',
    secureCode: `using System;
using System.Security.Cryptography;
using System.Text;

public class SecureTokenGenerator
{
    public string GenerateToken(int length = 32)
    {
        // Create a buffer of cryptographically strong random bytes
        byte[] randomBytes = new byte[length];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomBytes);
        }
        
        // Convert random bytes to a hex string
        StringBuilder sb = new StringBuilder(length * 2);
        for (int i = 0; i < randomBytes.Length; i++)
        {
            sb.Append(randomBytes[i].ToString("x2"));
        }
        
        return sb.ToString();
    }
    
    public static void Main()
    {
        var generator = new SecureTokenGenerator();
        string token = generator.GenerateToken();
        Console.WriteLine($"Generated token: {token}");
    }
}`,
    vulnerableCode: `using System;

public class TokenGenerator
{
    public string GenerateToken(int length = 32)
    {
        // Use the standard Random class
        Random random = new Random();
        
        // Create a string of allowed characters
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        
        // Build the token by selecting random characters
        char[] token = new char[length];
        for (int i = 0; i < length; i++)
        {
            token[i] = chars[random.Next(chars.Length)];
        }
        
        return new string(token);
    }
    
    public static void Main()
    {
        var generator = new TokenGenerator();
        string token = generator.GenerateToken();
        Console.WriteLine($"Generated token: {token}");
    }
}`,
    answer: 'secure',
    explanation: "The secure implementation uses the cryptographically secure RandomNumberGenerator.Create() method from System.Security.Cryptography, which generates random numbers suitable for security-sensitive applications. It produces unpredictable values that are much harder for attackers to guess. The vulnerable implementation uses System.Random which is a pseudo-random number generator that is deterministic and can be predicted if the seed is known. It's unsuitable for security purposes like generating authentication tokens, session IDs, or encryption keys."
  },
  {
    id: 'secure-coding-2',
    title: 'Regex Safety in JavaScript',
    description: 'This JavaScript function validates user input using regex. Does it have any security issues?',
    difficulty: 'medium',
    category: 'Secure Coding',
    languages: ['JavaScript'],
    type: 'single',
    vulnerabilityType: 'ReDoS (Regular Expression Denial of Service)',
    code: `/**
 * Validates if a string matches an email format
 * @param {string} input - The input to validate
 * @return {boolean} - Whether the input is a valid email
 */
function validateEmail(input) {
  // Check if input is a string
  if (typeof input !== 'string') {
    return false;
  }
  
  // Regex to validate email format
  const emailRegex = /^([a-zA-Z0-9]+([\\._-][a-zA-Z0-9]+)*)@([a-zA-Z0-9]+([\\.-][a-zA-Z0-9]+)*)\\.([a-zA-Z]{2,})$/;
  
  // Test if the input matches the regex pattern
  return emailRegex.test(input);
}

/**
 * Processes user registration
 */
function processRegistration(userData) {
  // Validate email
  if (!validateEmail(userData.email)) {
    return { success: false, error: 'Invalid email format' };
  }
  
  // Continue with registration process
  // ...
}`,
    answer: false,
    explanation: "This function is vulnerable to Regular Expression Denial of Service (ReDoS) attacks. The email regex contains multiple nested repetition operators (like * and +) with backtracking, creating a catastrophic backtracking scenario when given certain inputs. For example, a long input with many repeated characters before the @ symbol could cause exponential processing time. This vulnerability could be exploited to cause high CPU usage and potentially crash or slow down the server. To fix this, use a simpler regex pattern, set timeouts, or use a regex library that prevents catastrophic backtracking."
  }
];
