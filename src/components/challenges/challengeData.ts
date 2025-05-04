export const challenges = [
  // SQL Injection Challenges
  {
    id: 'sql-injection-1',
    title: 'Basic SQL Injection',
    description: 'Review the code for potential SQL injection vulnerabilities.',
    difficulty: 'easy',
    category: 'Injection Flaws',
    languages: ['PHP'],
    type: 'single',
    vulnerabilityType: 'SQL Injection',
    code: `<?php
// Get user ID from URL parameter
$userId = $_GET['id'];

// Connect to the database
$conn = new mysqli("localhost", "user", "password", "app_db");

// Query user data
$sql = "SELECT * FROM users WHERE id = " . $userId;
$result = $conn->query($sql);

// Display user information
if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    echo "Welcome, " . $row["username"] . "!";
} else {
    echo "User not found.";
}
$conn->close();
?>`,
    answer: false,
    explanation: "This code is vulnerable to SQL injection because it directly concatenates user input into the SQL query without any sanitization. An attacker could inject malicious SQL code by manipulating the 'id' parameter, for example by using '1 OR 1=1' to retrieve all users or '1; DROP TABLE users;' to delete the users table."
  },
  {
    id: 'sql-injection-2',
    title: 'SQL Injection in Java',
    description: 'Compare these two Java database query implementations. Which one is secure against SQL injection?',
    difficulty: 'medium',
    category: 'Injection Flaws',
    languages: ['Java'],
    type: 'comparison',
    vulnerabilityType: 'SQL Injection',
    secureCode: `import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class UserDAO {
    public User getUserById(Connection conn, String userId) throws SQLException {
        User user = null;
        String sql = "SELECT * FROM users WHERE id = ?";
        
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, userId);
            ResultSet rs = stmt.executeQuery();
            
            if (rs.next()) {
                user = new User();
                user.setId(rs.getString("id"));
                user.setUsername(rs.getString("username"));
                user.setEmail(rs.getString("email"));
            }
        }
        
        return user;
    }
}`,
    vulnerableCode: `import java.sql.Connection;
import java.sql.Statement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class UserDAO {
    public User getUserById(Connection conn, String userId) throws SQLException {
        User user = null;
        String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
        
        try (Statement stmt = conn.createStatement()) {
            ResultSet rs = stmt.executeQuery(sql);
            
            if (rs.next()) {
                user = new User();
                user.setId(rs.getString("id"));
                user.setUsername(rs.getString("username"));
                user.setEmail(rs.getString("email"));
            }
        }
        
        return user;
    }
}`,
    answer: 'secure',
    explanation: "The secure version uses a PreparedStatement with parameter binding (?), which sanitizes user input and prevents SQL injection. The vulnerable version directly concatenates the userId into the SQL statement, making it vulnerable to SQL injection attacks."
  },
  // XSS Challenges
  {
    id: 'xss-1',
    title: 'Cross-Site Scripting in React',
    description: 'Is this React component vulnerable to XSS attacks?',
    difficulty: 'medium',
    category: 'Cross-Site Scripting',
    languages: ['JavaScript', 'React'],
    type: 'single',
    vulnerabilityType: 'XSS',
    code: `import React from 'react';

function CommentDisplay({ comment }) {
  return (
    <div className="comment-box">
      <h3>User Comment:</h3>
      <div dangerouslySetInnerHTML={{ __html: comment }} />
    </div>
  );
}

export default CommentDisplay;`,
    answer: false,
    explanation: "This component is vulnerable to XSS attacks because it uses dangerouslySetInnerHTML to directly insert user-provided content (comment) into the DOM. If comment contains malicious JavaScript like '<script>alert(\"XSS\")</script>' or '<img src=\"x\" onerror=\"alert(1)\'>', it will be executed in the browser. To fix this, either avoid dangerouslySetInnerHTML or sanitize the input using a library like DOMPurify."
  },
  {
    id: 'xss-2',
    title: 'XSS Prevention in JavaScript',
    description: 'Compare these two JavaScript functions for displaying user comments. Which implementation is secure against XSS?',
    difficulty: 'easy',
    category: 'Cross-Site Scripting',
    languages: ['JavaScript'],
    type: 'comparison',
    vulnerabilityType: 'XSS',
    secureCode: `function displayUserComment(comment) {
  // Create text node instead of using innerHTML
  const commentNode = document.createTextNode(comment);
  const commentDiv = document.createElement('div');
  commentDiv.className = 'user-comment';
  commentDiv.appendChild(commentNode);
  
  // Add to the DOM
  document.getElementById('comments-container').appendChild(commentDiv);
}`,
    vulnerableCode: `function displayUserComment(comment) {
  // Directly insert the comment HTML
  const commentHTML = '<div class="user-comment">' + comment + '</div>';
  
  // Add to the DOM
  document.getElementById('comments-container').innerHTML += commentHTML;
}`,
    answer: 'secure',
    explanation: "The secure version uses document.createTextNode() which automatically escapes any HTML or JavaScript in the comment, preventing XSS. The vulnerable version uses innerHTML which directly interprets and executes any HTML or JavaScript in the comment string, making it vulnerable to XSS attacks."
  },
  // CSRF Challenges
  {
    id: 'csrf-1',
    title: 'CSRF Protection in Express.js',
    description: 'Review this Express.js code that handles user password changes. Is it protected against CSRF attacks?',
    difficulty: 'medium',
    category: 'CSRF',
    languages: ['JavaScript', 'Node.js'],
    type: 'single',
    vulnerabilityType: 'CSRF',
    code: `const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(session({
  secret: 'session-secret',
  resave: false,
  saveUninitialized: true
}));

// Password change endpoint
app.post('/change-password', (req, res) => {
  // Check if user is logged in
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const { newPassword, confirmPassword } = req.body;
  
  // Validate passwords match
  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }
  
  // Update password in database (pseudocode)
  updateUserPassword(req.session.userId, newPassword);
  
  return res.json({ message: 'Password updated successfully' });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});`,
    answer: false,
    explanation: "This code is vulnerable to CSRF attacks because it doesn't implement CSRF tokens. While it does check if the user is authenticated via session, it doesn't verify that the request originated from a legitimate form on the website. An attacker could create a malicious website that submits a form to this endpoint, and if the victim is logged in, the password change would succeed. To fix this, implement CSRF protection using a library like 'csurf' and include CSRF tokens in your forms."
  },
  // Path Traversal Challenges
  {
    id: 'path-traversal-1',
    title: 'Path Traversal in File Download',
    description: 'Compare these two Python functions that handle file downloads. Which one is secure against path traversal attacks?',
    difficulty: 'hard',
    category: 'Path Traversal',
    languages: ['Python'],
    type: 'comparison',
    vulnerabilityType: 'Path Traversal',
    secureCode: `import os
from flask import Flask, send_file, request, abort
import re

app = Flask(__name__)

@app.route('/download')
def download_file():
    filename = request.args.get('filename')
    
    if not filename or not re.match(r'^[a-zA-Z0-9_.-]+$', filename):
        abort(400, "Invalid filename")
    
    file_path = os.path.join('safe_files_directory', filename)
    
    # Ensure the resolved path is within the intended directory
    safe_directory = os.path.abspath('safe_files_directory')
    requested_path = os.path.abspath(file_path)
    
    if not requested_path.startswith(safe_directory):
        abort(403, "Access denied")
    
    if not os.path.exists(file_path):
        abort(404, "File not found")
    
    return send_file(file_path)`,
    vulnerableCode: `import os
from flask import Flask, send_file, request

app = Flask(__name__)

@app.route('/download')
def download_file():
    filename = request.args.get('filename')
    
    if not filename:
        return "Filename is required", 400
    
    file_path = os.path.join('safe_files_directory', filename)
    
    if not os.path.exists(file_path):
        return "File not found", 404
    
    return send_file(file_path)`,
    answer: 'secure',
    explanation: "The secure version prevents path traversal by: 1) Validating the filename with a regex to ensure it only contains safe characters, 2) Converting both the intended directory and the requested path to absolute paths, and 3) Checking that the requested path starts with the safe directory path. The vulnerable version doesn't validate the filename, allowing attackers to use '../' sequences to traverse outside the intended directory."
  },
  // Server-Side Request Forgery Challenges
  {
    id: 'ssrf-1',
    title: 'Server-Side Request Forgery',
    description: 'This Node.js code fetches an image from a URL provided by the user. Is it vulnerable to SSRF?',
    difficulty: 'hard',
    category: 'SSRF',
    languages: ['JavaScript', 'Node.js'],
    type: 'single',
    vulnerabilityType: 'SSRF',
    code: `const express = require('express');
const axios = require('axios');
const app = express();
app.use(express.json());

app.post('/fetch-image', async (req, res) => {
  const { imageUrl } = req.body;
  
  try {
    // Fetch the image from the provided URL
    const response = await axios.get(imageUrl, { responseType: 'arraybuffer' });
    
    // Return the image data
    res.set('Content-Type', response.headers['content-type']);
    res.send(Buffer.from(response.data, 'binary'));
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch image' });
  }
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});`,
    answer: false,
    explanation: "This code is vulnerable to SSRF (Server-Side Request Forgery) because it makes HTTP requests to any URL provided by the user without validation. An attacker could supply internal network URLs like 'http://localhost:27017' (MongoDB) or 'http://169.254.169.254/latest/meta-data/' (AWS metadata service) to access internal services or cloud instance metadata. To fix this, implement URL validation to allow only specific domains and protocols, and use a whitelist approach rather than a blacklist."
  },
  // Command Injection Challenges
  {
    id: 'command-injection-1',
    title: 'Command Injection in PHP',
    description: 'Compare these two PHP functions that execute a ping command. Which implementation is secure against command injection?',
    difficulty: 'medium',
    category: 'Injection Flaws',
    languages: ['PHP'],
    type: 'comparison',
    vulnerabilityType: 'Command Injection',
    secureCode: `<?php
function pingHost($host) {
    // Validate input: only allow hostnames/IPs with standard characters
    if (!preg_match('/^[a-zA-Z0-9.-]+$/', $host)) {
        return "Invalid hostname format";
    }
    
    // Use escapeshellarg to properly escape the argument
    $escapedHost = escapeshellarg($host);
    
    // Execute the command with proper escaping
    $output = [];
    $returnVar = 0;
    exec("ping -c 4 " . $escapedHost, $output, $returnVar);
    
    return implode("\\n", $output);
}

// Usage
$host = $_POST['host'] ?? '';
echo pingHost($host);
?>`,
    vulnerableCode: `<?php
function pingHost($host) {
    // Directly use the input in the command
    $command = "ping -c 4 " . $host;
    
    // Execute the command without validation or escaping
    $output = shell_exec($command);
    
    return $output;
}

// Usage
$host = $_POST['host'] ?? '';
echo pingHost($host);
?>`,
    answer: 'secure',
    explanation: "The secure version prevents command injection by: 1) Validating the input using a regular expression to ensure it only contains safe characters, and 2) Using escapeshellarg() to properly escape the user input before including it in the command. The vulnerable version directly concatenates user input into the command string without any validation or escaping, allowing attackers to inject additional commands using operators like ';', '&&', or '|'."
  },
  // Insecure Deserialization Challenges
  {
    id: 'insecure-deserialization-1',
    title: 'Insecure Deserialization in Java',
    description: 'Review this Java code that deserializes user data. Is it vulnerable to insecure deserialization attacks?',
    difficulty: 'hard',
    category: 'Insecure Deserialization',
    languages: ['Java'],
    type: 'single',
    vulnerabilityType: 'Insecure Deserialization',
    code: `import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UserDataServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Get serialized data from request
            String serializedData = request.getParameter("userData");
            byte[] data = Base64.getDecoder().decode(serializedData);
            
            // Deserialize the object
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bais);
            UserData userData = (UserData) ois.readObject();
            ois.close();
            
            // Use the deserialized object
            response.getWriter().println("Hello, " + userData.getUsername());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// User data class
class UserData implements Serializable {
    private String username;
    
    public String getUsername() {
        return username;
    }
    
    public void setUsername(String username) {
        this.username = username;
    }
}`,
    answer: false,
    explanation: "This code is vulnerable to insecure deserialization attacks because it deserializes user-provided data without any validation or filtering. An attacker could craft a malicious serialized object that, when deserialized, could execute arbitrary code through gadget chains in the classpath. To fix this, avoid deserializing untrusted data, or use safer alternatives like JSON. If deserialization is necessary, implement validation filters using ObjectInputFilter (Java 9+) or libraries like SerialKiller."
  },
  // Broken Authentication Challenges
  {
    id: 'broken-auth-1',
    title: 'Authentication Bypass Detection',
    description: 'This PHP code handles user authentication. Can you identify any authentication vulnerabilities?',
    difficulty: 'medium',
    category: 'Broken Authentication',
    languages: ['PHP'],
    type: 'single',
    vulnerabilityType: 'Authentication Bypass',
    code: `<?php
session_start();

function authenticateUser($username, $password) {
    // Connect to database
    $conn = new mysqli("localhost", "app_user", "app_password", "user_db");
    
    // Check connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }
    
    // Query for user with matching credentials
    $query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
    $result = $conn->query($query);
    
    if ($result->num_rows == 1) {
        // User exists and password matches
        $user = $result->fetch_assoc();
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['is_admin'] = ($user['role'] == 'admin');
        return true;
    }
    
    return false;
}

// Process login form
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    if (authenticateUser($username, $password)) {
        header("Location: dashboard.php");
        exit;
    } else {
        $error_message = "Invalid username or password";
    }
}
?>`,
    answer: false,
    explanation: "This code has multiple authentication vulnerabilities: 1) SQL Injection vulnerability in the authentication query by directly concatenating user inputs, allowing for authentication bypass, 2) Plaintext password storage and comparison instead of using secure hashing, 3) No brute force protection, 4) No account lockout mechanism, and 5) No CSRF protection for the login form. An attacker could bypass authentication with a username like: admin' -- which would make the SQL query return the admin user regardless of password."
  },
  // Sensitive Data Exposure Challenges
  {
    id: 'data-exposure-1',
    title: 'API Key Exposure',
    description: 'Compare these two JavaScript files that handle API key usage in a React Native mobile app. Which one securely handles the API key?',
    difficulty: 'easy',
    category: 'Sensitive Data Exposure',
    languages: ['JavaScript', 'React Native'],
    type: 'comparison',
    vulnerabilityType: 'API Key Exposure',
    secureCode: `import { Platform } from 'react-native';
import Config from 'react-native-config';
import * as SecureStore from 'expo-secure-store';

export async function getWeatherData(city) {
  try {
    // Get API key from environment variables or secure storage
    let apiKey;
    if (Platform.OS === 'web') {
      // For web, use environment variables
      apiKey = process.env.REACT_APP_WEATHER_API_KEY;
    } else {
      // For mobile, use secure storage
      apiKey = await SecureStore.getItemAsync('weather_api_key');
    }
    
    if (!apiKey) {
      console.error('API key not available');
      return null;
    }
    
    // Make the API request with the secure key
    const response = await fetch(
      \`https://api.weatherservice.com/data?city=\${encodeURIComponent(city)}&key=\${apiKey}\`,
      { method: 'GET' }
    );
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching weather data:', error);
    return null;
  }
}`,
    vulnerableCode: `// api.js - Weather API client

// API key directly hardcoded in the source code
const API_KEY = '9a8b7c6d5e4f3g2h1i0j';

export async function getWeatherData(city) {
  try {
    const response = await fetch(
      \`https://api.weatherservice.com/data?city=\${encodeURIComponent(city)}&key=\${API_KEY}\`,
      { method: 'GET' }
    );
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching weather data:', error);
    return null;
  }
}`,
    answer: 'secure',
    explanation: "The secure version handles API keys correctly by: 1) Using environment variables for web platforms and secure storage for mobile platforms instead of hardcoding the key, 2) Checking if the key exists before making the request, and 3) Providing appropriate error handling. The vulnerable version directly hardcodes the API key in the source code, which can be extracted from the compiled app or discovered through reverse engineering."
  },
  // Cryptographic Failures Challenges
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
  },
  // Access Control Challenges
  {
    id: 'access-control-1',
    title: 'Broken Access Control',
    description: 'Review this Express.js API endpoint that retrieves user data. Can you identify any access control vulnerabilities?',
    difficulty: 'medium',
    category: 'Broken Access Control',
    languages: ['JavaScript', 'Node.js'],
    type: 'single',
    vulnerabilityType: 'Broken Access Control',
    code: `const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  try {
    const decoded = jwt.verify(token, 'secret-key');
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// API endpoint to get user profile
router.get('/api/users/:userId/profile', isAuthenticated, async (req, res) => {
  try {
    const userId = req.params.userId;
    
    // Retrieve user data from database
    const user = await db.User.findById(userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Return user profile data
    return res.json({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
      settings: user.settings
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;`,
    answer: false,
    explanation: "This code has a broken access control vulnerability because it doesn't check if the authenticated user has permission to access the requested user profile. Any authenticated user can access any other user's profile by simply changing the userId parameter. To fix this issue, add authorization logic that checks if the requesting user has permission to access the specified profile, typically by comparing the authenticated user's ID with the requested userId or checking for admin role."
  },
  // More challenges for various languages and vulnerabilities...
  
  // XML External Entity (XXE) Challenges
  {
    id: 'xxe-1',
    title: 'XML External Entity (XXE) Vulnerability',
    description: 'Compare these two C# methods that parse XML data. Which one is protected against XXE attacks?',
    difficulty: 'hard',
    category: 'XXE',
    languages: ['C#'],
    type: 'comparison',
    vulnerabilityType: 'XXE',
    secureCode: `using System;
using System.IO;
using System.Xml;

public class XmlProcessor
{
    public XmlDocument ParseXmlSecurely(string xmlData)
    {
        XmlDocument xmlDoc = new XmlDocument();
        
        // Disable external entity processing
        xmlDoc.XmlResolver = null;
        
        // Load the XML with external entities disabled
        xmlDoc.LoadXml(xmlData);
        
        return xmlDoc;
    }
    
    public void ProcessXmlDocument(string xmlData)
    {
        try
        {
            XmlDocument doc = ParseXmlSecurely(xmlData);
            
            // Process the XML document...
            Console.WriteLine("XML processed successfully");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error processing XML: {ex.Message}");
        }
    }
}`,
    vulnerableCode: `using System;
using System.IO;
using System.Xml;

public class XmlProcessor
{
    public XmlDocument ParseXml(string xmlData)
    {
        XmlDocument xmlDoc = new XmlDocument();
        
        // Load the XML with default settings
        xmlDoc.LoadXml(xmlData);
        
        return xmlDoc;
    }
    
    public void ProcessXmlDocument(string xmlData)
    {
        try
        {
            XmlDocument doc = ParseXml(xmlData);
            
            // Process the XML document...
            Console.WriteLine("XML processed successfully");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error processing XML: {ex.Message}");
        }
    }
}`,
    answer: 'secure',
    explanation: "The secure version prevents XXE attacks by explicitly setting xmlDoc.XmlResolver = null, which disables the processing of external entities in the XML document. The vulnerable version uses default settings which allow external entity processing, making it vulnerable to XXE attacks where an attacker could include external entities that access local files or make network requests to internal services."
  },
  // Race Condition Challenges
  {
    id: 'race-condition-1',
    title: 'Race Condition in Account Balance Update',
    description: 'Review this Python code that updates a user account balance. Is it vulnerable to race conditions?',
    difficulty: 'hard',
    category: 'Race Conditions',
    languages: ['Python'],
    type: 'single',
    vulnerabilityType: 'Race Condition',
    code: `import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
DATABASE = 'bank.db'

def get_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/api/withdraw', methods=['POST'])
def withdraw():
    user_id = request.json.get('user_id')
    amount = request.json.get('amount')
    
    if not user_id or not amount or amount <= 0:
        return jsonify({'error': 'Invalid request parameters'}), 400
    
    conn = get_connection()
    cursor = conn.cursor()
    
    // Get current balance
    cursor.execute('SELECT balance FROM accounts WHERE user_id = ?', (user_id,))
    account = cursor.fetchone()
    
    if not account:
        conn.close()
        return jsonify({'error': 'Account not found'}), 404
    
    current_balance = account['balance']
    
    // Check if enough balance
    if current_balance < amount:
        conn.close()
        return jsonify({'error': 'Insufficient funds'}), 400
    
    // Update balance
    new_balance = current_balance - amount
    cursor.execute(
        'UPDATE accounts SET balance = ? WHERE user_id = ?',
        (new_balance, user_id)
    )
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'new_balance': new_balance})

if __name__ == '__main__':
    app.run(debug=True)`,
    answer: false,
    explanation: "This code is vulnerable to race conditions because it uses a 'read-then-write' pattern without proper synchronization. If two withdrawal requests for the same account are processed simultaneously, both might read the same initial balance and both could succeed even if together they exceed the available funds. To fix this, use database transactions with the appropriate isolation level, or implement row-level locking. For example, use 'SELECT ... FOR UPDATE' to lock the row until the transaction completes."
  },
  // API Security Challenges
  {
    id: 'api-security-1',
    title: 'Mass Assignment Vulnerability',
    description: 'This Express.js API endpoint updates a user profile. Can you identify any mass assignment vulnerabilities?',
    difficulty: 'medium',
    category: 'API Security',
    languages: ['JavaScript', 'Node.js'],
    type: 'single',
    vulnerabilityType: 'Mass Assignment',
    code: `const express = require('express');
const router = express.Router();
const User = require('../models/User');

// Middleware for authentication (simplified)
function authenticate(req, res, next) {
  const userId = req.headers['user-id'];
  
  if (!userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  req.userId = userId;
  next();
}

// Update user profile endpoint
router.put('/api/users/:id', authenticate, async (req, res) => {
  try {
    // Ensure the user is updating their own profile
    if (req.params.id !== req.userId) {
      return res.status(403).json({ error: 'Not authorized to update this profile' });
    }
    
    // Update user with all provided fields
    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );
    
    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    return res.json(updatedUser);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;`,
    answer: false,
    explanation: "This code is vulnerable to mass assignment attacks because it directly passes the entire req.body object to the database update operation. This allows an attacker to update any field in the user document, including privileged fields like 'role', 'isAdmin', or 'accountBalance' that they shouldn't be able to modify. To fix this, explicitly list the fields that can be updated or use a whitelist to filter the request body before passing it to the database operation."
  },
  
  //
