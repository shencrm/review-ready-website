
import { Challenge } from './challenge-types';

export const brokenAuthChallenges: Challenge[] = [
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
  }
];
