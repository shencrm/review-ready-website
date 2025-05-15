
import { Challenge } from './challenge-types';

export const accessControlChallenges: Challenge[] = [
  {
    id: 'access-control-1',
    title: 'Role-Based Access Control',
    description: 'Compare these two PHP implementations of access control. Which one correctly implements RBAC?',
    difficulty: 'medium',
    category: 'Broken Access Control',
    languages: ['PHP'],
    type: 'comparison',
    vulnerabilityType: 'Insufficient Authorization',
    secureCode: `<?php
session_start();

class AccessControl {
    // Define permission matrix - what roles can do what actions
    private $permissions = [
        'admin' => ['read_users', 'edit_users', 'delete_users', 'view_reports', 'edit_settings'],
        'manager' => ['read_users', 'view_reports', 'edit_settings'],
        'user' => ['view_reports'],
        'guest' => []
    ];
    
    /**
     * Check if the current user has permission for an action
     * 
     * @param string $action The permission to check
     * @return bool True if allowed, false otherwise
     */
    public function hasPermission($action) {
        // If not logged in, assign guest role
        if (!isset($_SESSION['user_role'])) {
            $_SESSION['user_role'] = 'guest';
        }
        
        $role = $_SESSION['user_role'];
        
        // Check if role exists
        if (!isset($this->permissions[$role])) {
            return false;
        }
        
        // Check if action is in the permitted actions for this role
        return in_array($action, $this->permissions[$role]);
    }
    
    /**
     * Apply authorization check to a function
     * 
     * @param string $action The required permission
     * @param callable $callback Function to execute if allowed
     * @return mixed Return value of callback or false
     */
    public function authorize($action, $callback) {
        if ($this->hasPermission($action)) {
            return call_user_func($callback);
        } else {
            header("HTTP/1.1 403 Forbidden");
            echo "You don't have permission to perform this action";
            return false;
        }
    }
}

// Example usage in a controller
$ac = new AccessControl();

// Edit user endpoint
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['action']) && $_GET['action'] === 'edit_user') {
    $ac->authorize('edit_users', function() {
        $userId = filter_input(INPUT_POST, 'user_id', FILTER_VALIDATE_INT);
        $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
        
        if ($userId && $email) {
            updateUser($userId, $email);
            echo "User updated successfully";
        } else {
            echo "Invalid input data";
        }
    });
}

// View users endpoint
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action']) && $_GET['action'] === 'view_users') {
    $ac->authorize('read_users', function() {
        $users = getAllUsers();
        echo json_encode($users);
    });
}`,
    vulnerableCode: `<?php
session_start();

// Edit user endpoint
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['action']) && $_GET['action'] === 'edit_user') {
    // Check if user is logged in
    if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
        $userId = $_POST['user_id'];
        $email = $_POST['email'];
        
        updateUser($userId, $email);
        echo "User updated successfully";
    } else {
        echo "You must be logged in to perform this action";
    }
}

// View users endpoint
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action']) && $_GET['action'] === 'view_users') {
    // Check if user is an admin based on client-side value
    if (isset($_GET['is_admin']) && $_GET['is_admin'] === 'true') {
        $users = getAllUsers();
        echo json_encode($users);
    } else {
        echo "Admin access required";
    }
}

function isAdmin() {
    // No server-side verification, trusts client parameter
    return isset($_GET['is_admin']) && $_GET['is_admin'] === 'true';
}`,
    answer: 'secure',
    explanation: "The secure implementation correctly implements RBAC through: 1) A defined permission matrix mapping roles to allowed actions, 2) Server-side verification of permissions based on the authenticated user's role stored in the session, 3) A reusable authorization mechanism that applies permission checks before executing actions, and 4) Proper input validation using filter_input(). The vulnerable implementation has multiple security flaws: it only checks if a user is logged in without verifying their role, it trusts client-provided parameters (is_admin) to determine authorization, it uses no permission matrix or structured approach to access control, and it has no input validation, making it vulnerable to SQL injection."
  },
  {
    id: 'access-control-2',
    title: 'API Access Control',
    description: 'This Node.js API handles user profile data. Is the access control implemented securely?',
    difficulty: 'hard',
    category: 'Broken Access Control',
    languages: ['JavaScript', 'Node.js'],
    type: 'single',
    vulnerabilityType: 'IDOR',
    code: `const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());

// JWT verification middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  jwt.verify(token, 'secret_key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    
    req.user = user;
    next();
  });
}

// Get user profile by ID
app.get('/api/users/:id/profile', authenticateToken, (req, res) => {
  const userId = req.params.id;
  
  // Get profile data from database
  const profile = getUserProfile(userId);
  
  if (!profile) {
    return res.status(404).json({ error: 'Profile not found' });
  }
  
  res.json(profile);
});

// Update user profile
app.put('/api/users/:id/profile', authenticateToken, (req, res) => {
  const userId = req.params.id;
  const profileData = req.body;
  
  // Update profile in database
  updateUserProfile(userId, profileData);
  
  res.json({ message: 'Profile updated successfully' });
});

// Mock database functions
function getUserProfile(id) {
  // Simulate database lookup
  return {
    id: id,
    name: 'User ' + id,
    email: 'user' + id + '@example.com',
    role: id === '1' ? 'admin' : 'user'
  };
}

function updateUserProfile(id, data) {
  // Simulate database update
  console.log('Updating profile for user', id, 'with data:', data);
  return true;
}

app.listen(3000, () => {
  console.log('Server running on port 3000');
});`,
    answer: false,
    explanation: "This API has several access control vulnerabilities: 1) It suffers from Insecure Direct Object Reference (IDOR) vulnerability because it doesn't verify if the authenticated user has permission to access or modify the requested profile - any authenticated user can access or modify any profile by simply changing the user ID in the URL, 2) It uses a hardcoded JWT secret ('secret_key') instead of an environment variable or secure key management, 3) It doesn't implement role-based access control for administrative actions, 4) It doesn't validate or sanitize the incoming profile data before updating, and 5) It doesn't implement rate limiting or other anti-abuse measures. To fix these issues, add owner/permission verification by comparing req.user.id with the requested userId or check user roles for administrative access."
  }
];
