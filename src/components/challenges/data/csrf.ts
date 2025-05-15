
import { Challenge } from './challenge-types';

export const csrfChallenges: Challenge[] = [
  {
    id: 'csrf-1',
    title: 'CSRF Protection in Web Forms',
    description: 'Compare these two PHP form handling implementations. Which one is protected against CSRF?',
    difficulty: 'medium',
    category: 'CSRF',
    languages: ['PHP'],
    type: 'comparison',
    vulnerabilityType: 'CSRF',
    secureCode: `<?php
session_start();

// Generate CSRF token if it doesn't exist
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('CSRF token validation failed');
    }
    
    // Process the form submission
    $newEmail = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
    
    if ($newEmail) {
        // Update user's email in the database
        updateUserEmail($userId, $newEmail);
        echo "Email updated successfully";
    } else {
        echo "Invalid email format";
    }
}
?>

<!-- Email change form -->
<form method="POST" action="/update_email.php">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    <label for="email">New Email:</label>
    <input type="email" id="email" name="email" required>
    <button type="submit">Update Email</button>
</form>`,
    vulnerableCode: `<?php
session_start();

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Process the form submission
    $newEmail = $_POST['email'];
    
    // Update user's email in the database
    updateUserEmail($userId, $newEmail);
    echo "Email updated successfully";
}
?>

<!-- Email change form -->
<form method="POST" action="/update_email.php">
    <label for="email">New Email:</label>
    <input type="email" id="email" name="email" required>
    <button type="submit">Update Email</button>
</form>`,
    answer: 'secure',
    explanation: "The secure implementation protects against CSRF by generating and validating a unique CSRF token. It creates a random token using cryptographically secure random_bytes() and stores it in the user's session. This token is included as a hidden field in the form and verified when processing the submission. The vulnerable implementation has no CSRF protection, making it susceptible to cross-site request forgery attacks where malicious websites could trick authenticated users into submitting the form without their knowledge."
  },
  {
    id: 'csrf-2',
    title: 'CSRF Protection in APIs',
    description: 'This Express.js API handles user profile updates. Is it properly protected against CSRF attacks?',
    difficulty: 'medium',
    category: 'CSRF',
    languages: ['JavaScript', 'Node.js'],
    type: 'single',
    vulnerabilityType: 'CSRF',
    code: `const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

// User authentication middleware (simplified)
function authenticate(req, res, next) {
  if (req.session.userId) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

// API to update user profile
app.put('/api/users/profile', authenticate, async (req, res) => {
  try {
    const userId = req.session.userId;
    const { name, email, bio } = req.body;
    
    // Update user profile in database
    await updateUserProfile(userId, { name, email, bio });
    
    res.json({ success: true, message: 'Profile updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});`,
    answer: false,
    explanation: "This API is vulnerable to CSRF attacks because it relies solely on session cookies for authentication without implementing specific CSRF protections. Even though it uses authentication middleware, a malicious website could still make requests to this API endpoint with the user's session cookie automatically included by the browser. To protect against CSRF, the API should implement one or more of these measures: 1) Use custom request headers like X-CSRF-Token that can't be set by cross-origin requests, 2) Verify that the Origin/Referer header matches your domain, 3) Implement the Double Submit Cookie pattern, or 4) Use the SameSite cookie attribute to restrict cookie usage in cross-site requests."
  }
];
