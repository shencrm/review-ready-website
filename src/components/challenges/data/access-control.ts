
import { Challenge } from './challenge-types';

export const accessControlChallenges: Challenge[] = [
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
  }
];
