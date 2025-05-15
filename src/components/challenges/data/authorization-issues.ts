
import { Challenge } from './challenge-types';

export const authorizationIssuesChallenges: Challenge[] = [
  {
    id: 'authorization-1',
    title: 'Missing Function-Level Authorization',
    description: 'Review this Express.js API endpoint. What authorization issue is present?',
    difficulty: 'medium',
    category: 'Broken Access Control',
    languages: ['JavaScript', 'Node.js'],
    type: 'multiple-choice',
    vulnerabilityType: 'Missing Authorization',
    code: `const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');

// Authentication middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ message: 'Invalid token' });
  }
};

// Get all users API
router.get('/api/users', authenticate, async (req, res) => {
  try {
    const users = await db.collection('users').find().toArray();
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete user API
router.delete('/api/users/:id', authenticate, async (req, res) => {
  try {
    const result = await db.collection('users').deleteOne({ _id: req.params.id });
    if (result.deletedCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;`,
    options: [
      'The JWT secret is exposed in the code',
      'Authentication middleware doesn\'t validate token expiration',
      'No function-level authorization checks based on user role',
      'The API endpoints aren\'t rate limited'
    ],
    answer: 2,
    explanation: "The code has authentication but lacks proper authorization. While it verifies users are authenticated (via JWT), it doesn't check if they have the appropriate permissions to perform the requested actions. Any authenticated user can access the list of all users and delete any user, regardless of their role or relationship to the target resource. To fix this, implement function-level authorization that verifies the user's role (e.g., admin) or relationship (e.g., account owner) before allowing sensitive operations like viewing all users or deleting accounts."
  }
];
