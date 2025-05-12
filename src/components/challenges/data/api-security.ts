
import { Challenge } from './challenge-types';

export const apiSecurityChallenges: Challenge[] = [
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
    explanation: "This code is vulnerable to mass assignment attacks because it directly passes the entire req.body object to the database update operation. This allows an attacker to update any field in the user document, including privileged fields like 'role', 'isAdmin', or 'accountBalance' that they shouldn't be able to modify. To fix this, explicitly list the fields that can be updated or use a whitelist to filter the request body to only allow intended fields."
  }
];
