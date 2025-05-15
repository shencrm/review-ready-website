
import { Challenge } from './challenge-types';

export const idorChallenges: Challenge[] = [
  {
    id: 'idor-1',
    title: 'Insecure Direct Object Reference',
    description: 'This Express.js endpoint retrieves user profiles. Identify the security vulnerability.',
    difficulty: 'medium',
    category: 'Broken Access Control',
    languages: ['JavaScript', 'Node.js'],
    type: 'multiple-choice',
    vulnerabilityType: 'IDOR',
    code: `const express = require('express');
const router = express.Router();

// GET user profile by ID
router.get('/profile/:id', async (req, res) => {
  try {
    // Get user ID from URL parameter
    const userId = req.params.id;
    
    // Query database for user profile
    const profile = await db.collection('users').findOne({ id: userId });
    
    if (!profile) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    // Return user profile
    res.json({
      id: profile.id,
      name: profile.name,
      email: profile.email,
      role: profile.role,
      privateData: profile.privateData
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;`,
    options: [
      'SQL Injection vulnerability',
      'Cross-Site Scripting vulnerability',
      'No authentication check before accessing user data',
      'Improper error handling'
    ],
    answer: 2,
    explanation: "This code has an Insecure Direct Object Reference (IDOR) vulnerability because it doesn't verify if the currently authenticated user has permission to access the requested profile. Any user can access any other user's profile by simply changing the ID parameter in the URL. The endpoint should check if the requesting user has appropriate permissions or if they're accessing their own profile before returning sensitive data."
  }
];
