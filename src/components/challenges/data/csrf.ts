
import { Challenge } from './challenge-types';

export const csrfChallenges: Challenge[] = [
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
  }
];
