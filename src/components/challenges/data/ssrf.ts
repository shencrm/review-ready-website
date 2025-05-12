
import { Challenge } from './challenge-types';

export const ssrfChallenges: Challenge[] = [
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
  }
];
