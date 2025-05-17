
import { Challenge } from './challenge-types';

export const secureArchitectureChallenges: Challenge[] = [
  {
    id: 'secure-arch-1',
    title: 'Microservice Authentication',
    description: 'Review this microservice authentication design. What security issue is present?',
    difficulty: 'hard',
    category: 'Microservice Security',
    languages: ['JavaScript', 'Node.js'],
    type: 'multiple-choice',
    vulnerabilityType: 'Authentication Design',
    code: `// user-service.js - Handles user authentication
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();
app.use(express.json());

const JWT_SECRET = 'shared-microservice-secret-key';
const SERVICE_API_KEY = 'internal-api-key-12345';

// Internal service-to-service authentication middleware
const authenticateService = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (apiKey === SERVICE_API_KEY) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized service' });
  }
};

// User authentication
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  // Authentication logic (simplified)
  const user = await authenticateUser(username, password);
  
  if (user) {
    // Generate JWT token
    const token = jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Internal endpoint for other services to validate tokens
app.post('/internal/validate-token', authenticateService, (req, res) => {
  const { token } = req.body;
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ valid: true, user: decoded });
  } catch (error) {
    res.json({ valid: false, error: error.message });
  }
});

app.listen(3000);

// ---------------------------------------------

// product-service.js - Uses the authentication from user-service
const express = require('express');
const axios = require('axios');
const app = express();
app.use(express.json());

const USER_SERVICE_URL = 'http://user-service:3000';
const SERVICE_API_KEY = 'internal-api-key-12345';

// Authenticate users based on JWT token
const authenticateUser = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]; // Bearer token
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  try {
    // Validate token with user-service
    const response = await axios.post(\`\${USER_SERVICE_URL}/internal/validate-token\`, 
      { token },
      { headers: { 'x-api-key': SERVICE_API_KEY } }
    );
    
    if (response.data.valid) {
      req.user = response.data.user;
      next();
    } else {
      res.status(401).json({ error: 'Invalid token' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Authentication service unavailable' });
  }
};

// Protected product endpoints
app.get('/products', authenticateUser, (req, res) => {
  // Return products based on user role/permissions
  res.json({ products: [/* products data */] });
});

app.listen(3001);`,
    options: [
      'Using the same API key for all services',
      'Hardcoded secrets in the service code',
      'No rate limiting on authentication endpoints',
      'All of the above'
    ],
    answer: 3,
    explanation: "This microservice architecture has multiple security issues: 1) It uses a single hardcoded API key ('internal-api-key-12345') shared across all services, creating a single point of failure; 2) Both the JWT secret and service API key are hardcoded in the application code rather than using proper secret management; 3) There's no rate limiting on the authentication endpoints, making them vulnerable to brute force attacks. Additional issues include: no use of HTTPS for service-to-service communication, lack of proper error handling that could leak information, and no consideration for circuit breaking or timeouts when services communicate. A secure design would use unique API keys per service, store secrets in a dedicated vault or environment variables, implement rate limiting, enforce HTTPS, and build in proper resilience patterns."
  },
  {
    id: 'secure-arch-2',
    title: 'Secure File Upload Design',
    description: 'Compare these two file upload implementations. Which one follows secure design principles?',
    difficulty: 'medium',
    category: 'Web Security',
    languages: ['JavaScript', 'Node.js'],
    type: 'comparison',
    vulnerabilityType: 'File Upload Vulnerabilities',
    secureCode: `const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

// File type whitelist
const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx'];
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

// Configure storage
const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    cb(null, path.join(__dirname, '../uploads'));
  },
  filename: function(req, file, cb) {
    // Generate random filename to prevent path traversal
    const randomName = uuidv4() + path.extname(file.originalname).toLowerCase();
    cb(null, randomName);
  }
});

// File filter function
const fileFilter = (req, file, cb) => {
  // Check file extension
  const ext = path.extname(file.originalname).toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return cb(new Error('File type not allowed'), false);
  }
  
  cb(null, true);
};

// Configure upload middleware
const upload = multer({
  storage: storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: fileFilter
});

// Set up virus scanning (mock)
const scanFile = (filePath) => {
  return new Promise((resolve, reject) => {
    console.log(\`Scanning file: \${filePath}\`);
    // In a real implementation, this would call an antivirus API
    setTimeout(() => resolve({ clean: true }), 1000);
  });
};

// Upload endpoint
router.post('/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    // Generate file metadata
    const fileHash = await hashFile(req.file.path);
    
    // Scan file for malware
    const scanResult = await scanFile(req.file.path);
    if (!scanResult.clean) {
      // Delete the file if it's not clean
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'File contains malware' });
    }
    
    // Store file metadata in database
    const metadata = {
      originalName: req.file.originalname,
      filename: req.file.filename,
      mimetype: req.file.mimetype,
      size: req.file.size,
      hash: fileHash,
      uploadedBy: req.user.id,
      uploadDate: new Date()
    };
    
    // Save metadata to database (mock)
    const savedFile = await saveFileMetadata(metadata);
    
    res.json({
      message: 'File uploaded successfully',
      fileId: savedFile.id,
      filename: req.file.filename
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'File upload failed' });
  }
});

// Helper function to hash file contents
async function hashFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    
    stream.on('error', err => reject(err));
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

module.exports = router;`,
    vulnerableCode: `const express = require('express');
const router = express.Router();
const fileUpload = require('express-fileupload');
const path = require('path');
const fs = require('fs');

// Configure middleware
router.use(fileUpload());

// Upload endpoint
router.post('/upload', (req, res) => {
  try {
    if (!req.files || Object.keys(req.files).length === 0) {
      return res.status(400).json({ error: 'No files were uploaded' });
    }
    
    const uploadedFile = req.files.file;
    const uploadPath = path.join(__dirname, '../uploads/', uploadedFile.name);
    
    // Check if file is an image (basic check)
    if (!uploadedFile.mimetype.startsWith('image/')) {
      return res.status(400).json({ error: 'Only image files are allowed' });
    }
    
    // Move the file to the upload directory
    uploadedFile.mv(uploadPath, function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      // Process the uploaded image
      processImage(uploadPath);
      
      res.json({
        message: 'File uploaded successfully',
        filename: uploadedFile.name,
        size: uploadedFile.size
      });
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'File upload failed' });
  }
});

// Simple image processing function
function processImage(filePath) {
  console.log(\`Processing image: \${filePath}\`);
  // In a real app, this might resize, compress, etc.
}

module.exports = router;`,
    answer: 'secure',
    explanation: "The secure implementation has multiple layers of protection: 1) It uses random UUIDs for filenames to prevent path traversal and overwriting; 2) It implements a strict file type whitelist based on file extensions; 3) It sets a maximum file size limit; 4) It scans uploaded files for malware; 5) It calculates a hash of the file for integrity checking; 6) It stores comprehensive metadata about uploads; and 7) It handles errors properly. In contrast, the vulnerable implementation has several security issues: 1) It uses the original filename, enabling path traversal attacks; 2) It relies only on MIME type checking which can be easily bypassed; 3) It has no file size limits; 4) It processes files without scanning for malware; 5) It lacks proper metadata tracking; and 6) It has minimal error handling. These weaknesses could allow attackers to upload malicious files, execute arbitrary code, or overwrite important files on the server."
  }
];
