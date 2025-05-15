
import { Challenge } from './challenge-types';

export const fileUploadVulnerabilitiesChallenges: Challenge[] = [
  {
    id: 'file-upload-1',
    title: 'Insecure File Upload',
    description: 'This PHP code handles file uploads. What security vulnerabilities are present?',
    difficulty: 'medium',
    category: 'Security Misconfigurations',
    languages: ['PHP'],
    type: 'single',
    vulnerabilityType: 'Unrestricted File Upload',
    code: `<?php
// Handle file upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['uploadedFile'])) {
    $uploadDir = 'uploads/';
    $uploadedFile = $_FILES['uploadedFile'];
    
    // Create uploads directory if it doesn't exist
    if (!file_exists($uploadDir)) {
        mkdir($uploadDir, 0777, true);
    }
    
    // Process the uploaded file
    $fileName = $uploadedFile['name'];
    $fileTmpPath = $uploadedFile['tmp_name'];
    $fileSize = $uploadedFile['size'];
    
    // Generate file path
    $uploadPath = $uploadDir . $fileName;
    
    // Move uploaded file to destination
    if (move_uploaded_file($fileTmpPath, $uploadPath)) {
        echo "File uploaded successfully. Path: $uploadPath";
    } else {
        echo "Error uploading file.";
    }
} else {
    echo "Invalid request.";
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>File Upload</title>
</head>
<body>
    <h1>Upload a File</h1>
    <form action="" method="post" enctype="multipart/form-data">
        <input type="file" name="uploadedFile" />
        <input type="submit" value="Upload" />
    </form>
</body>
</html>`,
    answer: false,
    explanation: "This file upload code has multiple security vulnerabilities: 1) No validation of file types, allowing attackers to upload malicious PHP scripts, shell scripts, or other executable files that could lead to remote code execution, 2) Uses the original user-supplied filename without sanitization, making it vulnerable to directory traversal attacks (e.g., '../config.php'), 3) No file size limit, enabling denial-of-service attacks via uploading extremely large files, 4) Creates the upload directory with excessive permissions (0777), giving everyone read/write/execute access, 5) No check for mime type or file content, allowing content-type spoofing, and 6) Displays the file path in the response, potentially leaking server directory structure."
  },
  {
    id: 'file-upload-2',
    title: 'Secure File Upload Implementation',
    description: 'Compare these two Node.js file upload implementations. Which one is secure?',
    difficulty: 'hard',
    category: 'Security Misconfigurations',
    languages: ['JavaScript', 'Node.js'],
    type: 'comparison',
    vulnerabilityType: 'Unrestricted File Upload',
    secureCode: `const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();

// Set up secure file storage configuration
const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    const uploadDir = path.join(__dirname, 'uploads');
    
    // Ensure directory exists with proper permissions
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { mode: 0o750 });
    }
    
    cb(null, uploadDir);
  },
  filename: function(req, file, cb) {
    // Generate random filename with original extension
    const fileExtension = path.extname(file.originalname).toLowerCase();
    const randomName = crypto.randomBytes(16).toString('hex');
    cb(null, randomName + fileExtension);
  }
});

// Set up file filter
const fileFilter = function(req, file, cb) {
  // Allow only specific image file types
  const allowedTypes = ['.jpg', '.jpeg', '.png', '.gif'];
  const fileExtension = path.extname(file.originalname).toLowerCase();
  
  if (allowedTypes.includes(fileExtension) && 
      /^image\\/(jpeg|jpg|png|gif)$/.test(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only JPG, JPEG, PNG and GIF files are allowed.'), false);
  }
};

// Set up multer with limits
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB max file size
    files: 1 // Max 1 file per request
  }
});

// File upload route
app.post('/upload', (req, res) => {
  upload.single('file')(req, res, function(err) {
    if (err instanceof multer.MulterError) {
      // Handle multer-specific errors
      return res.status(400).json({ error: \`Upload error: \${err.message}\` });
    } else if (err) {
      // Handle other errors
      return res.status(400).json({ error: err.message });
    }
    
    // No file uploaded
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    // Success - but don't return the actual path
    res.json({
      success: true,
      filename: req.file.filename
    });
  });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});`,
    vulnerableCode: `const express = require('express');
const multer = require('multer');
const path = require('path');

const app = express();

// Set up storage configuration
const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function(req, file, cb) {
    cb(null, file.originalname);
  }
});

// Set up multer
const upload = multer({ storage: storage });

// File upload route
app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  res.json({
    success: true,
    filePath: \`/uploads/\${req.file.filename}\`
  });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});`,
    answer: 'secure',
    explanation: "The secure implementation includes multiple file upload security controls: 1) File type validation checking both extension and MIME type, 2) Size limitations to prevent DoS attacks, 3) Randomized filenames to prevent overwriting or guessing files, 4) Proper directory permissions (0o750 instead of default), 5) Error handling for upload issues, 6) Not exposing the actual file path in the response, and 7) Using crypto.randomBytes for secure random name generation. The vulnerable implementation allows uploading any file type without validation, uses the original filename (allowing potential overwriting of files), doesn't limit file size, doesn't check if the upload directory exists with proper permissions, and exposes the file path in the response."
  }
];
