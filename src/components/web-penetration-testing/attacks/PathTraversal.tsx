
import React from 'react';
import { File } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const PathTraversal: React.FC = () => {
  return (
    <section id="file-traversal" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">File Inclusion/Path Traversal</h3>
      <p className="mb-6">
        Path traversal (also known as directory traversal) attacks exploit insufficient input validation to 
        access files and directories stored outside the intended directory. By manipulating variables that 
        reference files with "dot-dot-slash (../)" sequences and variations, attackers can access arbitrary files.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Example Attack</h4>
      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable File Access" 
        code={`// Node.js example with path traversal vulnerability
const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

// Vulnerable endpoint that serves files
app.get('/download', (req, res) => {
  const fileName = req.query.file;
  const filePath = path.join(__dirname, 'public/files', fileName);
  
  // Vulnerable: No validation if the resulting path is within intended directory
  fs.readFile(filePath, (err, data) => {
    if (err) {
      return res.status(404).send('File not found');
    }
    res.send(data);
  });
});

// Attacker input: ../../etc/passwd
// This could access files outside the intended directory`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure Implementation" 
        code={`// Secure version with path validation
const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

app.get('/download', (req, res) => {
  const fileName = req.query.file;
  
  // Validate filename format (e.g., only allow alphanumeric and some special chars)
  if (!fileName || /[^a-zA-Z0-9._-]/.test(fileName)) {
    return res.status(400).send('Invalid filename');
  }
  
  const publicDir = path.resolve(__dirname, 'public/files');
  const filePath = path.join(publicDir, fileName);
  
  // Verify the resolved path is within the intended directory
  if (!filePath.startsWith(publicDir)) {
    return res.status(403).send('Access denied');
  }
  
  fs.readFile(filePath, (err, data) => {
    if (err) {
      return res.status(404).send('File not found');
    }
    res.send(data);
  });
});`} 
      />
    </section>
  );
};

export default PathTraversal;
