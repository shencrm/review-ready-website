
import React from 'react';
import { Database } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const NoSQLInjection: React.FC = () => {
  return (
    <div className="mb-12">
      <h4 className="text-xl font-semibold mb-6 flex items-center gap-2">
        <Database className="h-6 w-6 text-cybr-primary" />
        NoSQL Injection
      </h4>
      
      <div className="mb-6">
        <h5 className="text-lg font-semibold mb-3">What is NoSQL Injection?</h5>
        <p className="mb-4">
          NoSQL injection allows attackers to manipulate NoSQL database queries by injecting malicious input,
          potentially bypassing authentication, accessing unauthorized data, or executing arbitrary database operations.
          Unlike SQL injection, NoSQL injection exploits the flexible schema and query structure of NoSQL databases.
        </p>
        <p className="mb-4">
          NoSQL databases like MongoDB, CouchDB, and others use different query languages and data structures,
          creating new attack vectors. The injection can occur through JSON manipulation, operator injection,
          or by exploiting the dynamic nature of NoSQL query construction.
        </p>
      </div>

      <div className="mb-6">
        <h5 className="text-lg font-semibold mb-3">Attacker Goals</h5>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>Authentication Bypass:</strong> Circumvent login mechanisms using NoSQL operator injection</li>
          <li><strong>Data Extraction:</strong> Access sensitive documents and collections without authorization</li>
          <li><strong>Privilege Escalation:</strong> Modify user roles or permissions stored in NoSQL documents</li>
          <li><strong>Data Manipulation:</strong> Insert, update, or delete unauthorized data</li>
          <li><strong>Denial of Service:</strong> Execute resource-intensive queries to overwhelm the database</li>
          <li><strong>Information Disclosure:</strong> Extract database schema, collection names, and sensitive data</li>
        </ul>
      </div>

      <div className="mb-6">
        <h5 className="text-lg font-semibold mb-3">Vulnerable Components</h5>
        <ul className="list-disc pl-6 space-y-2">
          <li><strong>MongoDB Applications:</strong> Using dynamic query construction</li>
          <li><strong>CouchDB Interfaces:</strong> Views and queries built from user input</li>
          <li><strong>Redis Applications:</strong> Commands constructed from user data</li>
          <li><strong>DocumentDB Services:</strong> AWS DocumentDB and similar services</li>
          <li><strong>API Endpoints:</strong> REST APIs that translate HTTP parameters to NoSQL queries</li>
          <li><strong>Search Functions:</strong> Applications using NoSQL for search and filtering</li>
        </ul>
      </div>

      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable MongoDB Authentication" 
        code={`// Node.js with MongoDB - vulnerable to NoSQL injection
const express = require('express');
const { MongoClient } = require('mongodb');

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Vulnerable: Direct object insertion without validation
    const query = { 
      username: username, 
      password: password 
    };
    
    const user = await db.collection('users').findOne(query);
    
    if (user) {
      // Set session and respond
      req.session.userId = user._id;
      res.json({ success: true, message: 'Login successful' });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

/*
ATTACK PAYLOADS:

1. Authentication Bypass (JSON):
POST /login
Content-Type: application/json
{
  "username": "admin",
  "password": { "$ne": null }
}
This creates query: { username: "admin", password: { $ne: null } }
Matches any user 'admin' with a non-null password

2. Authentication Bypass (URL-encoded):
POST /login
username=admin&password[$ne]=
Creates: { username: "admin", password: { $ne: "" } }

3. Data Extraction:
GET /users?department[$ne]=&role[$exists]=true
Creates: { department: { $ne: "" }, role: { $exists: true } }
Returns all users with any department and existing role
*/`} 
      />

      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure NoSQL Implementation" 
        code={`const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const joi = require('joi');

// Input validation schemas
const loginSchema = joi.object({
  username: joi.string().alphanum().min(3).max(30).required(),
  password: joi.string().min(6).max(128).required()
});

app.post('/login', async (req, res) => {
  try {
    // 1. Validate input structure and types
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid input format' 
      });
    }
    
    const { username, password } = value;
    
    // 2. Use only string values in query, never objects
    const query = { 
      username: String(username).toLowerCase(),
      active: true 
    };
    
    // 3. Find user first, then verify password separately
    const user = await db.collection('users').findOne(query, {
      projection: { password: 1, username: 1, role: 1, _id: 1 }
    });
    
    if (!user) {
      // Use consistent timing to prevent username enumeration
      await bcrypt.compare('dummy', '$2b$10$dummyhashtopreventtimingattacks');
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }
    
    // 4. Use bcrypt for password verification
    const isValidPassword = await bcrypt.compare(password, user.password);
    
    if (!isValidPassword) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }
    
    // 5. Create secure session
    req.session.userId = user._id.toString();
    req.session.role = user.role;
    
    res.json({ 
      success: true, 
      message: 'Login successful',
      user: { 
        id: user._id, 
        username: user.username, 
        role: user.role 
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});`} 
      />

      <div className="mb-6">
        <h5 className="text-lg font-semibold mb-3">Environment-Specific Considerations</h5>
        <div className="space-y-4">
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h6 className="font-semibold text-cybr-primary mb-2">MongoDB</h6>
            <ul className="list-disc pl-6 space-y-1">
              <li>Disable JavaScript execution ($where operator) in production</li>
              <li>Use MongoDB's built-in validation rules and schema validation</li>
              <li>Enable authentication and use role-based access control</li>
              <li>Regularly update MongoDB to patch security vulnerabilities</li>
            </ul>
          </div>
          
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h6 className="font-semibold text-cybr-primary mb-2">Node.js Applications</h6>
            <ul className="list-disc pl-6 space-y-1">
              <li>Use parameterized queries and object validation libraries</li>
              <li>Implement input sanitization middleware</li>
              <li>Use TypeScript for better type safety</li>
              <li>Enable strict mode and proper error handling</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NoSQLInjection;
