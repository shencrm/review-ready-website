
import { Challenge } from './challenge-types';

export const defensiveCodingChallenges: Challenge[] = [
  {
    id: 'defensive-coding-1',
    title: 'Error Handling Security',
    description: 'Review this API endpoint implementation. What security issue is present in the error handling?',
    difficulty: 'medium',
    category: 'Secure Coding',
    languages: ['JavaScript', 'Node.js'],
    type: 'single',
    vulnerabilityType: 'Information Disclosure',
    code: `const express = require('express');
const router = express.Router();
const db = require('../database');

/**
 * Get user transactions
 * GET /api/users/:userId/transactions
 */
router.get('/users/:userId/transactions', async (req, res) => {
  try {
    const userId = req.params.userId;
    
    // Check if user exists
    const user = await db.query(
      'SELECT * FROM users WHERE id = $1',
      [userId]
    );
    
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Get user transactions
    const transactions = await db.query(
      'SELECT * FROM transactions WHERE user_id = $1 ORDER BY date DESC',
      [userId]
    );
    
    return res.json(transactions.rows);
  } catch (error) {
    console.error('Failed to get transactions:', error);
    
    // Return detailed error to help with debugging
    return res.status(500).json({
      error: 'Database query failed',
      message: error.message,
      stack: error.stack,
      query: error.query,
      parameters: error.parameters
    });
  }
});

module.exports = router;`,
    answer: false,
    explanation: "The code exposes sensitive error details to clients in the catch block, creating a significant security vulnerability. When an error occurs, it returns the error message, stack trace, SQL query, and query parameters in the API response. This information disclosure could help attackers understand the database schema, SQL query structure, and application architecture, aiding in crafting more sophisticated attacks like SQL injection. Additionally, the stack trace might reveal file paths and code structure. A secure implementation would log detailed errors server-side for debugging but only return generic error messages to clients, such as 'An error occurred processing your request' without revealing technical details. Error handling should follow the principle of least privilege by only sharing what users need to know."
  },
  {
    id: 'defensive-coding-2',
    title: 'Secure API Input Validation',
    description: 'Compare these two API implementations. Which one implements proper input validation?',
    difficulty: 'medium',
    category: 'API Security',
    languages: ['JavaScript', 'Node.js'],
    type: 'comparison',
    vulnerabilityType: 'Missing Input Validation',
    secureCode: `const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const { sanitizeBody } = require('express-validator');

/**
 * Create a new product
 * POST /api/products
 */
router.post('/products', [
  // Validate required fields
  check('name')
    .trim()
    .notEmpty().withMessage('Product name is required')
    .isLength({ min: 3, max: 100 }).withMessage('Product name must be between 3 and 100 characters'),
    
  check('description')
    .trim()
    .notEmpty().withMessage('Product description is required')
    .isLength({ max: 1000 }).withMessage('Description cannot exceed 1000 characters'),
    
  check('price')
    .notEmpty().withMessage('Price is required')
    .isFloat({ min: 0.01 }).withMessage('Price must be a positive number'),
    
  check('category')
    .trim()
    .notEmpty().withMessage('Category is required')
    .isIn(['electronics', 'clothing', 'home', 'books', 'toys']).withMessage('Invalid category'),
    
  check('inStock')
    .isBoolean().withMessage('In stock must be a boolean value'),
    
  // Sanitize inputs
  sanitizeBody('name').trim().escape(),
  sanitizeBody('description').trim().escape()
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    // Extract validated data
    const { name, description, price, category, inStock } = req.body;
    
    // Create product in database
    const product = await createProduct({ name, description, price, category, inStock });
    
    return res.status(201).json(product);
  } catch (error) {
    console.error('Error creating product:', error);
    return res.status(500).json({ error: 'Failed to create product' });
  }
});

// Product creation function
async function createProduct(productData) {
  // Database logic would go here
  return { id: 123, ...productData };
}

module.exports = router;`,
    vulnerableCode: `const express = require('express');
const router = express.Router();

/**
 * Create a new product
 * POST /api/products
 */
router.post('/products', async (req, res) => {
  try {
    // Extract product data from request body
    const { name, description, price, category, inStock } = req.body;
    
    // Basic validation
    if (!name || !description || !price) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Create product in database
    const product = await createProduct({ name, description, price, category, inStock: Boolean(inStock) });
    
    return res.status(201).json(product);
  } catch (error) {
    console.error('Error creating product:', error);
    return res.status(500).json({ error: 'Failed to create product' });
  }
});

// Product creation function
async function createProduct(productData) {
  // Database logic would go here
  return { id: 123, ...productData };
}

module.exports = router;`,
    answer: 'secure',
    explanation: "The secure implementation demonstrates comprehensive input validation and sanitization practices using express-validator. It validates all fields with specific criteria: ensuring required fields are present, checking length constraints, validating data types (like price being a positive float), and enforcing enum values for categories. It also sanitizes inputs by trimming whitespace and escaping special characters to prevent XSS attacks. In contrast, the vulnerable implementation only performs minimal validation, checking only if required fields exist without validating their format, type, or content. It doesn't validate or sanitize the description field (potential XSS vector), doesn't check if price is a valid positive number, and doesn't validate the category against allowed values. The secure implementation follows defensive coding principles by never trusting user input and validating all data before processing it."
  }
];
