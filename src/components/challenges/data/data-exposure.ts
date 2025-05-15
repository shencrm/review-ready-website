
import { Challenge } from './challenge-types';

export const dataExposureChallenges: Challenge[] = [
  {
    id: 'data-exposure-1',
    title: 'Sensitive Data Exposure in API',
    description: 'This Node.js API returns user data. Does it expose sensitive information?',
    difficulty: 'medium',
    category: 'Sensitive Data Exposure',
    languages: ['JavaScript', 'Node.js'],
    type: 'single',
    vulnerabilityType: 'Data Exposure',
    code: `const express = require('express');
const app = express();

// Mock database of users
const users = [
  {
    id: 1,
    username: 'john_doe',
    email: 'john@example.com',
    password: '$2a$10$V4rJC1beIiJDVFGDsE/taebZbuuwtWZX0nL5jsHYF5HXJD7tcpGuS',
    ssn: '123-45-6789',
    creditCard: '4111-1111-1111-1111',
    role: 'user',
    apiKey: 'sk_live_abcdef123456',
    lastLogin: '2023-05-15T10:30:00Z',
    lastLoginIp: '192.168.1.1'
  },
  {
    id: 2,
    username: 'jane_smith',
    email: 'jane@example.com',
    password: '$2a$10$X3Gt9je/Mb5CW.WcjTJ5L.AU5CDYeo5UJ2CsXCIcGvz1HLxq2/4WW',
    ssn: '987-65-4321',
    creditCard: '5555-5555-5555-4444',
    role: 'admin',
    apiKey: 'sk_live_wxyz7890',
    lastLogin: '2023-05-14T08:15:00Z',
    lastLoginIp: '192.168.1.2'
  }
];

// API endpoint to get user details
app.get('/api/users/:id', (req, res) => {
  const userId = parseInt(req.params.id);
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  // Return user data
  res.json(user);
});

// API endpoint to get all users
app.get('/api/users', (req, res) => {
  res.json(users);
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});`,
    answer: false,
    explanation: "This API exposes highly sensitive user data including password hashes, Social Security Numbers (SSN), credit card numbers, and API keys. The endpoint directly returns the entire user objects without filtering sensitive fields. This violates security best practices and likely regulatory requirements like GDPR, PCI-DSS, and HIPAA. To fix this, implement a data sanitization layer that filters out sensitive information before sending responses, only returning necessary fields like id, username, and email. Additionally, sensitive endpoints should require proper authentication and authorization, and responses should be secured with HTTPS."
  },
  {
    id: 'data-exposure-2',
    title: 'Error Handling and Information Leakage',
    description: 'Compare these two error handling implementations in a Java application. Which one prevents information leakage?',
    difficulty: 'easy',
    category: 'Sensitive Data Exposure',
    languages: ['Java'],
    type: 'comparison',
    vulnerabilityType: 'Error Handling',
    secureCode: `import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class UserService {
    private static final Logger logger = Logger.getLogger(UserService.class.getName());
    
    public boolean updateUserProfile(int userId, String email, String address) {
        Connection conn = null;
        PreparedStatement stmt = null;
        
        try {
            conn = DatabaseUtil.getConnection();
            
            String sql = "UPDATE users SET email = ?, address = ? WHERE user_id = ?";
            stmt = conn.prepareStatement(sql);
            stmt.setString(1, email);
            stmt.setString(2, address);
            stmt.setInt(3, userId);
            
            int rowsAffected = stmt.executeUpdate();
            return rowsAffected > 0;
            
        } catch (SQLException e) {
            // Log the detailed error for server-side debugging
            logger.log(Level.SEVERE, "Database error occurred", e);
            
            // Return a generic error message to the client
            throw new ServiceException("An error occurred while updating your profile. Please try again later.");
            
        } finally {
            // Close resources properly
            try {
                if (stmt != null) stmt.close();
                if (conn != null) conn.close();
            } catch (SQLException e) {
                logger.log(Level.WARNING, "Error closing database resources", e);
            }
        }
    }
    
    // Custom exception that doesn't expose implementation details
    public static class ServiceException extends RuntimeException {
        public ServiceException(String message) {
            super(message);
        }
    }
}`,
    vulnerableCode: `import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class UserService {
    
    public boolean updateUserProfile(int userId, String email, String address) {
        Connection conn = null;
        PreparedStatement stmt = null;
        
        try {
            conn = DatabaseUtil.getConnection();
            
            String sql = "UPDATE users SET email = ?, address = ? WHERE user_id = ?";
            stmt = conn.prepareStatement(sql);
            stmt.setString(1, email);
            stmt.setString(2, address);
            stmt.setInt(3, userId);
            
            int rowsAffected = stmt.executeUpdate();
            return rowsAffected > 0;
            
        } catch (SQLException e) {
            // Print stack trace to console
            e.printStackTrace();
            
            // Return the detailed error message to the client
            throw new RuntimeException("SQL error: " + e.getMessage() + 
                                      " SQL State: " + e.getSQLState() + 
                                      " Error Code: " + e.getErrorCode());
            
        } finally {
            // Close resources (improperly handled)
            try {
                if (stmt != null) stmt.close();
                if (conn != null) conn.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }
}`,
    answer: 'secure',
    explanation: "The secure implementation prevents information leakage by: 1) Using proper logging instead of printStackTrace() which could expose sensitive information to console logs, 2) Creating a custom ServiceException that returns a generic error message to users without revealing implementation details, database structure, or SQL errors, 3) Properly logging detailed error information server-side for debugging purposes, and 4) Handling resource cleanup properly in the finally block. The vulnerable implementation directly exposes SQL error details including SQL state and error codes to the client, which could reveal database type, schema information, and potentially SQL injection vulnerabilities."
  }
];
