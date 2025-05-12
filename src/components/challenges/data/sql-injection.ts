
import { Challenge } from './challenge-types';

export const sqlInjectionChallenges: Challenge[] = [
  {
    id: 'sql-injection-1',
    title: 'Basic SQL Injection',
    description: 'Review the code for potential SQL injection vulnerabilities.',
    difficulty: 'easy',
    category: 'Injection Flaws',
    languages: ['PHP'],
    type: 'single',
    vulnerabilityType: 'SQL Injection',
    code: `<?php
// Get user ID from URL parameter
$userId = $_GET['id'];

// Connect to the database
$conn = new mysqli("localhost", "user", "password", "app_db");

// Query user data
$sql = "SELECT * FROM users WHERE id = " . $userId;
$result = $conn->query($sql);

// Display user information
if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    echo "Welcome, " . $row["username"] . "!";
} else {
    echo "User not found.";
}
$conn->close();
?>`,
    answer: false,
    explanation: "This code is vulnerable to SQL injection because it directly concatenates user input into the SQL query without any sanitization. An attacker could inject malicious SQL code by manipulating the 'id' parameter, for example by using '1 OR 1=1' to retrieve all users or '1; DROP TABLE users;' to delete the users table."
  },
  {
    id: 'sql-injection-2',
    title: 'SQL Injection in Java',
    description: 'Compare these two Java database query implementations. Which one is secure against SQL injection?',
    difficulty: 'medium',
    category: 'Injection Flaws',
    languages: ['Java'],
    type: 'comparison',
    vulnerabilityType: 'SQL Injection',
    secureCode: `import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class UserDAO {
    public User getUserById(Connection conn, String userId) throws SQLException {
        User user = null;
        String sql = "SELECT * FROM users WHERE id = ?";
        
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, userId);
            ResultSet rs = stmt.executeQuery();
            
            if (rs.next()) {
                user = new User();
                user.setId(rs.getString("id"));
                user.setUsername(rs.getString("username"));
                user.setEmail(rs.getString("email"));
            }
        }
        
        return user;
    }
}`,
    vulnerableCode: `import java.sql.Connection;
import java.sql.Statement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class UserDAO {
    public User getUserById(Connection conn, String userId) throws SQLException {
        User user = null;
        String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
        
        try (Statement stmt = conn.createStatement()) {
            ResultSet rs = stmt.executeQuery(sql);
            
            if (rs.next()) {
                user = new User();
                user.setId(rs.getString("id"));
                user.setUsername(rs.getString("username"));
                user.setEmail(rs.getString("email"));
            }
        }
        
        return user;
    }
}`,
    answer: 'secure',
    explanation: "The secure version uses a PreparedStatement with parameter binding (?), which sanitizes user input and prevents SQL injection. The vulnerable version directly concatenates the userId into the SQL statement, making it vulnerable to SQL injection attacks."
  }
];
