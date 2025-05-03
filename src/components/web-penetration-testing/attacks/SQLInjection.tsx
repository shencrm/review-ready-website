
import React from 'react';
import { Database } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const SQLInjection: React.FC = () => {
  return (
    <section id="sql-injection" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">SQL Injection</h3>
      <p className="mb-6">
        SQL Injection occurs when untrusted data is sent to an interpreter as part of a command or query,
        tricking the interpreter into executing unintended commands or accessing unauthorized data. This is one of the most
        prevalent and dangerous web application vulnerabilities, potentially allowing attackers to view, modify, or delete database data.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">How SQL Injection Works</h4>
      <p className="mb-4">
        SQL injection attacks exploit applications that fail to properly sanitize user input before incorporating it into SQL queries.
        Attackers inject malicious SQL code that changes the logic of the intended query, allowing them to:
      </p>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li>Bypass authentication</li>
        <li>Access sensitive data from the database</li>
        <li>Modify database data (insert, update, delete)</li>
        <li>Execute administration operations on the database</li>
        <li>Retrieve files from the system</li>
        <li>In some cases, issue commands to the operating system</li>
      </ul>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Example Attack</h4>
      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable SQL Query" 
        code={`// Server-side code
const userId = req.params.id;
const query = "SELECT * FROM users WHERE id = " + userId;
db.execute(query);

// Attacker input: 1 OR 1=1
// Resulting query: SELECT * FROM users WHERE id = 1 OR 1=1
// This returns all users in the database

// Another example - Login bypass:
const username = req.body.username;
const password = req.body.password;
const query = "SELECT * FROM users WHERE username = '" + username + 
              "' AND password = '" + password + "'";

// Attacker input: admin' --
// Resulting query: SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything'
// This comments out the password check`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure Implementation" 
        code={`// Server-side code with parameterized queries
const userId = req.params.id;
const query = "SELECT * FROM users WHERE id = ?";
db.execute(query, [userId]);

// Parameterized queries prevent SQL injection by separating code from data

// Using an ORM (Object-Relational Mapping) for extra safety
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

// Safe query using Prisma ORM
const user = await prisma.user.findUnique({
  where: {
    id: parseInt(userId)
  }
});

// Implementing additional controls:
// 1. Use the principle of least privilege for database accounts
// 2. Implement proper input validation (e.g., ensure 'id' is a number)
// 3. Use database stored procedures when possible
// 4. Enable proper error handling to avoid leaking schema details`} 
      />
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Testing for SQL Injection</h4>
      <ul className="list-disc pl-6 space-y-2">
        <li><strong>Single Quote Testing:</strong> Insert a single quote (') to break string literals and observe errors</li>
        <li><strong>Boolean Logic:</strong> Test conditions like OR 1=1, OR 1=2 to alter query logic</li>
        <li><strong>Comments:</strong> Use -- or /* */ to comment out portions of the query</li>
        <li><strong>UNION Attacks:</strong> Use UNION SELECT statements to extract data from other tables</li>
        <li><strong>Time Delays:</strong> Use SLEEP() or similar functions to test for blind SQL injection</li>
        <li><strong>Error-based:</strong> Force errors that reveal database information</li>
        <li><strong>Out-of-band:</strong> Make the database establish connections to external systems</li>
      </ul>
    </section>
  );
};

export default SQLInjection;
