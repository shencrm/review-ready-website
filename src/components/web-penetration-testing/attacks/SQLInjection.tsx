
import React from 'react';
import { Database } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const SQLInjection: React.FC = () => {
  return (
    <section id="sql-injection" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">SQL Injection</h3>
      <p className="mb-6">
        SQL Injection occurs when untrusted data is sent to an interpreter as part of a command or query,
        tricking the interpreter into executing unintended commands or accessing unauthorized data.
      </p>
      
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
// This returns all users in the database`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure Implementation" 
        code={`// Server-side code
const userId = req.params.id;
const query = "SELECT * FROM users WHERE id = ?";
db.execute(query, [userId]);

// Parameterized queries prevent SQL injection by separating code from data`} 
      />
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Testing for SQL Injection</h4>
      <ul className="list-disc pl-6 space-y-2">
        <li>Input single quotes (') and observe errors</li>
        <li>Test boolean conditions (OR 1=1, OR 1=2)</li>
        <li>Try commenting out the rest of the query (--)</li>
        <li>Use UNION attacks to extract data from other tables</li>
        <li>Test blind SQL injection techniques when no output is visible</li>
      </ul>
    </section>
  );
};

export default SQLInjection;
