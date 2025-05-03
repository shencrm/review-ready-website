
import React from 'react';
import { Database } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const GraphQLVulnerabilities: React.FC = () => {
  return (
    <section id="graphql" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">GraphQL Vulnerabilities</h3>
      <p className="mb-6">
        GraphQL is a query language and runtime for APIs that enables clients to request exactly the data they need.
        While powerful, GraphQL introduces unique security concerns that differ from traditional REST APIs,
        including introspection risks, denial of service, authorization flaws, and injection attacks.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Common Vulnerabilities</h4>
      <ul className="list-disc pl-6 space-y-2 mb-4">
        <li><strong>Introspection Attacks</strong>: Exposing schema details in production</li>
        <li><strong>Denial of Service</strong>: Complex queries causing server overload</li>
        <li><strong>Insufficient Authorization</strong>: Field-level access control issues</li>
        <li><strong>Injection Vulnerabilities</strong>: Passing unsanitized inputs to resolvers</li>
        <li><strong>Batching Attacks</strong>: Bypassing rate limits via batched queries</li>
      </ul>
      
      <CodeExample 
        language="graphql" 
        isVulnerable={true}
        title="Introspection Query Vulnerability" 
        code={`# This introspection query reveals the entire API structure
query IntrospectionQuery {
  __schema {
    queryType {
      name
    }
    mutationType {
      name
    }
    types {
      name
      kind
      fields {
        name
        args {
          name
          type {
            name
            kind
          }
        }
      }
    }
  }
}

# A malicious nested query that could cause DoS
query NestedQuery {
  posts {
    comments {
      author {
        posts {
          comments {
            author {
              posts {
                comments {
                  # Deeply nested query causing server strain
                }
              }
            }
          }
        }
      }
    }
  }
}`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure GraphQL Implementation" 
        code={`const { ApolloServer } = require('apollo-server-express');
const { depthLimit } = require('graphql-depth-limit');
const { createComplexityLimitRule } = require('graphql-validation-complexity');

// Create Apollo Server with security configurations
const server = new ApolloServer({
  typeDefs,
  resolvers,
  // Disable introspection in production
  introspection: process.env.NODE_ENV !== 'production',
  // Limit query depth to prevent deeply nested queries
  validationRules: [
    depthLimit(5),
    createComplexityLimitRule(1000, {
      // Customize field complexity
      scalarCost: 1,
      objectCost: 2,
      listFactor: 10
    })
  ],
  // Add authentication and authorization context
  context: ({ req }) => {
    // Get auth token from request
    const token = req.headers.authorization || '';
    // Validate token and get user info
    const user = validateToken(token);
    return { user };
  },
  formatError: (error) => {
    // Log the error internally
    console.error(error);
    
    // Return a generic error message to clients
    return {
      message: process.env.NODE_ENV === 'production' 
        ? 'An error occurred during execution'
        : error.message,
      // Only include locations and path in development
      locations: process.env.NODE_ENV !== 'production' ? error.locations : undefined,
      path: process.env.NODE_ENV !== 'production' ? error.path : undefined,
    };
  }
});

// Example secure resolver with proper authorization
const resolvers = {
  Query: {
    // Field-level authorization
    user: (_, { id }, context) => {
      // Check if user is authenticated
      if (!context.user) {
        throw new AuthenticationError('You must be logged in');
      }
      
      // Check if user has permission to access this data
      if (context.user.id !== id && !context.user.isAdmin) {
        throw new ForbiddenError('Not authorized to access this data');
      }
      
      // If authorized, return the data
      return getUserById(id);
    }
  },
  Mutation: {
    // Use validation and sanitization for inputs
    createPost: (_, { input }, context) => {
      // Authentication check
      if (!context.user) {
        throw new AuthenticationError('You must be logged in');
      }
      
      // Validate and sanitize input
      const sanitizedInput = sanitizeInput(input);
      
      // Create post with validated data
      return createPost(sanitizedInput, context.user.id);
    }
  }
};

// Additional security measures:
// 1. Use persisted queries to limit accepted queries
// 2. Implement query allowlisting
// 3. Use proper rate limiting
// 4. Set timeouts for query execution
// 5. Implement proper error handling to prevent information leakage`} 
      />
    </section>
  );
};

export default GraphQLVulnerabilities;
