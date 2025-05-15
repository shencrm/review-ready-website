
import { Challenge } from './challenge-types';

export const graphqlSecurityChallenges: Challenge[] = [
  {
    id: 'graphql-security-1',
    title: 'GraphQL Security Vulnerabilities',
    description: 'This GraphQL API has several security issues. Identify the most critical vulnerability.',
    difficulty: 'hard',
    category: 'API Security',
    languages: ['JavaScript', 'GraphQL', 'Node.js'],
    type: 'multiple-choice',
    vulnerabilityType: 'GraphQL Security',
    code: `const express = require('express');
const { ApolloServer, gql } = require('apollo-server-express');

// GraphQL schema
const typeDefs = gql\`
  type User {
    id: ID!
    username: String!
    email: String!
    password: String!
    isAdmin: Boolean!
    creditCardNumber: String
  }

  type Query {
    user(id: ID!): User
    allUsers: [User]
  }

  type Mutation {
    createUser(username: String!, email: String!, password: String!): User
    updateUser(id: ID!, username: String, email: String): User
    deleteUser(id: ID!): Boolean
  }
\`;

// Mock database
const users = [
  { id: "1", username: "admin", email: "admin@example.com", password: "admin123", isAdmin: true, creditCardNumber: "1234-5678-9012-3456" },
  { id: "2", username: "user1", email: "user1@example.com", password: "user123", isAdmin: false, creditCardNumber: "2345-6789-0123-4567" }
];

// Resolvers
const resolvers = {
  Query: {
    user: (_, { id }) => users.find(user => user.id === id),
    allUsers: () => users
  },
  Mutation: {
    createUser: (_, { username, email, password }) => {
      const newUser = {
        id: String(users.length + 1),
        username,
        email,
        password,
        isAdmin: false
      };
      users.push(newUser);
      return newUser;
    },
    updateUser: (_, { id, ...updates }) => {
      const userIndex = users.findIndex(user => user.id === id);
      if (userIndex === -1) return null;
      
      const updatedUser = { ...users[userIndex], ...updates };
      users[userIndex] = updatedUser;
      return updatedUser;
    },
    deleteUser: (_, { id }) => {
      const userIndex = users.findIndex(user => user.id === id);
      if (userIndex === -1) return false;
      
      users.splice(userIndex, 1);
      return true;
    }
  }
};

async function startServer() {
  const server = new ApolloServer({ 
    typeDefs, 
    resolvers,
    playground: true,
    introspection: true
  });
  
  const app = express();
  
  await server.start();
  server.applyMiddleware({ app });
  
  app.listen({ port: 4000 }, () =>
    console.log(\`Server ready at http://localhost:4000\${server.graphqlPath}\`)
  );
}

startServer();`,
    options: [
      'No rate limiting on GraphQL operations',
      'Password and credit card information exposed in the schema',
      'No authentication checks on resolvers',
      'GraphQL playground enabled in production'
    ],
    answer: 2,
    explanation: "The most critical vulnerability is the lack of authentication checks in the resolvers. Any client can query for any user's sensitive information (including passwords and credit card numbers) or perform mutations like updating or deleting users without authentication. While all the listed options are concerning security issues, the lack of authentication is the most severe as it completely bypasses any access control. This vulnerability should be fixed by implementing an authentication middleware that verifies user tokens before allowing access to sensitive operations. The code should also not expose sensitive fields like passwords and credit card numbers in the schema, disable introspection and playground in production, and implement rate limiting to prevent abuse."
  }
];
