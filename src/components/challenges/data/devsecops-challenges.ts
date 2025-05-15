
import { Challenge } from './challenge-types';

export const devSecOpsChallenges: Challenge[] = [
  {
    id: 'devsecops-1',
    title: 'Insecure Dependency Management',
    description: 'Review this GitHub workflow file. What security issue can you identify?',
    difficulty: 'medium',
    category: 'DevSecOps',
    languages: ['YAML'],
    type: 'multiple-choice',
    vulnerabilityType: 'Supply Chain Security',
    code: `name: Build and Deploy

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Node.js
      uses: actions/setup-node@v2
      with:
        node-version: 16
        
    - name: Install dependencies
      run: npm install
      
    - name: Run tests
      run: npm test
      
    - name: Build application
      run: npm run build
      
    - name: Deploy to production
      if: github.event_name == 'push' && github.ref == 'refs/heads/main'
      run: |
        echo "Deploying to production server..."
        curl -X POST "https://api.example.com/deploy" \\
          -H "Authorization: Bearer ${{ secrets.DEPLOY_TOKEN }}" \\
          -H "Content-Type: application/json" \\
          -d '{"version": "${{ github.sha }}", "environment": "production"}'`,
    options: [
      'No dependency vulnerability scanning',
      'Hardcoded deployment credentials',
      'Unrestricted npm install without locked dependencies',
      'Missing code quality checks'
    ],
    answer: 2,
    explanation: "The workflow has a significant security issue: it uses an unrestricted 'npm install' without dependency locking (no package-lock.json or npm ci command). This creates a supply chain security risk because it may install different package versions between environments or allow compromised newer versions of dependencies to be automatically installed. An attacker who compromises a dependency could execute code in the build environment or even in production. To fix this, the workflow should use 'npm ci' with a package-lock.json file to ensure consistent, locked dependencies. Additionally, implementing vulnerability scanning with tools like npm audit, Snyk, or Dependabot would further improve security by detecting known vulnerabilities in dependencies."
  },
  {
    id: 'devsecops-2',
    title: 'Docker Security Configuration',
    description: 'Review this Dockerfile for a Node.js application. What security best practice is being violated?',
    difficulty: 'medium',
    category: 'Container Security',
    languages: ['Docker'],
    type: 'multiple-choice',
    vulnerabilityType: 'Container Security',
    code: `FROM node:16

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
COPY package*.json ./
RUN npm install

# Bundle app source
COPY . .

# Expose port
EXPOSE 3000

# Run as root user
USER root

# Start application
CMD ["node", "server.js"]`,
    options: [
      'Using a specific Node version tag instead of latest',
      'Running the container as root user',
      'Copying all files instead of only necessary ones',
      'Not setting NODE_ENV to production'
    ],
    answer: 1,
    explanation: "The Dockerfile explicitly sets 'USER root' (although even without this line, containers run as root by default), which violates the principle of least privilege. Running containers as root gives the application unnecessary privileges and increases the security risk if the container is compromised - an attacker could potentially escape the container and gain access to the host system. The correct approach is to create a non-root user and switch to it before running the application. For example, add these lines before the CMD instruction: 'RUN groupadd -r nodeuser && useradd -r -g nodeuser nodeuser' and 'USER nodeuser'. While the other options are also good practices to follow, running as root is the most critical security issue."
  }
];
