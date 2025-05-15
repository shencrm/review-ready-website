
import { Challenge } from './challenge-types';

export const containerSecurityChallenges: Challenge[] = [
  {
    id: 'container-security-1',
    title: 'Docker Container Security',
    description: 'Compare these two Dockerfiles. Which one follows security best practices?',
    difficulty: 'medium',
    category: 'Container Security',
    languages: ['Docker'],
    type: 'comparison',
    vulnerabilityType: 'Container Security',
    secureCode: `# Use specific version of official slim base image
FROM node:18-slim

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set working directory
WORKDIR /app

# Copy package files first (for better layer caching)
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application code
COPY --chown=appuser:appuser . .

# Set proper permissions
RUN chmod -R 755 /app

# Remove unnecessary packages and files
RUN apt-get update && apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Verify no vulnerabilities in packages
RUN npm audit

# Health check
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:3000/health || exit 1

# Switch to non-root user
USER appuser

# Expose only necessary port
EXPOSE 3000

# Configure as read-only file system with temporary exceptions
CMD ["node", "--read-only-mode", "server.js"]`,
    vulnerableCode: `# Use base image without version
FROM node

# Set working directory
WORKDIR /app

# Copy all files
COPY . .

# Install dependencies
RUN npm install

# Run with root user (default)
CMD ["npm", "start"]`,
    answer: 'secure',
    explanation: "The secure Dockerfile implements multiple security best practices: 1) Uses a specific version of a slim image to reduce attack surface, 2) Creates and uses a non-root user, 3) Uses multi-stage build for better layer caching, 4) Installs only production dependencies with npm ci, 5) Sets proper file ownership and permissions, 6) Removes unnecessary packages and files, 7) Runs npm audit to check for vulnerabilities, 8) Implements a health check, 9) Exposes only necessary ports, and 10) Configures read-only filesystem. The vulnerable Dockerfile has several issues: uses an unversioned image, runs as root, copies all files including potential secrets, uses npm install instead of npm ci, and doesn't clean up unnecessary files."
  },
  {
    id: 'container-security-2',
    title: 'Kubernetes Pod Security',
    description: 'Review this Kubernetes Pod deployment YAML. Is it securely configured?',
    difficulty: 'hard',
    category: 'Container Security',
    languages: ['Kubernetes', 'YAML'],
    type: 'single',
    vulnerabilityType: 'Kubernetes Security',
    code: `apiVersion: v1
kind: Pod
metadata:
  name: app-pod
  labels:
    app: myapp
spec:
  containers:
  - name: app-container
    image: myapp:latest
    ports:
    - containerPort: 8080
    resources:
      limits:
        cpu: "1"
        memory: "512Mi"
      requests:
        cpu: "0.5"
        memory: "256Mi"
    securityContext:
      privileged: true
      allowPrivilegeEscalation: true
      capabilities:
        add: ["NET_ADMIN", "SYS_ADMIN"]
    volumeMounts:
    - name: host-vol
      mountPath: /host
    env:
    - name: DB_PASSWORD
      value: "super-secret-password"
    - name: API_KEY
      value: "api-key-12345"
  volumes:
  - name: host-vol
    hostPath:
      path: /
      type: Directory
  hostNetwork: true
  hostPID: true
  hostIPC: true`,
    answer: false,
    explanation: "This Kubernetes Pod has multiple critical security issues: 1) It uses 'privileged: true' giving containers full access to host resources, 2) 'allowPrivilegeEscalation: true' lets processes gain more privileges than their parent, 3) It adds dangerous capabilities like SYS_ADMIN, 4) It mounts the entire host filesystem (/) into the container, 5) It embeds secrets directly in the configuration rather than using Kubernetes Secrets, 6) It uses hostNetwork, hostPID, and hostIPC which share host namespaces with the container, 7) It uses the 'latest' tag which is mutable and can lead to unexpected changes, and 8) It lacks network policies, liveness/readiness probes, and proper resource quotas. A secure configuration would use non-privileged containers, avoid host mounts, use Kubernetes Secrets, disable privilege escalation, follow least privilege principles, and implement proper network isolation."
  }
];
