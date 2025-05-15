
import { Challenge } from './challenge-types';

export const containerSecurityChallenges: Challenge[] = [
  {
    id: 'container-security-1',
    title: 'Docker Image Security',
    description: 'Review this Dockerfile for a Node.js application. Is it following security best practices?',
    difficulty: 'medium',
    category: 'Container Security',
    languages: ['Docker'],
    type: 'single',
    vulnerabilityType: 'Insecure Container Configuration',
    code: `FROM node:latest

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
COPY package*.json ./
RUN npm install

# Bundle app source
COPY . .

# Expose port
EXPOSE 3000

# Run as root user (default)
CMD [ "node", "server.js" ]`,
    answer: false,
    explanation: "This Dockerfile has several security issues: 1) It uses the 'latest' tag which makes builds unpredictable and can introduce unexpected vulnerabilities, 2) It runs the container as root (default) which is a security risk if the application is compromised, 3) It installs all dependencies including dev dependencies, 4) It doesn't use multi-stage builds to minimize attack surface, and 5) It copies all files without considering what might be sensitive or unnecessary. To fix these issues: use a specific version tag, run as a non-root user, use npm ci --only=production, implement multi-stage builds, and use .dockerignore to exclude sensitive files."
  },
  {
    id: 'container-security-2',
    title: 'Kubernetes Security Context',
    description: 'Compare these two Kubernetes pod definitions. Which one follows security best practices?',
    difficulty: 'hard',
    category: 'Container Security',
    languages: ['Kubernetes', 'YAML'],
    type: 'comparison',
    vulnerabilityType: 'Insecure Pod Configuration',
    secureCode: `apiVersion: v1
kind: Pod
metadata:
  name: secure-webapp
spec:
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: webapp
    image: mycompany/webapp:1.2.3
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
      readOnlyRootFilesystem: true
    resources:
      limits:
        cpu: "1"
        memory: "512Mi"
      requests:
        cpu: "0.5"
        memory: "256Mi"
    ports:
    - containerPort: 8080
    volumeMounts:
    - mountPath: /tmp
      name: tmp-volume
  volumes:
  - name: tmp-volume
    emptyDir: {}`,
    vulnerableCode: `apiVersion: v1
kind: Pod
metadata:
  name: webapp
spec:
  containers:
  - name: webapp
    image: mycompany/webapp:latest
    ports:
    - containerPort: 8080
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host-volume
  volumes:
  - name: host-volume
    hostPath:
      path: /
      type: Directory`,
    answer: 'secure',
    explanation: "The secure configuration follows multiple Kubernetes security best practices: 1) Enforces running as non-root user, 2) Uses a specific image version tag (1.2.3) instead of 'latest', 3) Drops all Linux capabilities and prevents privilege escalation, 4) Mounts the filesystem as read-only with a separate writable volume just for /tmp, 5) Applies resource limits to prevent resource exhaustion attacks, 6) Enables seccomp profiles which restrict system calls. In contrast, the vulnerable configuration runs as privileged (essentially equivalent to root on the host), uses the unpredictable 'latest' tag, and mounts the entire host filesystem into the container, which could allow container escape."
  }
];
