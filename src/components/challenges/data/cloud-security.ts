
import { Challenge } from './challenge-types';

export const cloudSecurityChallenges: Challenge[] = [
  {
    id: 'cloud-security-1',
    title: 'AWS S3 Bucket Policy',
    description: 'Review this AWS S3 bucket policy. Is it securely configured?',
    difficulty: 'medium',
    category: 'Cloud Security',
    languages: ['AWS', 'JSON'],
    type: 'single',
    vulnerabilityType: 'Insecure Cloud Storage',
    code: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": [
        "arn:aws:s3:::example-bucket/*"
      ]
    },
    {
      "Sid": "AllowUpload",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:user/developer"
      },
      "Action": [
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::example-bucket/*"
      ]
    }
  ]
}`,
    answer: false,
    explanation: "This S3 bucket policy has security issues: 1) It allows public read access to all objects in the bucket by setting Principal to '*', which means anyone on the internet can read the bucket's contents, 2) There's no condition to enforce encryption in transit (using HTTPS), 3) It doesn't enforce object encryption at rest, 4) It doesn't include any restrictions based on IP ranges, VPC endpoints, or request conditions. This configuration could lead to sensitive data exposure if confidential files are uploaded to the bucket. Public access should be restricted unless absolutely necessary, and additional security controls should be implemented."
  },
  {
    id: 'cloud-security-2',
    title: 'Azure Function Security',
    description: 'Compare these two Azure Functions configurations. Which one is more secure?',
    difficulty: 'medium',
    category: 'Cloud Security',
    languages: ['Azure', 'JSON'],
    type: 'comparison',
    vulnerabilityType: 'Insecure Cloud Configuration',
    secureCode: `// host.json
{
  "version": "2.0",
  "functionTimeout": "00:05:00",
  "logging": {
    "logLevel": {
      "default": "Information",
      "Host.Results": "Error",
      "Function": "Error"
    },
    "applicationInsights": {
      "samplingSettings": {
        "isEnabled": true,
        "excludedTypes": "Request"
      }
    }
  },
  "managedDependency": {
    "enabled": true
  },
  "extensionBundle": {
    "id": "Microsoft.Azure.Functions.ExtensionBundle",
    "version": "[2.*, 3.0.0)"
  },
  "http": {
    "routePrefix": "api",
    "maxOutstandingRequests": 200,
    "maxConcurrentRequests": 100,
    "dynamicThrottlesEnabled": true
  }
}

// function.json
{
  "bindings": [
    {
      "authLevel": "function",
      "type": "httpTrigger",
      "direction": "in",
      "name": "req",
      "methods": ["post"],
      "route": "secure-endpoint"
    },
    {
      "type": "http",
      "direction": "out",
      "name": "res"
    }
  ]
}`,
    vulnerableCode: `// host.json
{
  "version": "2.0",
  "functionTimeout": "00:10:00",
  "logging": {
    "logLevel": {
      "default": "Debug"
    }
  },
  "http": {
    "routePrefix": "api"
  }
}

// function.json
{
  "bindings": [
    {
      "authLevel": "anonymous",
      "type": "httpTrigger",
      "direction": "in",
      "name": "req",
      "methods": ["get", "post", "put", "delete"],
      "route": "user-data"
    },
    {
      "type": "http",
      "direction": "out",
      "name": "res"
    }
  ]
}`,
    answer: 'secure',
    explanation: "The secure configuration improves security in several ways: 1) It uses 'function' authentication level requiring an API key, while the vulnerable version uses 'anonymous' allowing unauthenticated access, 2) It restricts HTTP methods to only 'post' rather than allowing all methods, 3) It implements request throttling with maxOutstandingRequests, maxConcurrentRequests, and dynamicThrottlesEnabled to prevent DoS attacks, 4) It uses a more moderate function timeout (5 minutes vs 10 minutes), 5) It restricts logging to only essential information rather than verbose debug logs that might contain sensitive data, and 6) It specifies an extension bundle version range to ensure security updates."
  }
];
