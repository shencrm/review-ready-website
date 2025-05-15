
import { Challenge } from './challenge-types';

export const cloudSecurityChallenges: Challenge[] = [
  {
    id: 'cloud-security-1',
    title: 'AWS S3 Bucket Configuration',
    description: 'Compare these two AWS S3 bucket policies. Which configuration is secure?',
    difficulty: 'medium',
    category: 'Cloud Security',
    languages: ['AWS', 'JSON'],
    type: 'comparison',
    vulnerabilityType: 'Cloud Misconfiguration',
    secureCode: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSpecificRoleAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/MyAppRole"
      },
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-app-bucket",
        "arn:aws:s3:::my-app-bucket/*"
      ],
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": ["192.168.1.0/24", "10.0.0.0/16"]
        },
        "Bool": {
          "aws:SecureTransport": "true"
        }
      }
    },
    {
      "Sid": "DenyPublicAccess",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::my-app-bucket",
        "arn:aws:s3:::my-app-bucket/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}`,
    vulnerableCode: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-app-bucket",
        "arn:aws:s3:::my-app-bucket/*"
      ]
    },
    {
      "Sid": "AdminAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:user/admin"
      },
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::my-app-bucket",
        "arn:aws:s3:::my-app-bucket/*"
      ]
    }
  ]
}`,
    answer: 'secure',
    explanation: "The secure policy implements several important security controls: 1) It restricts access to a specific IAM role instead of allowing public access, 2) It restricts actions to only what's needed (principle of least privilege), 3) It includes IP-based restrictions, allowing access only from specific IP ranges, 4) It enforces HTTPS by requiring aws:SecureTransport to be true and explicitly denying requests that don't use SSL/TLS, and 5) It explicitly denies public access. The vulnerable policy allows anyone (Principal: *) to read objects from the bucket and list bucket contents, making all data publicly accessible, and grants overly broad permissions (s3:*) to a user, which violates least-privilege principles."
  },
  {
    id: 'cloud-security-2',
    title: 'Azure Function Security',
    description: 'This Azure function handles file uploads to blob storage. Is it implemented securely?',
    difficulty: 'hard',
    category: 'Cloud Security',
    languages: ['JavaScript', 'Azure'],
    type: 'single',
    vulnerabilityType: 'Cloud Security Misconfigurations',
    code: `module.exports = async function (context, req) {
    const { BlobServiceClient } = require('@azure/storage-blob');
    
    context.log('Processing file upload request');
    
    try {
        // Get connection string from app settings
        const connectionString = process.env.AzureWebJobsStorage;
        const containerName = "useruploads";
        const fileName = req.query.filename || 'default.txt';
        
        // Get file content from request body
        const fileContent = req.body;
        
        if (!fileContent) {
            context.res = {
                status: 400,
                body: "No file content provided"
            };
            return;
        }
        
        // Create blob client and upload file
        const blobServiceClient = BlobServiceClient.fromConnectionString(connectionString);
        const containerClient = blobServiceClient.getContainerClient(containerName);
        
        // Ensure container exists
        await containerClient.createIfNotExists({ 
            access: 'blob' // Public read access for blobs only
        });
        
        const blockBlobClient = containerClient.getBlockBlobClient(fileName);
        await blockBlobClient.upload(fileContent, Buffer.byteLength(fileContent));
        
        const blobUrl = blockBlobClient.url;
        
        context.res = {
            status: 200,
            body: { 
                message: "File uploaded successfully", 
                url: blobUrl 
            }
        };
    } catch (error) {
        context.log.error("Error:", error);
        context.res = {
            status: 500,
            body: "An error occurred while uploading the file."
        };
    }
};`,
    answer: false,
    explanation: "This Azure Function has several security issues: 1) It doesn't validate the filename, allowing path traversal attacks via the query parameter, 2) It uses public access ('blob') for the container, allowing anyone to read uploaded files, 3) It doesn't validate file content or restrict file types, enabling upload of malicious files, 4) It doesn't limit file size, making it vulnerable to denial of service via large file uploads, 5) It returns the complete blob URL in the response, potentially exposing internal storage details, and 6) It doesn't implement authentication to verify the user's identity before allowing uploads. A secure implementation would validate inputs, restrict access to authenticated users, scan uploaded content, implement rate limiting, and follow the principle of least privilege."
  }
];
