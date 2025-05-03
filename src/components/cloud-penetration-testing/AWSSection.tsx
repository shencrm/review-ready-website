
import React from 'react';
import CodeExample from '@/components/CodeExample';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';

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
              </ul>
              
              <h4 className="text-xl font-bold mt-4 mb-2">Testing for S3 Issues</h4>
              <CodeExample 
                language="bash"
                title="Finding Public S3 Buckets"
                code={`# Using AWS CLI to check bucket permissions
aws s3api get-bucket-acl --bucket target-bucket-name

# Using AWS CLI to list objects in a bucket
aws s3 ls s3://target-bucket-name/ --no-sign-request

# Using tools like S3Scanner
python3 s3scanner.py --bucket-name target-bucket-name`}
              />
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">IAM Misconfigurations</h3>
              <p className="mb-4">
                Identity and Access Management (IAM) vulnerabilities can lead to privilege escalation and unauthorized access:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Overly permissive IAM policies</li>
                <li>Unused IAM user accounts with credentials</li>
                <li>Long-lived access keys</li>
                <li>Weak password policies</li>
                <li>Missing MFA on privileged accounts</li>
              </ul>
              
              <h4 className="text-xl font-bold mt-4 mb-2">Testing IAM Security</h4>
              <CodeExample 
                language="bash"
                title="IAM Enumeration and Analysis"
                code={`# List IAM users and inspect their policies
aws iam list-users
aws iam list-attached-user-policies --user-name target-user

# Check for policies allowing privilege escalation
aws iam get-policy-version --policy-arn <policy-arn> --version-id <version-id>

# Using tools like Pacu or ScoutSuite for IAM analysis
python3 pacu.py
> run iam__enum_users_roles_policies_groups
> run iam__privesc_scan`}
              />
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">EC2 Security Issues</h3>
              <p className="mb-4">
                Elastic Compute Cloud (EC2) instances can have several security issues:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Overly permissive security groups (firewall rules)</li>
                <li>Unpatched vulnerabilities in AMIs</li>
                <li>Exposed management interfaces</li>
                <li>Insecure key management</li>
                <li>Instance metadata service (IMDS) vulnerabilities</li>
              </ul>
              
              <h4 className="text-xl font-bold mt-4 mb-2">Testing EC2 Security</h4>
              <CodeExample 
                language="bash"
                title="EC2 Security Assessment"
                code={`# Check security groups for overly permissive rules
aws ec2 describe-security-groups

# Identify instances with public IP addresses
aws ec2 describe-instances --filters "Name=instance-state-name,Values=running"

# Testing for IMDS v1 vulnerability (no session required)
curl http://169.254.169.254/latest/meta-data/

# Testing for SSRF to IMDS
curl -H "X-Forwarded-For: 169.254.169.254" https://vulnerable-app/api
`}
              />
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Lambda Function Vulnerabilities</h3>
              <p className="mb-4">
                Serverless Lambda functions may contain vulnerabilities:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Overly permissive execution roles</li>
                <li>Code injection vulnerabilities</li>
                <li>Insecure dependencies</li>
                <li>Environment variable exposure</li>
                <li>Insufficient input validation</li>
              </ul>
              
              <h4 className="text-xl font-bold mt-4 mb-2">Testing Lambda Security</h4>
              <CodeExample 
                language="bash"
                title="Lambda Security Assessment"
                code={`# List Lambda functions
aws lambda list-functions

# Get function configuration and permissions
aws lambda get-function --function-name target-function
aws lambda get-policy --function-name target-function

# Using LambdaGuard for automated assessment
lambdaguard -f target-function`}
              />
            </div>
          </TabsContent>
          
          <TabsContent value="testing-approach" className="space-y-6 mt-6">
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Step-by-Step AWS Penetration Testing</h3>
              
              <div className="space-y-4">
                <div>
                  <h4 className="text-xl font-bold mb-2">1. Reconnaissance</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Identify AWS resources using tools like Recon-ng, Shodan</li>
                    <li>Look for S3 buckets, CloudFront distributions, API Gateways</li>
                    <li>Map out the AWS architecture based on discovered resources</li>
                    <li>Identify subdomains hosted on AWS services</li>
                    <li>Search for exposed AWS keys in public repositories</li>
                  </ul>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">2. Initial Access Vector Identification</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Test for public S3 buckets with read/write access</li>
                    <li>Scan for exposed EC2 instances and services</li>
                    <li>Check for vulnerable Lambda functions exposed via API Gateway</li>
                    <li>Test for SSRF vulnerabilities that could access IMDS</li>
                    <li>Look for leaked credentials in code, configuration files or logs</li>
                  </ul>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">3. Privilege Escalation</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Enumerate IAM permissions using the AWS CLI or SDK</li>
                    <li>Test for privilege escalation paths using tools like Pacu</li>
                    <li>Check for vulnerable IAM role trust relationships</li>
                    <li>Attempt to assume roles with inadequate restrictions</li>
                    <li>Check for excessive permissions on user/role policies</li>
                  </ul>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">4. Lateral Movement</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Move between AWS accounts using trusted relationships</li>
                    <li>Access EC2 instances using discovered SSH keys or credentials</li>
                    <li>Use instance profiles to access other AWS services</li>
                    <li>Pivot through VPC peering connections</li>
                    <li>Exploit trust relationships between resources</li>
                  </ul>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">5. Data Exfiltration Testing</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Test for unencrypted data in S3 buckets</li>
                    <li>Check RDS instance accessibility and encryption</li>
                    <li>Examine DynamoDB table permissions and encryption</li>
                    <li>Test CloudTrail logging bypass techniques</li>
                    <li>Assess GuardDuty detection capabilities</li>
                  </ul>
                </div>
              </div>
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
