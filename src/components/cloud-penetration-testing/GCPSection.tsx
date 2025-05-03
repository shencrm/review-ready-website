
import React from 'react';
import CodeExample from '@/components/CodeExample';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';

const GCPSection: React.FC = () => {
  return (
    <section className="space-y-12">
      <div>
        <h2 className="text-3xl font-bold mb-6">Google Cloud Platform (GCP) Penetration Testing</h2>
        <p className="mb-8">
          Google Cloud Platform has its own unique architecture and security model.
          Testing GCP environments requires understanding specific services, IAM system,
          and potential vulnerabilities unique to Google Cloud.
        </p>
        
        <Tabs defaultValue="common-vulnerabilities">
          <TabsList>
            <TabsTrigger value="common-vulnerabilities">Common Vulnerabilities</TabsTrigger>
            <TabsTrigger value="testing-approach">Testing Approach</TabsTrigger>
            <TabsTrigger value="tools">Tools</TabsTrigger>
          </TabsList>
          
          <TabsContent value="common-vulnerabilities" className="space-y-6 mt-6">
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">GCP IAM Vulnerabilities</h3>
              <p className="mb-4">
                Identity and Access Management in GCP can have several security issues:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Overly permissive IAM roles and bindings</li>
                <li>Service account key mismanagement</li>
                <li>Default service accounts with excessive permissions</li>
                <li>Improper use of primitive roles (Owner, Editor, Viewer)</li>
                <li>Missing separation of duties for privileged accounts</li>
              </ul>
              
              <h4 className="text-xl font-bold mt-4 mb-2">Testing GCP IAM Security</h4>
              <CodeExample 
                language="bash"
                title="GCP IAM Assessment"
                code={`# List IAM policies at project level
gcloud projects get-iam-policy PROJECT_ID

# List service accounts
gcloud iam service-accounts list --project=PROJECT_ID

# Check keys for a service account
gcloud iam service-accounts keys list --iam-account=SERVICE_ACCOUNT_EMAIL

# Examine IAM policy bindings
gcloud projects get-iam-policy PROJECT_ID --format=json`}
              />
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Cloud Storage Misconfigurations</h3>
              <p className="mb-4">
                GCP Cloud Storage buckets can have security issues:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Public bucket access without authentication</li>
                <li>Excessive IAM permissions on buckets</li>
                <li>Lack of object versioning for critical data</li>
                <li>Missing encryption for sensitive data</li>
                <li>Improper management of signed URLs</li>
              </ul>
              
              <h4 className="text-xl font-bold mt-4 mb-2">Testing Cloud Storage Security</h4>
              <CodeExample 
                language="bash"
                title="Cloud Storage Assessment"
                code={`# List buckets
gsutil ls

# Get bucket ACLs
gsutil iam get gs://BUCKET_NAME

# Check if bucket is publicly accessible
gsutil iam get gs://BUCKET_NAME | grep allUsers

# List objects in a bucket
gsutil ls -r gs://BUCKET_NAME/

# Using GCPBucketBrute for finding open buckets
python gcpbucketbrute.py -k KEYWORD -o output.txt`}
              />
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Compute Engine Vulnerabilities</h3>
              <p className="mb-4">
                GCP Compute Engine instances may have security issues:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Overly permissive firewall rules</li>
                <li>Public IP addresses on sensitive VMs</li>
                <li>Unpatched OS vulnerabilities</li>
                <li>Excessive service account permissions assigned to VMs</li>
                <li>Metadata service vulnerabilities</li>
              </ul>
              
              <h4 className="text-xl font-bold mt-4 mb-2">Testing Compute Engine Security</h4>
              <CodeExample 
                language="bash"
                title="Compute Engine Assessment"
                code={`# List Compute instances
gcloud compute instances list

# Get instance details
gcloud compute instances describe INSTANCE_NAME --zone=ZONE

# Check firewall rules
gcloud compute firewall-rules list

# Check for instances with public IPs
gcloud compute instances list --format="table(name,networkInterfaces[0].accessConfigs[0].natIP)"

# Testing metadata service from a VM
curl "http://metadata.google.internal/computeMetadata/v1/instance/" -H "Metadata-Flavor: Google"`}
              />
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Cloud Functions Vulnerabilities</h3>
              <p className="mb-4">
                GCP Cloud Functions may contain security issues:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Improper authentication configuration</li>
                <li>Vulnerable dependencies in function code</li>
                <li>Excessive IAM permissions for function service accounts</li>
                <li>Insecure handling of secrets</li>
                <li>Lack of input validation leading to injection attacks</li>
              </ul>
              
              <h4 className="text-xl font-bold mt-4 mb-2">Testing Cloud Functions</h4>
              <CodeExample 
                language="bash"
                title="Cloud Functions Assessment"
                code={`# List Cloud Functions
gcloud functions list

# Get function details
gcloud functions describe FUNCTION_NAME

# Check function permissions
gcloud functions get-iam-policy FUNCTION_NAME

# Test HTTP trigger function (if publicly accessible)
curl https://REGION-PROJECT_ID.cloudfunctions.net/FUNCTION_NAME`}
              />
            </div>
          </TabsContent>
          
          <TabsContent value="testing-approach" className="space-y-6 mt-6">
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Step-by-Step GCP Penetration Testing</h3>
              
              <div className="space-y-4">
                <div>
                  <h4 className="text-xl font-bold mb-2">1. Reconnaissance</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Identify GCP resources using DNS, Shodan, and other OSINT techniques</li>
                    <li>Look for Cloud Storage buckets, Cloud Functions, App Engine apps</li>
                    <li>Discover GCP project IDs and organization structure</li>
                    <li>Map out the GCP architecture based on discovered resources</li>
                    <li>Search for exposed GCP credentials in public repositories</li>
                  </ul>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">2. Initial Access Vector Identification</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Test for public Cloud Storage buckets</li>
                    <li>Check for exposed service account keys</li>
                    <li>Look for public Cloud Functions and HTTP endpoints</li>
                    <li>Test for SSRF vulnerabilities that could access metadata service</li>
                    <li>Check for open GCP APIs and services</li>
                  </ul>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">3. Privilege Escalation</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Enumerate IAM permissions using gcloud</li>
                    <li>Check for overly permissive IAM roles</li>
                    <li>Test for privilege escalation paths</li>
                    <li>Look for custom roles with excessive permissions</li>
                    <li>Test service account token abuse</li>
                  </ul>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">4. Lateral Movement</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Move between GCP projects using shared IAM roles</li>
                    <li>Exploit trust relationships between resources</li>
                    <li>Use service account impersonation</li>
                    <li>Pivot through VPC peering connections</li>
                    <li>Leverage shared VPC to access other projects</li>
                  </ul>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">5. Data Exfiltration Testing</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Test for unencrypted data in Cloud Storage</li>
                    <li>Check Cloud SQL database access controls</li>
                    <li>Test for sensitive data in Secret Manager</li>
                    <li>Assess Cloud Logging and monitoring bypass techniques</li>
                    <li>Test VPC Service Controls bypass methods</li>
                  </ul>
                </div>
              </div>
            </div>
          </TabsContent>
          
          <TabsContent value="tools" className="space-y-6 mt-6">
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Essential GCP Penetration Testing Tools</h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-xl font-bold mb-2">GCPBucketBrute</h4>
                  <p className="mb-2">Tool for finding open Cloud Storage buckets in GCP.</p>
                  <div className="bg-cybr-muted/50 p-3 rounded">
                    <h5 className="font-semibold mb-1">Key Features:</h5>
                    <ul className="list-disc list-inside text-sm">
                      <li>Brute force discovery of buckets</li>
                      <li>Permission checking capabilities</li>
                      <li>Content enumeration functionality</li>
                      <li>Customizable search parameters</li>
                    </ul>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">Google Cloud SDK (gcloud)</h4>
                  <p className="mb-2">Official command-line interface for Google Cloud Platform.</p>
                  <div className="bg-cybr-muted/50 p-3 rounded">
                    <h5 className="font-semibold mb-1">Key Features:</h5>
                    <ul className="list-disc list-inside text-sm">
                      <li>Complete API access to GCP services</li>
                      <li>Authentication and credential management</li>
                      <li>Scriptable for automated testing</li>
                      <li>Project and organization management</li>
                    </ul>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">ScoutSuite</h4>
                  <p className="mb-2">Multi-cloud security auditing tool with GCP support.</p>
                  <div className="bg-cybr-muted/50 p-3 rounded">
                    <h5 className="font-semibold mb-1">Key Features:</h5>
                    <ul className="list-disc list-inside text-sm">
                      <li>Comprehensive GCP service coverage</li>
                      <li>Rules-based assessment approach</li>
                      <li>Web-based reporting dashboard</li>
                      <li>Detailed security findings</li>
                    </ul>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">G-Scout</h4>
                  <p className="mb-2">Tool for auditing Google Cloud Platform configurations.</p>
                  <div className="bg-cybr-muted/50 p-3 rounded">
                    <h5 className="font-semibold mb-1">Key Features:</h5>
                    <ul className="list-disc list-inside text-sm">
                      <li>Rules-based security scanning</li>
                      <li>Database of findings for analysis</li>
                      <li>HTML report generation</li>
                      <li>Focus on IAM vulnerabilities</li>
                    </ul>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">GCP-IAM-Privilege-Escalation</h4>
                  <p className="mb-2">Scripts and tools for finding GCP privilege escalation paths.</p>
                  <div className="bg-cybr-muted/50 p-3 rounded">
                    <h5 className="font-semibold mb-1">Key Features:</h5>
                    <ul className="list-disc list-inside text-sm">
                      <li>IAM privilege escalation techniques</li>
                      <li>Reference documentation for attacks</li>
                      <li>Example scripts for common scenarios</li>
                      <li>Focus on service account attacks</li>
                    </ul>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-xl font-bold mb-2">GCPEnum</h4>
                  <p className="mb-2">Enumeration tool for GCP resources and services.</p>
                  <div className="bg-cybr-muted/50 p-3 rounded">
                    <h5 className="font-semibold mb-1">Key Features:</h5>
                    <ul className="list-disc list-inside text-sm">
                      <li>Resource discovery across projects</li>
                      <li>Permission verification</li>
                      <li>Output in various formats</li>
                      <li>Comprehensive service coverage</li>
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

export default GCPSection;
