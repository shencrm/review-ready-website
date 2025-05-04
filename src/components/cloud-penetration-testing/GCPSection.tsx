
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
                          <li>Look for *.appspot.com, *.cloudfunctions.net, storage.googleapis.com</li>
                          <li>Check DNS records for GCP-related CNAME entries</li>
                        </ul>
                      </li>
                      <li>Try to discover GCP project IDs from URLs, DNS records, source code</li>
                      <li>Search for exposed credentials in code repositories, public documents</li>
                      <li>Map identified resources to potential attack vectors</li>
                    </ol>
                  </AccordionContent>
                </AccordionItem>
                
                <AccordionItem value="item-2">
                  <AccordionTrigger className="text-lg font-medium">2. Configuration Analysis</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Once access is obtained or from external assessment, analyze the cloud configuration for security issues.
                    </p>
                    <h5 className="font-semibold mb-2">Key Activities:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Review IAM policies and permissions</li>
                      <li>Analyze service account configurations</li>
                      <li>Assess network security groups and firewall rules</li>
                      <li>Evaluate storage bucket permissions and encryption</li>
                      <li>Check logging and monitoring configurations</li>
                    </ul>
                    
                    <h5 className="font-semibold mb-2">Tools and Approaches:</h5>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-3">
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">GCP Security Scanner Tools</h6>
                        <CodeExample 
                          language="bash"
                          title="Security Scanning Commands"
                          code={`# Using GCP Security Command Center (if available)
gcloud scc assets list --organization=ORGANIZATION_ID --format=json

# Using Scout Suite for GCP
python scout.py gcp --report-dir ./output --account ACCOUNT

# Using G-Scout for role and permission analysis
python gscout.py --project-id PROJECT_ID

# Using GCP IAM Recommender
gcloud beta recommender recommendations list \
  --recommender=google.iam.policy.Recommender \
  --location=global \
  --project=PROJECT_ID`}
                        />
                      </div>
                      <div className="bg-cybr-muted/20 p-3 rounded">
                        <h6 className="font-medium mb-1">Manual Configuration Review</h6>
                        <CodeExample 
                          language="bash"
                          title="Configuration Analysis Commands"
                          code={`# Check organization policies
gcloud resource-manager org-policies list --organization=ORGANIZATION_ID

# Review IAM bindings on organization level
gcloud organizations get-iam-policy ORGANIZATION_ID

# Check for overly permissive firewall rules
gcloud compute firewall-rules list \
  --filter="disabled=false AND sourceRanges:0.0.0.0/0" \
  --project=PROJECT_ID

# Look for public buckets
gsutil ls
for bucket in $(gsutil ls | cut -d/ -f3); do
  gsutil iam get gs://$bucket | grep allUsers
done`}
                        />
                      </div>
                    </div>
                  </AccordionContent>
                </AccordionItem>
                
                <AccordionItem value="item-3">
                  <AccordionTrigger className="text-lg font-medium">3. Vulnerability Assessment</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Identify specific vulnerabilities in the GCP environment that could be exploited.
                    </p>
                    <h5 className="font-semibold mb-2">Areas to Assess:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Identity and access control weaknesses</li>
                      <li>Network security misconfigurations</li>
                      <li>Storage security issues</li>
                      <li>Compute instance vulnerabilities</li>
                      <li>Serverless function security</li>
                      <li>Database service security</li>
                    </ul>
                    
                    <h5 className="font-semibold mb-2">Common Techniques:</h5>
                    <CodeExample 
                      language="bash"
                      title="Vulnerability Assessment Commands"
                      code={`# Check for service account key files
gcloud iam service-accounts list --project=PROJECT_ID
gcloud iam service-accounts keys list --iam-account=SERVICE_ACCOUNT_EMAIL

# Identify VM instances with public IPs
gcloud compute instances list \
  --format="table(name,networkInterfaces[0].accessConfigs[0].natIP)" \
  --project=PROJECT_ID

# Check if Cloud SQL instances are publicly accessible
gcloud sql instances list \
  --format="table(name,settings.ipConfiguration.authorizedNetworks[].value)" \
  --project=PROJECT_ID | grep 0.0.0.0

# Check for unauthenticated Cloud Functions
gcloud functions list --project=PROJECT_ID
for func in $(gcloud functions list --format="value(name)" --project=PROJECT_ID); do
  gcloud functions get-iam-policy $func --project=PROJECT_ID | grep allUsers
done`}
                    />
                  </AccordionContent>
                </AccordionItem>
                
                <AccordionItem value="item-4">
                  <AccordionTrigger className="text-lg font-medium">4. Exploitation & Privilege Escalation</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Attempt to exploit identified vulnerabilities to demonstrate impact.
                    </p>
                    <h5 className="font-semibold mb-2">Common Techniques:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>IAM privilege escalation</li>
                      <li>Service account key misuse</li>
                      <li>Metadata service exploitation</li>
                      <li>Network access control bypass</li>
                      <li>Storage security bypass</li>
                    </ul>
                    
                    <h5 className="font-semibold mb-2">Example Attack Paths:</h5>
                    <CodeExample 
                      language="bash"
                      title="Privilege Escalation Examples"
                      code={`# Scenario 1: Service account impersonation
# If you have permissions to create service account keys
gcloud iam service-accounts keys create key.json --iam-account=TARGET_SA@PROJECT_ID.iam.gserviceaccount.com
gcloud auth activate-service-account --key-file=key.json

# Scenario 2: Using VM access to escalate
# SSH to VM, then access metadata service
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"

# Scenario 3: Custom role creation to escalate
# If you can create/update roles
gcloud iam roles create EscalationRole --project=PROJECT_ID \
  --permissions=resourcemanager.projects.setIamPolicy,iam.serviceAccounts.actAs

# Scenario 4: Exploiting overly permissive storage permissions
gsutil cp sensitive-file gs://public-bucket/
curl https://storage.googleapis.com/public-bucket/sensitive-file`}
                    />
                  </AccordionContent>
                </AccordionItem>
                
                <AccordionItem value="item-5">
                  <AccordionTrigger className="text-lg font-medium">5. Reporting & Remediation</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">
                      Document findings and provide clear remediation guidance.
                    </p>
                    <h5 className="font-semibold mb-2">Key Components:</h5>
                    <ul className="list-disc pl-6 mb-3 space-y-1">
                      <li>Vulnerabilities identified with clear impact assessment</li>
                      <li>Exploitation paths demonstrated</li>
                      <li>Practical remediation steps for each finding</li>
                      <li>Prioritization of issues based on risk</li>
                      <li>Strategic recommendations for improving cloud security</li>
                    </ul>
                    
                    <h5 className="font-semibold mb-2">Example Remediation Commands:</h5>
                    <CodeExample 
                      language="bash"
                      title="Common Remediation Steps"
                      code={`# Fix 1: Remove public IAM access to a bucket
gsutil iam ch -d allUsers:objectViewer gs://BUCKET_NAME

# Fix 2: Rotate compromised service account keys
gcloud iam service-accounts keys list --iam-account=SA_NAME@PROJECT_ID.iam.gserviceaccount.com
gcloud iam service-accounts keys delete KEY_ID --iam-account=SA_NAME@PROJECT_ID.iam.gserviceaccount.com

# Fix 3: Enable VPC Service Controls for sensitive services
gcloud access-context-manager perimeters create perimeter-name \
    --title="Security Perimeter" \
    --resources=projects/PROJECT_NUMBER \
    --restricted-services=storage.googleapis.com,bigquery.googleapis.com

# Fix 4: Restrict access to Cloud Functions
gcloud functions remove-iam-policy-binding FUNCTION_NAME \
    --member="allUsers" \
    --role="roles/cloudfunctions.invoker"

# Fix 5: Apply least privilege principle to service accounts
gcloud projects add-iam-policy-binding PROJECT_ID \
    --member="serviceAccount:SA_NAME@PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/SPECIFIC_LIMITED_ROLE" \
    --condition="expression=resource.name.startsWith('projects/PROJECT_ID/buckets/SPECIFIC_BUCKET'),title=BucketAccessOnly"
`}
                    />
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            </div>
          </TabsContent>
          
          <TabsContent value="tools" className="space-y-6 mt-6">
            <div className="card">
              <h3 className="text-2xl font-bold mb-4">GCP Penetration Testing Tools</h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-cybr-muted/20 p-4 rounded">
                  <h4 className="text-xl font-bold mb-2">Cloud Security Scanner</h4>
                  <p className="mb-3">Google's built-in vulnerability scanner for App Engine, Compute Engine, and GKE applications.</p>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Detects common web vulnerabilities</li>
                    <li>Scans for outdated libraries</li>
                    <li>Identifies misconfigurations</li>
                  </ul>
                  <CodeExample 
                    language="bash"
                    title="Using Cloud Security Scanner"
                    code={`# Enable Security Scanner API
gcloud services enable websecurityscanner.googleapis.com

# Scans are configured through the Google Cloud Console
# https://console.cloud.google.com/security/web-scanner`}
                  />
                </div>
                
                <div className="bg-cybr-muted/20 p-4 rounded">
                  <h4 className="text-xl font-bold mb-2">G-Scout</h4>
                  <p className="mb-3">Open-source tool that collects GCP resource metadata to identify security misconfigurations.</p>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Audits IAM policies and permissions</li>
                    <li>Checks firewall rules and network settings</li>
                    <li>Identifies exposed cloud storage</li>
                  </ul>
                  <CodeExample 
                    language="bash"
                    title="Using G-Scout"
                    code={`# Clone repository
git clone https://github.com/nccgroup/G-Scout.git
cd G-Scout

# Install dependencies
pip install -r requirements.txt

# Run G-Scout
python gscout.py --project-id PROJECT_ID

# Results will be in the "Report" folder`}
                  />
                </div>
                
                <div className="bg-cybr-muted/20 p-4 rounded">
                  <h4 className="text-xl font-bold mb-2">GCPBucketBrute</h4>
                  <p className="mb-3">Tool for enumerating Google Cloud Storage buckets to find publicly accessible buckets.</p>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Identifies open buckets based on keywords</li>
                    <li>Tests common naming patterns</li>
                    <li>Attempts directory listing</li>
                  </ul>
                  <CodeExample 
                    language="bash"
                    title="Using GCPBucketBrute"
                    code={`# Clone repository
git clone https://github.com/RhinoSecurityLabs/GCPBucketBrute.git
cd GCPBucketBrute

# Install dependencies
pip install -r requirements.txt

# Run with keyword
python3 gcpbucketbrute.py -k company-name -o results.txt

# Run with keyword list and permutations
python3 gcpbucketbrute.py -kl keywords.txt -p permutations.txt -o results.txt`}
                  />
                </div>
                
                <div className="bg-cybr-muted/20 p-4 rounded">
                  <h4 className="text-xl font-bold mb-2">ScoutSuite</h4>
                  <p className="mb-3">Multi-cloud security auditing tool with extensive GCP support.</p>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Comprehensive security rules</li>
                    <li>HTML reporting with findings</li>
                    <li>Covers all major GCP services</li>
                  </ul>
                  <CodeExample 
                    language="bash"
                    title="Using ScoutSuite"
                    code={`# Install ScoutSuite
pip install scoutsuite

# Run against a GCP project
scout gcp --project-id PROJECT_ID --report-dir ./scout-report

# Run with service account authentication
scout gcp --service-account /path/to/credentials.json --report-dir ./scout-report

# Open the report
firefox ./scout-report/scoutsuite-report/scoutsuite-results/scoutsuite_results_gcp-project.html`}
                  />
                </div>
                
                <div className="bg-cybr-muted/20 p-4 rounded">
                  <h4 className="text-xl font-bold mb-2">GCP Firewall Auditor</h4>
                  <p className="mb-3">Tool to analyze and visualize GCP VPC firewall rules.</p>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Identifies overly permissive rules</li>
                    <li>Visualizes potential attack paths</li>
                    <li>Highlights security gaps</li>
                  </ul>
                  <CodeExample 
                    language="bash"
                    title="Using GCP Firewall Auditor"
                    code={`# Export firewall rules to JSON
gcloud compute firewall-rules list --format=json > firewall-rules.json

# Run the analyzer (example tool)
python firewall-analyzer.py --input firewall-rules.json --output report.html

# Identify rules allowing public access
gcloud compute firewall-rules list \
  --filter="(sourceRanges:0.0.0.0/0) AND (allowed.ports:22 OR allowed.ports:3389)" \
  --format="table(name,network,sourceRanges,allowed)"`}
                  />
                </div>
                
                <div className="bg-cybr-muted/20 p-4 rounded">
                  <h4 className="text-xl font-bold mb-2">GCP IAM Explorer</h4>
                  <p className="mb-3">Tool for analyzing IAM policies and identifying privilege escalation paths.</p>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Maps effective permissions</li>
                    <li>Identifies excessive privileges</li>
                    <li>Shows potential escalation paths</li>
                  </ul>
                  <CodeExample 
                    language="bash"
                    title="GCP IAM Analysis"
                    code={`# Export IAM policies
gcloud projects get-iam-policy PROJECT_ID --format=json > iam-policy.json
gcloud organizations get-iam-policy ORGANIZATION_ID --format=json > org-policy.json

# Use IAM Recommender to identify excessive permissions
gcloud beta recommender recommendations list \
  --recommender=google.iam.policy.Recommender \
  --location=global \
  --project=PROJECT_ID

# Find service accounts with excessive permissions
gcloud projects get-iam-policy PROJECT_ID --format=json | \
  jq '.bindings[] | select(.role=="roles/owner" or .role=="roles/editor") | \
  select(.members[] | contains("serviceAccount:"))'`}
                  />
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
