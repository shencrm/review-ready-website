
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Globe } from 'lucide-react';

const OSINTSection: React.FC = () => {
  return (
    <Card className="bg-cybr-card border-cybr-muted">
      <CardHeader>
        <div className="flex items-center gap-2">
          <Globe className="h-6 w-6 text-cybr-primary" />
          <CardTitle className="text-cybr-primary">Advanced OSINT & Information Gathering</CardTitle>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* OSINT Advanced Techniques */}
        <div className="space-y-4">
          <h4 className="text-lg font-semibold text-cybr-accent">Search Engine Exploitation</h4>
          
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="font-semibold mb-2 text-cybr-primary">Google Dorking - Advanced Queries</h5>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <p className="text-sm mb-2 font-medium">Administrative Interfaces:</p>
                <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`site:example.com inurl:admin
site:example.com inurl:administrator  
site:example.com inurl:login
site:example.com inurl:wp-admin
site:example.com inurl:phpmyadmin
site:example.com intitle:"admin panel"
site:example.com inurl:management`}
                </pre>
              </div>
              <div>
                <p className="text-sm mb-2 font-medium">Configuration Files:</p>
                <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`site:example.com filetype:xml
site:example.com ext:cfg | ext:env | ext:ini
site:example.com inurl:web.config
site:example.com inurl:.htaccess
site:example.com filetype:properties`}
                </pre>
              </div>
            </div>
          </div>

          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="font-semibold mb-2 text-cybr-primary">Database & Backup Files</h5>
            <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Database Files Discovery
site:example.com filetype:sql | filetype:dbf | filetype:mdb
site:example.com ext:db | ext:sqlite | ext:sqlite3
site:example.com inurl:backup
site:example.com inurl:dump
site:example.com "phpMyAdmin" "running on"

# Backup Files
site:example.com ext:bak | ext:backup | ext:old | ext:orig
site:example.com inurl:backup
site:example.com filetype:tar | filetype:zip | filetype:rar`}
            </pre>
          </div>

          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <h5 className="font-semibold mb-2 text-cybr-primary">Sensitive Information Discovery</h5>
            <pre className="bg-black/50 p-3 rounded text-sm text-green-400 overflow-x-auto">
{`# Credentials & API Keys
site:example.com "password" | "passwd" | "pwd"
site:example.com "api_key" | "apikey" | "api-key"
site:example.com "secret_key" | "secretkey"
site:example.com "access_token" | "accesstoken"
site:example.com "aws_access_key_id"

# Error Messages & Debug Info
site:example.com "error" | "exception" | "warning"
site:example.com "stack trace" | "debug"
site:example.com "database error" | "mysql error"`}
            </pre>
          </div>
        </div>

        {/* Social Media Intelligence Techniques */}
        <div className="space-y-4">
          <h4 className="text-lg font-semibold text-cybr-accent">Social Media Intelligence Techniques</h4>
          <div className="bg-cybr-muted/20 p-4 rounded-lg">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
              <div>
                <h6 className="font-semibold text-cybr-primary mb-2">Employee Profiling:</h6>
                <ul className="space-y-1 list-disc list-inside opacity-90">
                  <li>LinkedIn reconnaissance and connection mapping</li>
                  <li>Twitter analysis for technology mentions</li>
                  <li>Facebook investigation for personal information</li>
                  <li>GitHub activity and repository analysis</li>
                </ul>
              </div>
              <div>
                <h6 className="font-semibold text-cybr-primary mb-2">Corporate Intelligence:</h6>
                <ul className="space-y-1 list-disc list-inside opacity-90">
                  <li>Company structure mapping through social media</li>
                  <li>Key personnel identification and roles</li>
                  <li>Technology stack discovery through job postings</li>
                  <li>Email pattern discovery and validation</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default OSINTSection;
