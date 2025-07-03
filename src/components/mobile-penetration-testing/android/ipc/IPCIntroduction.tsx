
import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { MessageSquare, Share2, Database, Radio, Settings, AlertTriangle } from 'lucide-react';

const IPCIntroduction: React.FC = () => {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <MessageSquare className="h-5 w-5" />
          IPC Components Overview
        </CardTitle>
        <CardDescription>
          Understanding Android's four main IPC mechanisms and their security implications
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div className="border rounded-lg p-4">
              <h3 className="font-semibold text-blue-600 mb-2 flex items-center gap-2">
                <Share2 className="h-4 w-4" />
                Intents
              </h3>
              <p className="text-sm text-gray-600 mb-3">
                Message objects used to communicate between app components
              </p>
              <div className="space-y-2">
                <Badge variant="outline">Explicit Intents</Badge>
                <Badge variant="outline">Implicit Intents</Badge>
                <Badge variant="outline">Intent Filters</Badge>
              </div>
            </div>

            <div className="border rounded-lg p-4">
              <h3 className="font-semibold text-green-600 mb-2 flex items-center gap-2">
                <Database className="h-4 w-4" />
                Content Providers
              </h3>
              <p className="text-sm text-gray-600 mb-3">
                Manage access to structured data sets
              </p>
              <div className="space-y-2">
                <Badge variant="outline">Data Sharing</Badge>
                <Badge variant="outline">URI Permissions</Badge>
                <Badge variant="outline">SQL Queries</Badge>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <div className="border rounded-lg p-4">
              <h3 className="font-semibold text-purple-600 mb-2 flex items-center gap-2">
                <Radio className="h-4 w-4" />
                Broadcast Receivers
              </h3>
              <p className="text-sm text-gray-600 mb-3">
                Respond to system-wide broadcast announcements
              </p>
              <div className="space-y-2">
                <Badge variant="outline">System Broadcasts</Badge>
                <Badge variant="outline">Custom Broadcasts</Badge>
                <Badge variant="outline">Ordered Broadcasts</Badge>
              </div>
            </div>

            <div className="border rounded-lg p-4">
              <h3 className="font-semibold text-orange-600 mb-2 flex items-center gap-2">
                <Settings className="h-4 w-4" />
                Services
              </h3>
              <p className="text-sm text-gray-600 mb-3">
                Background operations without user interface
              </p>
              <div className="space-y-2">
                <Badge variant="outline">Background Services</Badge>
                <Badge variant="outline">Bound Services</Badge>
                <Badge variant="outline">AIDL Interfaces</Badge>
              </div>
            </div>
          </div>
        </div>

        <Alert>
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            IPC components are the primary attack vectors for privilege escalation and data theft in Android applications. 
            Proper security analysis of these components is crucial for identifying vulnerabilities that could lead to 
            unauthorized access to sensitive data or system resources.
          </AlertDescription>
        </Alert>
      </CardContent>
    </Card>
  );
};

export default IPCIntroduction;
