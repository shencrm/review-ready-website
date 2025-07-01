
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Code2 } from 'lucide-react';

// Import the smaller components
import PythonAutomation from './script-development/PythonAutomation';
import PowerShellAutomation from './script-development/PowerShellAutomation';
import BashAutomation from './script-development/BashAutomation';
import APIIntegration from './script-development/APIIntegration';

const ScriptDevelopment: React.FC = () => {
  return (
    <Card className="bg-cybr-card border-cybr-muted">
      <CardHeader>
        <CardTitle className="text-cybr-primary flex items-center gap-2">
          <Code2 className="h-6 w-6" />
          Custom Script Development
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="python-automation" className="w-full">
          <TabsList className="grid grid-cols-2 md:grid-cols-4 w-full mb-6">
            <TabsTrigger value="python-automation">Python Scripts</TabsTrigger>
            <TabsTrigger value="powershell-automation">PowerShell</TabsTrigger>
            <TabsTrigger value="bash-automation">Bash Scripts</TabsTrigger>
            <TabsTrigger value="api-integration">API Integration</TabsTrigger>
          </TabsList>

          <TabsContent value="python-automation" className="space-y-6">
            <PythonAutomation />
          </TabsContent>

          <TabsContent value="powershell-automation" className="space-y-6">
            <PowerShellAutomation />
          </TabsContent>

          <TabsContent value="bash-automation" className="space-y-6">
            <BashAutomation />
          </TabsContent>

          <TabsContent value="api-integration" className="space-y-6">
            <APIIntegration />
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default ScriptDevelopment;
