import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Zap, Search, Globe, Code, Database, Shield, Eye, Target } from 'lucide-react';
import OSINTSection from './advanced/OSINTSection';
import WebApplicationMapping from './advanced/WebApplicationMapping';
import HTTPAnalysis from './advanced/HTTPAnalysis';
import JavaScriptAnalysis from './advanced/JavaScriptAnalysis';
import ModernToolsArsenal from './advanced/ModernToolsArsenal';

const AdvancedContentSection: React.FC = () => {
  return (
    <div className="space-y-8">
      <div className="text-center mb-8">
        <h2 className="text-3xl font-bold text-cybr-primary mb-4">
          Advanced Web Penetration Testing Techniques
        </h2>
        <p className="text-lg opacity-80 max-w-4xl mx-auto">
          Master-level techniques and methodologies for comprehensive web application security assessment. 
          This section covers advanced reconnaissance, exploitation, and analysis techniques used by professional penetration testers.
        </p>
      </div>

      <Tabs defaultValue="advanced-reconnaissance" className="w-full">
        <TabsList className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 w-full bg-cybr-muted/30 p-1 mb-8">
          <TabsTrigger value="advanced-reconnaissance" className="text-xs">
            <Search className="h-4 w-4 mr-1" />
            Advanced Reconnaissance
          </TabsTrigger>
          <TabsTrigger value="exploitation-techniques" className="text-xs">
            <Zap className="h-4 w-4 mr-1" />
            Exploitation
          </TabsTrigger>
          <TabsTrigger value="post-exploitation" className="text-xs">
            <Target className="h-4 w-4 mr-1" />
            Post-Exploitation
          </TabsTrigger>
          <TabsTrigger value="evasion-techniques" className="text-xs">
            <Eye className="h-4 w-4 mr-1" />
            Evasion
          </TabsTrigger>
          <TabsTrigger value="automation-scripting" className="text-xs">
            <Code className="h-4 w-4 mr-1" />
            Automation
          </TabsTrigger>
          <TabsTrigger value="reporting-analysis" className="text-xs">
            <Database className="h-4 w-4 mr-1" />
            Analysis
          </TabsTrigger>
        </TabsList>

        {/* Advanced Reconnaissance Tab */}
        <TabsContent value="advanced-reconnaissance" className="space-y-6">
          <div className="grid gap-6">
            <OSINTSection />
            
            <Card className="bg-cybr-card border-cybr-muted">
              <CardContent className="space-y-6 pt-6">
                <WebApplicationMapping />
                <HTTPAnalysis />
                <JavaScriptAnalysis />
                <ModernToolsArsenal />
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Other tabs content remains unchanged */}
        <TabsContent value="exploitation-techniques" className="space-y-6">
          <Card className="bg-cybr-card border-cybr-muted">
            <CardHeader>
              <CardTitle className="text-cybr-primary">Advanced Exploitation Techniques</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-cybr-foreground opacity-80">
                Advanced exploitation techniques content will be implemented here.
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="post-exploitation" className="space-y-6">
          <Card className="bg-cybr-card border-cybr-muted">
            <CardHeader>
              <CardTitle className="text-cybr-primary">Post-Exploitation Techniques</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-cybr-foreground opacity-80">
                Post-exploitation techniques content will be implemented here.
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="evasion-techniques" className="space-y-6">
          <Card className="bg-cybr-card border-cybr-muted">
            <CardHeader>
              <CardTitle className="text-cybr-primary">Evasion Techniques</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-cybr-foreground opacity-80">
                Evasion techniques content will be implemented here.
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="automation-scripting" className="space-y-6">
          <Card className="bg-cybr-card border-cybr-muted">
            <CardHeader>
              <CardTitle className="text-cybr-primary">Automation & Scripting</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-cybr-foreground opacity-80">
                Automation and scripting content will be implemented here.
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="reporting-analysis" className="space-y-6">
          <Card className="bg-cybr-card border-cybr-muted">
            <CardHeader>
              <CardTitle className="text-cybr-primary">Reporting & Analysis</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-cybr-foreground opacity-80">
                Reporting and analysis content will be implemented here.
              </p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default AdvancedContentSection;
