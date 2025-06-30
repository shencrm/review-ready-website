import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Zap, Search, Globe, Code, Database, Shield, Eye, Target } from 'lucide-react';
import OSINTSection from './advanced/OSINTSection';
import WebApplicationMapping from './advanced/WebApplicationMapping';
import HTTPAnalysis from './advanced/HTTPAnalysis';
import JavaScriptAnalysis from './advanced/JavaScriptAnalysis';
import ModernToolsArsenal from './advanced/ModernToolsArsenal';

// Import new exploitation components
import ManualExploitationTechniques from './advanced/exploitation/ManualExploitationTechniques';
import ModernAttackVectors from './advanced/exploitation/ModernAttackVectors';
import ClientSideExploitation from './advanced/exploitation/ClientSideExploitation';
import AuthenticationBypass from './advanced/exploitation/AuthenticationBypass';
import CloudContainerExploitation from './advanced/exploitation/CloudContainerExploitation';

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

        {/* Exploitation Techniques Tab */}
        <TabsContent value="exploitation-techniques" className="space-y-6">
          <div className="grid gap-6">
            <ManualExploitationTechniques />
            <ModernAttackVectors />
            <ClientSideExploitation />
            <AuthenticationBypass />
            <CloudContainerExploitation />
            
            {/* Additional exploitation sections placeholder */}
            <Card className="bg-cybr-card border-cybr-muted">
              <CardHeader>
                <CardTitle className="text-cybr-primary">Additional Advanced Techniques</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-sm">
                  <div className="bg-cybr-muted/20 p-3 rounded">
                    <h6 className="font-semibold text-cybr-accent mb-2">Binary & Memory Exploitation</h6>
                    <ul className="space-y-1 text-xs opacity-80">
                      <li>• WebAssembly (WASM) exploitation</li>
                      <li>• Buffer overflow in web context</li>
                      <li>• Heap exploitation techniques</li>
                      <li>• ROP/JOP chain construction</li>
                    </ul>
                  </div>
                  <div className="bg-cybr-muted/20 p-3 rounded">
                    <h6 className="font-semibold text-cybr-accent mb-2">AI/ML Security</h6>
                    <ul className="space-y-1 text-xs opacity-80">
                      <li>• LLM prompt injection attacks</li>
                      <li>• Model extraction techniques</li>
                      <li>• Adversarial example generation</li>
                      <li>• Training data poisoning</li>
                    </ul>
                  </div>
                  <div className="bg-cybr-muted/20 p-3 rounded">
                    <h6 className="font-semibold text-cybr-accent mb-2">Framework Exploitation</h6>
                    <ul className="space-y-1 text-xs opacity-80">
                      <li>• React/Vue/Angular attacks</li>
                      <li>• Node.js prototype pollution</li>
                      <li>• Python framework vulnerabilities</li>
                      <li>• Go/Rust memory safety bypasses</li>
                    </ul>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Other tabs content remains unchanged */}
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
