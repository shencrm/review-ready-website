import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Zap, Search, Globe, Code, Database, Shield, Eye, Target, Crown, Download, Network, EyeOff, Key, Terminal, TestTube, Cpu, Clock } from 'lucide-react';
import ErrorBoundary from '@/components/ErrorBoundary';
import OSINTSection from './advanced/OSINTSection';
import WebApplicationMapping from './advanced/WebApplicationMapping';
import HTTPAnalysis from './advanced/HTTPAnalysis';
import JavaScriptAnalysis from './advanced/JavaScriptAnalysis';
import ModernToolsArsenal from './advanced/ModernToolsArsenal';
import SectionNavigation from './advanced/SectionNavigation';
import { useActiveSection } from '@/hooks/useActiveSection';

// Import new exploitation components
import ManualExploitationTechniques from './advanced/exploitation/ManualExploitationTechniques';
import ModernAttackVectors from './advanced/exploitation/ModernAttackVectors';
import ClientSideExploitation from './advanced/exploitation/ClientSideExploitation';
import AuthenticationBypass from './advanced/exploitation/AuthenticationBypass';
import CloudContainerExploitation from './advanced/exploitation/CloudContainerExploitation';

// Import post-exploitation components
import PersistenceTechniques from './advanced/post-exploitation/PersistenceTechniques';
import PrivilegeEscalation from './advanced/post-exploitation/PrivilegeEscalation';
import DataExfiltration from './advanced/post-exploitation/DataExfiltration';
import LateralMovement from './advanced/post-exploitation/LateralMovement';
import CoveringTracks from './advanced/post-exploitation/CoveringTracks';
import MaintainingAccess from './advanced/post-exploitation/MaintainingAccess';
import AdvancedPostExploitation from './advanced/post-exploitation/AdvancedPostExploitation';

// Import evasion components
import WAFBypass from './advanced/evasion/WAFBypass';
import AntivirusEvasion from './advanced/evasion/AntivirusEvasion';
import NetworkEvasion from './advanced/evasion/NetworkEvasion';
import TrafficObfuscation from './advanced/evasion/TrafficObfuscation';
import StealthTechniques from './advanced/evasion/StealthTechniques';

// Import automation components
import ScriptDevelopment from './advanced/automation/ScriptDevelopment';
import TestingFrameworks from './advanced/automation/TestingFrameworks';
import VulnerabilityScanning from './advanced/automation/VulnerabilityScanning';

const AdvancedContentSection: React.FC = () => {
  // Navigation items for Advanced Reconnaissance
  const reconnaissanceItems = [{
    id: 'osint-section',
    title: 'OSINT Techniques',
    icon: <Search className="h-4 w-4" />
  }, {
    id: 'web-mapping-section',
    title: 'Web Application Mapping',
    icon: <Globe className="h-4 w-4" />
  }, {
    id: 'http-analysis-section',
    title: 'HTTP Traffic Analysis',
    icon: <Shield className="h-4 w-4" />
  }, {
    id: 'javascript-analysis-section',
    title: 'JavaScript Analysis',
    icon: <Code className="h-4 w-4" />
  }, {
    id: 'modern-tools-section',
    title: 'Modern Tools Arsenal',
    icon: <Database className="h-4 w-4" />
  }];

  // Navigation items for Exploitation Techniques
  const exploitationItems = [{
    id: 'manual-exploitation-section',
    title: 'Manual Exploitation',
    icon: <Target className="h-4 w-4" />
  }, {
    id: 'modern-attack-vectors-section',
    title: 'Modern Attack Vectors',
    icon: <Zap className="h-4 w-4" />
  }, {
    id: 'client-side-exploitation-section',
    title: 'Client-Side Exploitation',
    icon: <Code className="h-4 w-4" />
  }, {
    id: 'authentication-bypass-section',
    title: 'Authentication Bypass',
    icon: <Shield className="h-4 w-4" />
  }, {
    id: 'cloud-container-exploitation-section',
    title: 'Cloud & Container Exploitation',
    icon: <Globe className="h-4 w-4" />
  }];

  // Navigation items for Post-Exploitation
  const postExploitationItems = [
    {
      id: 'persistence-section',
      title: 'Persistence Techniques',
      icon: <Shield className="h-4 w-4" />
    },
    {
      id: 'privilege-escalation-section',
      title: 'Privilege Escalation',
      icon: <Crown className="h-4 w-4" />
    },
    {
      id: 'data-exfiltration-section',
      title: 'Data Exfiltration',
      icon: <Download className="h-4 w-4" />
    },
    {
      id: 'lateral-movement-section',
      title: 'Lateral Movement',
      icon: <Network className="h-4 w-4" />
    },
    {
      id: 'covering-tracks-section',
      title: 'Covering Tracks',
      icon: <EyeOff className="h-4 w-4" />
    },
    {
      id: 'maintaining-access-section',
      title: 'Maintaining Access',
      icon: <Key className="h-4 w-4" />
    },
    {
      id: 'advanced-post-exploitation-section',
      title: 'Advanced Techniques',
      icon: <Zap className="h-4 w-4" />
    }
  ];

  // Navigation items for Evasion Techniques
  const evasionItems = [
    {
      id: 'waf-bypass-section',
      title: 'WAF Bypass',
      icon: <Shield className="h-4 w-4" />
    },
    {
      id: 'antivirus-evasion-section',
      title: 'Antivirus Evasion',
      icon: <Eye className="h-4 w-4" />
    },
    {
      id: 'network-evasion-section',
      title: 'Network Evasion',
      icon: <Network className="h-4 w-4" />
    },
    {
      id: 'traffic-obfuscation-section',
      title: 'Traffic Obfuscation',
      icon: <Code className="h-4 w-4" />
    },
    {
      id: 'stealth-techniques-section',
      title: 'Stealth Techniques',
      icon: <EyeOff className="h-4 w-4" />
    }
  ];

  // Navigation items for Automation & Scripting
  const automationItems = [
    {
      id: 'script-development-section',
      title: 'Script Development',
      icon: <Code className="h-4 w-4" />
    },
    {
      id: 'testing-frameworks-section',
      title: 'Testing Frameworks',
      icon: <TestTube className="h-4 w-4" />
    },
    {
      id: 'vulnerability-scanning-section',
      title: 'Vulnerability Scanning',
      icon: <Search className="h-4 w-4" />
    },
    {
      id: 'payload-generation-section',
      title: 'Payload Generation',
      icon: <Terminal className="h-4 w-4" />
    },
    {
      id: 'continuous-monitoring-section',
      title: 'Continuous Monitoring',
      icon: <Clock className="h-4 w-4" />
    },
    {
      id: 'report-generation-section',
      title: 'Report Generation',
      icon: <Database className="h-4 w-4" />
    }
  ];

  const {
    activeSection: activeReconSection,
    setActiveSection: setActiveReconSection
  } = useActiveSection(reconnaissanceItems.map(item => item.id));
  const {
    activeSection: activeExploitSection,
    setActiveSection: setActiveExploitSection
  } = useActiveSection(exploitationItems.map(item => item.id));
  const {
    activeSection: activePostExploitSection,
    setActiveSection: setActivePostExploitSection
  } = useActiveSection(postExploitationItems.map(item => item.id));
  const {
    activeSection: activeEvasionSection,
    setActiveSection: setActiveEvasionSection
  } = useActiveSection(evasionItems.map(item => item.id));
  const {
    activeSection: activeAutomationSection,
    setActiveSection: setActiveAutomationSection
  } = useActiveSection(automationItems.map(item => item.id));

  // Debug logging
  React.useEffect(() => {
    console.log('AdvancedContentSection mounted');
    console.log('Post-exploitation components loaded:', {
      PersistenceTechniques: !!PersistenceTechniques,
      PrivilegeEscalation: !!PrivilegeEscalation,
      DataExfiltration: !!DataExfiltration,
      LateralMovement: !!LateralMovement,
      CoveringTracks: !!CoveringTracks,
      MaintainingAccess: !!MaintainingAccess,
      AdvancedPostExploitation: !!AdvancedPostExploitation
    });
  }, []);

  return (
    <div className="space-y-8">
      <ErrorBoundary>
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
            <TabsTrigger 
              value="post-exploitation" 
              className="text-xs"
              onClick={() => {
                console.log('Post-exploitation tab clicked');
                console.log('All post-exploitation items:', postExploitationItems);
              }}
            >
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
            <div className="grid grid-cols-[280px_1fr] gap-8 min-h-screen">
              <div className="w-full">
                <SectionNavigation items={reconnaissanceItems} activeSection={activeReconSection} onSectionChange={setActiveReconSection} />
              </div>
              
              <div className="min-w-0 space-y-8 max-w-none overflow-hidden">
                <div id="osint-section">
                  <OSINTSection />
                </div>
                
                <div id="web-mapping-section">
                  <Card className="bg-cybr-card border-cybr-muted">
                    <CardHeader>
                      <CardTitle className="text-cybr-primary">Web Application Mapping</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <WebApplicationMapping />
                    </CardContent>
                  </Card>
                </div>

                <div id="http-analysis-section">
                  <Card className="bg-cybr-card border-cybr-muted">
                    <CardHeader>
                      <CardTitle className="text-cybr-primary">HTTP Traffic Analysis</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <HTTPAnalysis />
                    </CardContent>
                  </Card>
                </div>

                <div id="javascript-analysis-section">
                  <Card className="bg-cybr-card border-cybr-muted">
                    <CardHeader>
                      <CardTitle className="text-cybr-primary">JavaScript Analysis</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <JavaScriptAnalysis />
                    </CardContent>
                  </Card>
                </div>

                <div id="modern-tools-section">
                  <Card className="bg-cybr-card border-cybr-muted">
                    <CardHeader>
                      <CardTitle className="text-cybr-primary">Modern Tools Arsenal</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ModernToolsArsenal />
                    </CardContent>
                  </Card>
                </div>
              </div>
            </div>
          </TabsContent>

          {/* Exploitation Techniques Tab */}
          <TabsContent value="exploitation-techniques" className="space-y-6">
            <div className="grid grid-cols-[280px_1fr] gap-8 min-h-screen">
              <div className="w-full">
                <SectionNavigation items={exploitationItems} activeSection={activeExploitSection} onSectionChange={setActiveExploitSection} />
              </div>
              
              <div className="min-w-0 space-y-8 max-w-none overflow-hidden">
                <div id="manual-exploitation-section">
                  <ManualExploitationTechniques />
                </div>
                
                <div id="modern-attack-vectors-section">
                  <ModernAttackVectors />
                </div>

                <div id="client-side-exploitation-section">
                  <ClientSideExploitation />
                </div>

                <div id="authentication-bypass-section">
                  <AuthenticationBypass />
                </div>

                <div id="cloud-container-exploitation-section">
                  <CloudContainerExploitation />
                </div>
              </div>
            </div>
          </TabsContent>

          {/* Post-Exploitation Tab with Error Boundaries */}
          <TabsContent value="post-exploitation" className="space-y-6">
            <div className="grid grid-cols-[280px_1fr] gap-8 min-h-screen">
              <div className="w-full">
                <ErrorBoundary>
                  <SectionNavigation 
                    items={postExploitationItems} 
                    activeSection={activePostExploitSection} 
                    onSectionChange={setActivePostExploitSection} 
                  />
                </ErrorBoundary>
              </div>
              
              <div className="min-w-0 space-y-8 max-w-none overflow-hidden">
                <div id="persistence-section">
                  <ErrorBoundary>
                    <PersistenceTechniques />
                  </ErrorBoundary>
                </div>
                
                <div id="privilege-escalation-section">
                  <ErrorBoundary>
                    <PrivilegeEscalation />
                  </ErrorBoundary>
                </div>

                <div id="data-exfiltration-section">
                  <ErrorBoundary>
                    <DataExfiltration />
                  </ErrorBoundary>
                </div>

                <div id="lateral-movement-section">
                  <ErrorBoundary>
                    <LateralMovement />
                  </ErrorBoundary>
                </div>

                <div id="covering-tracks-section">
                  <ErrorBoundary>
                    <CoveringTracks />
                  </ErrorBoundary>
                </div>

                <div id="maintaining-access-section">
                  <ErrorBoundary>
                    <MaintainingAccess />
                  </ErrorBoundary>
                </div>

                <div id="advanced-post-exploitation-section">
                  <ErrorBoundary>
                    <AdvancedPostExploitation />
                  </ErrorBoundary>
                </div>
              </div>
            </div>
          </TabsContent>

          {/* Evasion Techniques Tab */}
          <TabsContent value="evasion-techniques" className="space-y-6">
            <div className="grid grid-cols-[280px_1fr] gap-8 min-h-screen">
              <div className="w-full">
                <SectionNavigation 
                  items={evasionItems} 
                  activeSection={activeEvasionSection} 
                  onSectionChange={setActiveEvasionSection} 
                />
              </div>
              
              <div className="min-w-0 space-y-8 max-w-none overflow-hidden">
                <div id="waf-bypass-section">
                  <WAFBypass />
                </div>
                
                <div id="antivirus-evasion-section">
                  <AntivirusEvasion />
                </div>

                <div id="network-evasion-section">
                  <NetworkEvasion />
                </div>

                <div id="traffic-obfuscation-section">
                  <TrafficObfuscation />
                </div>

                <div id="stealth-techniques-section">
                  <StealthTechniques />
                </div>
              </div>
            </div>
          </TabsContent>

          {/* Automation & Scripting Tab */}
          <TabsContent value="automation-scripting" className="space-y-6">
            <div className="grid grid-cols-[280px_1fr] gap-8 min-h-screen">
              <div className="w-full">
                <SectionNavigation 
                  items={automationItems} 
                  activeSection={activeAutomationSection} 
                  onSectionChange={setActiveAutomationSection} 
                />
              </div>
              
              <div className="min-w-0 space-y-8 max-w-none overflow-hidden">
                <div id="script-development-section">
                  <ScriptDevelopment />
                </div>
                
                <div id="testing-frameworks-section">
                  <TestingFrameworks />
                </div>

                <div id="vulnerability-scanning-section">
                  <VulnerabilityScanning />
                </div>

                <div id="payload-generation-section">
                  <Card className="bg-cybr-card border-cybr-muted">
                    <CardHeader>
                      <CardTitle className="text-cybr-primary flex items-center gap-2">
                        <Terminal className="h-6 w-6" />
                        Payload Generation
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <p className="text-cybr-foreground opacity-80">
                        Advanced payload generation techniques will be implemented here.
                      </p>
                    </CardContent>
                  </Card>
                </div>

                <div id="continuous-monitoring-section">
                  <Card className="bg-cybr-card border-cybr-muted">
                    <CardHeader>
                      <CardTitle className="text-cybr-primary flex items-center gap-2">
                        <Clock className="h-6 w-6" />
                        Continuous Monitoring
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <p className="text-cybr-foreground opacity-80">
                        Continuous monitoring and alerting systems will be implemented here.
                      </p>
                    </CardContent>
                  </Card>
                </div>

                <div id="report-generation-section">
                  <Card className="bg-cybr-card border-cybr-muted">
                    <CardHeader>
                      <CardTitle className="text-cybr-primary flex items-center gap-2">
                        <Database className="h-6 w-6" />
                        Report Generation
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <p className="text-cybr-foreground opacity-80">
                        Automated report generation and visualization will be implemented here.
                      </p>
                    </CardContent>
                  </Card>
                </div>
              </div>
            </div>
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
      </ErrorBoundary>
    </div>
  );
};

export default AdvancedContentSection;
