
import React, { useState } from 'react';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Share2, MessageSquare, Database, Radio } from 'lucide-react';

// Import the refactored components
import IPCIntroduction from './ipc/IPCIntroduction';
import IntentAnalysisSection from './ipc/IntentAnalysisSection';
import ContentProviderSection from './ipc/ContentProviderSection';
import BroadcastServiceSection from './ipc/BroadcastServiceSection';

const AndroidIPCAnalysis: React.FC = () => {
  const [activeTab, setActiveTab] = useState('introduction');

  return (
    <div className="space-y-6">
      {/* Introduction Section */}
      <div className="bg-gradient-to-r from-blue-50 to-purple-50 p-6 rounded-lg border">
        <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
          <Share2 className="text-blue-600" />
          Android IPC (Inter-Process Communication) Analysis
        </h2>
        <p className="text-lg text-gray-700 mb-4">
          Android's Inter-Process Communication (IPC) mechanisms are fundamental to how Android applications 
          interact with each other and the system. IPC security analysis focuses on testing the security 
          of Intents, Content Providers, Broadcast Receivers, and Services - the four main components that 
          enable communication between different parts of an Android system.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
          <div className="bg-white p-4 rounded-lg border">
            <h3 className="font-semibold text-green-700 mb-2">Why IPC Analysis Matters</h3>
            <ul className="text-sm text-gray-600 space-y-1">
              <li>• Detects component hijacking vulnerabilities</li>
              <li>• Identifies data exposure through improper exports</li>
              <li>• Prevents privilege escalation attacks</li>
              <li>• Ensures proper access control implementation</li>
            </ul>
          </div>
          <div className="bg-white p-4 rounded-lg border">
            <h3 className="font-semibold text-blue-700 mb-2">Common IPC Vulnerabilities</h3>
            <ul className="text-sm text-gray-600 space-y-1">
              <li>• Exported components without proper protection</li>
              <li>• Intent-based attacks and data leakage</li>
              <li>• Broadcast injection and eavesdropping</li>
              <li>• SQL injection in Content Providers</li>
            </ul>
          </div>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList className="grid grid-cols-2 md:grid-cols-4 gap-1 h-auto p-1">
          <TabsTrigger value="introduction" className="flex items-center gap-1 py-2 text-xs">
            <MessageSquare className="h-3 w-3" />
            <span className="hidden md:inline">Overview</span>
          </TabsTrigger>
          <TabsTrigger value="intent-analysis" className="flex items-center gap-1 py-2 text-xs">
            <Share2 className="h-3 w-3" />
            <span className="hidden md:inline">Intents</span>
          </TabsTrigger>
          <TabsTrigger value="content-providers" className="flex items-center gap-1 py-2 text-xs">
            <Database className="h-3 w-3" />
            <span className="hidden md:inline">Providers</span>
          </TabsTrigger>
          <TabsTrigger value="broadcast-services" className="flex items-center gap-1 py-2 text-xs">
            <Radio className="h-3 w-3" />
            <span className="hidden md:inline">Broadcast</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="introduction" className="space-y-6">
          <IPCIntroduction />
        </TabsContent>

        <TabsContent value="intent-analysis" className="space-y-6">
          <IntentAnalysisSection />
        </TabsContent>

        <TabsContent value="content-providers" className="space-y-6">
          <ContentProviderSection />
        </TabsContent>

        <TabsContent value="broadcast-services" className="space-y-6">
          <BroadcastServiceSection />
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default AndroidIPCAnalysis;
