
import React from 'react';
import { Shield, FileCode, Check } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

const WelcomeSection: React.FC = () => {
  return (
    <div className="space-y-8">
      <div className="text-center max-w-3xl mx-auto">
        <h2 className="text-3xl font-bold mb-4">Welcome to Secure Code Review Challenges</h2>
        <p className="text-lg opacity-80">
          Test your skills in identifying security vulnerabilities through interactive code review exercises.
          Learn to spot and fix common security issues in various programming languages.
        </p>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-10">
        <Card className="bg-cybr-muted/50 border-cybr-primary/20 hover:border-cybr-primary/40 transition-all">
          <CardHeader className="pb-2">
            <div className="w-12 h-12 rounded-full bg-cybr-primary/10 flex items-center justify-center mb-2">
              <FileCode className="w-6 h-6 text-cybr-primary" />
            </div>
            <CardTitle>What You'll Learn</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="list-disc pl-5 space-y-1">
              <li>Identify common security vulnerabilities in code</li>
              <li>Understand secure coding practices</li>
              <li>Compare vulnerable vs. secure implementations</li>
              <li>Develop a security-focused code review mindset</li>
              <li>Apply security principles across multiple languages</li>
            </ul>
          </CardContent>
        </Card>
        
        <Card className="bg-cybr-muted/50 border-cybr-primary/20 hover:border-cybr-primary/40 transition-all">
          <CardHeader className="pb-2">
            <div className="w-12 h-12 rounded-full bg-cybr-primary/10 flex items-center justify-center mb-2">
              <Shield className="w-6 h-6 text-cybr-primary" />
            </div>
            <CardTitle>Challenge Types</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="list-disc pl-5 space-y-1">
              <li><strong>Single Code Review:</strong> Determine if a piece of code is secure</li>
              <li><strong>Code Comparison:</strong> Identify which implementation is secure</li>
              <li><strong>Vulnerability Spotting:</strong> Find specific security flaws</li>
              <li><strong>Multiple Vulnerabilities:</strong> Identify all issues in complex code</li>
              <li><strong>Fix The Code:</strong> Suggest secure alternatives (coming soon)</li>
            </ul>
          </CardContent>
        </Card>
        
        <Card className="bg-cybr-muted/50 border-cybr-primary/20 hover:border-cybr-primary/40 transition-all">
          <CardHeader className="pb-2">
            <div className="w-12 h-12 rounded-full bg-cybr-primary/10 flex items-center justify-center mb-2">
              <Check className="w-6 h-6 text-cybr-primary" />
            </div>
            <CardTitle>How to Participate</CardTitle>
          </CardHeader>
          <CardContent>
            <ol className="list-decimal pl-5 space-y-1">
              <li>Navigate to the Challenge Explorer tab</li>
              <li>Choose a challenge based on language or category</li>
              <li>Review the code and identify security issues</li>
              <li>Submit your answer and review the explanation</li>
              <li>Track your progress and improve your skills</li>
            </ol>
          </CardContent>
        </Card>
      </div>
      
      <div className="bg-gradient-to-r from-cybr-primary/10 to-cybr-accent/10 p-6 rounded-lg border border-cybr-primary/20 mt-6">
        <h3 className="text-xl font-bold mb-3">Ready to Test Your Skills?</h3>
        <p>
          Head to the <span className="text-cybr-primary font-semibold">Challenge Explorer</span> tab to start reviewing code for security vulnerabilities.
          The challenges range from beginner to advanced level and cover multiple programming languages and security categories.
        </p>
      </div>
    </div>
  );
};

export default WelcomeSection;
