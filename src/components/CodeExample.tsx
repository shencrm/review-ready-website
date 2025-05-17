
import React from 'react';

interface CodeExampleProps {
  language: string;
  code: string;
  title?: string;
  isVulnerable?: boolean;
}

const CodeExample: React.FC<CodeExampleProps> = ({ language, code, title, isVulnerable }) => {
  return (
    <div className={`code-block my-6 border ${isVulnerable ? 'border-red-400' : isVulnerable === false ? 'border-green-500' : 'border-cybr-muted'}`}>
      {title && (
        <div className={`flex items-center justify-between px-4 py-2 border-b ${
          isVulnerable ? 'bg-cybr-muted border-red-400' : 
          isVulnerable === false ? 'bg-cybr-muted border-green-500' : 
          'bg-cybr-card-muted border-cybr-muted'
        }`}>
          <div className="flex items-center">
            {isVulnerable !== undefined && (
              <span className={`inline-flex items-center justify-center w-6 h-6 rounded-full mr-2 text-white text-xs ${isVulnerable ? 'bg-red-500' : 'bg-green-500'}`}>
                {isVulnerable ? '!' : '✓'}
              </span>
            )}
            <span className="text-sm font-mono font-semibold text-slate-900 dark:text-slate-100">
              {title}
              {isVulnerable !== undefined && (
                <span className="ml-2 text-xs font-normal text-slate-700 dark:text-slate-300">
                  {isVulnerable ? '(Vulnerable - Do Not Use)' : '(Secure - Recommended)'}
                </span>
              )}
            </span>
          </div>
          <span className="text-xs text-cybr-primary">{language}</span>
        </div>
      )}
      <pre className="p-4 border-0 overflow-x-auto bg-cybr-card">
        <code className={`language-${language}`}>{code}</code>
      </pre>
    </div>
  );
};

export default CodeExample;
