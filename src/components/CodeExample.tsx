
import React from 'react';

interface CodeExampleProps {
  language: string;
  code: string;
  title?: string;
}

const CodeExample: React.FC<CodeExampleProps> = ({ language, code, title }) => {
  return (
    <div className="code-block my-6">
      {title && (
        <div className="flex items-center justify-between px-4 py-2 border-b border-cybr-muted">
          <span className="text-sm font-mono text-cybr-secondary">{title}</span>
          <span className="text-xs text-cybr-primary/70">{language}</span>
        </div>
      )}
      <pre className="p-0 border-0 overflow-x-auto">
        <code className="language-{language}">{code}</code>
      </pre>
    </div>
  );
};

export default CodeExample;
