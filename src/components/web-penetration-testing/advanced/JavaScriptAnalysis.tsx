
import React from 'react';

const JavaScriptAnalysis: React.FC = () => {
  return (
    <div className="space-y-4">
      <h4 className="text-lg font-semibold text-cybr-accent">Advanced JavaScript Analysis</h4>
      
      <div className="bg-cybr-muted/20 p-4 rounded-lg">
        <h5 className="font-semibold mb-2 text-cybr-primary">Source Map Discovery & Exploitation</h5>
        <div className="space-y-3">
          <div>
            <p className="text-sm font-medium mb-2">Source Map Analysis:</p>
            <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# Source Map Discovery
curl -s https://target.com/static/js/main.js | grep -oE 'sourceMappingURL=[^*]*'
curl -s https://target.com/static/js/main.js.map

# Automated Source Map Discovery
for js_file in $(curl -s https://target.com | grep -oE 'src="[^"]*\\.js"' | cut -d'"' -f2); do
  echo "Checking $js_file for source maps:"
  curl -s https://target.com$js_file | tail -5 | grep sourceMappingURL
done

# Source Map Analysis for Sensitive Info
curl -s https://target.com/static/js/main.js.map | jq -r '.sources[]' | grep -E '(config|secret|key|password|api)'`}
            </pre>
          </div>
        </div>
      </div>

      <div className="bg-cybr-muted/20 p-4 rounded-lg">
        <h5 className="font-semibold mb-2 text-cybr-primary">Webpack Bundle Analysis</h5>
        <div className="space-y-3">
          <div>
            <p className="text-sm font-medium mb-2">Bundle Decomposition:</p>
            <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# Webpack Module Extraction
curl -s https://target.com/static/js/main.js | grep -oE 'function\\([^)]*\\)\\{[^}]*\\}' | head -10

# Configuration Extraction
curl -s https://target.com/static/js/main.js | grep -oE 'process\\.env\\.[A-Z_]*' | sort -u
curl -s https://target.com/static/js/main.js | grep -oE 'NODE_ENV|API_URL|BASE_URL' 

# Module Mapping
curl -s https://target.com/static/js/main.js | grep -oE '__webpack_require__\\([0-9]*\\)' | sort -u

# Webpack Externals Discovery
curl -s https://target.com/static/js/main.js | grep -oE 'externals:\\{[^}]*\\}'`}
            </pre>
          </div>
        </div>
      </div>

      <div className="bg-cybr-muted/20 p-4 rounded-lg">
        <h5 className="font-semibold mb-2 text-cybr-primary">Hidden API Endpoints in JavaScript</h5>
        <div className="space-y-3">
          <div>
            <p className="text-sm font-medium mb-2">Endpoint Extraction Techniques:</p>
            <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# API Endpoint Regex Patterns
curl -s https://target.com/app.js | grep -oE '"/api/[a-zA-Z0-9/_-]*"' | sort -u
curl -s https://target.com/app.js | grep -oE "'\\/api\\/[a-zA-Z0-9\\/_-]*'" | sort -u
curl -s https://target.com/app.js | grep -oE 'endpoint:\\s*["\'][^"\']*["\']'

# GraphQL Schema Discovery
curl -s https://target.com/app.js | grep -oE 'query\\s*[A-Za-z]*\\s*\\{[^}]*\\}'
curl -s https://target.com/app.js | grep -oE 'mutation\\s*[A-Za-z]*\\s*\\{[^}]*\\}'

# REST API Pattern Discovery
curl -s https://target.com/app.js | grep -oE '\\$\\{[^}]*\\}\\/[a-zA-Z0-9/_-]*'
curl -s https://target.com/app.js | grep -oE 'baseURL[^,]*'`}
            </pre>
          </div>
        </div>
      </div>

      <div className="bg-cybr-muted/20 p-4 rounded-lg">
        <h5 className="font-semibold mb-2 text-cybr-primary">JavaScript Deobfuscation</h5>
        <div className="space-y-3">
          <div>
            <p className="text-sm font-medium mb-2">Deobfuscation Techniques:</p>
            <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# Basic Deobfuscation
# 1. Beautify minified code
curl -s https://target.com/app.min.js | js-beautify

# 2. Variable name pattern analysis
curl -s https://target.com/app.js | grep -oE 'var [a-zA-Z_$][a-zA-Z0-9_$]*=' | sort | uniq -c

# 3. String decoding (common patterns)
# Hex encoding: \\x41\\x42\\x43 = ABC
# Unicode encoding: \\u0041\\u0042\\u0043 = ABC
# Base64 decoding in JavaScript

# 4. Function call analysis
curl -s https://target.com/app.js | grep -oE '[a-zA-Z_$][a-zA-Z0-9_$]*\\([^)]*\\)' | head -20`}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};

export default JavaScriptAnalysis;
