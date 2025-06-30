
import React from 'react';
import { Badge } from '@/components/ui/badge';

const WebApplicationMapping: React.FC = () => {
  return (
    <div className="space-y-4">
      <h4 className="text-lg font-semibold text-cybr-accent">Advanced Web Application Mapping</h4>
      
      <div className="bg-cybr-muted/20 p-4 rounded-lg">
        <h5 className="font-semibold mb-2 text-cybr-primary">Single Page Application (SPA) Reconnaissance</h5>
        <p className="text-sm mb-3 opacity-80">
          Modern SPAs require specialized reconnaissance techniques due to their client-side routing and dynamic content loading.
        </p>
        
        <div className="space-y-3">
          <div>
            <p className="text-sm font-medium mb-2">Client-Side Route Discovery:</p>
            <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# JavaScript Route Analysis
grep -r "route\\|path\\|component" ./js/
grep -rE "(Route|Switch|Router)" ./js/
grep -rE "history\\.(push|replace)" ./js/

# React Router Discovery
curl -s https://target.com | grep -oE 'window\\.__INITIAL_STATE__[^;]*'
curl -s https://target.com | grep -oE 'window\\.__PRELOADED_STATE__[^;]*'`}
            </pre>
          </div>
          
          <div>
            <p className="text-sm font-medium mb-2">Dynamic Content Discovery:</p>
            <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# Headless Browser Reconnaissance
# Using Puppeteer/Playwright for SPA crawling
const browser = await puppeteer.launch();
const page = await browser.newPage();
await page.goto('https://target.com');

// Intercept network requests
page.on('request', request => {
  console.log('Request:', request.url());
});

// Execute JavaScript to trigger route changes
await page.evaluate(() => {
  // Trigger all possible routes
  if (window.history) {
    window.history.pushState({}, '', '/admin');
    window.history.pushState({}, '', '/api/users');
  }
});`}
            </pre>
          </div>
        </div>
      </div>

      <div className="bg-cybr-muted/20 p-4 rounded-lg">
        <h5 className="font-semibold mb-2 text-cybr-primary">Progressive Web App (PWA) Analysis</h5>
        <div className="space-y-3">
          <div>
            <p className="text-sm font-medium mb-2">Service Worker Analysis:</p>
            <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# Service Worker Discovery
curl -s https://target.com/sw.js
curl -s https://target.com/service-worker.js
curl -s https://target.com/serviceworker.js

# Web App Manifest Analysis
curl -s https://target.com/manifest.json
curl -s https://target.com/manifest.webmanifest

# PWA Cache Analysis
# Service worker cache endpoints
curl -s https://target.com/sw.js | grep -oE 'cache\\.addAll\\([^)]*\\)'`}
            </pre>
          </div>
        </div>
      </div>

      <div className="bg-cybr-muted/20 p-4 rounded-lg">
        <h5 className="font-semibold mb-2 text-cybr-primary">API Endpoint Discovery</h5>
        <div className="space-y-3">
          <div>
            <p className="text-sm font-medium mb-2">Multiple Discovery Methods:</p>
            <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# JavaScript API Endpoint Extraction
curl -s https://target.com | grep -oE 'api/[a-zA-Z0-9/_-]*'
curl -s https://target.com/app.js | grep -oE '"/api/[^"]*"'

# Network Tab Monitoring (Manual)
# 1. Open Developer Tools → Network Tab
# 2. Use application normally
# 3. Filter by XHR/Fetch requests
# 4. Document all API endpoints

# Webpack Bundle Analysis
curl -s https://target.com/static/js/main.*.js | grep -oE 'endpoint[^,]*'`}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};

export default WebApplicationMapping;
