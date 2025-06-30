
import React from 'react';

const HTTPAnalysis: React.FC = () => {
  return (
    <div className="space-y-4">
      <h4 className="text-lg font-semibold text-cybr-accent">HTTP/HTTPS Deep Analysis</h4>
      
      <div className="bg-cybr-muted/20 p-4 rounded-lg">
        <h5 className="font-semibold mb-2 text-cybr-primary">HTTP Method Comprehensive Testing</h5>
        <div className="space-y-3">
          <div>
            <p className="text-sm font-medium mb-2">Method Enumeration & Testing:</p>
            <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# OPTIONS Method Discovery
curl -X OPTIONS https://target.com -v

# Comprehensive Method Testing
for method in GET POST PUT DELETE PATCH HEAD OPTIONS TRACE CONNECT; do
  echo "Testing $method:"
  curl -X $method https://target.com/api/users -v
done

# WebDAV Methods
curl -X PROPFIND https://target.com -v
curl -X MKCOL https://target.com/test -v
curl -X COPY https://target.com/file.txt -H "Destination: /copy.txt" -v`}
            </pre>
          </div>
          
          <div>
            <p className="text-sm font-medium mb-2">Custom Header Injection:</p>
            <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# X-HTTP-Method-Override Testing
curl -X POST https://target.com/api/users/1 -H "X-HTTP-Method-Override: DELETE"
curl -X POST https://target.com/api/users/1 -H "X-HTTP-Method-Override: PUT"

# Custom Headers for Bypass
curl https://target.com -H "X-Forwarded-For: 127.0.0.1"
curl https://target.com -H "X-Real-IP: 192.168.1.1"
curl https://target.com -H "X-Originating-IP: 10.0.0.1"
curl https://target.com -H "Client-IP: 172.16.0.1"`}
            </pre>
          </div>
        </div>
      </div>

      <div className="bg-cybr-muted/20 p-4 rounded-lg">
        <h5 className="font-semibold mb-2 text-cybr-primary">SSL/TLS Certificate Deep Analysis</h5>
        <div className="space-y-3">
          <div>
            <p className="text-sm font-medium mb-2">Certificate Transparency Analysis:</p>
            <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# Certificate Transparency Logs
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# SSL Certificate Analysis
openssl s_client -connect target.com:443 -servername target.com < /dev/null 2>/dev/null | openssl x509 -text
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -subject -issuer -dates

# SNI (Server Name Indication) Testing
for subdomain in www api admin dev test; do
  echo "Testing SNI for $subdomain.target.com:"
  openssl s_client -connect target.com:443 -servername $subdomain.target.com -verify_return_error 2>/dev/null
done`}
            </pre>
          </div>
        </div>
      </div>

      <div className="bg-cybr-muted/20 p-4 rounded-lg">
        <h5 className="font-semibold mb-2 text-cybr-primary">HTTP/2 & HTTP/3 Reconnaissance</h5>
        <div className="space-y-3">
          <div>
            <p className="text-sm font-medium mb-2">Protocol-Specific Testing:</p>
            <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# HTTP/2 Testing
curl --http2 https://target.com -v
curl --http2-prior-knowledge http://target.com -v

# HTTP/2 Server Push Detection
curl --http2 https://target.com -v 2>&1 | grep -i "push"

# HTTP/3 (QUIC) Testing
curl --http3 https://target.com -v
# Note: Requires curl with HTTP/3 support

# Protocol Downgrade Testing
curl --http1.1 https://target.com -v
curl --http2 https://target.com -H "Connection: Upgrade, HTTP2-Settings"  -v`}
            </pre>
          </div>
        </div>
      </div>

      <div className="bg-cybr-muted/20 p-4 rounded-lg">
        <h5 className="font-semibold mb-2 text-cybr-primary">WebSocket Endpoint Discovery</h5>
        <div className="space-y-3">
          <div>
            <p className="text-sm font-medium mb-2">WebSocket Reconnaissance:</p>
            <pre className="bg-black/50 p-2 rounded text-xs text-green-400 overflow-x-auto">
{`# WebSocket Endpoint Discovery
curl -s https://target.com | grep -oE 'ws://[^"]*|wss://[^"]*'
curl -s https://target.com/app.js | grep -oE 'WebSocket\\([^)]*\\)'

# WebSocket Connection Testing
wscat -c wss://target.com/socket
wscat -c ws://target.com:8080/websocket

# JavaScript WebSocket Discovery
# In browser console:
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() { console.log('Connected'); };
ws.onmessage = function(event) { console.log('Message:', event.data); };`}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HTTPAnalysis;
