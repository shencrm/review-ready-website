
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Code2, Terminal, FileCode, Zap } from 'lucide-react';

const ScriptDevelopment: React.FC = () => {
  return (
    <Card className="bg-cybr-card border-cybr-muted">
      <CardHeader>
        <CardTitle className="text-cybr-primary flex items-center gap-2">
          <Code2 className="h-6 w-6" />
          Custom Script Development
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="python-automation" className="w-full">
          <TabsList className="grid grid-cols-2 md:grid-cols-4 w-full mb-6">
            <TabsTrigger value="python-automation">Python Scripts</TabsTrigger>
            <TabsTrigger value="powershell-automation">PowerShell</TabsTrigger>
            <TabsTrigger value="bash-automation">Bash Scripts</TabsTrigger>
            <TabsTrigger value="api-integration">API Integration</TabsTrigger>
          </TabsList>

          <TabsContent value="python-automation" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Python Automation Scripts</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Multi-threaded Port Scanner</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`#!/usr/bin/env python3
import socket
import threading
import argparse
from queue import Queue

class PortScanner:
    def __init__(self, target, threads=100):
        self.target = target
        self.threads = threads
        self.port_queue = Queue()
        self.open_ports = []
        
    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                self.open_ports.append(port)
                print(f"Port {port}: Open")
            sock.close()
        except Exception as e:
            pass
    
    def worker(self):
        while not self.port_queue.empty():
            port = self.port_queue.get()
            self.scan_port(port)
            self.port_queue.task_done()
    
    def run_scan(self, start_port=1, end_port=1000):
        # Fill the queue
        for port in range(start_port, end_port + 1):
            self.port_queue.put(port)
        
        # Start threads
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
        
        self.port_queue.join()
        return self.open_ports

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-t", "--threads", type=int, default=100)
    args = parser.parse_args()
    
    scanner = PortScanner(args.target, args.threads)
    open_ports = scanner.run_scan()
    print(f"Open ports: {open_ports}")`}
                </pre>
              </div>

              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Web Vulnerability Scanner</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`import requests
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time

class WebVulnScanner:
    def __init__(self, target_url, delay=1):
        self.target_url = target_url
        self.delay = delay
        self.session = requests.Session()
        self.vulnerabilities = []
        
    def get_forms(self, url):
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            return []
    
    def test_sql_injection(self, url):
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "1' AND 1=1--",
            "1' AND 1=2--"
        ]
        
        forms = self.get_forms(url)
        for form in forms:
            for payload in sql_payloads:
                form_data = {}
                for input_tag in form.find_all('input'):
                    if input_tag.get('name'):
                        form_data[input_tag.get('name')] = payload
                
                try:
                    response = self.session.post(url, data=form_data)
                    if any(error in response.text.lower() for error in 
                          ['mysql', 'sql syntax', 'warning', 'error']):
                        self.vulnerabilities.append({
                            'type': 'SQL Injection',
                            'url': url,
                            'payload': payload,
                            'severity': 'High'
                        })
                except Exception as e:
                    pass
                
                time.sleep(self.delay)
    
    def test_xss(self, url):
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>"
        ]
        
        forms = self.get_forms(url)
        for form in forms:
            for payload in xss_payloads:
                form_data = {}
                for input_tag in form.find_all('input'):
                    if input_tag.get('name'):
                        form_data[input_tag.get('name')] = payload
                
                try:
                    response = self.session.post(url, data=form_data)
                    if payload in response.text:
                        self.vulnerabilities.append({
                            'type': 'Cross-Site Scripting',
                            'url': url,
                            'payload': payload,
                            'severity': 'Medium'
                        })
                except Exception as e:
                    pass
                
                time.sleep(self.delay)
    
    def crawl_and_scan(self):
        print(f"Starting scan of {self.target_url}")
        self.test_sql_injection(self.target_url)
        self.test_xss(self.target_url)
        
        return self.vulnerabilities

# Usage
scanner = WebVulnScanner("http://example.com")
results = scanner.crawl_and_scan()
for vuln in results:
    print(f"[{vuln['severity']}] {vuln['type']} at {vuln['url']}")`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="powershell-automation" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">PowerShell Automation</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Network Discovery Script</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`# Advanced Network Discovery and Enumeration
param(
    [Parameter(Mandatory=$true)]
    [string]$Network,
    [int]$Threads = 50,
    [switch]$PortScan,
    [switch]$ServiceEnum
)

function Invoke-PingSweep {
    param([string]$Network, [int]$Threads)
    
    $Jobs = @()
    $AliveHosts = @()
    
    1..254 | ForEach-Object {
        $IP = "$Network.$_"
        $Jobs += Start-Job -ScriptBlock {
            param($IP)
            if (Test-Connection -ComputerName $IP -Count 1 -Quiet) {
                return $IP
            }
        } -ArgumentList $IP
        
        # Limit concurrent jobs
        while ((Get-Job -State Running).Count -ge $Threads) {
            Start-Sleep -Milliseconds 100
        }
    }
    
    # Wait for all jobs and collect results
    $Jobs | ForEach-Object {
        $Result = Receive-Job -Job $_ -Wait
        if ($Result) {
            $AliveHosts += $Result
        }
        Remove-Job -Job $_
    }
    
    return $AliveHosts
}

function Invoke-PortScan {
    param([string[]]$Hosts, [int[]]$Ports = @(21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5900,8080))
    
    $Results = @()
    
    foreach ($Host in $Hosts) {
        foreach ($Port in $Ports) {
            try {
                $Socket = New-Object System.Net.Sockets.TcpClient
                $Connect = $Socket.BeginConnect($Host, $Port, $null, $null)
                $Wait = $Connect.AsyncWaitHandle.WaitOne(1000, $false)
                
                if ($Wait) {
                    $Socket.EndConnect($Connect)
                    $Results += [PSCustomObject]@{
                        Host = $Host
                        Port = $Port
                        Status = "Open"
                    }
                    Write-Host "[$Host:$Port] Open" -ForegroundColor Green
                }
                $Socket.Close()
            } catch {
                # Port closed or filtered
            }
        }
    }
    
    return $Results
}

function Get-ServiceInfo {
    param([string]$Host, [int]$Port)
    
    try {
        $Socket = New-Object System.Net.Sockets.TcpClient($Host, $Port)
        $Stream = $Socket.GetStream()
        $Writer = New-Object System.IO.StreamWriter($Stream)
        $Reader = New-Object System.IO.StreamReader($Stream)
        
        # Send HTTP request for web services
        if ($Port -eq 80 -or $Port -eq 8080) {
            $Writer.WriteLine("GET / HTTP/1.1")
            $Writer.WriteLine("Host: $Host")
            $Writer.WriteLine("")
            $Writer.Flush()
            
            $Response = $Reader.ReadLine()
            return $Response
        }
        
        $Socket.Close()
    } catch {
        return $null
    }
}

# Main execution
Write-Host "Starting network discovery for $Network.0/24" -ForegroundColor Cyan

$AliveHosts = Invoke-PingSweep -Network $Network -Threads $Threads
Write-Host "Found $($AliveHosts.Count) alive hosts" -ForegroundColor Yellow

if ($PortScan -and $AliveHosts.Count -gt 0) {
    Write-Host "Starting port scan..." -ForegroundColor Cyan
    $PortResults = Invoke-PortScan -Hosts $AliveHosts
    
    if ($ServiceEnum) {
        Write-Host "Enumerating services..." -ForegroundColor Cyan
        foreach ($Result in $PortResults) {
            $ServiceInfo = Get-ServiceInfo -Host $Result.Host -Port $Result.Port
            if ($ServiceInfo) {
                Write-Host "[$($Result.Host):$($Result.Port)] $ServiceInfo" -ForegroundColor Magenta
            }
        }
    }
}

# Export results
$AliveHosts | Export-Csv -Path "alive_hosts.csv" -NoTypeInformation
if ($PortResults) {
    $PortResults | Export-Csv -Path "port_scan_results.csv" -NoTypeInformation
}`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="bash-automation" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Bash Automation Scripts</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Automated Reconnaissance Framework</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`#!/bin/bash

# Automated Web Application Reconnaissance Framework
# Usage: ./recon.sh target.com

TARGET=$1
OUTPUT_DIR="recon_$TARGET"
DATE=$(date +%Y%m%d_%H%M%S)

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
NC='\\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}"
    echo "=================================="
    echo "  Automated Recon Framework"
    echo "  Target: $TARGET"
    echo "  Date: $DATE"
    echo "=================================="
    echo -e "${NC}"
}

setup_directories() {
    echo -e "${YELLOW}[+] Setting up directories${NC}"
    mkdir -p $OUTPUT_DIR/{subdomains,ports,urls,screenshots,vulnerabilities}
}

subdomain_enumeration() {
    echo -e "${YELLOW}[+] Starting subdomain enumeration${NC}"
    
    # Subfinder
    if command -v subfinder &> /dev/null; then
        echo -e "${GREEN}[*] Running subfinder${NC}"
        subfinder -d $TARGET -o $OUTPUT_DIR/subdomains/subfinder.txt -silent
    fi
    
    # Amass
    if command -v amass &> /dev/null; then
        echo -e "${GREEN}[*] Running amass${NC}"
        amass enum -d $TARGET -o $OUTPUT_DIR/subdomains/amass.txt
    fi
    
    # Assetfinder
    if command -v assetfinder &> /dev/null; then
        echo -e "${GREEN}[*] Running assetfinder${NC}"
        assetfinder $TARGET > $OUTPUT_DIR/subdomains/assetfinder.txt
    fi
    
    # Combine and sort unique subdomains
    cat $OUTPUT_DIR/subdomains/*.txt | sort -u > $OUTPUT_DIR/subdomains/all_subdomains.txt
    SUBDOMAIN_COUNT=$(wc -l < $OUTPUT_DIR/subdomains/all_subdomains.txt)
    echo -e "${GREEN}[+] Found $SUBDOMAIN_COUNT unique subdomains${NC}"
}

port_scanning() {
    echo -e "${YELLOW}[+] Starting port scanning${NC}"
    
    # Fast scan for alive hosts
    nmap -sn -iL $OUTPUT_DIR/subdomains/all_subdomains.txt > $OUTPUT_DIR/ports/alive_hosts.txt
    
    # Extract alive IPs
    grep -oE "\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b" $OUTPUT_DIR/ports/alive_hosts.txt > $OUTPUT_DIR/ports/alive_ips.txt
    
    # Port scan alive hosts
    if [ -s $OUTPUT_DIR/ports/alive_ips.txt ]; then
        echo -e "${GREEN}[*] Scanning ports on alive hosts${NC}"
        nmap -sS -T4 -top-ports 1000 -iL $OUTPUT_DIR/ports/alive_ips.txt -oA $OUTPUT_DIR/ports/nmap_scan
    fi
}

url_discovery() {
    echo -e "${YELLOW}[+] Starting URL discovery${NC}"
    
    # Use alive subdomains for URL discovery
    while read -r subdomain; do
        if [ ! -z "$subdomain" ]; then
            echo -e "${GREEN}[*] Discovering URLs for $subdomain${NC}"
            
            # Waybackurls
            if command -v waybackurls &> /dev/null; then
                waybackurls $subdomain >> $OUTPUT_DIR/urls/waybackurls.txt
            fi
            
            # Gospider
            if command -v gospider &> /dev/null; then
                gospider -s "http://$subdomain" -c 10 -d 2 --blacklist "jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt" -o $OUTPUT_DIR/urls/gospider/
            fi
            
            # Directory brute force
            if command -v gobuster &> /dev/null; then
                gobuster dir -u "http://$subdomain" -w /usr/share/wordlists/dirb/common.txt -o $OUTPUT_DIR/urls/gobuster_$subdomain.txt -q
            fi
        fi
    done < $OUTPUT_DIR/subdomains/all_subdomains.txt
    
    # Combine all URLs
    find $OUTPUT_DIR/urls/ -name "*.txt" -exec cat {} \\; | sort -u > $OUTPUT_DIR/urls/all_urls.txt
}

vulnerability_scanning() {
    echo -e "${YELLOW}[+] Starting vulnerability scanning${NC}"
    
    # Nuclei scanning
    if command -v nuclei &> /dev/null; then
        echo -e "${GREEN}[*] Running nuclei${NC}"
        nuclei -l $OUTPUT_DIR/subdomains/all_subdomains.txt -o $OUTPUT_DIR/vulnerabilities/nuclei_results.txt -silent
    fi
    
    # Nikto scanning on web ports
    if command -v nikto &> /dev/null; then
        while read -r subdomain; do
            if [ ! -z "$subdomain" ]; then
                echo -e "${GREEN}[*] Running nikto on $subdomain${NC}"
                nikto -h "http://$subdomain" -o $OUTPUT_DIR/vulnerabilities/nikto_$subdomain.txt -Format txt
            fi
        done < $OUTPUT_DIR/subdomains/all_subdomains.txt
    fi
}

take_screenshots() {
    echo -e "${YELLOW}[+] Taking screenshots${NC}"
    
    if command -v aquatone &> /dev/null; then
        cat $OUTPUT_DIR/subdomains/all_subdomains.txt | aquatone -out $OUTPUT_DIR/screenshots/
    fi
}

generate_report() {
    echo -e "${YELLOW}[+] Generating report${NC}"
    
    REPORT_FILE="$OUTPUT_DIR/recon_report_$DATE.txt"
    {
        echo "Reconnaissance Report for $TARGET"
        echo "Generated on: $DATE"
        echo "=================================="
        echo ""
        echo "SUBDOMAINS FOUND: $(wc -l < $OUTPUT_DIR/subdomains/all_subdomains.txt)"
        echo "URLS DISCOVERED: $(wc -l < $OUTPUT_DIR/urls/all_urls.txt)"
        echo ""
        echo "Top 10 Subdomains:"
        head -10 $OUTPUT_DIR/subdomains/all_subdomains.txt
        echo ""
        echo "Vulnerability Summary:"
        if [ -f $OUTPUT_DIR/vulnerabilities/nuclei_results.txt ]; then
            echo "Nuclei findings: $(wc -l < $OUTPUT_DIR/vulnerabilities/nuclei_results.txt)"
        fi
    } > $REPORT_FILE
    
    echo -e "${GREEN}[+] Report saved to $REPORT_FILE${NC}"
}

# Main execution
print_banner
setup_directories
subdomain_enumeration
port_scanning
url_discovery
vulnerability_scanning
take_screenshots
generate_report

echo -e "${GREEN}[+] Reconnaissance completed! Results saved in $OUTPUT_DIR${NC}"
echo -e "${BLUE}[*] Total execution time: $SECONDS seconds${NC}"`}
                </pre>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="api-integration" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">API Integration Scripts</h3>
              
              <div className="bg-cybr-muted/20 p-4 rounded-lg">
                <h4 className="font-medium text-cybr-accent mb-2">Multi-Scanner API Integration</h4>
                <pre className="bg-cybr-background p-3 rounded text-sm overflow-x-auto">
{`import requests
import json
import time
from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class ScanResult:
    scanner: str
    target: str
    vulnerabilities: List[Dict]
    scan_time: str
    status: str

class SecurityScannerAPI:
    def __init__(self):
        self.shodan_api_key = "YOUR_SHODAN_API_KEY"
        self.virustotal_api_key = "YOUR_VT_API_KEY"
        self.censys_api_id = "YOUR_CENSYS_ID"
        self.censys_api_secret = "YOUR_CENSYS_SECRET"
        
    def shodan_scan(self, target: str) -> Optional[Dict]:
        """Shodan host information lookup"""
        try:
            url = f"https://api.shodan.io/shodan/host/{target}"
            params = {"key": self.shodan_api_key}
            
            response = requests.get(url, params=params, timeout=30)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Shodan API error: {response.status_code}")
                return None
        except Exception as e:
            print(f"Shodan scan error: {e}")
            return None
    
    def virustotal_scan(self, domain: str) -> Optional[Dict]:
        """VirusTotal domain reputation check"""
        try:
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {
                "apikey": self.virustotal_api_key,
                "domain": domain
            }
            
            response = requests.get(url, params=params, timeout=30)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"VirusTotal API error: {response.status_code}")
                return None
        except Exception as e:
            print(f"VirusTotal scan error: {e}")
            return None
    
    def censys_search(self, query: str) -> Optional[Dict]:
        """Censys search for hosts"""
        try:
            url = "https://search.censys.io/api/v2/hosts/search"
            headers = {"Content-Type": "application/json"}
            auth = (self.censys_api_id, self.censys_api_secret)
            
            data = {
                "q": query,
                "per_page": 50,
                "virtual_hosts": "EXCLUDE"
            }
            
            response = requests.post(url, headers=headers, auth=auth, 
                                   json=data, timeout=30)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Censys API error: {response.status_code}")
                return None
        except Exception as e:
            print(f"Censys search error: {e}")
            return None
    
    def nessus_scan(self, target: str, nessus_url: str, 
                   access_key: str, secret_key: str) -> Optional[str]:
        """Initiate Nessus scan"""
        try:
            # Create scan
            url = f"{nessus_url}/scans"
            headers = {
                "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}",
                "Content-Type": "application/json"
            }
            
            scan_data = {
                "uuid": "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6",  # Basic Network Scan
                "settings": {
                    "name": f"Automated Scan - {target}",
                    "text_targets": target,
                    "scanner_id": 1
                }
            }
            
            response = requests.post(url, headers=headers, 
                                   json=scan_data, verify=False, timeout=30)
            if response.status_code == 200:
                scan_id = response.json()["scan"]["id"]
                
                # Launch scan
                launch_url = f"{nessus_url}/scans/{scan_id}/launch"
                launch_response = requests.post(launch_url, headers=headers, 
                                              verify=False, timeout=30)
                
                if launch_response.status_code == 200:
                    return scan_id
            
            return None
        except Exception as e:
            print(f"Nessus scan error: {e}")
            return None
    
    def comprehensive_scan(self, target: str) -> List[ScanResult]:
        """Run comprehensive scans using multiple APIs"""
        results = []
        
        print(f"Starting comprehensive scan of {target}")
        
        # Shodan scan
        print("Running Shodan scan...")
        shodan_data = self.shodan_scan(target)
        if shodan_data:
            vulnerabilities = []
            if 'vulns' in shodan_data:
                vulnerabilities = [{"cve": cve, "severity": "Unknown"} 
                                 for cve in shodan_data['vulns']]
            
            results.append(ScanResult(
                scanner="Shodan",
                target=target,
                vulnerabilities=vulnerabilities,
                scan_time=time.strftime("%Y-%m-%d %H:%M:%S"),
                status="Completed"
            ))
        
        # VirusTotal scan
        print("Running VirusTotal scan...")
        vt_data = self.virustotal_scan(target)
        if vt_data and vt_data.get('response_code') == 1:
            vulnerabilities = []
            if vt_data.get('detected_urls'):
                vulnerabilities = [{"url": url['url'], "positives": url['positives']} 
                                 for url in vt_data['detected_urls'][:10]]
            
            results.append(ScanResult(
                scanner="VirusTotal",
                target=target,
                vulnerabilities=vulnerabilities,
                scan_time=time.strftime("%Y-%m-%d %H:%M:%S"),
                status="Completed"
            ))
        
        # Censys search
        print("Running Censys search...")
        censys_data = self.censys_search(f"ip:{target}")
        if censys_data:
            vulnerabilities = []
            for result in censys_data.get('result', {}).get('hits', []):
                services = result.get('services', [])
                for service in services:
                    if 'vulnerabilities' in service:
                        for vuln in service['vulnerabilities']:
                            vulnerabilities.append({
                                "cve": vuln.get('cve'),
                                "port": service.get('port'),
                                "service": service.get('service_name')
                            })
            
            results.append(ScanResult(
                scanner="Censys",
                target=target,
                vulnerabilities=vulnerabilities,
                scan_time=time.strftime("%Y-%m-%d %H:%M:%S"),
                status="Completed"
            ))
        
        return results
    
    def generate_report(self, results: List[ScanResult], output_file: str):
        """Generate comprehensive report"""
        report = {
            "scan_summary": {
                "target": results[0].target if results else "Unknown",
                "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
                "scanners_used": [r.scanner for r in results],
                "total_vulnerabilities": sum(len(r.vulnerabilities) for r in results)
            },
            "detailed_results": []
        }
        
        for result in results:
            report["detailed_results"].append({
                "scanner": result.scanner,
                "status": result.status,
                "scan_time": result.scan_time,
                "vulnerability_count": len(result.vulnerabilities),
                "vulnerabilities": result.vulnerabilities
            })
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

# Usage example
if __name__ == "__main__":
    scanner = SecurityScannerAPI()
    target = "8.8.8.8"  # Example target
    
    results = scanner.comprehensive_scan(target)
    scanner.generate_report(results, f"scan_report_{target}.json")
    
    print(f"Scan completed. Found {sum(len(r.vulnerabilities) for r in results)} total vulnerabilities.")`}
                </pre>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default ScriptDevelopment;
