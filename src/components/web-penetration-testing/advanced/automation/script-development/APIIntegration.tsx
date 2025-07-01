
import React from 'react';

const APIIntegration: React.FC = () => {
  return (
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
  );
};

export default APIIntegration;
