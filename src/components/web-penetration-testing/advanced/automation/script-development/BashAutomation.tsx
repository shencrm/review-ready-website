
import React from 'react';

const BashAutomation: React.FC = () => {
  return (
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
    echo -e "\\$\{BLUE\}"
    echo "=================================="
    echo "  Automated Recon Framework"
    echo "  Target: $TARGET"
    echo "  Date: $DATE"
    echo "=================================="
    echo -e "\\$\{NC\}"
}

setup_directories() {
    echo -e "\\$\{YELLOW\}[+] Setting up directories\\$\{NC\}"
    mkdir -p $OUTPUT_DIR/{subdomains,ports,urls,screenshots,vulnerabilities}
}

subdomain_enumeration() {
    echo -e "\\$\{YELLOW\}[+] Starting subdomain enumeration\\$\{NC\}"
    
    # Subfinder
    if command -v subfinder &> /dev/null; then
        echo -e "\\$\{GREEN\}[*] Running subfinder\\$\{NC\}"
        subfinder -d $TARGET -o $OUTPUT_DIR/subdomains/subfinder.txt -silent
    fi
    
    # Amass
    if command -v amass &> /dev/null; then
        echo -e "\\$\{GREEN\}[*] Running amass\\$\{NC\}"
        amass enum -d $TARGET -o $OUTPUT_DIR/subdomains/amass.txt
    fi
    
    # Assetfinder
    if command -v assetfinder &> /dev/null; then
        echo -e "\\$\{GREEN\}[*] Running assetfinder\\$\{NC\}"
        assetfinder $TARGET > $OUTPUT_DIR/subdomains/assetfinder.txt
    fi
    
    # Combine and sort unique subdomains
    cat $OUTPUT_DIR/subdomains/*.txt | sort -u > $OUTPUT_DIR/subdomains/all_subdomains.txt
    SUBDOMAIN_COUNT=$(wc -l < $OUTPUT_DIR/subdomains/all_subdomains.txt)
    echo -e "\\$\{GREEN\}[+] Found $SUBDOMAIN_COUNT unique subdomains\\$\{NC\}"
}

port_scanning() {
    echo -e "\\$\{YELLOW\}[+] Starting port scanning\\$\{NC\}"
    
    # Fast scan for alive hosts
    nmap -sn -iL $OUTPUT_DIR/subdomains/all_subdomains.txt > $OUTPUT_DIR/ports/alive_hosts.txt
    
    # Extract alive IPs
    grep -oE "\\\\b([0-9]{1,3}\\\\.){3}[0-9]{1,3}\\\\b" $OUTPUT_DIR/ports/alive_hosts.txt > $OUTPUT_DIR/ports/alive_ips.txt
    
    # Port scan alive hosts
    if [ -s $OUTPUT_DIR/ports/alive_ips.txt ]; then
        echo -e "\\$\{GREEN\}[*] Scanning ports on alive hosts\\$\{NC\}"
        nmap -sS -T4 -top-ports 1000 -iL $OUTPUT_DIR/ports/alive_ips.txt -oA $OUTPUT_DIR/ports/nmap_scan
    fi
}

url_discovery() {
    echo -e "\\$\{YELLOW\}[+] Starting URL discovery\\$\{NC\}"
    
    # Use alive subdomains for URL discovery
    while read -r subdomain; do
        if [ ! -z "$subdomain" ]; then
            echo -e "\\$\{GREEN\}[*] Discovering URLs for $subdomain\\$\{NC\}"
            
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
    find $OUTPUT_DIR/urls/ -name "*.txt" -exec cat {} \\\\; | sort -u > $OUTPUT_DIR/urls/all_urls.txt
}

vulnerability_scanning() {
    echo -e "\\$\{YELLOW\}[+] Starting vulnerability scanning\\$\{NC\}"
    
    # Nuclei scanning
    if command -v nuclei &> /dev/null; then
        echo -e "\\$\{GREEN\}[*] Running nuclei\\$\{NC\}"
        nuclei -l $OUTPUT_DIR/subdomains/all_subdomains.txt -o $OUTPUT_DIR/vulnerabilities/nuclei_results.txt -silent
    fi
    
    # Nikto scanning on web ports
    if command -v nikto &> /dev/null; then
        while read -r subdomain; do
            if [ ! -z "$subdomain" ]; then
                echo -e "\\$\{GREEN\}[*] Running nikto on $subdomain\\$\{NC\}"
                nikto -h "http://$subdomain" -o $OUTPUT_DIR/vulnerabilities/nikto_$subdomain.txt -Format txt
            fi
        done < $OUTPUT_DIR/subdomains/all_subdomains.txt
    fi
}

take_screenshots() {
    echo -e "\\$\{YELLOW\}[+] Taking screenshots\\$\{NC\}"
    
    if command -v aquatone &> /dev/null; then
        cat $OUTPUT_DIR/subdomains/all_subdomains.txt | aquatone -out $OUTPUT_DIR/screenshots/
    fi
}

generate_report() {
    echo -e "\\$\{YELLOW\}[+] Generating report\\$\{NC\}"
    
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
    
    echo -e "\\$\{GREEN\}[+] Report saved to $REPORT_FILE\\$\{NC\}"
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

echo -e "\\$\{GREEN\}[+] Reconnaissance completed! Results saved in $OUTPUT_DIR\\$\{NC\}"
echo -e "\\$\{BLUE\}[*] Total execution time: $SECONDS seconds\\$\{NC\}"`}
        </pre>
      </div>
    </div>
  );
};

export default BashAutomation;
