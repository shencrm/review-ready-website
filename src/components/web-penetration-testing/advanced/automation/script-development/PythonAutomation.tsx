
import React from 'react';

const PythonAutomation: React.FC = () => {
  return (
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
  );
};

export default PythonAutomation;
