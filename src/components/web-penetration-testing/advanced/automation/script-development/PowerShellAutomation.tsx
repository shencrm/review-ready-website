
import React from 'react';

const PowerShellAutomation: React.FC = () => {
  return (
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
  );
};

export default PowerShellAutomation;
