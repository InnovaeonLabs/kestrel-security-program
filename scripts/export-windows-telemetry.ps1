<#
.SYNOPSIS
  Export real Windows endpoint telemetry (Sysmon + PowerShell script-block logging)
  to JSONL that the Kestrel normalizer ingests. No EDR / no VM required.

.DESCRIPTION
  This is how "endpoint telemetry" is collected in this $0 lab: from the builder's
  OWN Windows host, under their own authorization. Run in an ELEVATED PowerShell.

  Prereqs (one-time, elevated):
    1) Install Sysmon:  sysmon64 -accepteula -i config\sysmon\sysmon-config.xml
    2) Enable PowerShell Script Block Logging (Group Policy or registry):
       reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

.EXAMPLE
  .\scripts\export-windows-telemetry.ps1 -Minutes 60
#>
param(
  [int]$Minutes = 120,
  [string]$OutDir = "$(Split-Path $PSScriptRoot -Parent)\automation\normalize\samples"
)

$ErrorActionPreference = "Stop"
$start = (Get-Date).AddMinutes(-$Minutes)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$sysmonOut = Join-Path $OutDir "sysmon-host.jsonl"

Write-Host "[*] Exporting Sysmon events since $start ..."
$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    StartTime = $start
} -ErrorAction SilentlyContinue

if (-not $events) {
  Write-Warning "No Sysmon events found. Is Sysmon installed and the config applied?"
} else {
  $events | ForEach-Object {
    $x = [ordered]@{ EventID = $_.Id; UtcTime = $_.TimeCreated.ToUniversalTime().ToString("s") + "Z"; Computer = $_.MachineName }
    # Flatten Sysmon's <Data Name=...> fields into top-level keys the normalizer expects.
    ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { if ($_.Name) { $x[$_.Name] = $_.'#text' } }
    $x | ConvertTo-Json -Compress
  } | Set-Content -Encoding utf8 $sysmonOut
  Write-Host "[+] Wrote $($events.Count) Sysmon events -> $sysmonOut"
}

# PowerShell script-block logging (Event ID 4104) -> same folder, as sysmon-like rows.
$psOut = Join-Path $OutDir "powershell-host.jsonl"
$ps = Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=$start
} -ErrorAction SilentlyContinue
if ($ps) {
  $ps | ForEach-Object {
    [ordered]@{ EventID = 1; UtcTime = $_.TimeCreated.ToUniversalTime().ToString("s")+"Z";
                Computer = $_.MachineName; Image = "powershell.exe";
                CommandLine = ($_.Message -split "`n" | Select-Object -First 1) } | ConvertTo-Json -Compress
  } | Add-Content -Encoding utf8 $psOut
  Write-Host "[+] Wrote $($ps.Count) PowerShell 4104 events -> $psOut"
}

Write-Host "[*] Next: python automation\normalize\normalize.py  (ingest into DuckDB)"
