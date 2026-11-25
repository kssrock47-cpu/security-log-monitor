# Stops the Elasticsearch and Kibana started by elk\start-windows.ps1 (only those in the elk folder).
param([string]$Dir = "$env:USERPROFILE\elk")
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -and $_.CommandLine -like "*$Dir*" -and $_.Name -in "java.exe", "node.exe", "cmd.exe" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; Write-Host "Stopped $($_.Name) ($($_.ProcessId))" }
