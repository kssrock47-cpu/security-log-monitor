# Stops the MySQL server started by mysql\start-windows.ps1 (cleanly, so no data is lost).
param([string]$Version = "8.4.13.1", [string]$Dir = "$env:USERPROFILE\mysql")
& (Join-Path $Dir "mysql-$Version-winx64\bin\mysqladmin.exe") --defaults-file="$(Join-Path $Dir 'my.ini')" -u root shutdown
if ($LASTEXITCODE -eq 0) { Write-Host "MySQL stopped." } else { Write-Host "MySQL wasn't running, or didn't answer." }
