# Starts the MySQL server set up by mysql\setup-windows.ps1 in the background and waits until it answers.
# Its log is mysql-error.log in the mysql folder. Stop it with mysql\stop-windows.ps1.
param([string]$Version = "8.4.13.1", [string]$Dir = "$env:USERPROFILE\mysql")
$ErrorActionPreference = "Stop"
$bin = Join-Path $Dir "mysql-$Version-winx64\bin"
$ini = Join-Path $Dir "my.ini"
if (!(Test-Path "$bin\mysqld.exe")) { throw "Run mysql\setup-windows.ps1 first." }

function Answers {
    try { $c = New-Object Net.Sockets.TcpClient; $c.Connect("127.0.0.1", 3306); $c.Close(); return $true } catch { return $false }
}
if (!(Answers)) {
    Write-Host "Starting MySQL ..."
    Start-Process "$bin\mysqld.exe" -ArgumentList "--defaults-file=`"$ini`"" -WorkingDirectory $Dir -WindowStyle Hidden
}
$t = 0
while (-not (Answers)) {
    if ($t -ge 90) { throw "MySQL did not start within 90 seconds. The reason is in $Dir\mysql-error.log" }
    Start-Sleep 2; $t += 2
}
Write-Host "MySQL is up on 127.0.0.1:3306 ($t s)."
Write-Host ""
Write-Host "In the monitor, open Connect logs and switch on 'Keep a copy in MySQL' (address mysql://root@127.0.0.1:3306/seclog)."
