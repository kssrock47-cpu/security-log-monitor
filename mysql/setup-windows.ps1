# Downloads MySQL Community Server (8.4 LTS) from mysql.com, checks it, and sets it up for this monitor on this
# PC only: reachable only from 127.0.0.1, data in %USERPROFILE%\mysql\data. Nothing is installed system-wide,
# no Windows service is created, and no administrator rights are needed.
#   powershell -ExecutionPolicy Bypass -File mysql\setup-windows.ps1
# About 270 MB to download. Then run mysql\start-windows.ps1.
param([string]$Version = "8.4.13.1", [string]$Md5 = "d05e97a33b1bb0f49d88f09447bc3f9c", [string]$Dir = "$env:USERPROFILE\mysql")
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
New-Item -ItemType Directory -Force $Dir | Out-Null
$name = "mysql-$Version-winx64"
$home_ = Join-Path $Dir $name

if (!(Test-Path "$home_\bin\mysqld.exe")) {
    $zip = Join-Path $Dir "$name.zip"
    if (!(Test-Path $zip)) {
        Write-Host "Downloading $name.zip ..."
        $urls = "https://cdn.mysql.com/Downloads/MySQL-8.4/$name.zip", "https://downloads.mysql.com/archives/get/p/23/file/$name.zip"
        $ok = $false
        foreach ($u in $urls) {
            curl.exe -fL --retry 3 -o "$zip.part" $u
            if ($LASTEXITCODE -eq 0) { $ok = $true; break }
        }
        if (!$ok) { throw "Download failed. Check the version on https://dev.mysql.com/downloads/mysql/" }
        Move-Item "$zip.part" $zip
    }
    if ($Md5) {
        Write-Host "Checking $name.zip against mysql.com's MD5 checksum ..."
        if ((Get-FileHash $zip -Algorithm MD5).Hash -ne $Md5.ToUpper()) { Remove-Item $zip; throw "Checksum mismatch. Run the script again." }
    }
    Write-Host "Unpacking ..."
    tar.exe -xf $zip -C $Dir
    if ($LASTEXITCODE -ne 0) { throw "Could not unpack $name.zip" }
    Remove-Item $zip
}

# Settings: local only, small memory footprint, logs next to the data
$ini = Join-Path $Dir "my.ini"
$fwd = { param($p) $p -replace "\\", "/" }
Set-Content $ini @"
[mysqld]
basedir=$(& $fwd $home_)
datadir=$(& $fwd (Join-Path $Dir "data"))
port=3306
bind-address=127.0.0.1
mysqlx=OFF
max_connections=50
innodb_buffer_pool_size=256M
log-error=$(& $fwd (Join-Path $Dir "mysql-error.log"))

[client]
port=3306
host=127.0.0.1
"@

if (!(Test-Path (Join-Path $Dir "data"))) {
    Write-Host "Creating the database files (root user without a password, reachable only from this PC) ..."
    & "$home_\bin\mysqld.exe" --defaults-file="$ini" --initialize-insecure
    if ($LASTEXITCODE -ne 0) { throw "MySQL could not create its data folder. See $Dir\mysql-error.log" }
}
Write-Host ""
Write-Host "Done. MySQL $Version is in $Dir"
Write-Host "Start it with:  powershell -ExecutionPolicy Bypass -File mysql\start-windows.ps1"
