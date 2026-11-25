# Downloads Elasticsearch and Kibana (the E and K of the ELK Stack) from elastic.co, checks them, and sets them up
# for this monitor on this PC only. Nothing is installed system-wide and no administrator rights are needed.
#   powershell -ExecutionPolicy Bypass -File elk\setup-windows.ps1
# About 1 GB to download. Afterwards start them with elk\start-windows.ps1.
param([string]$Version = "8.19.26", [string]$Dir = "$env:USERPROFILE\elk")
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
New-Item -ItemType Directory -Force $Dir | Out-Null

foreach ($p in "elasticsearch", "kibana") {
    $folder = Join-Path $Dir "$p-$Version"
    if (Test-Path (Join-Path $folder "bin")) { Write-Host "$p $Version is already there."; continue }
    $name = "$p-$Version-windows-x86_64.zip"
    $zip = Join-Path $Dir $name
    $url = "https://artifacts.elastic.co/downloads/$p/$name"
    if (!(Test-Path $zip)) {
        Write-Host "Downloading $name ..."
        curl.exe -fL --retry 3 -o "$zip.part" $url
        if ($LASTEXITCODE -ne 0) { throw "Download failed: $url" }
        Move-Item "$zip.part" $zip
    }
    Write-Host "Checking $name against elastic.co's SHA-512 checksum ..."
    $expected = ((curl.exe -fsL "$url.sha512") -split "\s+")[0].ToUpper()
    $actual = (Get-FileHash $zip -Algorithm SHA512).Hash
    if ($expected -ne $actual) { Remove-Item $zip; throw "Checksum mismatch for $name. Run the script again." }
    Write-Host "Unpacking $name ..."
    tar.exe -xf $zip -C $Dir
    if ($LASTEXITCODE -ne 0) { throw "Could not unpack $name" }
    $unpacked = Get-ChildItem $Dir -Directory | Where-Object { $_.Name -like "$p-$Version*" -and $_.FullName -ne $folder } | Select-Object -First 1
    if ($unpacked) { Rename-Item $unpacked.FullName $folder }
    Remove-Item $zip
}

# Elasticsearch: one node, only reachable from this PC, 1 GB of memory, login switched off (local use only)
$es = Join-Path $Dir "elasticsearch-$Version"
$yml = Join-Path $es "config\elasticsearch.yml"
if (!(Select-String -Path $yml -Pattern "Security Log Monitor" -Quiet)) {
    Add-Content $yml @"

# ---- added by the Security Log Monitor setup
cluster.name: security-log-monitor
discovery.type: single-node
network.host: 127.0.0.1
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
xpack.ml.enabled: false
"@
}
if (!(Select-String -Path $yml -Pattern "disk.watermark" -Quiet)) {
    # By default Elasticsearch stops storing data once the disk is 90% full, which is common on laptops.
    # Use free space instead: stop only when less than a few GB are left.
    Add-Content $yml @"
cluster.routing.allocation.disk.watermark.low: 5gb
cluster.routing.allocation.disk.watermark.high: 3gb
cluster.routing.allocation.disk.watermark.flood_stage: 2gb
"@
}
Set-Content (Join-Path $es "config\jvm.options.d\heap.options") "-Xms1g`n-Xmx1g"

# Kibana: only reachable from this PC, pointed at the local Elasticsearch
$kb = Join-Path $Dir "kibana-$Version"
$kyml = Join-Path $kb "config\kibana.yml"
if (!(Select-String -Path $kyml -Pattern "Security Log Monitor" -Quiet)) {
    Add-Content $kyml @"

# ---- added by the Security Log Monitor setup
server.host: "127.0.0.1"
elasticsearch.hosts: ["http://127.0.0.1:9200"]
telemetry.optIn: false
"@
}
Write-Host ""
Write-Host "Done. Elasticsearch and Kibana $Version are in $Dir"
Write-Host "Start them with:  powershell -ExecutionPolicy Bypass -File elk\start-windows.ps1"
