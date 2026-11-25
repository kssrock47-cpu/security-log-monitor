# Starts Elasticsearch and Kibana (set up by elk\setup-windows.ps1) in the background, waits until both answer,
# and loads the monitor's Kibana dashboard. Their output goes to elasticsearch.log and kibana.log in the elk
# folder. Stop them with elk\stop-windows.ps1.
#   powershell -ExecutionPolicy Bypass -File elk\start-windows.ps1
param([string]$Version = "8.19.26", [string]$Dir = "$env:USERPROFILE\elk")
$ErrorActionPreference = "Stop"
$es = Join-Path $Dir "elasticsearch-$Version"
$kb = Join-Path $Dir "kibana-$Version"
if (!(Test-Path "$es\bin") -or !(Test-Path "$kb\bin")) { throw "Run elk\setup-windows.ps1 first." }

function Answers($url) {
    try { $null = Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 3; return $true } catch { return $false }
}
function WaitFor($what, $test, $seconds) {
    $t = 0
    while (-not (& $test)) {
        if ($t -ge $seconds) { throw "$what did not start within $seconds seconds. The reason is in the log files in $Dir." }
        Start-Sleep 3; $t += 3
    }
    Write-Host "$what is up ($t s)."
}

# Elasticsearch uses its own bundled Java; an older JAVA_HOME on this PC must not get in the way
$env:ES_JAVA_HOME = ""
if (!(Answers "http://127.0.0.1:9200")) {
    Write-Host "Starting Elasticsearch ..."
    Start-Process cmd -ArgumentList "/c", "`"$es\bin\elasticsearch.bat`" > `"$Dir\elasticsearch.log`" 2>&1" -WorkingDirectory $es -WindowStyle Hidden
}
WaitFor "Elasticsearch (http://127.0.0.1:9200)" { Answers "http://127.0.0.1:9200" } 240

$kibanaUp = {
    try { (Invoke-RestMethod "http://127.0.0.1:5601/api/status" -TimeoutSec 3).status.overall.level -eq "available" }
    catch { $false }
}
if (!(& $kibanaUp)) {
    Write-Host "Starting Kibana (the first start takes a few minutes) ..."
    Start-Process cmd -ArgumentList "/c", "`"$kb\bin\kibana.bat`" > `"$Dir\kibana.log`" 2>&1" -WorkingDirectory $kb -WindowStyle Hidden
}
WaitFor "Kibana (http://127.0.0.1:5601)" $kibanaUp 600

$ndjson = Join-Path $PSScriptRoot "kibana-dashboard.ndjson"
$out = curl.exe -s -X POST "http://127.0.0.1:5601/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form "file=@$ndjson"
if ($out -notmatch '"success":true') { throw "Kibana did not accept the dashboard: $out" }
Write-Host "Dashboard loaded."
Write-Host ""
Write-Host "In the monitor, open Connect logs and switch on 'Send to Elasticsearch'."
Write-Host "Kibana dashboard: http://127.0.0.1:5601/app/dashboards#/view/seclog-overview"
