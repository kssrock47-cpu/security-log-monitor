# Starts Elasticsearch, Logstash (if it was set up) and Kibana from elk\setup-windows.ps1 in the background,
# waits until each answers, and loads the monitor's Kibana dashboard. Their output goes to elasticsearch.log,
# logstash.log and kibana.log in the elk folder. Stop them with elk\stop-windows.ps1.
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

# (cmd /c "...": the outer quotes keep cmd from mangling the quoted paths inside)
# Elasticsearch uses its own bundled Java; an older JAVA_HOME on this PC must not get in the way
$env:ES_JAVA_HOME = ""
if (!(Answers "http://127.0.0.1:9200")) {
    Write-Host "Starting Elasticsearch ..."
    Start-Process cmd -ArgumentList "/c", "`"`"$es\bin\elasticsearch.bat`" > `"$Dir\elasticsearch.log`" 2>&1`"" -WorkingDirectory $es -WindowStyle Hidden
}
WaitFor "Elasticsearch (http://127.0.0.1:9200)" { Answers "http://127.0.0.1:9200" } 240

$ls = Join-Path $Dir "logstash-$Version"
if (Test-Path "$ls\bin") {
    $logstashUp = {
        try { $null = Invoke-WebRequest "http://127.0.0.1:5080" -Method Post -Body "[]" -ContentType "application/json" -UseBasicParsing -TimeoutSec 3; $true }
        catch { $false }
    }
    if (!(& $logstashUp)) {
        Write-Host "Starting Logstash ..."
        $pipeline = Join-Path $PSScriptRoot "logstash\seclog.conf"  # Windows-style path: Logstash finds no config with C:/...
        Start-Process cmd -ArgumentList "/c", "`"`"$ls\bin\logstash.bat`" -f `"$pipeline`" > `"$Dir\logstash.log`" 2>&1`"" -WorkingDirectory $ls -WindowStyle Hidden
    }
    WaitFor "Logstash (pipeline on http://127.0.0.1:5080)" $logstashUp 300
} else {
    Write-Host "Logstash isn't set up; the monitor can still send straight to Elasticsearch."
}

$kibanaUp = {
    try { (Invoke-RestMethod "http://127.0.0.1:5601/api/status" -TimeoutSec 3).status.overall.level -eq "available" }
    catch { $false }
}
if (!(& $kibanaUp)) {
    Write-Host "Starting Kibana (it can take 5 to 10 minutes, longest the first time) ..."
    Start-Process cmd -ArgumentList "/c", "`"`"$kb\bin\kibana.bat`" > `"$Dir\kibana.log`" 2>&1`"" -WorkingDirectory $kb -WindowStyle Hidden
}
WaitFor "Kibana (http://127.0.0.1:5601)" $kibanaUp 900

$ndjson = Join-Path $PSScriptRoot "kibana-dashboard.ndjson"
$out = curl.exe -s -X POST "http://127.0.0.1:5601/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form "file=@$ndjson"
if ($out -notmatch '"success":true') { throw "Kibana did not accept the dashboard: $out" }
Write-Host "Dashboard loaded."
Write-Host ""
Write-Host "In the monitor, open Connect logs and switch on 'Send to Elasticsearch' (and 'Go through Logstash' for map locations)."
Write-Host "Kibana dashboard: http://127.0.0.1:5601/app/dashboards#/view/seclog-overview"
