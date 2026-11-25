# Using the monitor with the ELK Stack

The monitor can copy every log line it reads and every threat it raises into **Elasticsearch**. You can then search them and use a ready-made dashboard in **Kibana**, or feed them to a SOC's own SIEM that runs on Elasticsearch (for example Elastic Security).

Optionally the data goes through **Logstash** on the way. Logstash's pipeline (`elk/logstash/seclog.conf`) looks up the city and map location of every outside address in its GeoIP database, which the dashboard's attack map needs.

    monitor ──► Logstash (adds locations) ──► Elasticsearch ──► Kibana dashboard
       └──────────── or straight to ────────────┘

The monitor works the same with this switched off. Elasticsearch only receives a copy.

## 1. Set up Elasticsearch, Logstash and Kibana (once, Windows)

From the project folder, in PowerShell:

    powershell -ExecutionPolicy Bypass -File elk\setup-windows.ps1

This step:

* Downloads Elasticsearch, Logstash and Kibana 8.19.26 from elastic.co, about 1.4 GB, into `%USERPROFILE%\elk`. Add `-NoLogstash` to skip Logstash (about 0.4 GB); everything except the map still works.
* Checks each download against elastic.co's SHA-512 checksum.
* Sets both up for local use on this PC only:
  * single node
  * reachable only from `127.0.0.1`
  * 1 GB of memory for Elasticsearch
  * no login

No administrator rights are needed and nothing is installed system-wide. To remove everything, delete the `elk` folder.

Mac and Linux: download the same three versions from elastic.co. Add the settings the script appends to `elasticsearch.yml` and `kibana.yml` (shown in the script), then start `bin/elasticsearch`, `bin/logstash -f elk/logstash/seclog.conf` and `bin/kibana`.

## 2. Start them

    powershell -ExecutionPolicy Bypass -File elk\start-windows.ps1

This starts all three in the background and waits until each answers. Kibana is slow to start on Windows: 5 to 10 minutes, longest the first time, because it loads thousands of small files (antivirus scanning adds to it). It then loads the monitor's Kibana dashboard (`elk/kibana-dashboard.ndjson`). Their output goes to `elasticsearch.log`, `logstash.log` and `kibana.log` in the `elk` folder.

To stop them, run `elk\stop-windows.ps1`. Together they use about 3 to 4 GB of memory while running.

## 3. Switch it on in the monitor

1. Open **Connect logs**. Under **Send to Elasticsearch and Kibana**, keep the address `http://127.0.0.1:9200` and tick **Send to Elasticsearch**. Tick **Go through Logstash** (address `http://127.0.0.1:5080`) for map locations.
2. When you switch it on, it also sends every threat so far and the latest 20,000 log lines. After that it sends in batches every couple of seconds.
3. Click **Open the Kibana dashboard**.

You can also switch it on at start-up with the environment variables `SECLOG_ELASTIC=http://127.0.0.1:9200` and, for Logstash, `SECLOG_LOGSTASH=http://127.0.0.1:5080`. For a secured cluster, set `SECLOG_ELASTIC_API_KEY` to an Elasticsearch API key.

## What is sent

There are two indices. Field names follow the **Elastic Common Schema (ECS)**, so Kibana, Elastic Security and other ECS tools understand them as they are.

| Index | One document per | Main fields |
|---|---|---|
| `seclog-events` | log line | `@timestamp`, `message`, `event.outcome`, `event.dataset`, `source.ip`, `source.geo.country_name` (and through Logstash `source.geo.city_name`, `source.geo.location`), `user.name`, `host.name`, `process.name` |
| `seclog-alerts` | threat (updated when its count or status changes) | `@timestamp`, `rule.name`, `rule.category` (AI or known pattern), `event.severity` (0–100), `labels.severity`, `threat.tactic.name`, `threat.technique.id` (MITRE ATT&CK), `source.ip`, `user.name`, `labels.status`, `labels.count` |

## The Kibana dashboard

**Security Log Monitor: threat overview** shows:

* the numbers of threats, log lines and failed logins
* threats over time by severity
* log lines over time by outcome
* threats by MITRE ATT&CK tactic
* where attacks come from: a world map of failed logins (sized by number) and threats, built from Logstash's locations
* the AI against known patterns
* failed logins by country
* the most active attackers
* the attack techniques seen
* the accounts targeted
* the latest threats

It shows the last 24 hours and refreshes every 10 seconds. If you checked an older log file, widen the time range at the top right.

## If something goes wrong

* **"Can't reach Elasticsearch"**: it isn't running. Run `elk\start-windows.ps1`. The monitor keeps up to 200,000 documents waiting and sends them once Elasticsearch is back. Beyond that, the oldest are dropped and counted.
* **The map is empty**: the locations come from Logstash. Tick **Go through Logstash**; only data sent after that has locations. The map's background tiles come from Elastic's map service, so they need internet.
* **A map layer shows a red error mark**: Kibana remembered the field list from before the locations existed. Reload the Kibana page.
* **"Logstash isn't answering"**: run `elk\start-windows.ps1`, or untick **Go through Logstash** to send straight to Elasticsearch.
* **The dashboard is empty**: check the time range, and that the status line in the monitor says "Connected".
* **Elasticsearch stores nothing (index health "red")**: the disk is nearly full. The setup lets it keep storing until less than 3 GB are free; free some space.
* **Port 9200, 5080 or 5601 is in use**: another Elasticsearch, Logstash or Kibana is running. Use that one, or stop it first.
