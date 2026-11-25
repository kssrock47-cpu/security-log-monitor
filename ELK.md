# Using the monitor with the ELK Stack

The monitor can copy every log line it reads and every threat it raises into **Elasticsearch**. You can then search them and use a ready-made dashboard in **Kibana**, or feed them to a SOC's own SIEM that runs on Elasticsearch (for example Elastic Security).

The monitor works the same with this switched off. Elasticsearch only receives a copy.

## 1. Set up Elasticsearch and Kibana (once, Windows)

From the project folder, in PowerShell:

    powershell -ExecutionPolicy Bypass -File elk\setup-windows.ps1

This step:

* Downloads Elasticsearch and Kibana 8.19.26 from elastic.co, about 1 GB, into `%USERPROFILE%\elk`.
* Checks each download against elastic.co's SHA-512 checksum.
* Sets both up for local use on this PC only:
  * single node
  * reachable only from `127.0.0.1`
  * 1 GB of memory for Elasticsearch
  * no login

No administrator rights are needed and nothing is installed system-wide. To remove everything, delete the `elk` folder.

Mac and Linux: download the same two versions from elastic.co. Add the settings the script appends to `elasticsearch.yml` and `kibana.yml` (shown in the script), then start `bin/elasticsearch` and `bin/kibana`.

## 2. Start them

    powershell -ExecutionPolicy Bypass -File elk\start-windows.ps1

This starts both in the background and waits until they answer. The first Kibana start takes a few minutes. It then loads the monitor's Kibana dashboard (`elk/kibana-dashboard.ndjson`). Their output goes to `elasticsearch.log` and `kibana.log` in the `elk` folder.

To stop them, run `elk\stop-windows.ps1`. Together they use about 2 to 3 GB of memory while running.

## 3. Switch it on in the monitor

1. Open **Connect logs**. Under **Send to Elasticsearch and Kibana**, keep the address `http://127.0.0.1:9200` and tick **Send to Elasticsearch**.
2. When you switch it on, it also sends every threat so far and the latest 20,000 log lines. After that it sends in batches every couple of seconds.
3. Click **Open the Kibana dashboard**.

You can also switch it on at start-up with the environment variable `SECLOG_ELASTIC=http://127.0.0.1:9200`. For a secured cluster, set `SECLOG_ELASTIC_API_KEY` to an Elasticsearch API key.

## What is sent

There are two indices. Field names follow the **Elastic Common Schema (ECS)**, so Kibana, Elastic Security and other ECS tools understand them as they are.

| Index | One document per | Main fields |
|---|---|---|
| `seclog-events` | log line | `@timestamp`, `message`, `event.outcome`, `event.dataset`, `source.ip`, `source.geo.country_name`, `user.name`, `host.name`, `process.name` |
| `seclog-alerts` | threat (updated when its count or status changes) | `@timestamp`, `rule.name`, `rule.category` (AI or known pattern), `event.severity` (0–100), `labels.severity`, `threat.tactic.name`, `threat.technique.id` (MITRE ATT&CK), `source.ip`, `user.name`, `labels.status`, `labels.count` |

## The Kibana dashboard

**Security Log Monitor: threat overview** shows:

* the numbers of threats, log lines and failed logins
* threats over time by severity
* log lines over time by outcome
* threats by MITRE ATT&CK tactic
* the AI against known patterns
* failed logins by country
* the most active attackers
* the attack techniques seen
* the accounts targeted
* the latest threats

It shows the last 24 hours and refreshes every 10 seconds. If you checked an older log file, widen the time range at the top right.

## If something goes wrong

* **"Can't reach Elasticsearch"**: it isn't running. Run `elk\start-windows.ps1`. The monitor keeps up to 200,000 documents waiting and sends them once Elasticsearch is back. Beyond that, the oldest are dropped and counted.
* **The dashboard is empty**: check the time range, and that the status line in the monitor says "Connected".
* **Elasticsearch stores nothing (index health "red")**: the disk is nearly full. The setup lets it keep storing until less than 3 GB are free; free some space.
* **Port 9200 or 5601 is in use**: another Elasticsearch or Kibana is running. Use that one, or stop it first.
