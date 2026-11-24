# Security Log Monitor

**AI-Based Security Log Analysis and Threat Monitoring System**, the FYP1 (AP1) prototype by Kyaw Swe Sien Marma, Universiti Malaya.
Supervisor: Dr. Shapla Khanam. Collaborator: Ts. Dr. Muhammad Faiz bin Mohd Zaki.

It takes security logs from anywhere, watches them live or checks them offline, and raises a threat when something looks wrong, explained in plain words with the log lines as proof. **The AI does a first check. A person still decides what matters.**

## Two parts

**1. Live monitor (any security logs)**
* **Connect logs, online or offline:**
  * drop a file
  * watch a file or folder on this PC
  * link a web address
  * receive syslog from routers, servers and other PCs
  * read this PC's Windows Event Log
  * use the built-in attack lab
* **Reads:** Linux syslog and auth.log (SSH, sudo, useradd, firewall), Apache and Nginx web logs, Windows events (live or `.evtx`), JSON lines, HDFS and plain text.
* **Finds threats two ways:**
  * **AI:** an Isolation Forest learns what normal looks like for each address or user over 30-second windows, then flags anything unusual.
  * **Known attack patterns:** 15 patterns, including password guessing, password spraying, a login right after guessing, SQL injection and other web attacks, scanners, hidden-page hunting, port scans, admin rights and new accounts, cleared logs, malware, and new services. In technical mode each one is mapped to MITRE ATT&CK.
* **Learns and adapts** in three ways:
  * It learns normal behaviour when a connection starts.
  * It re-learns normal every few minutes, so it keeps up as things change.
  * It learns from your answers. "Real threat" makes it more watchful of that behaviour; "False alarm" makes it calmer and stops that exact alert coming back. This is a small reinforcement loop: the sensitivities are the policy and your answers are the reward.
  * The lessons are saved and shared across all connections. The **AI learning** page shows what changed. In the attack lab, "Sneaky data theft" gets through until you confirm a "Quiet data theft" as real; after that the AI catches it.
* **Screens:** a radar of who's active, a live threat level, pop-up alerts, a threats inbox with evidence and advice, and buttons to mark each alert as real or a false alarm.
* **Attack story:** separate alerts from one attacker (and the accounts it logged in as) are joined into one story across 7 attack steps, following the MITRE ATT&CK tactics: looking around, guessing passwords, getting in, becoming admin, staying in, hiding tracks, taking data or doing harm.
* **Attack map:** a world map of where activity comes from, with lines from attackers to your systems. The country lookup is offline (geoip2fast, built from MaxMind GeoLite2 data), so it works without internet.
* **Risk score and profiles:** every address and user gets a risk score from 0 to 100. Recent threats count most and fade with a 30-minute half-life; threats marked real count more, false alarms count nothing. Click any address for its profile: country, risk trend, accounts used, activity, threats and log lines.
* **Respond:** block an address for 30 minutes. In the attack lab the lab firewall really drops its traffic; elsewhere the block is simulated in this prototype (a real firewall rule is planned for FYP2). Addresses inside your own network are on an allowlist and can never be blocked.
* **Incident report:** one click makes a PDF of any threat: what happened, the attack story, the evidence and the response.
* **Presentation mode:** a full-screen view for a projector, with the map, the radar, live threats and the riskiest addresses. Press M to switch view, Esc to leave.
* **Guided demo:** a 23-step tour that explains every screen and runs the whole story live (about 6 minutes). Tick "Start fresh" to clear old threats and lessons first.
* **Attack lab:** a pretend company network in Malaysia with 9 attacks to launch, timed to show how fast each one is caught. "Quiet data theft" matches no known pattern, so only the AI can catch it. "Sneaky data theft" gets through until you teach the AI. The AI learning page shows a before and after chart.

**2. Research on HDFS_v1 (the FYP evaluation)**
The full benchmark run on 11,175,629 real log lines: Drain3 parsing, Random Forest and Isolation Forest with a time-ordered split, accuracy against the official answer key, and a replay of the newer logs. Results are below.

## Run it (Windows)

Double-click `run.bat`. The first run sets everything up (needs internet once). After that it works offline and opens http://localhost:8600 in your browser.
To read the Windows **Security** log (logons, failed passwords), right-click `run.bat` and choose **Run as administrator**.
For `.evtx` files, also run `pip install python-evtx`.

### Connecting other machines
Linux server (rsyslog): add `*.* @@<this-PC's-address>:5140` to `/etc/rsyslog.conf`, then `sudo systemctl restart rsyslog`.
Router or firewall: set the remote syslog server to this PC's address, port 5140. Allow the port in Windows Firewall.

Any other system:

    python -m venv .venv
    .venv/bin/pip install -r requirements.txt   # Windows: .venv\Scripts\pip
    .venv/bin/python server.py

## Research screens

1. **What the AI found**: how many storage tasks look unusual, when it happened, and what kind of problems they were.
2. **Review the alerts**: each alert shows the usual routine next to this task's (as a row of beads), what to check next, and the log lines as evidence. Mark each one *Real problem*, *False alarm* or *Not sure*. Keys: `1` `2` `3` to answer, `J` `K` to move.
3. **Watch it live**: replays the newer part of the log as if it were arriving now. Each line is sorted as it arrives, each storage task is checked when it finishes, and alerts pop up in real time.
4. **How often it's right**: real problems caught and false alarms, checked against an answer key.
5. **How it works**: follow one task through the five stages, from raw text to alert.

Switch on **Show technical terms** (top right) to see the algorithm names and precision, recall and F1.

## How it works

| Stage | In plain words | Built with |
|---|---|---|
| Read | Read the log file line by line | Python |
| Sort | Group similar lines into message types (thousands of lines become about a dozen types) | Drain3 |
| Count | Turn each storage task (block) into counts of each message type | pandas |
| Check | Detector A learns what normal looks like and flags anything different; Detector B learns from labelled examples | scikit-learn: Isolation Forest, Random Forest |
| Explain | Compare the task with the usual routine and write the difference in plain words | Python, SQLite |
| Show | Web dashboard with live replay | FastAPI, HTML/CSS/JavaScript, server-sent events |

Training is fair: the detectors learn from the **older 70%** of storage tasks and are tested on the **newer 30%**. Live mode only replays the newer part.

## Run on the real HDFS_v1 dataset

Download HDFS_v1 from loghub: https://zenodo.org/records/8196385/files/HDFS_v1.zip?download=1 and unzip it.
In the dashboard press **Check a log file**, choose **My own file**, and give the paths to `HDFS.log` and `anomaly_label.csv`. Start with the first 1,000,000 lines.

Command-line alternative:

    python -m seclog.pipeline --log C:\path\HDFS.log --labels C:\path\anomaly_label.csv --max-lines 1000000

The full file (about 11 million lines) takes about 9 minutes and stays under 2 GB of memory.

## Results on HDFS_v1 (full dataset)

Run on 23 Nov 2026: all 11,175,629 lines and 575,061 storage tasks (blocks), using the official `anomaly_label.csv`. Detectors trained on the older 402,542 tasks and tested on the newer 172,519 (3,723 real problems among them). The full run took 8.8 minutes on a laptop (Intel i9-14900HX, 32 GB RAM).

| Detector | Real problems caught | False alarms | Precision | Recall | F1 |
|---|---|---|---|---|---|
| Random Forest (supervised) | 3,717 of 3,723 | 0 | 1.000 | 0.998 | 0.999 |
| Isolation Forest (unsupervised) | 2,116 of 3,723 | 510 | 0.806 | 0.568 | 0.667 |

Live mode on the same data (first 20,000 newer tasks replayed): checking a task after 30 minutes of quiet caught 326 of 359 real problems with 0 false alarms. Checking after only 1 minute raised 715 false alarms, because real tasks often send their last messages minutes later. Live mode therefore waits 30 minutes of log time on real logs.

Message sorting: Drain3 with masking and similarity 0.9 found 53 message types. On loghub's labelled HDFS_2k sample it groups 99.75% of lines correctly.

## What is real and what is not

* `data/sample/demo_hdfs_style.log` and `demo_labels.csv` are **made up** by `seclog/make_demo.py`, built to look like HDFS logs. They show how the monitor works. **Numbers on them are not research results.**
* `data/sample/HDFS_2k.log` is 2,000 real lines from loghub, used only to test the parser.
* The HDFS_v1 results above come from the real dataset; the demo numbers do not.

## Not built yet (planned for FYP2)

* A second dataset (BGL), and comparing against published results
* A deep sequence model (for example LSTM)
* Deeper per-alert explanations (SHAP)
* A supervised model trained on many confirmed threats, building on today's feedback loop
* Real automatic response: firewall rules (Windows Firewall, iptables) instead of the simulated block, and alerts to Telegram or email

## Project layout

    server.py            web server and API
    web/                 dashboard (index.html, app.css, app.js, bundled IBM Plex fonts)
    seclog/parse.py      read lines, Drain3 message types
    seclog/features.py   counts per storage task
    seclog/models.py     Isolation Forest, Random Forest, time-ordered split
    seclog/plain.py      plain-language explanations
    seclog/pipeline.py   offline check end to end, saves results to SQLite
    seclog/live.py       live replay: parse and check tasks as lines arrive
    seclog/make_demo.py  generates the made-up demo log
    seclog/formats.py    reads many log formats into one shape
    seclog/rules.py      15 known attack patterns (MITRE ATT&CK)
    seclog/ai.py         live AI: per-address windows, Isolation Forest, plain reasons
    seclog/learning.py   learning from people's answers (feedback loop)
    seclog/sources.py    connections: file, folder, web address, syslog, Windows events, attack lab
    seclog/simulator.py  the attack lab
    seclog/monitor.py    the live engine and its SQLite store
    seclog/insight.py    location, risk score and attack-story steps
    seclog/report.py     PDF incident reports (fonts in seclog/fonts)
    web/monitor.js       live monitor screens
    web/insight.js       attack story, map, profiles, blocking, presentation mode
    web/world.js         world map shapes (Natural Earth, public domain)
    web/tour.js          the guided demo
    tests/               25 tests (python -m pytest)

## Credits

HDFS, OpenSSH, Linux and Apache sample logs: loghub (He et al., 2023). Log parsing: Drain3 (IBM). Fonts: IBM Plex (SIL Open Font License). Map shapes: Natural Earth via world-atlas (public domain). Country lookup: geoip2fast with MaxMind GeoLite2 data (CC BY-SA 4.0). PDF: fpdf2.
