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
* **Reads:** Linux syslog and auth.log (SSH, sudo, useradd, firewall), Linux audit logs, DNS server logs (dnsmasq, BIND), OpenVPN, Apache and Nginx web and error logs, Windows events (live or `.evtx`), JSON lines, HDFS and plain text; also `.gz` and `.zip` files.
* **Finds threats two ways:**
  * **AI:** an Isolation Forest learns what normal looks like for each address or user over 30-second windows, then flags anything unusual.
  * **Known attack patterns:** 23 patterns, including password guessing (fast, slow, and spread over a network), password spraying, DNS tunnelling and DNS scans, a website account switching user, admin rights used on password files, logins from a new address, a login right after guessing, SQL injection and other web attacks, scanners, hidden-page hunting, port scans, admin rights and new accounts, cleared logs, malware, and new services. In technical mode each one is mapped to MITRE ATT&CK.
* **Learns and adapts** in three ways:
  * It learns normal behaviour when a connection starts. For a file you drop in, it first reads the whole file, learns what is normal for that file, then judges every part of it (offline mode).
  * It re-learns normal every few minutes, so it keeps up as things change.
  * It learns from your answers. "Real threat" makes it more watchful of that behaviour; "False alarm" makes it calmer and stops that exact alert coming back. This is a small reinforcement loop: the sensitivities are the policy and your answers are the reward.
  * The lessons are saved and shared across all connections. The **AI learning** page shows what changed. In the attack lab, "Sneaky data theft" gets through until you confirm a "Quiet data theft" as real; after that the AI catches it.
* **Screens:** a radar of who's active, a live threat level, pop-up alerts, a threats inbox with evidence and advice, and buttons to mark each alert as real or a false alarm.
* **Attack story:** separate alerts from one attacker (and the accounts it logged in as) are joined into one story across 7 attack steps, following the MITRE ATT&CK tactics: looking around, guessing passwords, getting in, becoming admin, staying in, hiding tracks, taking data or doing harm.
* **Attack map:** a world map of where activity comes from, with lines from attackers to your systems. The country lookup is offline (geoip2fast, built from MaxMind GeoLite2 data), so it works without internet.
* **Risk score and profiles:** every address and user gets a risk score from 0 to 100. Recent threats count most and fade with a 30-minute half-life; threats marked real count more, false alarms count nothing. Click any address for its profile: country, risk trend, accounts used, activity, threats and log lines.
* **Respond:** block an address for 30 minutes. In the attack lab the lab firewall really drops its traffic. For real addresses, switch on **Block with the Windows Firewall** on the Connect logs page (off by default; needs `run.bat` started with "Run as administrator"). Each block then adds an inbound Windows Firewall rule named `SecurityLogMonitor block <address>`, removed automatically when the block ends, when you unblock, when you switch the option off, or at the next start if one was left behind. **Test it safely** adds and removes a rule for 203.0.113.50, an address reserved for examples. Addresses inside your own network are on an allowlist and are never blocked. Without the option, blocks are simulated.
* **ELK Stack:** switch on **Send to Elasticsearch** on the Connect logs page and every log line and threat is copied to Elasticsearch, using Elastic Common Schema field names (`source.ip`, `user.name`, `event.outcome`, `rule.name`, `threat.technique.id`, ...). Optionally it goes through a Logstash pipeline that adds the city and map location of each outside address. A ready-made Kibana dashboard shows threats over time, a map of where attacks come from, MITRE ATT&CK tactics, top attackers, targeted accounts and failed logins by country. The same data can feed a SOC's own SIEM. Setup scripts download and start Elasticsearch, Logstash and Kibana on Windows without administrator rights; see [ELK.md](ELK.md).
* **MySQL:** switch on **Keep a copy in MySQL** on the Connect logs page and every log line and threat is also stored in MySQL tables (`sources`, `events`, `alerts`, with foreign keys and indexes) plus views for the usual questions (top attackers, threats per hour, accounts under attack, threats by MITRE ATT&CK tactic). The page shows those reports live from MySQL; `mysql/queries.sql` has more. The monitor's own store stays one SQLite file. Setup scripts download and start MySQL 8.4 on Windows without administrator rights; see [MYSQL.md](MYSQL.md).
* **Incident report:** one click makes a PDF of any threat: what happened, the attack story, the evidence and the response.
* **Presentation mode:** a full-screen view for a projector, with the map, the radar, live threats and the riskiest addresses. Press M to switch view, Esc to leave.
* **Guided demo:** a 23-step tour that explains every screen and runs the whole story live (about 6 minutes). Tick "Start fresh" to clear old threats and lessons first.
* **Attack lab:** a pretend company network in Malaysia with 9 attacks to launch, timed to show how fast each one is caught. "Quiet data theft" matches no known pattern, so only the AI can catch it. "Sneaky data theft" gets through until you teach the AI. The AI learning page shows a before and after chart.

* **AI assistant:** a chat panel on every page (**Ask the AI**, bottom right) and an **Ask the AI to explain** button on every threat. It runs a large language model on this PC through [Ollama](https://ollama.com), so no log line leaves the computer, and it answers only from the monitor's own data: the threats, their evidence lines, address profiles, attack stories, the arena results and the HDFS_v1 results (retrieval-augmented generation). **Show what the AI was given** lists exactly those facts under each answer. Setup: install Ollama, then pick a model in the panel (qwen2.5:7b, 4.7 GB, or qwen2.5:3b, 1.9 GB, for PCs without a graphics card).

**2. Research on HDFS_v1 (the FYP evaluation)**
The full benchmark run on 11,175,629 real log lines: Drain3 parsing, Random Forest and Isolation Forest with a time-ordered split, accuracy against the official answer key, and a replay of the newer logs. Results are below.

## Run it

You need Python 3.10 or newer (from https://www.python.org/downloads/; on Windows tick "Add python.exe to PATH" during setup).

* **Windows:** double-click `run.bat`.
* **Mac or Linux:** run `bash run.sh` in a terminal.

The first run sets everything up (needs internet once, a few minutes). If Python is missing, the launcher says what to install. After that it works offline and opens http://localhost:8600 in your browser.
The real HDFS_v1 results come with the project (`data/research`, 18 MB), so any PC shows them; there is no need to download the dataset.
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

The results of the full run already come with the project as a small snapshot (`data/research`): every task's result, the log lines of every flagged task, the trained models and the first 400,000 lines of the newer log for the replay. The dashboard unpacks it on first start. "Re-run the HDFS check" > "Saved HDFS_v1 results" brings it back at any time.

To run it yourself, download HDFS_v1 from loghub: https://zenodo.org/records/8196385/files/HDFS_v1.zip?download=1 and unzip it.
In the dashboard press **Check a log file**, choose **My own file**, and give the paths to `HDFS.log` and `anomaly_label.csv`. Start with the first 1,000,000 lines.

Command-line alternative:

    python -m seclog.pipeline --log C:\path\HDFS.log --labels C:\path\anomaly_label.csv --max-lines 1000000

The full file (about 11 million lines) takes about 9 minutes and stays under 2 GB of memory. Afterwards, `python -m seclog.snapshot export` makes a new portable snapshot of the results.

## Results on HDFS_v1 (full dataset)

Run on 23 Nov 2026: all 11,175,629 lines and 575,061 storage tasks (blocks), using the official `anomaly_label.csv`. Detectors trained on the older 402,542 tasks and tested on the newer 172,519 (3,723 real problems among them). The full run took 8.8 minutes on a laptop (Intel i9-14900HX, 32 GB RAM).

| Detector | Real problems caught | False alarms | Precision | Recall | F1 |
|---|---|---|---|---|---|
| Random Forest (supervised) | 3,717 of 3,723 | 0 | 1.000 | 0.998 | 0.999 |
| Isolation Forest (unsupervised) | 2,116 of 3,723 | 510 | 0.806 | 0.568 | 0.667 |

### Eight machine-learning techniques compared

The same data, features and split, run through the eight techniques of the standard log anomaly benchmark (He et al., 2016, *Experience Report: System Log Analysis for Anomaly Detection*), with scikit-learn defaults and no tuning. The unsupervised ones never see the answer key; each raises an alert for anything more unusual than the 3% most unusual older tasks. One-Class SVM and Local Outlier Factor learn from a random 20,000 of the older tasks, because they slow down sharply with more. Run with `python -m seclog.compare` (about 6 minutes, most of it reading the database); results go to `data/eval/compare.json` and the dashboard's Accuracy page.

| Technique | Learns from | Caught (of 3,723) | False alarms | Precision | Recall | F1 | Time to learn |
|---|---|---|---|---|---|---|---|
| Decision Tree | labelled examples | 3,717 | 0 | 1.000 | 0.998 | 0.999 | 2 s |
| Random Forest (Detector B) | labelled examples | 3,717 | 0 | 1.000 | 0.998 | 0.999 | 11 s |
| Linear SVM | labelled examples | 3,707 | 5 | 0.999 | 0.996 | 0.997 | 54 s |
| Logistic Regression | labelled examples | 3,707 | 83 | 0.978 | 0.996 | 0.987 | 2 s |
| PCA | normal only | 2,226 | 492 | 0.819 | 0.598 | 0.691 | 1 s |
| Isolation Forest (Detector A) | normal only | 2,116 | 510 | 0.806 | 0.568 | 0.667 | 5 s |
| One-Class SVM | normal only | 1,491 | 2,624 | 0.362 | 0.401 | 0.381 | 2 s |
| Local Outlier Factor | normal only | 900 | 182 | 0.832 | 0.242 | 0.375 | 1 s |

What this shows: with an answer key to learn from, HDFS_v1 is almost solved by any supervised technique, which matches published results. Without one, the best technique catches about 60% of problems with roughly one false alarm for every four real catches. PCA edges out Isolation Forest here; both are far ahead of One-Class SVM and LOF at default settings. Real security logs rarely come with an answer key, which is why the live monitor relies on the unsupervised side plus known attack patterns and people's feedback.

Live mode on the same data (first 20,000 newer tasks replayed): checking a task after 30 minutes of quiet caught 326 of 359 real problems with 0 false alarms. Checking after only 1 minute raised 715 false alarms, because real tasks often send their last messages minutes later. Live mode therefore waits 30 minutes of log time on real logs.

Message sorting: Drain3 with masking and similarity 0.9 found 53 message types. On loghub's labelled HDFS_2k sample it groups 99.75% of lines correctly.

### Algorithm arena

The **Algorithm arena** page lets algorithms fight on the same HDFS_v1 tasks (older 70% to learn, newer 30% to test) and shows how each one performs, its settings and how they compare:

* **15 algorithms** to pick from. From examples: Logistic Regression, Decision Tree, Random Forest, Extra Trees, Gradient Boosting, Linear SVM, k-Nearest Neighbours, Naive Bayes, AdaBoost. Normal only: Isolation Forest, PCA, One-Class SVM, Local Outlier Factor. Deep learning: a Neural Network (multi-layer perceptron) and an Autoencoder.
* **Add, change, copy or delete** any of them. Every setting (parameter) has a form field with its range, default and meaning. Results from older settings are marked out of date.
* **Fight:** tick any contenders and run them; each lane fills in as it finishes. The leaderboard ranks them by F1 and shows caught, false alarms, precision, recall, time and every setting. Charts compare precision, recall and F1, quality against speed, and the precision-recall curves.
* **Each algorithm's page:** caught, missed and false alarms as dots and a confusion matrix, precision, recall, F1, PR-AUC, ROC-AUC, timings, its precision-recall curve, and a table of its settings next to the defaults.
* **AI tuning:** the AI searches for better settings (random search). Each try learns on the older 80% of the training tasks and is scored on the newest 20% of them; the best is then tested once on the newer test tasks, so the test set never influences the choice. The trials are shown and kept.
* **The AI's pick** names the best algorithm, the best one that needs no answer key, and the fastest near-best one. **Ask the AI about these results** sends the whole leaderboard to the assistant.

The HDFS_v1 features (every task's message counts) are made once from a full run: `python -m seclog.arena build-features` (or with `--log HDFS.log --labels anomaly_label.csv` if the full database is gone). They are saved to `data/research/hdfs_features.npz`, which comes with the project. Without it, the arena uses the current research run (for example the demo logs). `python -m seclog.arena fight` runs every contender from the command line.

## Tested on real-world logs

`python -m seclog.evaluate ssh <SSH.log>` runs a whole log through the monitor in its own throwaway database and writes `data/eval/ssh.json`.

**Loghub OpenSSH: a real SSH server on the internet** (655,147 lines, about a month, unlabelled; download: https://zenodo.org/records/3227177/files/SSH.tar.gz?download=1).
Testing on it showed two weaknesses, which were then fixed and measured again on the same log:

| | Before | After |
|---|---|---|
| Alerts | 4,591 | 1,924 |
| Alerts per 1,000 lines | 7.0 | 2.9 |
| Most alerts for one address | 594 | 86 |
| Addresses with 20+ failed logins that were flagged | 267 of 305 (87.5%) | 302 of 305 (99.0%) |
| Speed on a laptop | 4,400 lines a second | 6,250 lines a second |

* **Slow guessing:** some attackers stayed under the "8 failures in 2 minutes" rule, for example 1,707 failures over 12 days at most 9 an hour. New rule: 20+ failures in 24 hours with almost no successful logins (staff typos are followed by a login, so they don't count).
* **Distributed guessing:** groups of addresses in one network took turns (183.136.x.x, 122.224.x.x, 115.233.91.x). New rule: 4+ addresses from one network with 40+ failures in 6 hours; 4 such networks found.
* **Alert fatigue:** a long attack raised a new alert every 5 minutes. Now an ongoing attack updates its open alert for as long as it continues (until a person marks it).
* No successful break-in was found. 66 alerts came from the AI. The 3 addresses still missed spread fewer than 20 attempts over each day.

**AIT Log Data Set V2.0** (scenario russellmitchell: a simulated company with real attack tools; every attack line is labelled with its step; https://zenodo.org/records/5789064). `python -m seclog.evaluate ait <folder>` feeds each labelled log (with its older rotated days first) through the monitor and scores it.
Testing on it first meant teaching the monitor four formats it misread (dnsmasq, Linux audit, Apache error timestamps, OpenVPN users) and masking random DNS names, which had slowed message sorting to a crawl.

| | First run | After adding 6 standard rules |
|---|---|---|
| Attack steps detected | 6 of 12 | **10 of 12** |
| Attack lines inside an alert | 15,077 of 61,813 | 19,390 of 61,813 |
| False alarms | 16 in 234,524 normal lines (0.07 per 1,000) | 16 (unchanged) |

Caught: dirb and WPScan scans (100% of lines), webshell upload (100%), webshell commands (73%), nmap service scan (100%), DNS name guessing (100%), the website account switching user, sudo reading /etc/shadow, data theft over DNS.
Missed: a reverse-lookup network sweep (too spread out for the rule) and the attacker's VPN login with a stolen certificate (the account had too few earlier logins to compare with).
The 6 rules were added after the first run, so this scenario is no longer a fair test of them; each is a standard detection with general thresholds (DNS tunnelling, website account using su, sudo on /etc/shadow, DNS name guessing, reverse-lookup sweep, login from a new address).

**Hold-out check on a scenario not looked at during development (fox).** Same attack steps, different company, different timing, and a much bigger web scan (410,000 requests). Nothing was tuned on it. `python -m seclog.evaluate ait-extract fox.zip <folder>` unpacks just the 23 files the evaluation reads (0.2 of 15.8 GB).

| fox (hold-out) | Without the 6 rules | With the 6 rules |
|---|---|---|
| Attack steps detected | 6 of 12 | **11 of 12** |
| Attack lines inside an alert | 412,812 of 456,838 | 455,276 of 456,838 |
| Data theft over DNS, lines covered | 4% | **100%** |
| False alarms | 57 in 219,961 normal lines (0.26 per 1,000) | 57 (unchanged) |

* The 6 rules carry over: on unseen data they add 5 attack steps (DNS name guessing, the reverse-lookup sweep that russellmitchell's was too spread out for, the website account switching user, sudo commands, other attacker activity) and raise no false alarms of their own.
* Still missed: the attacker's VPN login, as on russellmitchell.
* Weak point: 54 of the 57 false alarms are the AI flagging the DNS server's own busy periods. On this scenario the AI is noisier than on russellmitchell (0.07 per 1,000); making it adapt to each server's normal rhythm is FYP2 work.
* The big scan exposed two slow spots, both fixed: the hidden-page rule re-counted the last minute's pages on every line, and every top-level page (/admin, /backup, ...) became its own message type. The 413,000-line web log now takes 19 seconds to sort instead of over 30 minutes. The russellmitchell results above were re-run with these fixes and did not change.

**LANL Comprehensive Multi-Source Cyber-Security Events** (58 days of real logins from Los Alamos National Laboratory, with real red-team compromises; https://csr.lanl.gov/data/cyber1/). `python -m seclog.evaluate lanl auth.txt.gz redteam.txt.gz` learns where each account logs in during the first 40 hours, then alerts when an account reaches k new computers within 24 hours. 500 million login lines were read in 18 minutes.

| k new computers in 24 h | Red-team logins caught | Red-team accounts caught | Alerts per day |
|---|---|---|---|
| 1 | 77% (541 of 701) | 70 of 104 | 1,947 |
| 2 | 65% | 51 of 104 | 1,179 |
| 3 | 57% | 43 of 104 | 638 |
| 5 | 43% | 29 of 104 | 296 |

The simple "new place" signal finds most of the red team but is far too noisy for a person to use on its own; ranking these alerts with machine learning is planned for FYP2.

## What is real and what is not

* `data/sample/demo_hdfs_style.log` and `demo_labels.csv` are **made up** by `seclog/make_demo.py`, built to look like HDFS logs. They show how the monitor works. **Numbers on them are not research results.**
* `data/sample/HDFS_2k.log` is 2,000 real lines from loghub, used only to test the parser.
* The HDFS_v1 results above come from the real dataset; the demo numbers do not.

## Not built yet (planned for FYP2)

* A second dataset (BGL), and comparing against published results
* A deep sequence model (for example LSTM); the arena already has a neural network and an autoencoder
* Deeper per-alert explanations (SHAP)
* A supervised model trained on many confirmed threats, building on today's feedback loop
* More automatic response: firewall rules on Linux (iptables), and alerts to Telegram or email

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
    seclog/rules.py      23 known attack patterns (MITRE ATT&CK)
    seclog/compare.py    eight machine-learning techniques compared on HDFS_v1
    seclog/arena.py      algorithm arena: 15 algorithms, editable settings, fights, AI tuning
    seclog/assistant.py  AI assistant: local language model (Ollama), grounded in the monitor's data
    seclog/evaluate.py   evaluation on real and labelled datasets (loghub SSH, LANL, AIT-LDS)
    seclog/ai.py         live AI: per-address windows, Isolation Forest, plain reasons
    seclog/learning.py   learning from people's answers (feedback loop)
    seclog/sources.py    connections: file, folder, web address, syslog, Windows events, attack lab
    seclog/simulator.py  the attack lab
    seclog/monitor.py    the live engine and its SQLite store
    seclog/insight.py    location, risk score and attack-story steps
    seclog/report.py     PDF incident reports (fonts in seclog/fonts)
    seclog/firewall.py   optional real blocking with the Windows Firewall
    seclog/elk.py        sends events and alerts to Elasticsearch (ELK Stack, ECS fields)
    seclog/sqlstore.py   keeps a copy of events and alerts in MySQL (tables, keys, views)
    mysql/               MySQL setup, start and stop scripts, example SQL queries (see MYSQL.md)
    elk/                 ELK Stack setup, start and stop scripts, Logstash pipeline, Kibana dashboard (see ELK.md)
    seclog/snapshot.py   portable copy of the HDFS_v1 results (data/research)
    run.bat, run.sh      launchers for Windows, and for Mac and Linux
    web/monitor.js       live monitor screens
    web/insight.js       attack story, map, profiles, blocking, presentation mode
    web/world.js         world map shapes (Natural Earth, public domain)
    web/tour.js          the guided demo
    web/arena.js         the algorithm arena page
    web/assistant.js     the AI assistant panel
    tests/               52 tests (python -m pytest)

## Credits

HDFS, OpenSSH, Linux and Apache sample logs: loghub (He et al., 2023). Log parsing: Drain3 (IBM). Fonts: IBM Plex (SIL Open Font License). Map shapes: Natural Earth via world-atlas (public domain). Country lookup: geoip2fast with MaxMind GeoLite2 data (CC BY-SA 4.0). PDF: fpdf2.
