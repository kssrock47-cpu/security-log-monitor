# Security Log Monitor

**AI-Based Security Log Analysis and Threat Monitoring System**, the FYP1 (AP1) prototype by Kyaw Swe Sien Marma, Universiti Malaya.
Supervisor: Dr. Shapla Khanam. Collaborator: Ts. Dr. Muhammad Faiz bin Mohd Zaki.

Computers keep a diary of everything they do, called a log. Real systems write millions of lines, far too many for a person to read. This monitor reads the log, learns the usual routine, flags the parts that break it, and explains each one in plain words with the lines that prove it. **The AI does a first check. A person still decides what matters.**

## Run it (Windows)

Double-click `run.bat`. The first run sets everything up (needs internet once). After that it works offline and opens http://localhost:8600 in your browser.

Any other system:

    python -m venv .venv
    .venv/bin/pip install -r requirements.txt   # Windows: .venv\Scripts\pip
    .venv/bin/python server.py

## What you can do

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

The full file (about 11 million lines) has not been run yet.

## What is real and what is not

* `data/sample/demo_hdfs_style.log` and `demo_labels.csv` are **made up** by `seclog/make_demo.py`, built to look like HDFS logs. They show how the monitor works. **Numbers on them are not research results.**
* `data/sample/HDFS_2k.log` is 2,000 real lines from loghub, used only to test the parser.
* No results on HDFS_v1 are claimed yet.

## Not built yet (planned for FYP2)

* Full HDFS_v1 run and a second dataset (BGL)
* A deep sequence model (for example LSTM)
* Deeper per-alert explanations (SHAP)
* Learning from the saved reviews to improve over time (the reviews are already stored in the `feedback` table)

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
    tests/               11 tests (python -m pytest)

## Credits

HDFS logs: loghub (He et al., 2023). Log parsing: Drain3 (IBM). Fonts: IBM Plex (SIL Open Font License).
