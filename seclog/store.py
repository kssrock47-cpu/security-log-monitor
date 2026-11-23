"""SQLite storage for parsed events, blocks, alerts and model runs."""
import sqlite3
from contextlib import closing

SCHEMA = """
DROP TABLE IF EXISTS log_events;
DROP TABLE IF EXISTS templates;
DROP TABLE IF EXISTS blocks;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS model_runs;
DROP TABLE IF EXISTS meta;
DROP TABLE IF EXISTS template_stats;
DROP TABLE IF EXISTS feedback;
CREATE TABLE log_events (line_no INTEGER, block_id TEXT, ts TEXT, level TEXT,
                         component TEXT, template_id INTEGER, content TEXT);
CREATE TABLE templates (template_id INTEGER PRIMARY KEY, template TEXT);
CREATE TABLE blocks (block_id TEXT PRIMARY KEY, first_ts TEXT, n_events INTEGER,
                     label TEXT, split TEXT);
CREATE TABLE alerts (block_id TEXT, model TEXT, score REAL, flagged INTEGER,
                     severity TEXT, reason TEXT);
CREATE TABLE model_runs (model TEXT, labelled INTEGER, n_train INTEGER, n_test INTEGER,
                         precision REAL, recall REAL, f1 REAL, run_at TEXT);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE template_stats (template_id INTEGER PRIMARY KEY, normal_share REAL,
                             normal_median REAL, typical_pos REAL);
CREATE TABLE feedback (block_id TEXT PRIMARY KEY, verdict TEXT, at TEXT);
CREATE INDEX idx_events_block ON log_events(block_id);
CREATE INDEX idx_alerts_block ON alerts(block_id);
CREATE INDEX idx_events_line ON log_events(line_no);
"""


def connect(db_path: str) -> sqlite3.Connection:
    return sqlite3.connect(db_path)


def reset(db_path: str) -> None:
    with closing(connect(db_path)) as con:
        con.executescript(SCHEMA)
        con.commit()


def insert_many(con, table: str, rows, ncols: int, chunk: int = 50_000):
    q = f"INSERT INTO {table} VALUES ({','.join('?' * ncols)})"
    rows = list(rows) if not hasattr(rows, "__next__") else rows
    batch = []
    for r in rows:
        batch.append(r)
        if len(batch) >= chunk:
            con.executemany(q, batch)
            batch.clear()
    if batch:
        con.executemany(q, batch)
