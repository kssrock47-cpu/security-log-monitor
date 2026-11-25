"""Step 1-2: read raw HDFS log lines and group similar lines into event types with Drain3."""
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator, Optional

from drain3 import TemplateMiner
from drain3.masking import MaskingInstruction
from drain3.template_miner_config import TemplateMinerConfig

# Example: 081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_... terminating
LINE_RE = re.compile(r"^(\d{6}) (\d{6}) (\d+) (\w+) ([\w.$]+): (.*)$")
BLOCK_RE = re.compile(r"blk_-?\d+")


@dataclass
class LogEvent:
    line_no: int
    block_id: str
    ts: str          # ISO timestamp
    level: str
    component: str
    template_id: int
    content: str


def make_miner(live: bool = False) -> TemplateMiner:
    cfg = TemplateMinerConfig()
    # Everything that varies is masked first, so a strict similarity (0.9) can keep
    # near-identical but different messages apart (e.g. "terminating" vs "Interrupted").
    # Checked on loghub's HDFS_2k ground truth: 99.75% grouping accuracy.
    cfg.drain_sim_th = 0.9
    cfg.drain_depth = 4
    cfg.masking_instructions = [
        MaskingInstruction(r"blk_-?\d+", "BLK"),
        MaskingInstruction(r"((?<=[^A-Za-z0-9])|^)(\d{1,3}\.){3}\d{1,3}(:\d+)?((?=[^A-Za-z0-9])|$)", "IP"),
        MaskingInstruction(r"(?<![\w])/(?:[\w.\-]+/)+[\w.\-]*", "PATH"),
        MaskingInstruction(r"((?<=[^A-Za-z0-9])|^)(\d+)((?=[^A-Za-z0-9])|$)", "NUM"),
    ]
    if live:
        # Live monitor only (the HDFS research results keep the masks above). Found on the AIT-LDS DNS log:
        # data stolen over DNS turns every lookup into a new random name, and each one became a new message
        # type, slowing everything down. Long random strings and domain names are masked first, and the number
        # of message types is capped (least used are forgotten).
        # Found on the second AIT-LDS scenario: a web scan asks for 400,000 different pages, and every top-level
        # page (/admin, /backup, ...) became its own message type until matching each line took seconds. In live
        # mode every path is masked, one level deep or many (how many pages someone asks for is an AI feature).
        cfg.masking_instructions[2:2] = [
            MaskingInstruction(r"(?<![\w*/+=.-])[\w*/+=.-]{30,}(?![\w*/+=.-])", "LONG"),
            MaskingInstruction(r"(?<![\w.-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![\w.-])", "HOST"),
            MaskingInstruction(r"(?<![\w.:/<>-])/[^\s\"']*", "PATH"),
        ]
        cfg.drain_max_clusters = 5000
    return TemplateMiner(config=cfg)


def parse_line(raw: str) -> Optional[tuple]:
    """Return (iso_ts, level, component, content) or None if the line is not in HDFS format."""
    m = LINE_RE.match(raw.strip())
    if not m:
        return None
    date, time_, _pid, level, comp, content = m.groups()
    try:
        ts = datetime.strptime(date + time_, "%y%m%d%H%M%S").isoformat()
    except ValueError:
        return None
    return ts, level, comp, content


def parse_file(path: str, max_lines: Optional[int] = None, return_miner: bool = False):
    """Parse a log file. Returns (events, templates) where templates maps id -> template text.

    Lines without a block id are skipped (HDFS anomaly labels are per block).
    A line that mentions several blocks is counted once for each block.
    """
    miner = make_miner()
    events: list[LogEvent] = []
    with open(path, "r", errors="replace") as f:
        for i, raw in enumerate(f, start=1):
            if max_lines and i > max_lines:
                break
            parsed = parse_line(raw)
            if not parsed:
                continue
            ts, level, comp, content = parsed
            blocks = sorted(set(BLOCK_RE.findall(content)))
            if not blocks:
                continue
            res = miner.add_log_message(content)
            tid = res["cluster_id"]
            for b in blocks:
                events.append(LogEvent(i, b, ts, level, comp, tid, raw.strip()))
    # Template text can be refined while parsing, so read the final text at the end.
    templates = {c.cluster_id: c.get_template() for c in miner.drain.clusters}
    if return_miner:
        return events, templates, miner
    return events, templates


def parse_to_db(path: str, con, max_lines: Optional[int] = None, chunk: int = 50_000,
                checkpoint_every: int = 200_000):
    """Memory-lean parse for big files (HDFS_v1 has 11 million lines).

    Raw lines go straight into the log_events table; only small integer arrays stay in memory.
    Returns a dict with numpy arrays (block code, template id, unix time, line number),
    the block id list, templates, the miner, and byte-offset checkpoints for live replay.
    """
    import numpy as np
    miner = make_miner()
    block_ix: dict[str, int] = {}
    b_codes, t_ids, ts_arr, ln_arr = [], [], [], []
    rows, checkpoints = [], []
    q = "INSERT INTO log_events VALUES (?,?,?,?,?,?,?)"
    offset = 0
    with open(path, "rb") as f:
        for i, raw_b in enumerate(f, start=1):
            if max_lines and i > max_lines:
                break
            line_start, offset = offset, offset + len(raw_b)
            raw = raw_b.decode("utf-8", "replace")
            parsed = parse_line(raw)
            if not parsed:
                continue
            ts, level, comp, content = parsed
            if (i - 1) % checkpoint_every == 0:
                checkpoints.append((i, line_start, ts))
            blocks = sorted(set(BLOCK_RE.findall(content)))
            if not blocks:
                continue
            tid = miner.add_log_message(content)["cluster_id"]
            unix = int(datetime.fromisoformat(ts).timestamp())
            text = raw.strip()
            for b in blocks:
                code = block_ix.setdefault(b, len(block_ix))
                b_codes.append(code); t_ids.append(tid); ts_arr.append(unix); ln_arr.append(i)
                rows.append((i, b, ts, level, comp, tid, text))
            if len(rows) >= chunk:
                con.executemany(q, rows)
                rows.clear()
    if rows:
        con.executemany(q, rows)
    con.commit()
    templates = {c.cluster_id: c.get_template() for c in miner.drain.clusters}
    return {"block": np.asarray(b_codes, dtype=np.int32), "tid": np.asarray(t_ids, dtype=np.int32),
            "ts": np.asarray(ts_arr, dtype=np.int64), "line": np.asarray(ln_arr, dtype=np.int64),
            "block_ids": list(block_ix), "templates": templates, "miner": miner, "checkpoints": checkpoints}
