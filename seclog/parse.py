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


def make_miner() -> TemplateMiner:
    cfg = TemplateMinerConfig()
    cfg.drain_sim_th = 0.5
    cfg.drain_depth = 4
    cfg.masking_instructions = [
        MaskingInstruction(r"blk_-?\d+", "BLK"),
        MaskingInstruction(r"((?<=[^A-Za-z0-9])|^)(\d{1,3}\.){3}\d{1,3}(:\d+)?((?=[^A-Za-z0-9])|$)", "IP"),
        MaskingInstruction(r"((?<=[^A-Za-z0-9])|^)(\d+)((?=[^A-Za-z0-9])|$)", "NUM"),
    ]
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
