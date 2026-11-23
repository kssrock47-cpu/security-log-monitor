"""Online mode: replay a saved log as if it were arriving now, and check each task as it finishes.

The models are the ones trained in the offline run (on the older part of the log).
Replay starts where the training part ended, so the models only ever see "tomorrow's" logs.
Each new line is parsed with the same Drain3 miner, grouped by storage task (block),
and a task is checked once it has been quiet for `idle_secs` of log time.
"""
from dataclasses import dataclass, field
from datetime import datetime

import joblib
import numpy as np
import pandas as pd

from . import plain
from .parse import BLOCK_RE, parse_line


@dataclass
class OpenTask:
    first_ts: datetime
    last_ts: datetime
    counts: dict = field(default_factory=dict)
    unknown: int = 0
    n: int = 0


class LiveEngine:
    def __init__(self, bundle_path: str, log_path: str, start_ts: str, idle_secs: int = 60):
        b = joblib.load(bundle_path)
        self.tids = b["tids"]
        self.templates = b["templates"]
        self.miner = b["miner"]
        self.if_model, self.if_thr, self.rf_model = b["if_model"], b["if_thr"], b["rf_model"]
        if self.rf_model is not None:
            self.rf_model.n_jobs = 1  # one task at a time: threads only add overhead
        self.stats = pd.DataFrame(b["stats_rows"], columns=["template_id", "normal_share", "normal_median",
                                                            "typical_pos"]).set_index("template_id")
        self.log_path = log_path
        self.start = datetime.fromisoformat(start_ts)
        self.idle = idle_secs
        self.open: dict[str, OpenTask] = {}
        self.started_before: set[str] = set()  # tasks already under way when replay starts: skip them
        self.col = {t: i for i, t in enumerate(self.tids)}
        self._cache: dict = {}

    # ---- scoring -------------------------------------------------------
    def _check(self, bid: str, task: OpenTask) -> dict:
        x = np.zeros((1, len(self.tids)))
        for t, c in task.counts.items():
            if t in self.col:
                x[0, self.col[t]] = c
        x = np.log1p(x)
        if_score, rf_p = self._score(x)
        votes = []
        if if_score > self.if_thr:
            votes.append("Isolation Forest")
        if rf_p is not None and rf_p >= 0.5:
            votes.append("Random Forest")
        if task.unknown and not votes:
            votes.append("New message type")  # something the models have never seen
        out = {"type": "task", "block": bid, "time": task.first_ts.isoformat(), "lines": task.n,
               "flagged": bool(votes), "detectors": votes, "if_score": round(if_score, 3),
               "rf_prob": None if rf_p is None else round(rf_p, 3)}
        if votes:
            st = plain.story(pd.Series(task.counts), self.stats, self.templates)
            out["headline"] = st["headline"] if not task.unknown else st["headline"] + " New kinds of message appeared."
            n_models = 1 + (self.rf_model is not None)
            agreed = len([v for v in votes if v != "New message type"])
            out["priority"] = "first" if (agreed == n_models and n_models == 2) or (n_models == 1 and agreed) else "check"
        return out

    def _score(self, x):
        """Most tasks look identical, so remember scores per count pattern (big speed-up)."""
        key = x.tobytes()
        hit = self._cache.get(key)
        if hit is None:
            if_score = float(-self.if_model.score_samples(x)[0])
            rf_p = None
            if self.rf_model is not None:
                classes = list(self.rf_model.classes_)
                rf_p = float(self.rf_model.predict_proba(x)[0, classes.index(1)]) if 1 in classes else 0.0
            hit = self._cache[key] = (if_score, rf_p)
            if len(self._cache) > 50_000:
                self._cache.clear()
        return hit

    def _close_idle(self, now: datetime):
        done = [b for b, t in self.open.items() if (now - t.last_ts).total_seconds() > self.idle]
        return [self._check(b, self.open.pop(b)) for b in done]

    # ---- replay ----------------------------------------------------------
    def events(self):
        """Yield ('line', dict) and ('task', dict) events in log-time order."""
        with open(self.log_path, "r", errors="replace") as f:
            for raw in f:
                p = parse_line(raw)
                if not p:
                    continue
                ts_s, level, comp, content = p
                ts = datetime.fromisoformat(ts_s)
                blocks = sorted(set(BLOCK_RE.findall(content)))
                if ts < self.start:
                    self.started_before.update(blocks)
                    continue
                blocks = [b for b in blocks if b not in self.started_before]
                if not blocks:
                    continue
                for ev in self._close_idle(ts):
                    yield ev
                cl = self.miner.match(content)
                tid = cl.cluster_id if cl else None
                for bid in blocks:
                    task = self.open.get(bid)
                    if task is None:
                        task = self.open[bid] = OpenTask(ts, ts)
                    task.last_ts, task.n = ts, task.n + 1
                    if tid is None:
                        task.unknown += 1
                    else:
                        task.counts[tid] = task.counts.get(tid, 0) + 1
                known = tid is not None
                yield {"type": "line", "time": ts_s, "level": level, "raw": raw.strip()[:220],
                       "plain": plain.friendly(self.templates[tid]) if known else "A new kind of message",
                       "problem": plain.is_problem(self.templates[tid]) if known else True, "block": blocks[0]}
        for bid in list(self.open):
            yield self._check(bid, self.open.pop(bid))
