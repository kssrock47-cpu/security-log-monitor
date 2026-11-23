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
    def __init__(self, bundle_path: str, log_path: str, start_ts: str, idle_secs: int = 60,
                 offset: int = 0, skip_blocks: set | None = None):
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
        # tasks already under way when replay starts are skipped (they belong to the training part)
        self.started_before: set[str] = set(skip_blocks or ())
        self.offset = offset
        self.rare = set(self.stats.index[self.stats["normal_share"] < 0.05])
        self.closed: set[str] = set()
        self.col = {t: i for i, t in enumerate(self.tids)}
        self._cache: dict = {}
        self.sweep = 10  # seconds of log time between checks
        self._plain = {t: plain.friendly(txt) for t, txt in self.templates.items()}
        self._last_sweep = None

    # ---- scoring -------------------------------------------------------
    def _vector(self, task: OpenTask):
        x = np.zeros(len(self.tids))
        for t, c in task.counts.items():
            if t in self.col:
                x[self.col[t]] = c
        return np.log1p(x)

    def _score_many(self, X):
        """Score many tasks in one call (per-call overhead dominates), reusing earlier results."""
        keys = [row.tobytes() for row in X]
        todo = [k for k in dict.fromkeys(keys) if k not in self._cache]
        if todo:
            idx = {k: i for i, k in enumerate(keys)}
            Xn = X[[idx[k] for k in todo]]
            if_s = -self.if_model.score_samples(Xn)
            rf_p = [None] * len(todo)
            if self.rf_model is not None:
                classes = list(self.rf_model.classes_)
                rf_p = self.rf_model.predict_proba(Xn)[:, classes.index(1)] if 1 in classes else np.zeros(len(todo))
            for k, a, b in zip(todo, if_s, rf_p):
                self._cache[k] = (float(a), None if b is None else float(b))
            if len(self._cache) > 200_000:
                self._cache.clear()
                for k, a, b in zip(todo, if_s, rf_p):
                    self._cache[k] = (float(a), None if b is None else float(b))
        return [self._cache[k] for k in keys]

    def _check_many(self, items):
        if not items:
            return []
        X = np.vstack([self._vector(t) for _, t in items])
        out = []
        for (bid, task), (if_score, rf_p) in zip(items, self._score_many(X)):
            votes = []
            if if_score > self.if_thr:
                votes.append("Isolation Forest")
            if rf_p is not None and rf_p >= 0.5:
                votes.append("Random Forest")
            if task.unknown and not votes:
                votes.append("New message type")  # something the models have never seen
            ev = {"type": "task", "block": bid, "time": task.first_ts.isoformat(), "lines": task.n,
                  "flagged": bool(votes), "detectors": votes, "if_score": round(if_score, 3),
                  "rf_prob": None if rf_p is None else round(rf_p, 3)}
            if votes:
                st = plain.story(pd.Series(task.counts, dtype=float), self.stats, self.templates)
                ev["headline"] = st["headline"] + (" New kinds of message appeared." if task.unknown else "")
                n_models = 1 + (self.rf_model is not None)
                agreed = len([v for v in votes if v != "New message type"])
                ev["priority"] = "first" if (n_models == 2 and agreed == 2) or (n_models == 1 and agreed) else "check"
            out.append(ev)
        return out

    def _close_idle(self, now: datetime):
        """Every `sweep` seconds of log time, check all tasks that have gone quiet, in one batch."""
        if self._last_sweep is not None and (now - self._last_sweep).total_seconds() < self.sweep:
            return []
        self._last_sweep = now
        done = [b for b, t in self.open.items() if (now - t.last_ts).total_seconds() > self.idle]
        self.closed.update(done)  # a task is judged once, when it goes quiet
        return self._check_many([(b, self.open.pop(b)) for b in done])

    # ---- replay ----------------------------------------------------------
    def events(self):
        """Yield ('line', dict) and ('task', dict) events in log-time order."""
        with open(self.log_path, "rb") as fb:
            fb.seek(self.offset)  # jump close to where the newer part starts
            for raw_b in fb:
                raw = raw_b.decode("utf-8", "replace")
                p = parse_line(raw)
                if not p:
                    continue
                ts_s, level, comp, content = p
                ts = datetime.fromisoformat(ts_s)
                blocks = sorted(set(BLOCK_RE.findall(content)))
                if ts < self.start:
                    self.started_before.update(blocks)
                    continue
                blocks = [b for b in blocks if b not in self.started_before and b not in self.closed]
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
                       "plain": self._plain.get(tid, "A new kind of message") if known else "A new kind of message",
                       "problem": (tid in self.rare) if known else True, "block": blocks[0]}
        for ev in self._check_many([(b, self.open.pop(b)) for b in list(self.open)]):
            yield ev
