"""The AI part of the live monitor: learn normal behaviour, flag what doesn't fit.

Events are grouped into short windows per "who" (an IP address, user or machine).
Each window becomes a row of numbers: how many lines, failures, successes, different
users, pages and ports, errors, plus how often each message type appeared.
An Isolation Forest learns from the first windows (the learning period), then scores
every new window. Anything far outside normal raises an alert, with the reason in plain words.
The model retrains now and then on recent windows it judged normal, so it keeps up.

Offline mode (for files you drop in): the AI first reads the whole file, learns what is normal
for that file, then judges every window in it, so short files are checked too.
"""
from collections import defaultdict
from datetime import datetime, timedelta

import numpy as np
from sklearn.ensemble import IsolationForest

HASH_DIM = 24
AGG = ["lines", "failures", "successes", "users", "pages", "ports", "not_found", "server_errors", "warnings"]
AGG_TEXT = {
    "lines": "wrote {v} log lines", "failures": "had {v} failed logins or refusals",
    "successes": "logged in successfully {v} times", "users": "used {v} different usernames",
    "pages": "asked for {v} different web pages", "ports": "touched {v} different network ports",
    "not_found": "got {v} 'not found' or 'forbidden' answers", "server_errors": "caused {v} server errors",
    "warnings": "produced {v} warnings or errors",
}


class _Win:
    __slots__ = ("n", "fail", "succ", "users", "paths", "ports", "h4", "h5", "warn", "tpl", "ids", "first")

    def __init__(self, first):
        self.n = self.fail = self.succ = self.h4 = self.h5 = self.warn = 0
        self.users, self.paths, self.ports = set(), set(), set()
        self.tpl = np.zeros(HASH_DIM)
        self.ids = []
        self.first = first

    def vector(self):
        agg = [self.n, self.fail, self.succ, len(self.users), len(self.paths), len(self.ports), self.h4, self.h5, self.warn]
        return np.log1p(np.concatenate([np.array(agg, float), self.tpl]))

    def raw(self):
        return dict(zip(AGG, [self.n, self.fail, self.succ, len(self.users), len(self.paths), len(self.ports),
                              self.h4, self.h5, self.warn]))


class WindowAI:
    OFFLINE_CAP = 150000  # windows kept in memory for offline mode; bigger files fall back to streaming

    def __init__(self, window_secs=30, learn_windows=120, quantile=0.995, retrain_every=400, learner=None, offline=False):
        self.ws = window_secs
        self.offline = offline
        self.held: list = []        # offline mode: every window, judged once the whole file is read
        self.learner = learner  # shared lessons from people's answers (learning.py); None = defaults only
        self.retrains = 0
        self.trained_on = 0
        self.learn_n = learn_windows
        self.q = quantile
        self.retrain_every = retrain_every
        self.open: dict = {}
        self.train: list = []       # vectors used to learn normal
        self.train_raw: list = []
        self.recent_ok: list = []
        self.model = None
        self.threshold = None
        self.baseline = None        # per-feature typical (median) and high (99th pct) values
        self.seen_since_train = 0
        self.tpl_seen = defaultdict(int)

    @property
    def learning(self):
        return self.model is None

    @property
    def progress(self):
        if self.model is not None:
            return 1.0
        return min(0.95, len(self.held) / 2000) if self.offline else min(1.0, len(self.train) / self.learn_n)

    def _key(self, ent, ts):
        start = int(ts.timestamp()) // self.ws * self.ws
        return ent, start

    def add(self, ev: dict, ent: str, template_id: int, event_id: int):
        k = self._key(ent, ev["ts"])
        w = self.open.get(k)
        if w is None:
            w = self.open[k] = _Win(ev["ts"])
        w.n += 1
        w.fail += ev.get("outcome") == "fail"
        w.succ += ev.get("outcome") == "success"
        if ev.get("user"):
            w.users.add(ev["user"])
        if ev.get("path"):
            w.paths.add(ev["path"].split("?")[0])
        if ev.get("port"):
            w.ports.add(ev["port"])
        st = ev.get("status") or 0
        w.h4 += 400 <= st < 500
        w.h5 += st >= 500
        w.warn += (ev.get("level") or "") in ("warning", "warn", "error", "err", "crit", "critical", "fatal", "alert")
        w.tpl[template_id % HASH_DIM] += 1
        if len(w.ids) < 60:
            w.ids.append(event_id)

    def close(self, watermark: datetime, grace=5):
        """Score every window that ended before the watermark. Returns list of results."""
        cutoff = int(watermark.timestamp()) - grace
        done = [k for k in self.open if k[1] + self.ws <= cutoff]
        return self._judge([(k, self.open.pop(k)) for k in done])

    def flush(self):
        return self._judge(list(self.open.items()), final=True) + ([] if self.open.clear() else [])

    def _judge(self, items, final=False):
        if self.offline and self.model is None:
            self.held.extend(items)
            if not final and len(self.held) < self.OFFLINE_CAP:
                return []
            items, self.held = self.held, []
            if len(items) < 20:
                return []  # too little to learn anything from
            X = np.vstack([w.vector() for _, w in items])
            self.train = list(X)
            self.train_raw = [w.raw() for _, w in items]
            self._fit(X)
            self.offline = False  # anything after this (a very big file) is judged as it streams
            return self._score(items, X)
        out = []
        if not items:
            return out
        X = np.vstack([w.vector() for _, w in items])
        if self.model is None:
            self.train.extend(X)
            self.train_raw.extend(w.raw() for _, w in items)
            if len(self.train) >= self.learn_n or (final and len(self.train) >= 20):
                self._fit(np.vstack(self.train))
            if self.model is None:
                return out
            # windows that completed the learning set are not judged
            return out
        return self._score(items, X)

    def _score(self, items, X):
        out = []
        scores = -self.model.score_samples(X)
        L = self.learner
        for (k, w), x, s in zip(items, X, scores):
            reasons = self._reasons(w)

            # Two learned checks must agree with common sense before an alert:
            #  1) far beyond the normal range of a number (Isolation Forest can't score past what it has seen)
            #  2) the forest finds the overall mix unusual AND at least one number is clearly above normal
            # How far is "far" is adjusted by what people taught it (learning.py).
            def decide(default):
                if L is None:
                    far = [r for r in reasons if r[0] >= 3 and r[2] >= r[3] + 5]
                    mix = s > self.threshold and any(r[2] >= r[3] + 3 for r in reasons)
                else:
                    far = [r for r in reasons if L.far(r[4], r[2], r[3], default)]
                    mix = s > self.threshold + L.thr_shift(default) and any(L.mix_ok(r[4], r[2], r[3], default) for r in reasons)
                return bool(far or mix), bool(far)

            flagged, far = decide(False)
            base, _ = decide(True)
            if L is not None and base and not flagged:
                L.count("avoided")  # would have alerted, but people taught it this is normal
            if not flagged:
                self.recent_ok.append(x)
                continue
            learned = L is not None and not base
            if learned:
                L.count("caught")
            out.append({"entity": k[0], "start": datetime.fromtimestamp(k[1]), "score": float(s),
                        "threshold": float(self.threshold), "why": [r[1] for r in reasons[:3]], "ids": w.ids,
                        "raw": w.raw(), "far": far, "strength": max([r[0] for r in reasons] or [1]),
                        "features": [r[4] for r in reasons[:3]], "learned": learned})
        self.seen_since_train += len(items)
        if self.seen_since_train >= self.retrain_every and len(self.recent_ok) >= 50:
            keep = np.vstack(self.recent_ok[-3000:])
            self._fit(np.vstack([np.vstack(self.train[-1000:]), keep]), refresh=True)
            self.recent_ok = self.recent_ok[-1000:]
        return out

    def _fit(self, X, refresh=False):
        m = IsolationForest(n_estimators=150, random_state=0, contamination="auto")
        m.fit(X)
        s = -m.score_samples(X)
        # alert line: a little above the most unusual normal windows seen while learning
        self.threshold = float(np.quantile(s, self.q) + 0.02)
        self.model = m
        self.trained_on = len(X)
        if refresh:
            self.retrains += 1
        if not refresh:
            raw = np.array([[r[a] for a in AGG] for r in self.train_raw], float)
            self.baseline = {a: (float(np.median(raw[:, i])), float(np.quantile(raw[:, i], 0.99)))
                             for i, a in enumerate(AGG)}
        self.seen_since_train = 0

    def _reasons(self, w: _Win):
        """Which numbers are clearly above normal: (how many times the normal maximum, text, value, normal max)."""
        if not self.baseline:
            return []
        r = w.raw()
        out = []
        for a in AGG:
            med, hi = self.baseline[a]
            v = r[a]
            if v > max(hi, 1) and v >= 2 * max(med, 0.5):
                usual = "never" if hi == 0 else f"normally at most {int(round(hi))}"
                out.append((v / max(hi, 1), AGG_TEXT[a].format(v=v) + f" ({usual})", v, hi, a))
        out.sort(key=lambda t: -t[0])
        return out

    def current_features(self, ent):
        """Which numbers are already above normal for this address or user right now (for teaching)."""
        feats = []
        for (e, _), w in self.open.items():
            if e == ent:
                feats += [r[4] for r in self._reasons(w)]
        return list(dict.fromkeys(feats))[:3]
