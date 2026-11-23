"""The AI learns from you.

Every time a person marks a threat "real" or "false alarm", that answer is a reward signal:
  * real threat  -> the AI becomes more watchful of the behaviour that made it suspicious
                    (lower alert line for those numbers, slightly lower overall line)
  * false alarm  -> the AI becomes calmer about that behaviour, and a known-pattern alert
                    for that same address and pattern is not raised again
This is a small reinforcement loop: the sensitivities are the policy, your answers are the reward.
Everything it learns is kept in the database, so it survives restarts, and is shared by all connections.
"""
import json
from copy import deepcopy

from .ai import AGG

DEFAULT = {"ratio": 3.0, "margin": 5.0, "mix": 3.0}
LIMITS = {"ratio": (1.4, 8.0), "margin": (2.0, 20.0), "mix": (1.0, 12.0)}

NAMES = {
    "lines": "lots of log lines", "failures": "failed logins", "successes": "lots of successful logins",
    "users": "many different usernames", "pages": "grabbing many different web pages",
    "ports": "knocking on many network ports", "not_found": "'not found' answers",
    "server_errors": "server errors", "warnings": "warnings and errors",
}


def _clip(k, v):
    lo, hi = LIMITS[k]
    return max(lo, min(hi, v))


class Learner:
    def __init__(self, state: dict | None = None):
        self.state = self._fresh()
        if state:
            self.state.update(state)
            for f in AGG:
                self.state["sens"].setdefault(f, dict(DEFAULT))

    @staticmethod
    def _fresh():
        return {"sens": {f: dict(DEFAULT) for f in AGG}, "thr_shift": 0.0, "muted": [],
                "stats": {"lessons": 0, "real": 0, "false": 0, "caught": 0, "avoided": 0}}

    # ---- used by the detectors ------------------------------------------------------
    def params(self, f, default=False):
        return DEFAULT if default else self.state["sens"][f]

    def far(self, f, v, hi, default=False):
        p = self.params(f, default)
        return v / max(hi, 1) >= p["ratio"] and v >= hi + p["margin"]

    def mix_ok(self, f, v, hi, default=False):
        return v >= hi + self.params(f, default)["mix"]

    def thr_shift(self, default=False):
        return 0.0 if default else self.state["thr_shift"]

    def muted(self, rule, entity):
        return [rule, entity] in self.state["muted"]

    def count(self, key, n=1):
        self.state["stats"][key] += n

    # ---- learning from a person's answer ---------------------------------------------------
    def learn(self, label: str, kind: str, rule: str, entity: str, features: list, title: str) -> list:
        """Update the policy from one answer. Returns plain-language lessons."""
        st, lessons = self.state, []
        feats = [f for f in (features or []) if f in AGG]
        if label == "real":
            st["stats"]["real"] += 1
            for f in feats:
                p = st["sens"][f]
                p["ratio"] = _clip("ratio", p["ratio"] * 0.55)
                p["margin"] = _clip("margin", p["margin"] - 2.5)
                p["mix"] = _clip("mix", p["mix"] - 1.5)
                lessons.append(f"Watching for {NAMES[f]} more closely.")
            st["thr_shift"] = max(-0.06, st["thr_shift"] - 0.01)
            if not feats:
                lessons.append(f"Noted that '{title}' was a real threat.")
        elif label == "false":
            st["stats"]["false"] += 1
            for f in feats:
                p = st["sens"][f]
                p["ratio"] = _clip("ratio", p["ratio"] * 1.25)
                p["margin"] = _clip("margin", p["margin"] + 2)
                p["mix"] = _clip("mix", p["mix"] + 1)
                lessons.append(f"Calmer about {NAMES[f]}.")
            st["thr_shift"] = min(0.08, st["thr_shift"] + 0.015)
            if kind == "pattern" and [rule, entity] not in st["muted"]:
                st["muted"].append([rule, entity])
                lessons.append(f"Won't raise '{title}' for {entity} again.")
        st["stats"]["lessons"] += len(lessons)
        return lessons

    def reset(self):
        self.state = self._fresh()

    def dump(self):
        return json.dumps(self.state)

    def view(self):
        """For the dashboard: how watchful the AI is about each behaviour (0 = calmest, 1 = most watchful)."""
        out = []
        for f in AGG:
            p = self.state["sens"][f]
            lo, hi = LIMITS["ratio"]
            watch = 1 - (p["ratio"] - lo) / (hi - lo)
            base = 1 - (DEFAULT["ratio"] - lo) / (hi - lo)
            out.append({"feature": f, "name": NAMES[f], "watch": round(watch, 3), "default": round(base, 3),
                        "ratio": round(p["ratio"], 2), "margin": round(p["margin"], 1)})
        return {"features": out, "thr_shift": round(self.state["thr_shift"], 3), "muted": deepcopy(self.state["muted"]),
                "stats": dict(self.state["stats"])}
