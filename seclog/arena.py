"""Algorithm arena: many machine-learning algorithms fight on the same data, with settings you can change.

Every contender learns from the same older tasks and is tested on the same newer ones (time-ordered split),
so the numbers are comparable. A contender is one algorithm plus its settings (parameters). You can:

  * add any algorithm from the catalogue below and set its parameters,
  * change the parameters of an existing contender, copy it or delete it,
  * run a fight between any contenders and compare how each performs,
  * let the AI search for the best parameters ("AI tuning"). It tries settings on a validation slice
    of the OLDER tasks only, keeps the best, and tests that once on the newer tasks, so the test set
    never leaks into the choice.

Data: HDFS_v1 features (how often each message type appears in each storage task) from
data/research/hdfs_features.npz, which comes with the project, or the current research run.

    python -m seclog.arena build-features      # make hdfs_features.npz from a full HDFS_v1 run (data/seclog.db)
    python -m seclog.arena fight               # run every contender once and print the leaderboard
"""
import argparse
import copy
import hashlib
import json
import os
import random
import sqlite3
import threading
import time
import uuid
from contextlib import closing

import numpy as np
from sklearn.decomposition import PCA
from sklearn.ensemble import (AdaBoostClassifier, ExtraTreesClassifier, HistGradientBoostingClassifier,
                              IsolationForest, RandomForestClassifier)
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, f1_score, precision_recall_curve, precision_score,
                             recall_score, roc_auc_score)
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier, LocalOutlierFactor
from sklearn.neural_network import MLPClassifier, MLPRegressor
from sklearn.svm import LinearSVC, OneClassSVM
from sklearn.tree import DecisionTreeClassifier

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(HERE, "data")
FEATURES = os.path.join(DATA, "research", "hdfs_features.npz")
ARENA_DIR = os.path.join(DATA, "arena")
SEED = 42

FAMILIES = {
    "supervised": ("Learns from examples", "Needs past tasks marked normal or problem (an answer key)."),
    "unsupervised": ("Learns normal only", "Needs no answer key: it learns what the older tasks look like and flags anything unusual."),
    "deep": ("Deep learning (neural networks)", "Layers of artificial neurons. One learns from examples; the autoencoder learns normal only."),
}


# ---------------------------------------------------------------- parameters
def P(name, label, kind, default, help="", lo=None, hi=None, choices=None, tune=None, log=False):
    """One setting of an algorithm. `tune` is the range the AI searches (defaults to lo..hi or choices)."""
    return {"name": name, "label": label, "type": kind, "default": default, "help": help, "min": lo, "max": hi,
            "choices": choices, "tune": tune, "log": log}


THRESH = P("threshold", "Alert when the chance of a problem is at least", "float", 0.5,
           "Lower catches more problems but raises more false alarms.", 0.05, 0.95, tune=[0.2, 0.8])
TOP = P("alert_top_pct", "Alert on the most unusual % of older tasks", "float", 3.0,
        "The alert line: anything more unusual than this share of the older tasks raises an alert.", 0.1, 20.0,
        tune=[0.5, 10.0], log=True)


def SAMPLE(default, help="Learn from a random sample of this many older tasks (0 = all). Slow algorithms need fewer."):
    return P("max_train", "Learn from at most this many tasks", "int", default, help, 0, 1_000_000)


def layers(s):
    out = tuple(int(x) for x in str(s).replace(" ", "").split(",") if x)
    if not out or any(n < 1 or n > 1024 for n in out) or len(out) > 6:
        raise ValueError("Layers must be 1 to 6 numbers between 1 and 1024, for example 64,32")
    return out


CATALOG = {
    # ---------------- learns from examples
    "logreg": {
        "name": "Logistic Regression", "family": "supervised",
        "plain": "Gives each message type a weight and adds them up into a chance of a problem.",
        "params": [P("C", "Regularisation strength C", "float", 1.0, "Smaller C keeps the weights small and simple.", 0.001, 1000.0, tune=[0.01, 100.0], log=True),
                   P("class_weight", "Balance rare problems", "choice", "balanced", "Count each rare problem task as more important.", choices=["balanced", "none"]),
                   P("max_iter", "Max training rounds", "int", 2000, "", 100, 20000), THRESH]},
    "tree": {
        "name": "Decision Tree", "family": "supervised",
        "plain": "A chain of yes/no questions about the counts, like a flowchart.",
        "params": [P("max_depth", "Max depth (0 = no limit)", "int", 0, "How many questions in a row it may ask.", 0, 100, tune=[0, 30]),
                   P("min_samples_leaf", "Min tasks per answer", "int", 1, "Bigger values make it less likely to memorise noise.", 1, 1000, tune=[1, 50], log=True),
                   P("criterion", "Split rule", "choice", "gini", "How it picks the best question.", choices=["gini", "entropy"]),
                   P("class_weight", "Balance rare problems", "choice", "balanced", "", choices=["balanced", "none"]), THRESH]},
    "forest": {
        "name": "Random Forest", "family": "supervised",
        "plain": "Many decision trees, each trained on a random part of the data, vote.",
        "params": [P("n_estimators", "Number of trees", "int", 200, "More trees are steadier but slower.", 10, 1000, tune=[50, 400]),
                   P("max_depth", "Max depth (0 = no limit)", "int", 0, "", 0, 100, tune=[0, 40]),
                   P("min_samples_leaf", "Min tasks per answer", "int", 1, "", 1, 1000, tune=[1, 20], log=True),
                   P("max_features", "Message types each question may use", "choice", "sqrt", "", choices=["sqrt", "log2", "all"]),
                   P("class_weight", "Balance rare problems", "choice", "balanced", "", choices=["balanced", "none"]), THRESH]},
    "extratrees": {
        "name": "Extra Trees", "family": "supervised",
        "plain": "Like a random forest, but each tree picks its questions more randomly, so it trains faster.",
        "params": [P("n_estimators", "Number of trees", "int", 200, "", 10, 1000, tune=[50, 400]),
                   P("max_depth", "Max depth (0 = no limit)", "int", 0, "", 0, 100, tune=[0, 40]),
                   P("min_samples_leaf", "Min tasks per answer", "int", 1, "", 1, 1000, tune=[1, 20], log=True),
                   P("class_weight", "Balance rare problems", "choice", "balanced", "", choices=["balanced", "none"]), THRESH]},
    "hgb": {
        "name": "Gradient Boosting", "family": "supervised",
        "plain": "Builds small trees one after another, each fixing the mistakes of the ones before.",
        "params": [P("learning_rate", "Learning rate", "float", 0.1, "How big a step each new tree takes.", 0.001, 1.0, tune=[0.02, 0.5], log=True),
                   P("max_iter", "Number of trees", "int", 200, "", 10, 2000, tune=[50, 500]),
                   P("max_depth", "Max depth (0 = no limit)", "int", 0, "", 0, 50, tune=[0, 12]),
                   P("class_weight", "Balance rare problems", "choice", "balanced", "", choices=["balanced", "none"]), THRESH]},
    "linsvm": {
        "name": "Linear SVM", "family": "supervised",
        "plain": "Draws the widest possible line between normal and problem tasks.",
        "params": [P("C", "Regularisation strength C", "float", 1.0, "Smaller C allows a wider, simpler line.", 0.001, 1000.0, tune=[0.01, 100.0], log=True),
                   P("class_weight", "Balance rare problems", "choice", "balanced", "", choices=["balanced", "none"]),
                   P("max_iter", "Max training rounds", "int", 5000, "", 100, 50000)]},
    "knn": {
        "name": "k-Nearest Neighbours", "family": "supervised",
        "plain": "Looks up the most similar past tasks and copies their answer.",
        "params": [P("n_neighbors", "Neighbours to ask (k)", "int", 5, "", 1, 200, tune=[1, 50], log=True),
                   P("weights", "Closer neighbours count more", "choice", "distance", "", choices=["uniform", "distance"]),
                   SAMPLE(20000), THRESH]},
    "nbayes": {
        "name": "Naive Bayes", "family": "supervised",
        "plain": "Uses simple probability: how likely are these counts for normal tasks versus problem tasks.",
        "params": [P("var_smoothing", "Smoothing", "float", 1e-9, "Adds a little spread so unseen counts don't break it.", 1e-12, 1.0, tune=[1e-11, 1e-2], log=True), THRESH]},
    "adaboost": {
        "name": "AdaBoost", "family": "supervised",
        "plain": "Many one-question trees; each new one focuses on the tasks the others got wrong.",
        "params": [P("n_estimators", "Number of rounds", "int", 100, "", 10, 1000, tune=[25, 400], log=True),
                   P("learning_rate", "Learning rate", "float", 1.0, "", 0.01, 5.0, tune=[0.05, 2.0], log=True), THRESH]},
    # ---------------- learns normal only
    "iforest": {
        "name": "Isolation Forest", "family": "unsupervised",
        "plain": "Unusual tasks are easier to separate from the rest with random cuts.",
        "params": [P("n_estimators", "Number of trees", "int", 200, "", 10, 1000, tune=[50, 400]),
                   P("max_samples", "Tasks per tree (0 = auto, 256)", "int", 0, "", 0, 100000, tune=[64, 4096], log=True),
                   P("max_features", "Share of message types per tree", "float", 1.0, "", 0.1, 1.0, tune=[0.3, 1.0]), TOP]},
    "pca": {
        "name": "PCA", "family": "unsupervised",
        "plain": "Normal tasks follow a few main patterns; problems don't fit them.",
        "params": [P("variance", "Share of variation the main patterns keep", "float", 0.95, "", 0.5, 0.999, tune=[0.8, 0.99]), TOP]},
    "ocsvm": {
        "name": "One-Class SVM", "family": "unsupervised",
        "plain": "Draws a boundary around normal tasks; anything outside is unusual.",
        "params": [P("nu", "Share allowed outside the boundary (nu)", "float", 0.03, "", 0.001, 0.5, tune=[0.005, 0.2], log=True),
                   P("kernel", "Boundary shape", "choice", "rbf", "", choices=["rbf", "linear", "sigmoid"]),
                   P("gamma", "Boundary flexibility", "choice", "scale", "", choices=["scale", "auto"]),
                   SAMPLE(20000), TOP]},
    "lof": {
        "name": "Local Outlier Factor", "family": "unsupervised",
        "plain": "Problem tasks sit in sparse areas, far from their neighbours.",
        "params": [P("n_neighbors", "Neighbours to compare with", "int", 20, "", 2, 500, tune=[5, 100], log=True),
                   SAMPLE(20000), TOP]},
    # ---------------- deep learning
    "mlp": {
        "name": "Neural Network", "family": "deep", "learns": "supervised",
        "plain": "Layers of artificial neurons learn from tasks marked normal or problem (a multi-layer perceptron).",
        "params": [P("hidden_layers", "Neurons per layer", "layers", "64,32", "Comma-separated, one number per hidden layer.", tune=["32", "64", "64,32", "128,64", "128,64,32"]),
                   P("activation", "Activation", "choice", "relu", "", choices=["relu", "tanh", "logistic"]),
                   P("alpha", "Weight penalty (alpha)", "float", 1e-4, "Stops the network memorising noise.", 1e-7, 1.0, tune=[1e-6, 1e-2], log=True),
                   P("learning_rate_init", "Learning rate", "float", 1e-3, "", 1e-5, 0.5, tune=[1e-4, 1e-2], log=True),
                   P("max_iter", "Max passes over the data (epochs)", "int", 30, "", 5, 500, tune=[10, 60]),
                   SAMPLE(0), THRESH]},
    "autoencoder": {
        "name": "Autoencoder", "family": "deep", "learns": "unsupervised",
        "plain": "A neural network learns to squeeze each task through a narrow middle and rebuild it; tasks it rebuilds badly are unusual.",
        "params": [P("hidden_layers", "Neurons per layer", "layers", "32,8,32", "Narrow in the middle, e.g. 32,8,32.", tune=["16,4,16", "32,8,32", "64,16,64", "32,16,8,16,32"]),
                   P("activation", "Activation", "choice", "relu", "", choices=["relu", "tanh", "logistic"]),
                   P("alpha", "Weight penalty (alpha)", "float", 1e-4, "", 1e-7, 1.0, tune=[1e-6, 1e-2], log=True),
                   P("max_iter", "Max passes over the data (epochs)", "int", 50, "", 5, 500, tune=[20, 120]),
                   SAMPLE(50000), TOP]},
}

# The starting line-up: the eight of the standard benchmark (as in seclog.compare) plus three more and the two neural networks
DEFAULT_LINEUP = ["forest", "tree", "linsvm", "logreg", "hgb", "mlp", "pca", "iforest", "autoencoder", "ocsvm", "lof"]
DETECTORS = {"forest": "Detector B", "iforest": "Detector A"}


def kind(algo):
    a = CATALOG[algo]
    return a.get("learns", a["family"])


def resolve(algo, params=None):
    """Full, checked settings: defaults filled in, numbers kept in range, choices checked."""
    if algo not in CATALOG:
        raise ValueError(f"Unknown algorithm: {algo}")
    params = params or {}
    out = {}
    for p in CATALOG[algo]["params"]:
        v = params.get(p["name"], p["default"])
        try:
            if p["type"] == "int":
                v = int(round(float(v)))
            elif p["type"] == "float":
                v = float(v)
            elif p["type"] == "choice":
                v = str(v)
                if v not in p["choices"]:
                    raise ValueError
            elif p["type"] == "layers":
                v = ",".join(str(n) for n in layers(v))
        except (TypeError, ValueError):
            raise ValueError(f"{p['label']}: '{params.get(p['name'])}' is not a valid value")
        if p["min"] is not None and v < p["min"]:
            v = p["min"]
        if p["max"] is not None and v > p["max"]:
            v = p["max"]
        out[p["name"]] = v
    return out


def phash(algo, params):
    return hashlib.sha1(json.dumps([algo, resolve(algo, params)], sort_keys=True).encode()).hexdigest()[:10]


# ---------------------------------------------------------------- models
def _cw(v):
    return None if v == "none" else v


def build(algo, p, n_rows):
    """The scikit-learn model for these settings."""
    if algo == "logreg":
        return LogisticRegression(C=p["C"], class_weight=_cw(p["class_weight"]), max_iter=p["max_iter"])
    if algo == "tree":
        return DecisionTreeClassifier(max_depth=p["max_depth"] or None, min_samples_leaf=p["min_samples_leaf"],
                                      criterion=p["criterion"], class_weight=_cw(p["class_weight"]), random_state=SEED)
    if algo == "forest":
        return RandomForestClassifier(n_estimators=p["n_estimators"], max_depth=p["max_depth"] or None,
                                      min_samples_leaf=p["min_samples_leaf"],
                                      max_features=None if p["max_features"] == "all" else p["max_features"],
                                      class_weight=_cw(p["class_weight"]), random_state=SEED, n_jobs=-1)
    if algo == "extratrees":
        return ExtraTreesClassifier(n_estimators=p["n_estimators"], max_depth=p["max_depth"] or None,
                                    min_samples_leaf=p["min_samples_leaf"], class_weight=_cw(p["class_weight"]),
                                    random_state=SEED, n_jobs=-1)
    if algo == "hgb":
        return HistGradientBoostingClassifier(learning_rate=p["learning_rate"], max_iter=p["max_iter"],
                                              max_depth=p["max_depth"] or None, class_weight=_cw(p["class_weight"]),
                                              random_state=SEED)
    if algo == "linsvm":
        return LinearSVC(C=p["C"], class_weight=_cw(p["class_weight"]), max_iter=p["max_iter"], random_state=SEED)
    if algo == "knn":
        return KNeighborsClassifier(n_neighbors=p["n_neighbors"], weights=p["weights"], n_jobs=-1)
    if algo == "nbayes":
        return GaussianNB(var_smoothing=p["var_smoothing"])
    if algo == "adaboost":
        return AdaBoostClassifier(n_estimators=p["n_estimators"], learning_rate=p["learning_rate"], random_state=SEED)
    if algo == "mlp":
        return MLPClassifier(hidden_layer_sizes=layers(p["hidden_layers"]), activation=p["activation"], alpha=p["alpha"],
                             learning_rate_init=p["learning_rate_init"], max_iter=p["max_iter"], early_stopping=True,
                             n_iter_no_change=5, random_state=SEED)
    if algo == "iforest":
        return IsolationForest(n_estimators=p["n_estimators"], max_samples=p["max_samples"] or "auto",
                               max_features=p["max_features"], random_state=SEED, n_jobs=-1)
    if algo == "ocsvm":
        return OneClassSVM(nu=p["nu"], kernel=p["kernel"], gamma=p["gamma"])
    if algo == "lof":
        return LocalOutlierFactor(n_neighbors=min(p["n_neighbors"], max(1, n_rows - 1)), novelty=True)
    if algo == "autoencoder":
        return MLPRegressor(hidden_layer_sizes=layers(p["hidden_layers"]), activation=p["activation"], alpha=p["alpha"],
                            max_iter=p["max_iter"], early_stopping=True, n_iter_no_change=5, random_state=SEED)
    raise ValueError(algo)


class _PCA:
    """PCA anomaly score: the squared error of what the main patterns cannot explain."""
    def __init__(self, variance):
        self.variance = variance

    def fit(self, X):
        self.mu = X.mean(axis=0)
        self.m = PCA(n_components=self.variance, svd_solver="full", random_state=SEED).fit(X - self.mu)
        return self

    def score(self, X):
        Z = X - self.mu
        return ((Z - self.m.inverse_transform(self.m.transform(Z))) ** 2).sum(axis=1)


def _sample(idx, n, seed=SEED):
    if not n or n >= len(idx):
        return idx
    return np.sort(np.random.default_rng(seed).choice(idx, size=n, replace=False))


def fit_score(algo, p, X, y, fit_idx, eval_idx):
    """Train on fit_idx and return (score on the train sample, score on eval_idx, extra info, train s, check s).
    Higher score = more likely a problem. Unsupervised models never see y."""
    learns = kind(algo)
    fit_idx = _sample(fit_idx, p.get("max_train", 0))
    info = {"n_fit": int(len(fit_idx))}
    t0 = time.time()
    if learns == "supervised":
        if len(np.unique(y[fit_idx])) < 2:
            raise ValueError("The training tasks contain only one kind (no problems or no normal ones).")
        m = build(algo, p, len(fit_idx)).fit(X[fit_idx], y[fit_idx])
        t1 = time.time()
        if hasattr(m, "predict_proba"):
            s = m.predict_proba(X[eval_idx])[:, list(m.classes_).index(1)]
        else:
            s = m.decision_function(X[eval_idx])
        if algo == "mlp":
            info["epochs"] = int(m.n_iter_)
        return None, s, info, t1 - t0, time.time() - t1
    if algo == "pca":
        m = _PCA(p["variance"]).fit(X[fit_idx])
        t1 = time.time()
        info["main_patterns"] = int(m.m.n_components_)
        return m.score(X[fit_idx]), m.score(X[eval_idx]), info, t1 - t0, time.time() - t1
    if algo == "autoencoder":
        m = build(algo, p, len(fit_idx)).fit(X[fit_idx], X[fit_idx])
        t1 = time.time()
        err = lambda A: ((m.predict(A) - A) ** 2).mean(axis=1)
        info["epochs"] = int(m.n_iter_)
        return err(X[fit_idx]), err(X[eval_idx]), info, t1 - t0, time.time() - t1
    m = build(algo, p, len(fit_idx)).fit(X[fit_idx])
    t1 = time.time()
    s_fit = -m.negative_outlier_factor_ if algo == "lof" else -m.score_samples(X[fit_idx])
    return s_fit, -m.score_samples(X[eval_idx]), info, t1 - t0, time.time() - t1


def flags_for(algo, p, s_fit, s_eval):
    """Which tasks raise an alert, and the alert line used."""
    if kind(algo) == "supervised":
        line = 0.0 if algo == "linsvm" else p["threshold"]
        return (s_eval > line) if algo == "linsvm" else (s_eval >= line), line
    line = float(np.quantile(s_fit, 1 - p["alert_top_pct"] / 100.0))
    return s_eval > line, line


def metrics(y, flags, score):
    real = int(y.sum())
    out = {"precision": float(precision_score(y, flags, zero_division=0)),
           "recall": float(recall_score(y, flags, zero_division=0)),
           "f1": float(f1_score(y, flags, zero_division=0)),
           "caught": int((flags & (y == 1)).sum()), "real": real, "missed": int(((~flags) & (y == 1)).sum()),
           "false_alarms": int((flags & (y == 0)).sum()), "quiet": int(((~flags) & (y == 0)).sum()),
           "raised": int(flags.sum()), "n": int(len(y))}
    if 0 < real < len(y):
        out["pr_auc"] = float(average_precision_score(y, score))
        out["roc_auc"] = float(roc_auc_score(y, score))
    return out


def pr_curve(y, score, points=60):
    """A small precision-recall curve for charts: up to `points` (recall, precision) pairs."""
    if y.sum() == 0 or y.sum() == len(y):
        return []
    p, r, _ = precision_recall_curve(y, score)
    keep = np.unique(np.linspace(0, len(r) - 1, min(points, len(r))).astype(int))
    return [[round(float(r[i]), 4), round(float(p[i]), 4)] for i in keep]


# ---------------------------------------------------------------- data
_DATA: dict = {}


def build_features(db=os.path.join(DATA, "seclog.db"), out=FEATURES, progress=print):
    """Save the task x message-type counts of a full HDFS_v1 run as a small file that ships with the project."""
    from . import compare
    with closing(sqlite3.connect(db)) as con:
        n_blocks = con.execute("select count(*) from blocks").fetchone()[0]
        n_events = con.execute("select count(*) from log_events").fetchone()[0]
        m = dict(con.execute("select key, value from meta").fetchall())
    if m.get("labelled") != "1":
        raise SystemExit("This run has no answer key (anomaly_label.csv), so the arena can't score it.")
    if n_events < n_blocks * 5:
        raise SystemExit(f"{db} keeps the log lines of only some tasks ({n_events:,} lines for {n_blocks:,} tasks). "
                         "It is the small saved snapshot, not a full run. Run the full HDFS_v1 check first "
                         "(python -m seclog.pipeline --log HDFS.log --labels anomaly_label.csv).")
    X, y, tr, te = compare.load(db, progress)
    counts = np.rint(np.expm1(X)).clip(0, 65535).astype(np.uint16)
    is_train = np.zeros(len(y), dtype=bool)
    is_train[tr] = True
    os.makedirs(os.path.dirname(out), exist_ok=True)
    np.savez_compressed(out, counts=counts, y=y.astype(np.uint8), is_train=is_train,
                        source=np.array(m.get("source", "HDFS.log")), demo=np.array(m.get("demo", "0")),
                        run_at=np.array(m.get("run_at", "")), n_lines=np.array(m.get("n_lines", "")))
    progress(f"  saved {out} ({os.path.getsize(out) / 1e6:.1f} MB): {len(y):,} tasks x {counts.shape[1]} message types")
    return out


def datasets():
    """The datasets the arena can use right now."""
    out = []
    if os.path.exists(FEATURES):
        try:
            with np.load(FEATURES) as z:
                n, k, real = int(len(z["y"])), int(z["counts"].shape[1]), int(z["y"].sum())
            out.append({"id": "hdfs", "name": "HDFS_v1 (real logs, official answer key)", "tasks": n, "types": k,
                        "problems": real, "demo": False})
        except Exception:
            pass
    db = os.path.join(DATA, "seclog.db")
    try:
        with closing(sqlite3.connect(db)) as con:
            m = dict(con.execute("select key, value from meta").fetchall())
            n = con.execute("select count(*) from blocks").fetchone()[0]
            ev = con.execute("select count(*) from log_events").fetchone()[0]
            real = con.execute("select count(*) from blocks where label='Anomaly'").fetchone()[0]
        if m.get("labelled") == "1" and ev >= n * 5:
            demo = m.get("demo") == "1"
            out.append({"id": "current", "name": f"Current research run: {m.get('source', '')}" +
                        (" (made-up demo logs)" if demo else ""), "tasks": n, "types": None, "problems": real, "demo": demo,
                        "run_at": m.get("run_at")})
    except Exception:
        pass
    return out


def load(ds):
    """(X, y, train index, test index) for a dataset, cached in memory."""
    if ds == "hdfs":
        key = ("hdfs", os.path.getmtime(FEATURES))
        if _DATA.get("key") != key:
            with np.load(FEATURES) as z:
                X = np.log1p(z["counts"].astype(np.float32))
                y = z["y"].astype(int)
                tr = np.where(z["is_train"])[0]
                te = np.where(~z["is_train"])[0]
            _DATA.clear()
            _DATA.update(key=key, v=(X, y, tr, te))
        return _DATA["v"]
    if ds == "current":
        from . import compare
        db = os.path.join(DATA, "seclog.db")
        with closing(sqlite3.connect(db)) as con:
            run_at = dict(con.execute("select key, value from meta").fetchall()).get("run_at")
        key = ("current", run_at)
        if _DATA.get("key") != key:
            v = compare.load(db, progress=lambda *_: None)
            _DATA.clear()
            _DATA.update(key=key, v=v)
        return _DATA["v"]
    raise ValueError(f"Unknown dataset: {ds}")


# ---------------------------------------------------------------- one run
def run_one(algo, params, ds, keep_curve=True):
    """Train on the older tasks, test on the newer ones; everything the arena shows about the result."""
    p = resolve(algo, params)
    X, y, tr, te = load(ds)
    s_fit, s_te, info, t_fit, t_chk = fit_score(algo, p, X, y, tr, te)
    flags, line = flags_for(algo, p, s_fit, s_te)
    out = {"algo": algo, "params": p, "dataset": ds, "n_train": int(len(tr)), "n_test": int(len(te)),
           "train_seconds": round(t_fit, 2), "check_seconds": round(t_chk, 2), "alert_line": round(float(line), 6),
           "info": info, "run_at": time.strftime("%Y-%m-%dT%H:%M:%S"), **metrics(y[te], flags, s_te)}
    if keep_curve:
        out["curve"] = pr_curve(y[te], s_te)
    return out


# ---------------------------------------------------------------- AI tuning
def _draw(p, rng):
    t = p["tune"]
    if p["type"] == "choice":
        return rng.choice(t or p["choices"])
    if p["type"] == "layers":
        return rng.choice(t)
    lo, hi = (t or [p["min"], p["max"]])
    if p["log"] and lo > 0:
        v = float(np.exp(rng.uniform(np.log(lo), np.log(hi))))
    else:
        v = rng.uniform(lo, hi)
    return int(round(v)) if p["type"] == "int" else float(f"{v:.4g}")


def tune(algo, ds, trials=12, base=None, progress=None, stop=None):
    """AI tuning by random search. Each trial learns on the older 80% of the training tasks and is scored (F1) on the
    newest 20% of them. The newer test tasks are never looked at here."""
    X, y, tr, te = load(ds)
    cut = int(len(tr) * 0.8)
    fit_idx, val_idx = tr[:cut], tr[cut:]
    if y[val_idx].sum() == 0:
        raise ValueError("The validation slice has no problem tasks, so settings can't be compared.")
    rng = random.Random(SEED)
    start = resolve(algo, base)
    tried, out = set(), []
    tunable = [p for p in CATALOG[algo]["params"] if p["tune"] is not None or p["type"] == "choice"]
    for i in range(trials):
        if stop and stop():
            break
        if i == 0:
            cand = dict(start)  # the current settings are always trial 1, so tuning can only help
        else:
            cand = dict(start)
            for p in tunable:
                cand[p["name"]] = _draw(p, rng)
            cand = resolve(algo, cand)
        key = json.dumps(cand, sort_keys=True)
        if key in tried:
            continue
        tried.add(key)
        t0 = time.time()
        try:
            s_fit, s_val, _, _, _ = fit_score(algo, cand, X, y, fit_idx, val_idx)
            flags, _ = flags_for(algo, cand, s_fit, s_val)
            mm = metrics(y[val_idx], flags, s_val)
            row = {"trial": i + 1, "params": cand, "val_f1": round(mm["f1"], 4), "val_precision": round(mm["precision"], 4),
                   "val_recall": round(mm["recall"], 4), "seconds": round(time.time() - t0, 1)}
        except Exception as e:
            row = {"trial": i + 1, "params": cand, "val_f1": None, "error": str(e)[:200], "seconds": round(time.time() - t0, 1)}
        out.append(row)
        if progress:
            progress(row, i + 1, trials)
    ok = [r for r in out if r.get("val_f1") is not None]
    if not ok:
        raise ValueError("No setting could be trained.")
    best = max(ok, key=lambda r: (r["val_f1"], -r["trial"]))  # ties keep the earlier (current) settings
    return {"best": best["params"], "best_val_f1": best["val_f1"], "trials": out,
            "validation": {"fit_tasks": int(len(fit_idx)), "val_tasks": int(len(val_idx)), "val_problems": int(y[val_idx].sum())}}


# ---------------------------------------------------------------- the arena (contenders, results, jobs)
class Arena:
    def __init__(self, folder=ARENA_DIR):
        self.dir = folder
        self.lock = threading.RLock()
        self.job = {"state": "idle"}
        self._stop = False
        os.makedirs(folder, exist_ok=True)
        self.contenders = self._read("contenders.json", None)
        if self.contenders is None:
            self.contenders = self._defaults()
            self._save()
        self.results = self._read("results.json", {})  # {dataset: {contender id: result}}
        self.tunings = self._read("tunings.json", {})  # {contender id: tuning record}

    # ---------- storage
    def _read(self, name, default):
        try:
            with open(os.path.join(self.dir, name), encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return default

    def _write(self, name, data):
        tmp = os.path.join(self.dir, name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1)
        os.replace(tmp, os.path.join(self.dir, name))

    def _save(self):
        with self.lock:
            self._write("contenders.json", self.contenders)
            self._write("results.json", self.results if hasattr(self, "results") else {})
            self._write("tunings.json", self.tunings if hasattr(self, "tunings") else {})

    def _defaults(self):
        return [{"id": f"d-{a}", "algo": a, "name": CATALOG[a]["name"], "params": resolve(a), "builtin": True,
                 "created": time.strftime("%Y-%m-%dT%H:%M:%S")} for a in DEFAULT_LINEUP]

    # ---------- contenders
    def get(self, cid):
        c = next((c for c in self.contenders if c["id"] == cid), None)
        if not c:
            raise KeyError("No such contender")
        return c

    def add(self, algo, name=None, params=None, tuned=None):
        p = resolve(algo, params)
        with self.lock:
            base = (name or "").strip() or CATALOG[algo]["name"]
            names = {c["name"] for c in self.contenders}
            nm, k = base, 2
            while nm in names:
                nm, k = f"{base} ({k})", k + 1
            c = {"id": uuid.uuid4().hex[:8], "algo": algo, "name": nm[:60], "params": p, "builtin": False,
                 "created": time.strftime("%Y-%m-%dT%H:%M:%S")}
            if tuned:
                c["tuned"] = True
            self.contenders.append(c)
            self._save()
        return c

    def update(self, cid, name=None, params=None):
        with self.lock:
            c = self.get(cid)
            if params is not None:
                c["params"] = resolve(c["algo"], {**c["params"], **params})
            if name is not None and name.strip():
                c["name"] = name.strip()[:60]
            c["modified"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            self._save()
        return c

    def duplicate(self, cid):
        c = self.get(cid)
        return self.add(c["algo"], f"{c['name']} copy", c["params"])

    def delete(self, cid):
        with self.lock:
            self.get(cid)
            self.contenders = [c for c in self.contenders if c["id"] != cid]
            for r in self.results.values():
                r.pop(cid, None)
            self.tunings.pop(cid, None)
            self._save()

    def reset(self):
        with self.lock:
            if self.job.get("state") == "running":
                raise RuntimeError("Wait for the running fight to finish, or stop it.")
            self.contenders, self.results, self.tunings = self._defaults(), {}, {}
            self._save()

    # ---------- views
    def result(self, cid, ds):
        return self.results.get(ds, {}).get(cid)

    def view(self, ds):
        rows = []
        for c in self.contenders:
            a = CATALOG[c["algo"]]
            r = self.result(c["id"], ds)
            row = {**c, "family": a["family"], "learns": kind(c["algo"]), "algo_name": a["name"], "plain": a["plain"],
                   "detector": DETECTORS.get(c["algo"]) if c.get("builtin") else None,
                   "defaults_changed": [k for k, v in c["params"].items() if resolve(c["algo"])[k] != v],
                   "tuning": self.tunings.get(c["id"], {}).get("summary")}
            if r:
                rr = {k: v for k, v in r.items() if k != "curve"}
                rr["outdated"] = r.get("hash") != phash(c["algo"], c["params"])
                row["result"] = rr
            rows.append(row)
        return {"contenders": rows, "job": self.job_view(), "recommendation": self.recommend(ds)}

    def detail(self, cid, ds):
        c = self.get(cid)
        a = CATALOG[c["algo"]]
        r = self.result(cid, ds)
        params = []
        for p in a["params"]:
            params.append({**{k: p[k] for k in ("name", "label", "type", "default", "help", "min", "max", "choices")},
                           "value": c["params"].get(p["name"], p["default"])})
        return {"contender": c, "algo": {"id": c["algo"], "name": a["name"], "family": a["family"], "learns": kind(c["algo"]),
                                         "plain": a["plain"], "family_text": FAMILIES[a["family"]][1]},
                "params": params, "result": r, "outdated": bool(r) and r.get("hash") != phash(c["algo"], c["params"]),
                "tuning": self.tunings.get(cid)}

    def recommend(self, ds):
        """Plain-language pick from the latest results (the AI assistant can explain more)."""
        done = []
        for c in self.contenders:
            r = self.result(c["id"], ds)
            if r and r.get("hash") == phash(c["algo"], c["params"]):
                done.append((c, r))
        if len(done) < 2:
            return None
        best = max(done, key=lambda x: (x[1]["f1"], -x[1]["train_seconds"]))
        unsup = [x for x in done if kind(x[0]["algo"]) == "unsupervised"]
        best_u = max(unsup, key=lambda x: x[1]["f1"]) if unsup else None
        near = [x for x in done if x[1]["f1"] >= best[1]["f1"] - 0.01]
        fast = min(near, key=lambda x: x[1]["train_seconds"] + x[1]["check_seconds"])
        out = {"best": {"id": best[0]["id"], "name": best[0]["name"], "f1": best[1]["f1"],
                        "false_alarms": best[1]["false_alarms"], "caught": best[1]["caught"], "real": best[1]["real"]},
               "fastest_good": {"id": fast[0]["id"], "name": fast[0]["name"], "f1": fast[1]["f1"],
                                "seconds": round(fast[1]["train_seconds"] + fast[1]["check_seconds"], 1)},
               "n": len(done)}
        if best_u:
            out["best_unsupervised"] = {"id": best_u[0]["id"], "name": best_u[0]["name"], "f1": best_u[1]["f1"],
                                        "false_alarms": best_u[1]["false_alarms"], "caught": best_u[1]["caught"],
                                        "real": best_u[1]["real"]}
        return out

    # ---------- jobs (one at a time, in the background)
    def job_view(self):
        with self.lock:
            return copy.deepcopy(self.job)

    def stop(self):
        self._stop = True

    def _start(self, kind_, target, **info):
        with self.lock:
            if self.job.get("state") == "running":
                raise RuntimeError("A fight is already running. Wait for it or stop it first.")
            self._stop = False
            self.job = {"state": "running", "kind": kind_, "started": time.time(), "dataset": info.get("dataset"),
                        "lanes": info.get("lanes", []), "trials": [], "message": "Starting…"}
        threading.Thread(target=target, daemon=True).start()

    def fight(self, ids, ds):
        ids = [i for i in ids if any(c["id"] == i for c in self.contenders)]
        if not ids:
            raise ValueError("Pick at least one contender.")
        if ds not in {d["id"] for d in datasets()}:
            raise ValueError("That dataset isn't available on this PC.")
        lanes = [{"id": i, "name": self.get(i)["name"], "state": "waiting"} for i in ids]

        def work():
            try:
                self.job["message"] = "Loading the tasks…"
                load(ds)
                for lane in self.job["lanes"]:
                    if self._stop:
                        lane["state"] = "skipped"
                        continue
                    c = self.get(lane["id"])
                    lane["state"] = "running"
                    lane["started"] = time.time()
                    self.job["message"] = f"{c['name']} is learning…"
                    try:
                        r = run_one(c["algo"], c["params"], ds)
                        r["hash"] = phash(c["algo"], c["params"])
                        with self.lock:
                            self.results.setdefault(ds, {})[c["id"]] = r
                            self._save()
                        lane.update(state="done", f1=r["f1"], precision=r["precision"], recall=r["recall"],
                                    caught=r["caught"], real=r["real"], false_alarms=r["false_alarms"],
                                    seconds=round(r["train_seconds"] + r["check_seconds"], 1))
                    except Exception as e:
                        lane.update(state="failed", error=str(e)[:300])
                self.job.update(state="done", message="Stopped." if self._stop else "Finished.", ended=time.time())
            except Exception as e:
                self.job.update(state="failed", message=str(e)[:300], ended=time.time())

        self._start("fight", work, dataset=ds, lanes=lanes)

    def tune_job(self, cid, ds, trials=12):
        c = self.get(cid)
        trials = max(3, min(int(trials), 60))
        if ds not in {d["id"] for d in datasets()}:
            raise ValueError("That dataset isn't available on this PC.")

        def work():
            try:
                self.job["message"] = "Loading the tasks…"
                self.job["target"] = {"id": c["id"], "name": c["name"], "algo": c["algo"], "trials": trials}

                def prog(row, i, n):
                    self.job["trials"].append(row)
                    self.job["message"] = f"Trial {i} of {n}: validation F1 {row['val_f1'] if row.get('val_f1') is not None else 'failed'}"
                t = tune(c["algo"], ds, trials, c["params"], prog, lambda: self._stop)
                self.job["message"] = "Testing the best settings once on the newer tasks…"
                new = self.add(c["algo"], f"{CATALOG[c['algo']]['name']} (AI-tuned)", t["best"], tuned=True)
                r = run_one(new["algo"], new["params"], ds)
                r["hash"] = phash(new["algo"], new["params"])
                base = self.result(c["id"], ds)
                summary = {"from": c["name"], "trials": len(t["trials"]), "best_val_f1": t["best_val_f1"],
                           "test_f1": r["f1"], "before_test_f1": base["f1"] if base and base.get("hash") == phash(c["algo"], c["params"]) else None,
                           "changed": {k: [c["params"].get(k), v] for k, v in t["best"].items() if c["params"].get(k) != v}}
                with self.lock:
                    self.results.setdefault(ds, {})[new["id"]] = r
                    self.tunings[new["id"]] = {**t, "summary": summary, "dataset": ds}
                    self._save()
                self.job.update(state="done", new_id=new["id"], summary=summary, ended=time.time(),
                                message=f"Done. Best of {len(t['trials'])} settings saved as {new['name']}.")
            except Exception as e:
                self.job.update(state="failed", message=str(e)[:300], ended=time.time())

        self._start("tune", work, dataset=ds)

    def catalog(self):
        out = []
        for aid, a in CATALOG.items():
            out.append({"id": aid, "name": a["name"], "family": a["family"], "learns": kind(aid), "plain": a["plain"],
                        "params": [{k: p[k] for k in ("name", "label", "type", "default", "help", "min", "max", "choices")}
                                   for p in a["params"]]})
        return {"algorithms": out, "families": {k: {"title": v[0], "text": v[1]} for k, v in FAMILIES.items()}}


# ---------------------------------------------------------------- command line
def main():
    ap = argparse.ArgumentParser(description="Algorithm arena for HDFS_v1.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build-features", help="save the HDFS_v1 task features from a full run")
    b.add_argument("--db", default=os.path.join(DATA, "seclog.db"))
    b.add_argument("--log", help="HDFS.log: if the full run's database is gone, read the log again (about 9 minutes)")
    b.add_argument("--labels", help="anomaly_label.csv (needed with --log)")
    f = sub.add_parser("fight", help="run every contender and print the leaderboard")
    f.add_argument("--dataset", default=None)
    a = ap.parse_args()
    if a.cmd == "build-features":
        if a.log:
            if not a.labels:
                raise SystemExit("Give the answer key too: --labels anomaly_label.csv")
            from . import pipeline
            tmp = os.path.join(DATA, "arena_build.db")
            print(f"Reading {a.log} again into a temporary database (about 9 minutes for all of HDFS_v1)…")
            pipeline.run(a.log, tmp, a.labels, None, 0.03)
            try:
                build_features(tmp)
            finally:
                for ext in ("", "-wal", "-shm"):
                    if os.path.exists(tmp + ext):
                        os.remove(tmp + ext)
                if os.path.exists(tmp.replace(".db", ".models.joblib")):
                    os.remove(tmp.replace(".db", ".models.joblib"))
        else:
            build_features(a.db)
        return
    ds = a.dataset or (datasets()[0]["id"] if datasets() else None)
    if not ds:
        raise SystemExit("No dataset: run build-features first, or a labelled research run.")
    ar = Arena()
    rows = []
    for c in ar.contenders:
        r = run_one(c["algo"], c["params"], ds, keep_curve=True)
        r["hash"] = phash(c["algo"], c["params"])
        ar.results.setdefault(ds, {})[c["id"]] = r
        rows.append((c["name"], r))
        print(f"  {c['name']:24s} F1 {r['f1']:.3f}  P {r['precision']:.3f}  R {r['recall']:.3f}  "
              f"false alarms {r['false_alarms']:,}  {r['train_seconds']:.1f} s")
    ar._save()


if __name__ == "__main__":
    main()
