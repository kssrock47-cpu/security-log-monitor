"""Algorithm arena: every algorithm runs, settings are checked, AI tuning never looks at the test tasks."""
import time

import numpy as np
import pytest

from seclog import arena, assistant


@pytest.fixture
def data(monkeypatch):
    rng = np.random.default_rng(1)
    n, k = 1500, 8
    X = np.log1p(rng.poisson(1.0, (n, k)).astype(np.float32))
    y = (rng.random(n) < 0.06).astype(int)
    X[y == 1, 7] += 2.5  # problems have an unusual message type
    tr, te = np.arange(1050), np.arange(1050, n)
    monkeypatch.setattr(arena, "load", lambda ds: (X, y, tr, te))
    monkeypatch.setattr(arena, "datasets", lambda: [{"id": "t", "name": "test", "tasks": n, "demo": True}])
    return X, y, tr, te


def test_every_algorithm_runs(data):
    for algo in arena.CATALOG:
        p = {"max_train": 400} if "max_train" in arena.resolve(algo) else {}
        r = arena.run_one(algo, p, "t")
        assert 0 <= r["f1"] <= 1 and r["n_test"] == 450 and r["caught"] + r["missed"] == r["real"], algo
        assert r["false_alarms"] + r["quiet"] == r["n_test"] - r["real"]
        assert r["curve"], algo
    rf = arena.run_one("forest", {}, "t")
    assert rf["f1"] > 0.8


def test_settings_are_checked():
    p = arena.resolve("forest", {"n_estimators": "50", "max_depth": -3, "max_features": "log2"})
    assert p["n_estimators"] == 50 and p["max_depth"] == 0 and p["max_features"] == "log2"
    assert arena.resolve("mlp", {"hidden_layers": "128, 64"})["hidden_layers"] == "128,64"
    with pytest.raises(ValueError):
        arena.resolve("forest", {"max_features": "most"})
    with pytest.raises(ValueError):
        arena.resolve("mlp", {"hidden_layers": "0,abc"})
    with pytest.raises(ValueError):
        arena.resolve("no-such-algorithm")


def test_tuning_uses_only_older_tasks(data, monkeypatch):
    X, y, tr, te = data
    seen = []
    real = arena.fit_score
    monkeypatch.setattr(arena, "fit_score", lambda a, p, X_, y_, f, e: (seen.append((set(f), set(e))), real(a, p, X_, y_, f, e))[1])
    t = arena.tune("tree", "t", trials=5)
    assert t["trials"][0]["params"] == arena.resolve("tree")  # trial 1 is the starting settings
    assert t["best_val_f1"] >= t["trials"][0]["val_f1"]
    test = set(te)
    assert seen and all(not (f & test) and not (e & test) for f, e in seen)


def test_arena_contenders_and_fight(data, tmp_path):
    ar = arena.Arena(str(tmp_path))
    assert [c["algo"] for c in ar.contenders] == arena.DEFAULT_LINEUP
    c = ar.add("knn", "My kNN", {"n_neighbors": 3, "max_train": 300})
    assert c["params"]["n_neighbors"] == 3 and not c["builtin"]
    ar.fight([c["id"], "d-tree"], "t")
    for _ in range(200):
        if ar.job_view()["state"] != "running":
            break
        time.sleep(0.05)
    j = ar.job_view()
    assert j["state"] == "done" and all(l["state"] == "done" for l in j["lanes"])
    v = ar.view("t")
    row = next(x for x in v["contenders"] if x["id"] == c["id"])
    assert row["result"] and not row["result"]["outdated"]
    ar.update(c["id"], params={"n_neighbors": 7})
    row = next(x for x in ar.view("t")["contenders"] if x["id"] == c["id"])
    assert row["result"]["outdated"] and "n_neighbors" in row["defaults_changed"]
    assert ar.view("t")["recommendation"] is None  # only the tree is still up to date, and a pick needs two
    ar2 = arena.Arena(str(tmp_path))  # saved to disk
    assert any(x["name"] == "My kNN" for x in ar2.contenders)
    ar.delete(c["id"])
    assert all(x["id"] != c["id"] for x in ar.contenders)


def test_assistant_prompt_is_grounded():
    msgs = assistant.messages_for("Why is PCA better?", [{"role": "user", "content": "hi"}, {"role": "bogus", "content": "x"}],
                                  "Algorithm arena: PCA F1 0.691")
    assert msgs[0]["role"] == "system" and "ONLY from the FACTS" in msgs[0]["content"] and "PCA F1 0.691" in msgs[0]["content"]
    assert [m["role"] for m in msgs] == ["system", "user", "user"]
    assert len(assistant.build_facts(["a" * 6000, "b" * 6000])) <= assistant.MAX_CONTEXT + 2


def test_assistant_status_without_ollama(monkeypatch):
    monkeypatch.setattr(assistant, "OLLAMA", "http://127.0.0.1:9")
    s = assistant.status()
    assert s["running"] is False and s["model"] is None and s["recommended"]
