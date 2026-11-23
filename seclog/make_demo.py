"""Generate a SYNTHETIC HDFS-style demo log (not real data, not HDFS_v1).

Purpose: show the full flow (parse -> detect -> alert -> evidence) when the real
HDFS_v1 files are not on the machine. Scores computed on this file are NOT project results.
"""
import argparse
import csv
import random
from datetime import datetime, timedelta


def ip(r):
    return f"10.250.{r.randint(6, 19)}.{r.randint(10, 250)}"


def block_lines(r, bid, t0):
    """Return list of (time, level, component, message). Normal lifecycle of one block."""
    nodes = [ip(r) for _ in range(3)]
    src = ip(r)
    t = t0
    out = [(t, "INFO", "dfs.FSNamesystem",
            f"BLOCK* NameSystem.allocateBlock: /user/root/rand/_temporary/_task_200811092030_0001_m_{r.randint(0, 999999):06d}_0/part-{r.randint(0, 99999):05d}. {bid}")]
    for n in nodes:
        t += timedelta(seconds=r.randint(0, 2))
        out.append((t, "INFO", "dfs.DataNode$DataXceiver", f"Receiving block {bid} src: /{src}:{r.randint(30000, 60000)} dest: /{n}:50010"))
    for k, n in enumerate(nodes):
        t += timedelta(seconds=r.randint(1, 20))
        out.append((t, "INFO", "dfs.DataNode$PacketResponder", f"PacketResponder {k} for block {bid} terminating"))
        out.append((t, "INFO", "dfs.DataNode$DataXceiver", f"Received block {bid} of size 67108864 from /{src}"))
        out.append((t, "INFO", "dfs.FSNamesystem", f"BLOCK* NameSystem.addStoredBlock: blockMap updated: {n}:50010 is added to {bid} size 67108864"))
    return out


def make_anomalous(r, bid, t0):
    lines = block_lines(r, bid, t0)
    kind = r.choice(["reset", "delete", "redundant", "empty", "lost"])
    n = ip(r)
    t = lines[-1][0] + timedelta(seconds=r.randint(1, 30))
    if kind == "reset":
        lines = lines[:5]  # lifecycle cut short
        lines.append((t, "WARN", "dfs.DataNode$DataXceiver", f"{n}:50010:Got exception while serving {bid} to /{ip(r)}:"))
        lines.append((t, "INFO", "dfs.DataNode$DataXceiver", f"writeBlock {bid} received exception java.io.IOException: Connection reset by peer"))
        lines.append((t, "ERROR", "dfs.DataNode$DataXceiver", f"{n}:50010:DataXceiver: java.io.IOException: Connection reset by peer"))
    elif kind == "delete":
        lines.append((t, "WARN", "dfs.FSDataset", f"Unexpected error trying to delete block {bid}. BlockInfo not found in volumeMap."))
        lines.append((t, "INFO", "dfs.FSNamesystem", f"BLOCK* NameSystem.delete: {bid} is added to invalidSet of {n}:50010"))
    elif kind == "redundant":
        for _ in range(r.randint(2, 4)):
            lines.append((t, "WARN", "dfs.FSNamesystem", f"BLOCK* NameSystem.addStoredBlock: Redundant addStoredBlock request received for {bid} on {n}:50010 size 67108864"))
    elif kind == "empty":
        lines.append((t, "INFO", "dfs.DataNode$PacketResponder", f"Received empty packet for block {bid}"))
        lines.append((t, "WARN", "dfs.DataNode$PacketResponder", f"PacketResponder {bid} Exception java.io.IOException: Broken pipe"))
    else:  # lost
        lines = lines[:3]
        lines.append((t, "WARN", "dfs.DataNode$DataXceiver", f"Exception in receiveBlock for block {bid} java.io.IOException: Connection reset by peer"))
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--blocks", type=int, default=3000)
    ap.add_argument("--anomaly-rate", type=float, default=0.04)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default="data/sample/demo_hdfs_style.log")
    ap.add_argument("--labels", default="data/sample/demo_labels.csv")
    a = ap.parse_args()
    r = random.Random(a.seed)
    start = datetime(2008, 11, 9, 20, 30, 0)
    all_lines, labels = [], []
    for i in range(a.blocks):
        bid = "blk_" + str(r.randint(-(10**18), 10**18))
        t0 = start + timedelta(seconds=int(i * 6 + r.randint(0, 5)))
        bad = r.random() < a.anomaly_rate
        all_lines += (make_anomalous if bad else block_lines)(r, bid, t0)
        labels.append((bid, "Anomaly" if bad else "Normal"))
    all_lines.sort(key=lambda x: x[0])
    with open(a.out, "w") as f:
        for t, lvl, comp, msg in all_lines:
            f.write(f"{t:%y%m%d} {t:%H%M%S} {r.randint(10, 999)} {lvl} {comp}: {msg}\n")
    with open(a.labels, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["BlockId", "Label"])
        w.writerows(labels)
    print(f"wrote {len(all_lines)} lines, {a.blocks} blocks, {sum(l == 'Anomaly' for _, l in labels)} anomalous")


if __name__ == "__main__":
    main()
