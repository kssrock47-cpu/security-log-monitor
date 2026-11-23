"""Turn technical log events into plain-language sentences for non-experts.

The phrases below are hand-written translations of known HDFS log messages.
Unknown messages fall back to the original text, so nothing is invented.
"""
import re

import pandas as pd

# (pattern in the Drain3 template, plain phrase, is_problem)
# Covers all 29 HDFS_v1 message types (loghub E1-E29). More specific patterns come first.
_WHY = [  # the reason inside an exception, in plain words
    (r"Connection reset", "the connection was cut off"),
    (r"Could not read from stream", "the incoming data stream broke"),
    (r"Broken pipe", "the connection broke"),
    (r"SocketTimeout|timeout while waiting", "it timed out"),
    (r"Interrup", "it was interrupted"),
    (r"EOFException", "the data ended too early"),
    (r"is valid, and cannot be written to", "that copy already exists and is locked"),
    (r"No space left", "the disk was full"),
]


def _why(t):
    for pat, w in _WHY:
        if re.search(pat, t):
            return w
    return None


PHRASES = [
    (r"Redundant addStoredBlock", "The same copy was recorded more than once", True),
    (r"does not belong to any file", "A copy was reported that belongs to no file", True),
    (r"Removing block .*neededReplications", "The system dropped a copy that belongs to no file", True),
    (r"Adding an already existing block", "The system tried to add a copy that already exists", True),
    (r"Unexpected error trying to delete", "The system tried to delete data that was not there", True),
    (r"PendingReplicationMonitor timed out", "Making an extra copy took too long", True),
    (r"NameSystem\.delete|invalidSet", "The data was marked for deletion", True),
    (r"Got exception while serving", "A storage computer hit an error while sending data to a reader", True),
    (r"writeBlock .*received exception", "Writing the data failed", True),
    (r"Exception in receiveBlock", "Receiving the data failed", True),
    (r"PacketResponder .*Exception", "Sending a copy failed", True),
    (r"PacketResponder .*Interrupted", "A copy was interrupted before it finished sending", True),
    (r"Exception writing block .*mirror", "Passing the data on to the next computer failed", True),
    (r"Failed to transfer", "Copying the data to another computer failed", True),
    (r"empty packet", "An empty piece of data arrived", True),
    (r"Broken pipe", "The data transfer broke off", True),
    (r"Connection reset by peer", "The connection was cut off unexpectedly", True),
    (r"Changing block file offset", "A storage computer rewound a partly written copy", True),
    (r"Reopen Block", "A storage computer reopened a copy to keep writing", False),
    (r"allocateBlock", "A new piece of a file was created for storage", False),
    (r"Receiving block", "A storage computer started receiving the data", False),
    (r"PacketResponder .*terminating", "A copy finished sending", False),
    (r"Received block .*src.*dest.*of size", "A copy arrived from another storage computer", False),
    (r"Received block .*of size", "A storage computer confirmed it received the data", False),
    (r"addStoredBlock: blockMap updated", "The system recorded where the copy is kept", False),
    (r"Deleting block", "Data was deleted from a storage computer", False),
    (r"Verification succeeded", "A routine storage check passed", False),
    (r"Served block", "Data was sent to a reader", False),
    (r"Starting thread to transfer", "Started copying the data to another computer", False),
    (r"Transmitted block", "Data was copied to another computer", False),
    (r"ask .*to replicate", "The system asked for an extra copy to be made", False),
]

NEXT_STEPS = [
    (r"Connection reset|Broken pipe|exception while serving|receiveBlock|Could not read|timeout|Interrup|EOFException",
     "Check whether the storage computer involved was overloaded or lost its network at that time."),
    (r"trying to delete|invalidSet", "Check whether the data was already removed, or the records are out of date."),
    (r"Redundant|already existing|does not belong", "Check for duplicate or orphaned records of the same data."),
    (r"PendingReplicationMonitor|replicate", "Check whether enough healthy storage computers were available to make copies."),
    (r"empty packet", "Check the sending computer; it may have sent incomplete data."),
]


def friendly(template: str) -> str:
    for pat, phrase, bad in PHRASES:
        if re.search(pat, template):
            why = _why(template) if bad and "failed" in phrase.lower() else None
            return f"{phrase}: {why}" if why else phrase
    return f"Log message: {template}"


def is_problem(template: str) -> bool:
    for pat, _, bad in PHRASES:
        if re.search(pat, template):
            return bad
    return False


def story(block_counts: pd.Series, stats: pd.DataFrame, templates: dict,
          rare_below=0.05, usual_above=0.95) -> dict:
    """Compare one block with the normal profile.

    stats: indexed by template_id with columns normal_share, normal_median, typical_pos.
    Returns headline, usual steps (with what happened here), unusual events, next steps.
    """
    usual = stats[stats["normal_share"] >= usual_above].sort_values("typical_pos")
    steps = []
    for tid, row in usual.iterrows():
        here, normal = int(block_counts.get(tid, 0)), int(round(row["normal_median"]))
        if here == 0:
            status = "missing"
        elif here != normal:
            status = "different"
        else:
            status = "ok"
        steps.append({"text": friendly(templates[tid]), "normal": normal, "here": here, "status": status})

    present = [t for t, c in block_counts.items() if c > 0]
    rare = sorted((stats.loc[t, "normal_share"] if t in stats.index else 0.0, t) for t in present
                  if (stats.loc[t, "normal_share"] if t in stats.index else 0.0) < rare_below)
    unusual = [{"text": friendly(templates[t]), "share": sh, "times": int(block_counts[t]), "template_id": t}
               for sh, t in rare]

    missing = [s for s in steps if s["status"] == "missing"]
    different = [s for s in steps if s["status"] == "different"]
    if unusual and missing:
        headline = f"{unusual[0]['text']}, and the task never finished."
    elif unusual:
        headline = f"{unusual[0]['text']}."
    elif missing:
        headline = "The task stopped before it finished."
    elif different:
        headline = "The usual steps happened an unusual number of times."
    else:
        headline = "An unusual mix of otherwise normal messages."

    joined = " ".join(templates[u["template_id"]] for u in unusual)
    nexts = [txt for pat, txt in NEXT_STEPS if re.search(pat, joined)]
    if missing:
        nexts.append("Check whether the file was saved completely, and send it again if not.")
    nexts.append("Look for other alerts around the same time. Many at once can point to a wider problem.")
    return {"headline": headline, "steps": steps, "unusual": unusual, "next_steps": nexts,
            "rare_ids": {u["template_id"] for u in unusual}}
