"""Step 3: turn each block's sequence of events into a row of numbers."""
import numpy as np
import pandas as pd


def build_blocks(events, labels: dict | None = None) -> pd.DataFrame:
    """One row per block: first timestamp, number of events, label (if known)."""
    df = pd.DataFrame(
        [(e.block_id, e.ts, e.template_id) for e in events],
        columns=["block_id", "ts", "template_id"],
    )
    g = df.groupby("block_id")
    blocks = pd.DataFrame({"first_ts": g["ts"].min(), "n_events": g.size()}).reset_index()
    blocks["label"] = blocks["block_id"].map(labels) if labels else None
    # Oldest blocks first, so we can train on older logs and test on newer ones.
    blocks = blocks.sort_values(["first_ts", "block_id"]).reset_index(drop=True)
    return blocks


def count_matrix(events, blocks: pd.DataFrame, template_ids: list[int]) -> pd.DataFrame:
    """Rows = blocks (same order as `blocks`), columns = event types, values = counts."""
    df = pd.DataFrame([(e.block_id, e.template_id) for e in events], columns=["block_id", "template_id"])
    m = pd.crosstab(df["block_id"], df["template_id"]).reindex(
        index=blocks["block_id"], columns=template_ids, fill_value=0
    )
    return m


def to_model_input(counts: pd.DataFrame) -> np.ndarray:
    """log1p keeps big counts from dominating."""
    return np.log1p(counts.values.astype(float))
