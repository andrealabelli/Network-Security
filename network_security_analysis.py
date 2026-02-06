#!/usr/bin/env python3
"""Network Security dataset visualization for TON_IoT (Kaggle).

Generates plots for:
- Dataset overview (protocol distribution)
- TCP flooding: suspicious vs. non-suspicious connection states
- UDP flooding: mean src/dst packets & bytes (suspicious vs. non-suspicious)
- Attack comparisons: sending packets across attack types (e.g., ransomware, xss)
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, Optional

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns


NORMAL_LABELS = {"normal", "benign", "legit", "legitimate"}


def _pick_column(df: pd.DataFrame, candidates: Iterable[str]) -> Optional[str]:
    lower_map = {col.lower(): col for col in df.columns}
    for candidate in candidates:
        if candidate.lower() in lower_map:
            return lower_map[candidate.lower()]
    return None


def _pick_like(df: pd.DataFrame, substrings: Iterable[str]) -> Optional[str]:
    for col in df.columns:
        lower_col = col.lower()
        if all(sub in lower_col for sub in substrings):
            return col
    return None


def _detect_columns(df: pd.DataFrame) -> dict:
    proto = _pick_column(df, ["proto", "protocol"])
    conn_state = _pick_column(df, ["conn_state", "state", "connection_state"])

    label = _pick_column(df, ["label", "attack", "type", "category", "class"])

    src_pkts = _pick_column(df, ["src_pkts", "source_pkts", "src_packets", "s_pkts"]) or _pick_like(
        df, ["src", "pkts"]
    )
    dst_pkts = _pick_column(df, ["dst_pkts", "dest_pkts", "dst_packets", "d_pkts"]) or _pick_like(
        df, ["dst", "pkts"]
    )
    src_bytes = _pick_column(df, ["src_bytes", "source_bytes", "s_bytes"]) or _pick_like(
        df, ["src", "bytes"]
    )
    dst_bytes = _pick_column(df, ["dst_bytes", "dest_bytes", "d_bytes"]) or _pick_like(
        df, ["dst", "bytes"]
    )

    return {
        "proto": proto,
        "conn_state": conn_state,
        "label": label,
        "src_pkts": src_pkts,
        "dst_pkts": dst_pkts,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
    }


def _is_suspicious(series: pd.Series) -> pd.Series:
    return ~series.astype(str).str.lower().isin(NORMAL_LABELS)


def _save_plot(output_dir: Path, name: str) -> Path:
    path = output_dir / f"{name}.png"
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()
    return path


def plot_protocol_distribution(df: pd.DataFrame, proto_col: str, output_dir: Path) -> Path:
    counts = df[proto_col].value_counts().head(10)
    sns.barplot(x=counts.values, y=counts.index, palette="viridis")
    plt.title("Top Protocols (by count)")
    plt.xlabel("Count")
    plt.ylabel("Protocol")
    return _save_plot(output_dir, "protocol_distribution")


def plot_tcp_conn_states(
    df: pd.DataFrame, proto_col: str, conn_state_col: str, label_col: str, output_dir: Path
) -> Path:
    tcp_df = df[df[proto_col].str.upper() == "TCP"].copy()
    tcp_df["suspicious"] = _is_suspicious(tcp_df[label_col])
    counts = (
        tcp_df.groupby(["suspicious", conn_state_col])
        .size()
        .reset_index(name="count")
    )

    sns.barplot(
        data=counts,
        x="count",
        y=conn_state_col,
        hue="suspicious",
        palette={True: "#d62728", False: "#2ca02c"},
    )
    plt.title("TCP Connection States: Suspicious vs Non-suspicious")
    plt.xlabel("Count")
    plt.ylabel("Connection State")
    return _save_plot(output_dir, "tcp_conn_state_flooding")


def plot_udp_means(
    df: pd.DataFrame,
    proto_col: str,
    label_col: str,
    src_pkts_col: str,
    dst_pkts_col: str,
    src_bytes_col: str,
    dst_bytes_col: str,
    output_dir: Path,
) -> Path:
    udp_df = df[df[proto_col].str.upper() == "UDP"].copy()
    udp_df["suspicious"] = _is_suspicious(udp_df[label_col])
    summary = udp_df.groupby("suspicious")[[src_pkts_col, dst_pkts_col, src_bytes_col, dst_bytes_col]].mean()

    summary.plot(kind="bar", figsize=(10, 5), color=["#1f77b4", "#ff7f0e", "#2ca02c", "#9467bd"])
    plt.title("UDP Mean Src/Dst Packets & Bytes (Suspicious vs Non-suspicious)")
    plt.xlabel("Suspicious")
    plt.ylabel("Mean Value")
    plt.xticks(rotation=0)
    return _save_plot(output_dir, "udp_mean_packets_bytes")


def plot_attack_comparison(
    df: pd.DataFrame,
    label_col: str,
    src_pkts_col: str,
    output_dir: Path,
    top_n: int,
) -> Path:
    attack_df = df.copy()
    attack_df["label_clean"] = attack_df[label_col].astype(str).str.lower()
    attack_df = attack_df[~attack_df["label_clean"].isin(NORMAL_LABELS)]

    summary = attack_df.groupby(label_col)[src_pkts_col].mean().sort_values(ascending=False).head(top_n)

    sns.barplot(x=summary.values, y=summary.index, palette="magma")
    plt.title("Mean Src Packets by Attack Type")
    plt.xlabel("Mean Src Packets")
    plt.ylabel("Attack Type")
    return _save_plot(output_dir, "attack_src_packets_comparison")


def main() -> int:
    parser = argparse.ArgumentParser(description="TON_IoT dataset visualization")
    parser.add_argument("--input", required=True, help="Path to TON_IoT Train/Test CSV")
    parser.add_argument("--output", default="outputs", help="Directory to save plots")
    parser.add_argument("--top-attacks", type=int, default=10, help="Top N attacks to compare")

    args = parser.parse_args()
    input_path = Path(args.input)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(input_path)
    columns = _detect_columns(df)

    missing = [key for key, value in columns.items() if value is None]
    if missing:
        missing_str = ", ".join(missing)
        raise SystemExit(f"Missing required columns for: {missing_str}. Available columns: {list(df.columns)}")

    sns.set_theme(style="whitegrid")

    plot_protocol_distribution(df, columns["proto"], output_dir)
    plot_tcp_conn_states(df, columns["proto"], columns["conn_state"], columns["label"], output_dir)
    plot_udp_means(
        df,
        columns["proto"],
        columns["label"],
        columns["src_pkts"],
        columns["dst_pkts"],
        columns["src_bytes"],
        columns["dst_bytes"],
        output_dir,
    )
    plot_attack_comparison(
        df,
        columns["label"],
        columns["src_pkts"],
        output_dir,
        args.top_attacks,
    )

    print(f"Plots saved to {output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
