"""Prefilter visualization helpers: heatmaps, occupancy plots, MI matrix."""

from pathlib import Path

import numpy as np
import matplotlib

from pfbench.constants import NUM_LANES

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def plot_bit_bias_heatmap(
    bias: np.ndarray, out: Path, title: str = "Lane × Bit Bias"
) -> None:
    fig, ax = plt.subplots(figsize=(max(6, bias.shape[1] * 0.5), 12))
    im = ax.imshow(bias, aspect="auto", cmap="RdBu_r", vmin=0, vmax=1)
    ax.set_xlabel("Bit position")
    ax.set_ylabel("Lane")
    ax.set_title(title)
    fig.colorbar(im, ax=ax, label="P(bit=1)")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)


def plot_occupancy_stripe(
    occupancy_by_lane: dict[int, list[int]],
    bits: int,
    out: Path,
    title: str = "Lane × Address Occupancy",
) -> None:
    size = 1 << bits
    matrix = np.zeros((NUM_LANES, size))
    for lane, addrs in occupancy_by_lane.items():
        for addr in addrs:
            matrix[lane, addr] += 1

    fig, ax = plt.subplots(figsize=(14, 12))
    im = ax.imshow(matrix, aspect="auto", cmap="hot", interpolation="nearest")
    ax.set_xlabel("Address bin")
    ax.set_ylabel("Lane")
    ax.set_title(title)
    fig.colorbar(im, ax=ax, label="Hit count")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)


def plot_mi_matrix(
    addresses_by_lane: dict[int, list[int]],
    bits: int,
    out: Path,
    title: str = "Reduced-Bit Mutual Information",
) -> None:
    all_addrs = []
    for addrs in addresses_by_lane.values():
        all_addrs.extend(addrs)

    if not all_addrs:
        return

    arr = np.array(all_addrs, dtype=np.uint32)
    bit_vectors = np.array([(arr >> b) & 1 for b in range(bits)], dtype=np.float64)

    mi = np.zeros((bits, bits))
    n = len(arr)
    for i in range(bits):
        for j in range(i, bits):
            p11 = np.mean(bit_vectors[i] * bit_vectors[j])
            p1i = np.mean(bit_vectors[i])
            p1j = np.mean(bit_vectors[j])
            if p11 > 0 and p1i > 0 and p1j > 0:
                mi[i, j] = p11 * np.log2(p11 / (p1i * p1j))
            p10 = np.mean(bit_vectors[i] * (1 - bit_vectors[j]))
            p0i = 1 - p1i
            p0j = 1 - p1j
            if p10 > 0 and p1i > 0 and p0j > 0:
                mi[i, j] += p10 * np.log2(p10 / (p1i * p0j))
            p01 = np.mean((1 - bit_vectors[i]) * bit_vectors[j])
            if p01 > 0 and p0i > 0 and p1j > 0:
                mi[i, j] += p01 * np.log2(p01 / (p0i * p1j))
            p00 = np.mean((1 - bit_vectors[i]) * (1 - bit_vectors[j]))
            if p00 > 0 and p0i > 0 and p0j > 0:
                mi[i, j] += p00 * np.log2(p00 / (p0i * p0j))
            mi[j, i] = mi[i, j]

    fig, ax = plt.subplots(figsize=(8, 7))
    im = ax.imshow(mi, cmap="viridis")
    ax.set_xlabel("Bit")
    ax.set_ylabel("Bit")
    ax.set_title(title)
    fig.colorbar(im, ax=ax, label="MI (bits)")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)


def plot_comparison(
    labels: list[str],
    metrics_list: list[dict],
    metric_key: str,
    out: Path,
    title: str = "Experiment Comparison",
) -> None:
    fig, ax = plt.subplots(figsize=(10, 5))
    values = [m.get(metric_key, 0) for m in metrics_list]
    ax.bar(labels, values)
    ax.set_ylabel(metric_key)
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
