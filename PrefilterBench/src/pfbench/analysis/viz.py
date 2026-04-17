"""Prefilter visualization helpers: heatmaps, occupancy plots, MI matrix."""

from pathlib import Path

import numpy as np
import matplotlib

from pfbench.constants import NUM_LANES

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LogNorm


def plot_bit_bias_heatmap(
    bias: np.ndarray, out: Path, title: str = "Lane * Bit Bias (deviation from 0.5)"
) -> None:
    # Auto-zoom to the observed range but always symmetric around 0.5 so the
    # diverging colormap is meaningful.
    dev = float(np.max(np.abs(bias - 0.5))) if bias.size else 0.0
    dev = max(dev, 0.02)  # avoid a degenerate zero range
    vmin, vmax = 0.5 - dev, 0.5 + dev

    fig, ax = plt.subplots(figsize=(max(6, bias.shape[1] * 0.5), 12))
    im = ax.imshow(bias, aspect="auto", cmap="RdBu_r", vmin=vmin, vmax=vmax)
    ax.set_xlabel("Bit position")
    ax.set_ylabel("Lane")
    ax.set_title(f"{title}  (range ±{dev:.3f})")
    fig.colorbar(im, ax=ax, label="P(bit=1)")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)


def plot_occupancy_stripe(
    occupancy_by_lane: dict[int, list[int]],
    bits: int,
    out: Path,
    title: str = "Lane × Address Occupancy (log scale)",
) -> None:
    size = 1 << bits
    matrix = np.zeros((NUM_LANES, size), dtype=np.int64)
    for lane, addrs in occupancy_by_lane.items():
        for addr in addrs:
            matrix[lane, addr] += 1

    max_hit = int(matrix.max()) if matrix.size else 0
    fig, ax = plt.subplots(figsize=(14, 12))
    if max_hit <= 1:
        # Fall back to linear scale when nothing interesting to log.
        im = ax.imshow(matrix, aspect="auto", cmap="hot", interpolation="nearest")
    else:
        # +1 so empty cells render as the colormap minimum instead of NaN.
        im = ax.imshow(
            matrix + 1,
            aspect="auto",
            cmap="hot",
            interpolation="nearest",
            norm=LogNorm(vmin=1, vmax=max_hit + 1),
        )
    ax.set_xlabel("Address bin")
    ax.set_ylabel("Lane")
    ax.set_title(f"{title}  (max hit={max_hit})")
    fig.colorbar(im, ax=ax, label="Hit count (+1, log)")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)


def plot_mi_matrix(
    addresses_by_lane: dict[int, list[int]],
    bits: int,
    out: Path,
    title: str = "Reduced-Bit Mutual Information (diagonal masked)",
) -> None:
    all_addrs = []
    for addrs in addresses_by_lane.values():
        all_addrs.extend(addrs)

    if not all_addrs:
        return

    arr = np.array(all_addrs, dtype=np.uint32)
    bit_vectors = np.array([(arr >> b) & 1 for b in range(bits)], dtype=np.float64)

    mi = np.zeros((bits, bits))
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

    # Mask the trivially-1 self-MI diagonal so off-diagonal structure is visible.
    mi_plot = mi.copy()
    np.fill_diagonal(mi_plot, np.nan)
    off_diag_max = float(np.nanmax(mi_plot)) if mi.size > 1 else 0.0

    fig, ax = plt.subplots(figsize=(8, 7))
    cmap = plt.get_cmap("viridis").copy()
    cmap.set_bad("lightgrey")
    im = ax.imshow(mi_plot, cmap=cmap, vmin=0, vmax=max(off_diag_max, 1e-6))
    ax.set_xlabel("Bit")
    ax.set_ylabel("Bit")
    ax.set_title(f"{title}  (off-diag max={off_diag_max:.4f})")
    fig.colorbar(im, ax=ax, label="MI (bits)")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)


def plot_per_pcap_fp_histogram(
    fp_rates: list[float],
    out: Path,
    title: str = "Per-PCAP FP Rate Distribution",
) -> None:
    if not fp_rates:
        return
    arr = np.asarray(fp_rates, dtype=np.float64)
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.hist(arr, bins=40, color="steelblue", edgecolor="black")
    ax.axvline(
        float(arr.mean()), color="red", linestyle="--", label=f"mean={arr.mean():.4f}"
    )
    ax.axvline(
        float(np.median(arr)),
        color="orange",
        linestyle="--",
        label=f"median={np.median(arr):.4f}",
    )
    ax.set_xlabel("Per-packet FP rate")
    ax.set_ylabel("PCAP count")
    ax.set_title(title)
    ax.legend()
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
