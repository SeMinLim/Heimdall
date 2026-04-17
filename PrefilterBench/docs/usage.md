# PrefilterBench Usage Guide

## Overview

PrefilterBench is an offline benchmarking tool that evaluates how IPS representative patterns interact with bloom-filter-based prefilter address spaces. It measures collision behavior, false positive rates, and hash quality before hardware decisions are fixed.

## Prerequisites

### PatternSelector

PrefilterBench consumes **selected 8-byte representative patterns** produced by the PatternSelector C++ reference implementation. PrefilterBench does not re-implement pattern scoring or selection logic; PatternSelector is the upstream producer.

The data pipeline is:

```text
IPS XLSX workbook
  -> PatternSelector/scripts/export_hpat.py  (XLSX -> HPAT binary)
  -> PatternSelector/reference/pattern_selector --export-json  (HPAT -> JSON)
  -> PrefilterBench  (JSON -> bloom filter experiments)
```

### Generating Rule Input

1. **Export HPAT binary from IPS workbook:**

   ```bash
   cd PatternSelector/scripts
   uv run export_hpat.py --ips-xlsx path/to/workbook.xlsx --output ../data/real_patterns.bin
   ```

2. **Build PatternSelector:**

   ```bash
   cd PatternSelector/reference
   make
   ```

3. **Export selected patterns as JSON:**

   ```bash
   ./pattern_selector --export-json ../data/real_patterns.bin > selected_rules.json
   ```

   Output format:
   ```json
   [
     {"index": 0, "offset": 12, "pattern_hex": "deadbeefcafebabe", "score": 0.8421},
     {"index": 1, "offset": 5,  "pattern_hex": "0102030405060708", "score": 0.7632}
   ]
   ```

   Each record contains:
   - `index`: record index in the original HPAT dataset
   - `offset`: byte offset within the 64-byte record where the best 8-byte window was selected
   - `pattern_hex`: the selected 8-byte representative pattern in hex
   - `score`: composite quality score from the selection model

4. **Alternative: hex-list format** (for fixtures and debugging)

   If you don't have real IPS data, you can create a simple text file:
   ```
   # offset pattern_hex
   0 DEADBEEFCAFEBABE
   3 0102030405060708
   10 AABBCCDD11223344
   ```

## Running an Experiment

```bash
cd PrefilterBench

# With real rules (JSON from PatternSelector)
uv run python scripts/run_experiment.py \
  --hash crc32 \
  --reduce truncate \
  --bits 19 \
  --rules ../PatternSelector/reference/selected_rules.json \
  --rules-format json \
  --packets synthetic_uniform \
  --packet-count 10000 \
  --output experiments/results/crc32_truncate_19

# With fixture rules (hex-list)
uv run python scripts/run_experiment.py \
  --hash crc32c \
  --reduce xor_fold_overlap \
  --bits 19 \
  --rules path/to/rules.txt \
  --rules-format hex_list \
  --packets synthetic_ascii \
  --packet-count 5000 \
  --output experiments/results/crc32c_xor_ascii

# With PCAP traffic
uv run python scripts/run_experiment.py \
  --hash crc32 \
  --reduce xor_fold_kway \
  --bits 19 \
  --rules path/to/rules.json \
  --rules-format json \
  --packets path/to/capture.pcap \
  --output experiments/results/crc32_kway_pcap
```

### CLI Options

| Flag | Values | Description |
|------|--------|-------------|
| `--hash` | `crc32`, `crc32c` | Hash function |
| `--reduce` | `truncate`, `xor_fold_overlap`, `xor_fold_kway`, `xor_fold_16` | 32-bit to N-bit reduction |
| `--bits` | 17–20 (typically 19) | Bloom filter address width |
| `--rules` | path | Rule patterns file |
| `--rules-format` | `hex_list`, `json` | Rule file format |
| `--packets` | `synthetic_uniform`, `synthetic_ascii`, `synthetic_mixed`, or pcap path | Packet source |
| `--packet-count` | int | Number of synthetic packets |
| `--packet-seed` | int | RNG seed for synthetic traffic |
| `--short-ratio` | float | Short packet fraction (for `synthetic_mixed`) |
| `--output` | path | Output directory for results and plots |

### Reduction Strategies

- **truncate**: Extract lower N bits. `addr = hash & ((1 << N) - 1)`
- **xor_fold_overlap**: XOR two overlapping N-bit windows. `hash[0:N] ^ hash[32-N:32]`
- **xor_fold_kway**: Split 32 bits into `ceil(32/N)` chunks, XOR all.
- **xor_fold_16**: Fold 32->16 bits first, then truncate to N. Only supports N <= 16.

## Output

Each experiment writes to the specified output directory:

```
results/
├── metrics.json         # self-describing report (see structure below)
├── bit_bias.png         # lane × bit position bias heatmap (auto-zoomed, diverging)
├── occupancy_stripe.png # lane × address bin hit heatmap (log scale)
└── mi_matrix.png        # pairwise bit mutual information (diagonal masked)
```

Batch runs (`--packets` = directory) additionally produce:
- `summary.json` — batch-level headline + per-PCAP table (per-PCAP mode)
- `per_pcap_fp_hist.png` — distribution of per-PCAP FP rates (per-PCAP mode)
- one subdirectory per PCAP with its own `metrics.json` + plots (per-PCAP mode)

### `metrics.json` structure

Every report is self-describing — it carries the full config, provenance, and
human-readable summary stats so results can be interpreted without any external
context:

```jsonc
{
  "config":    { "hash_fn": "crc32", "reduce_fn": "truncate", "address_bits": 19, ... },
  "provenance": { "timestamp_utc": "...", "git_sha": "...", "pfbench_version": "...",
                  "python_version": "...", "platform": "..." },
  "inputs":    { "rules_count": 500, "packets_count": 13843, ... },
  "headline":  {
    "fill_rate": 0.000954,
    "per_packet_fp_rate": 0.0614,
    "theoretical_fp_lower_bound": 0.0529,      // 1 - (1-fill)^57
    "fp_overhead_vs_theoretical": 1.16,        // observed / lower bound
    "rule_collisions": 0
  },
  "metrics":   { "fill_rate": ..., "per_lane_fp_rates": [...57 floats...], ... },
  "summary":   {
    "per_lane_fp": { "mean": ..., "std": ..., "max": ..., "argmax_lane": 4,
                     "top3_lanes": [[4, 0.0038], ...] },
    "occupancy":   { "total_slots": 524288, "nonzero_slots": 247774,
                     "max_hits": 8314, "p50_hits_nonzero": 1, "p95_hits_nonzero": 5,
                     "top_k_addrs": [[188265, 8314], ...] }
  }
}
```

The `headline` block is the primary thing to read; `summary` answers "which lane
is worst?" and "how skewed is the address space?" without ever dumping the raw
524K-slot occupancy array.

## Experiment Design

### Two kinds of "collision"

PrefilterBench measures two distinct phenomena that are sometimes both called "collision":

**A) Rule-Rule Collision** - different rule patterns that hash to the same bloom filter address. This raises the filter's fill rate (fraction of 1-bits), which in turn raises the probability of false positives. Measurable from the rule set alone, no packets needed. Reported as `rule_collisions` in `metrics.json`.

**B) Packet-Rule False Positive** - a packet anchor hashes to an address that is set to 1, but the packet does not actually match any rule. This is the metric that directly impacts IPS throughput. Requires both rules and packet traffic. Reported as `per_lane_fp_rates` and `per_packet_fp_rate`.

A and B are correlated but not equivalent: high rule collision does not guarantee high packet FP (if real traffic avoids those addresses), and low collision does not guarantee low FP (if traffic clusters around occupied addresses).

### Exploration axes

| Axis | Variable | Values | Rationale |
|------|----------|--------|-----------|
| Hash function | `--hash` | `crc32`, `crc32c` | 1st / 2nd prefilter use different hash functions |
| Reduction | `--reduce` | `truncate`, `xor_fold_overlap`, `xor_fold_kway`, `xor_fold_16` | Different 32→N bit mappings affect address uniformity |
| Address bits | `--bits` | 17, 18, 19, 20 | BRAM/URAM budget trade-off (see table below) |
| Rule set | `--rules` | Real IPS rules (500), scaled-up sets (4K, 16K, 64K) | Fill rate scales with rule count |
| Packet traffic | `--packets` | Real PCAP, `synthetic_uniform`, `synthetic_ascii`, `synthetic_mixed` | FP rate depends on traffic distribution |

### Address bits vs. hardware cost

| Bits | Slots | Memory per copy | ×57 copies | 500-rule fill rate |
|------|-------|-----------------|------------|-------------------|
| 17 | 128K | 16 KB | 0.9 MB | ~0.4% |
| 18 | 256K | 32 KB | 1.8 MB | ~0.2% |
| **19** | **512K** | **64 KB** | **3.6 MB** | **~0.1%** |
| 20 | 1M | 128 KB | 7.1 MB | ~0.05% |

At 4K rules, fill rates are roughly 8× higher. The optimal bit width depends on the target FPGA's BRAM/URAM budget.

### Metrics summary

| Metric | Requires | What it tells you |
|--------|----------|-------------------|
| **Fill rate** | Rules only | Fraction of bloom filter slots set to 1 — baseline collision density |
| **Rule collisions** | Rules only | Number of address-space collisions between distinct rules |
| **Per-lane FP rate** | Rules + Packets | Per extraction-offset false hit rate — reveals position-dependent traffic bias |
| **Per-packet FP rate** | Rules + Packets | Fraction of packets with ≥1 false hit across all 57 lanes — the end metric for IPS throughput impact |

## Architecture Notes

### Hardware prefilter design

The Heimdall hardware prefilter extracts up to **57 overlapping 8-byte anchors** from each incoming packet's application-layer payload (sliding window at offsets 0–56). Every anchor is looked up in a bloom filter to decide whether the packet might match any IPS rule.

To perform all 57 lookups in a single cycle, the hardware physically **replicates the bloom filter 57 times** — one copy per extraction lane. All 57 copies are **identical**: every rule pattern's hash address is written to every copy during the offline programming phase. The replication is purely a throughput optimization; logically there is one shared filter.

### What PrefilterBench models

Since all 57 hardware copies contain the same bits, PrefilterBench maintains **a single bloom filter** (one bit array of $2^N$ slots). All selected rule patterns(substrings) are inserted into this one filter, and all 57 packet anchors are queried against it.

- **Rule insertion**: `hash(pattern) → addr`, set `filter[addr] = 1`. The `offset` field from PatternSelector records where the 8-byte window was selected within the 64-byte rule record; it is stored for traceability but does not affect the bloom filter.
- **Packet query**: For each packet, extract anchors at offsets 0 through `min(payload_len - 8, 56)`. Each anchor is hashed and looked up in the same filter. A packet is flagged if **any** anchor matches.
- **Application-layer payload**: PCAP packets are stripped to their application-layer payload (past Ethernet / IP / TCP-UDP headers) before anchor extraction.
