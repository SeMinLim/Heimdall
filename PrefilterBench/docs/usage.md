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
   - `offset`: byte offset within the 64-byte record where the best 8-byte window was selected (determines which bloom filter lane this rule populates)
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
├── metrics.json         # machine-readable metrics summary
├── bit_bias.png         # lane × bit position bias heatmap
├── occupancy_stripe.png # lane × address bin hit heatmap
└── mi_matrix.png        # pairwise bit mutual information
```

## Architecture Notes

- **Per-lane filters**: The hardware prefilter uses 57 independent bloom filters (one per extraction lane). A rule selected at offset K populates only lane K's filter. Each lane is sparse (~rules/57 entries).
- **Application-layer payload**: PCAP packets are stripped to application-layer payload (after Ethernet/IP/TCP-UDP headers) before anchor extraction.
- **57 overlapping anchors**: From a 64-byte payload of length L, valid anchors at offset `i` where `i + 8 <= L`, up to 57 lanes maximum.
