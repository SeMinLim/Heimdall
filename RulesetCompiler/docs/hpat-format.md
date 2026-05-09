# HPAT v1 Format

HPAT is Heimdall's fixed-size pattern dataset format. It is used to move
prefilter pattern records from RulesetCompiler into benchmark and
hardware-facing experiments.

HPAT is not a general Snort, Suricata, or custom rule format. It does not encode
full rule semantics, parser state, actions, SIDs, match contexts, hash tables,
or FPGA loader sections. Those belong in the RulesetCompiler IR and manifest, or
in a future hardware image format if the project grows beyond this simple data
exchange need.

## Current Role

The current compiler pipeline is intentionally split into two layers:

```text
source rules -> RulesetCompiler IR/manifest -> HPAT v1 pattern records
```

The IR and manifest preserve source-level information such as rule provenance,
match context, unsupported features, selected anchors, and scoring metadata.
HPAT keeps only the bytes needed by fixed-record benchmark or loader consumers.

Current producers:

- `RulesetCompiler/ruleset_compiler/emit_hpat.py`
- `RulesetCompiler` CLI with `--hpat`


## Binary Layout

All multi-byte integer fields are little-endian.

```text
Offset  Size   Field
------  -----  --------------------------------
0       4      magic        ASCII "HPAT"
4       2      version      uint16, currently 1
6       2      record_size  uint16, usually 64
8       2      window_size  uint16, usually 8
10      4      num_records  uint32
------  -----  --------------------------------
14      2      pattern_len[0]  uint16
16      R      record[0]       R = record_size bytes
16+R    2      pattern_len[1]  uint16
18+R    R      record[1]
...     ...    repeated num_records times
```

Header size is 14 bytes. Each entry is `2 + record_size` bytes, so the expected
file size is:

```text
14 + num_records * (2 + record_size)
```

## Field Semantics

`magic`
: Must be the ASCII bytes `HPAT`.

`version`
: Format version. The only supported version is `1`.

`record_size`
: Fixed byte length of every record slot. The current repository convention is
64 bytes, and RulesetCompiler mirrors that convention with `record_size=64`
defaults in both anchor selection and HPAT emission.

`window_size`
: Candidate window width used by fixed-record consumers. The default is 8.
Readers should reject `window_size == 0` and `window_size > record_size`.

`num_records`
: Number of entries following the header.

`pattern_len`
: Number of valid bytes at the beginning of `record`. The remaining bytes are
padding and must not be scored as real pattern bytes. Readers should reject
`pattern_len > record_size`.

`record`
: A fixed-size slot containing pattern bytes followed by zero padding. Writers
clip patterns longer than `record_size` before padding.

## Writer Policy

The RulesetCompiler HPAT writer serializes `RulesetIR.patterns` as records.
Patterns shorter than `window_size` are skipped because they cannot provide one
full candidate window.

The meaning of `RulesetIR.patterns` depends on the parser that created the IR:

- IPS workbook input stores source literal bytes, clipped or padded to the HPAT
  record size.
- Snort input stores one selected rule-level `SNORT_RULE_ANCHOR` per rule that
  has a usable positive content anchor. This is necessary because multiple
  `content` clauses in one Snort rule are AND conditions.

By default, `nocase` patterns are ASCII-lowercased during HPAT emission. This is
an emitter policy, not part of the core anchor selection algorithm. Passing
`--case-sensitive-hpat` to the RulesetCompiler CLI disables that normalization.

## Reader Requirements

Readers should validate at least these conditions before consuming records:

- `magic == "HPAT"`
- `version == 1`
- `record_size` is supported by the reader
- `0 < window_size <= record_size`
- each `pattern_len <= record_size`
- each record payload is exactly `record_size` bytes

Consumers that run window scoring or matching must use `pattern_len` to exclude
zero padding from candidate windows.

## Example

A file with one 8-byte pattern, `record_size = 64`, and `window_size = 8` has:

```text
Header:
  magic        = "HPAT"
  version      = 1
  record_size  = 64
  window_size  = 8
  num_records  = 1

Entry 0:
  pattern_len  = 8
  record       = 41 42 43 44 45 46 47 48 00 00 ... 00
                 A  B  C  D  E  F  G  H  zero padding to 64 bytes
```

## Non-goals

HPAT v1 deliberately does not contain:

- source rule text or source file hashes
- Snort SID/GID/rev, Suricata metadata, or custom IDs
- action, severity, enable/disable state, or unsupported feature reasons
- match context such as HTTP URI, header, direction, stream scope, or protocol
- selected-anchor scores or alternative candidates
- CRC, Bloom table, bucket layout, or FPGA profile data
- extension sections or nested binary containers

If future hardware loaders need more than fixed pattern records, add a separate
hardware image format instead of turning HPAT into a universal rule container.