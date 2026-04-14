/// @file benchmark_data.hpp
/// @brief Reader for the HPAT binary format (Python <-> C++ data exchange).
///
/// File layout (little-endian):
/// @code
///   Offset  Size   Field
///   ──────  ─────  ────────────────────────────
///    0      4      magic           "HPAT"
///    4      2      version         uint16 (1)
///    6      2      record_size     uint16 (64)
///    8      2      window_size     uint16 (8)
///   10      4      num_records     uint32 (N)
///   ──────  ─────  ────────────────────────────
///   14      2      pattern_len[0]  uint16
///   16      R      record[0]       R = record_size
///   ...     ...    ... repeated N times ...
/// @endcode
///
/// The Python writer lives in scripts/export_hpat.py.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "pattern_selector.hpp"

namespace pattern_selector::benchmark_data {

using Record = std::array<uint8_t, kDefaultRecordSize>;

inline constexpr char kRealPatternFileMagic[4] = {'H', 'P', 'A', 'T'};
inline constexpr std::uint16_t kRealPatternFileVersion = 1;

struct RealDataset {
  std::vector<Record> records;
  std::vector<std::size_t> pattern_lens;
  std::size_t window_size = kDefaultWindowSize;
};

RealDataset load_real_patterns(const std::string& path);

}  // namespace pattern_selector::benchmark_data
