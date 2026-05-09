#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "heimdall_prefilter/crc_hw.hpp"
#include "heimdall_prefilter/hpat.hpp"

namespace heimdall::prefilter {

inline constexpr std::size_t kHardwareWindowBytes = 8;
inline constexpr std::size_t kPrefilterAddrBits = 19;
inline constexpr std::size_t kPrefilterBitCount = std::size_t{1}
                                                  << kPrefilterAddrBits;
inline constexpr std::size_t kPrefilterByteCount = kPrefilterBitCount / 8;

using BloomBitset = std::array<std::uint8_t, kPrefilterByteCount>;

struct BloomBuildStats {
  std::size_t records = 0;
  std::size_t skipped_short_records = 0;
  std::size_t windows_hashed = 0;
  std::size_t new_bits_set = 0;
  std::size_t duplicate_bit_sets = 0;
};

BloomBitset build_bloom_bitset(const HpatFile& hpat, CrcKind kind,
                               BloomBuildStats* stats);

}  // namespace heimdall::prefilter