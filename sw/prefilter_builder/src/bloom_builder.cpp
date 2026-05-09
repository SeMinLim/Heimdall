#include "heimdall_prefilter/bloom_builder.hpp"

#include <algorithm>
#include <stdexcept>

namespace heimdall::prefilter {
namespace {

void set_bit(BloomBitset& bitset, std::uint32_t addr,
             BloomBuildStats* stats) {
  const std::size_t byte_index = addr >> 3;
  const std::uint8_t bit_mask = static_cast<std::uint8_t>(1u << (addr & 7u));
  if ((bitset[byte_index] & bit_mask) == 0) {
    bitset[byte_index] |= bit_mask;
    if (stats) {
      stats->new_bits_set++;
    }
  } else if (stats) {
    stats->duplicate_bit_sets++;
  }
}

}  // namespace

BloomBitset build_bloom_bitset(const HpatFile& hpat, CrcKind kind,
                               BloomBuildStats* stats) {
  if (hpat.window_size != kHardwareWindowBytes) {
    throw std::runtime_error("HPAT window_size must be 8 for current hardware");
  }

  BloomBitset bitset{};
  if (stats) {
    *stats = BloomBuildStats{};
    stats->records = hpat.records.size();
  }

  for (const auto& record : hpat.records) {
    const std::size_t valid_len = std::min<std::size_t>(
        record.pattern_len, record.record.size());
    if (valid_len < kHardwareWindowBytes) {
      if (stats) {
        stats->skipped_short_records++;
      }
      continue;
    }

    for (std::size_t offset = 0; offset + kHardwareWindowBytes <= valid_len;
         ++offset) {
      const std::uint32_t hash =
          crc64_hw_compatible(record.record.data() + offset, kind);
      const std::uint32_t addr = reduce_crc_to_prefilter_addr(hash);
      set_bit(bitset, addr, stats);
      if (stats) {
        stats->windows_hashed++;
      }
    }
  }

  return bitset;
}

}  // namespace heimdall::prefilter