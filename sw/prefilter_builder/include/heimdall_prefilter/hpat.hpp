#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>

namespace heimdall::prefilter {

struct HpatRecord {
  std::uint16_t pattern_len = 0;
  std::vector<std::uint8_t> record;
};

struct HpatFile {
  std::uint16_t record_size = 0;
  std::uint16_t window_size = 0;
  std::vector<HpatRecord> records;
};

HpatFile read_hpat(const std::filesystem::path& path);

}  // namespace heimdall::prefilter