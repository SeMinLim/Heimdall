#include "heimdall_prefilter/hpat.hpp"

#include <array>
#include <fstream>
#include <stdexcept>
#include <string>

namespace heimdall::prefilter {
namespace {

constexpr std::array<char, 4> kMagic{'H', 'P', 'A', 'T'};
constexpr std::uint16_t kSupportedVersion = 1;
constexpr std::size_t kHeaderBytes = 14;

std::uint16_t read_le16(const std::vector<std::uint8_t>& data,
                        std::size_t offset) {
  return static_cast<std::uint16_t>(data[offset]) |
         static_cast<std::uint16_t>(data[offset + 1] << 8);
}

std::uint32_t read_le32(const std::vector<std::uint8_t>& data,
                        std::size_t offset) {
  return static_cast<std::uint32_t>(data[offset]) |
         (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
         (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
         (static_cast<std::uint32_t>(data[offset + 3]) << 24);
}

std::vector<std::uint8_t> read_all(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input) {
    throw std::runtime_error("cannot open HPAT file: " + path.string());
  }

  const auto size = input.tellg();
  if (size < 0) {
    throw std::runtime_error("cannot determine HPAT file size: " +
                             path.string());
  }
  input.seekg(0);

  std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
  if (!data.empty() &&
      !input.read(reinterpret_cast<char*>(data.data()),
                  static_cast<std::streamsize>(data.size()))) {
    throw std::runtime_error("failed to read HPAT file: " + path.string());
  }
  return data;
}

}  // namespace

HpatFile read_hpat(const std::filesystem::path& path) {
  const auto data = read_all(path);
  if (data.size() < kHeaderBytes) {
    throw std::runtime_error("HPAT file is shorter than its 14-byte header");
  }
  for (std::size_t i = 0; i < kMagic.size(); ++i) {
    if (static_cast<char>(data[i]) != kMagic[i]) {
      throw std::runtime_error("invalid HPAT magic");
    }
  }

  const std::uint16_t version = read_le16(data, 4);
  if (version != kSupportedVersion) {
    throw std::runtime_error("unsupported HPAT version: " +
                             std::to_string(version));
  }

  HpatFile hpat;
  hpat.record_size = read_le16(data, 6);
  hpat.window_size = read_le16(data, 8);
  const std::uint32_t num_records = read_le32(data, 10);

  if (hpat.record_size == 0) {
    throw std::runtime_error("HPAT record_size must be positive");
  }
  if (hpat.window_size == 0 || hpat.window_size > hpat.record_size) {
    throw std::runtime_error("invalid HPAT window_size");
  }

  const std::size_t entry_size = 2 + hpat.record_size;
  const std::size_t expected_size =
      kHeaderBytes + static_cast<std::size_t>(num_records) * entry_size;
  if (data.size() != expected_size) {
    throw std::runtime_error("HPAT file size mismatch: expected " +
                             std::to_string(expected_size) + ", got " +
                             std::to_string(data.size()));
  }

  hpat.records.reserve(num_records);
  std::size_t offset = kHeaderBytes;
  for (std::uint32_t index = 0; index < num_records; ++index) {
    HpatRecord record;
    record.pattern_len = read_le16(data, offset);
    offset += 2;
    if (record.pattern_len > hpat.record_size) {
      throw std::runtime_error("HPAT pattern_len exceeds record_size at entry " +
                               std::to_string(index));
    }
    record.record.assign(data.begin() + static_cast<std::ptrdiff_t>(offset),
                         data.begin() +
                             static_cast<std::ptrdiff_t>(offset +
                                                         hpat.record_size));
    offset += hpat.record_size;
    hpat.records.push_back(std::move(record));
  }

  return hpat;
}

}  // namespace heimdall::prefilter