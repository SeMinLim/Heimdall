#include "benchmark_data.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>

namespace {

template <typename T>
void read_or_die(std::ifstream& stream, T& value, const std::string& path,
                 const char* label) {
  if (!stream.read(reinterpret_cast<char*>(&value), sizeof(value))) {
    std::fprintf(stderr, "Failed to read %s from %s\n", label, path.c_str());
    std::exit(1);
  }
}

void read_bytes_or_die(std::ifstream& stream, char* buffer,
                       std::streamsize size, const std::string& path,
                       const char* label) {
  if (!stream.read(buffer, size)) {
    std::fprintf(stderr, "Failed to read %s from %s\n", label, path.c_str());
    std::exit(1);
  }
}

}  // namespace

namespace pattern_selector::benchmark_data {

RealDataset load_real_patterns(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    std::fprintf(stderr, "Cannot open %s\n", path.c_str());
    std::exit(1);
  }

  char magic[4] = {};
  std::uint16_t version = 0;
  std::uint16_t record_size = 0;
  std::uint16_t window_size = 0;
  std::uint32_t num_records = 0;

  read_bytes_or_die(stream, magic, sizeof(magic), path, "file magic");
  for (std::size_t i = 0; i < sizeof(kRealPatternFileMagic); ++i) {
    if (magic[i] != kRealPatternFileMagic[i]) {
      std::fprintf(stderr, "Unsupported binary format in %s\n", path.c_str());
      std::exit(1);
    }
  }

  read_or_die(stream, version, path, "file version");
  read_or_die(stream, record_size, path, "record size");
  read_or_die(stream, window_size, path, "window size");
  read_or_die(stream, num_records, path, "record count");

  if (version != kRealPatternFileVersion) {
    std::fprintf(stderr, "Unsupported binary version %u in %s\n", version,
                 path.c_str());
    std::exit(1);
  }
  if (record_size != kDefaultRecordSize) {
    std::fprintf(stderr, "Unexpected record size %u in %s\n", record_size,
                 path.c_str());
    std::exit(1);
  }
  if (window_size == 0 || window_size > record_size) {
    std::fprintf(stderr, "Invalid window size %u in %s\n", window_size,
                 path.c_str());
    std::exit(1);
  }

  RealDataset dataset;
  dataset.records.resize(num_records);
  dataset.pattern_lens.resize(num_records);
  dataset.window_size = window_size;

  for (std::uint32_t i = 0; i < num_records; ++i) {
    std::uint16_t pattern_len = 0;
    read_or_die(stream, pattern_len, path, "pattern length");
    read_bytes_or_die(stream,
                      reinterpret_cast<char*>(dataset.records[i].data()),
                      static_cast<std::streamsize>(kDefaultRecordSize), path,
                      "record payload");

    if (pattern_len > kDefaultRecordSize) {
      std::fprintf(stderr, "Invalid pattern length %u in %s\n", pattern_len,
                   path.c_str());
      std::exit(1);
    }
    dataset.pattern_lens[i] = pattern_len;
  }

  return dataset;
}

}  // namespace pattern_selector::benchmark_data