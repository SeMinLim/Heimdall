#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#include "heimdall_prefilter/bloom_builder.hpp"

namespace pf = heimdall::prefilter;

namespace {

void print_usage(const char* argv0) {
  std::cerr << "Usage: " << argv0
            << " [--hash crc32|crc32c] <input.hpat> <output.bitset>\n"
            << "\n"
            << "Build a raw 64KiB 1-bit Bloom table for Heimdall's current\n"
            << "hardware prefilter. Bit address A maps to byte A/8, bit A%8.\n";
}

void write_bitset(const std::filesystem::path& path,
                  const pf::BloomBitset& bitset) {
  std::ofstream output(path, std::ios::binary);
  if (!output) {
    throw std::runtime_error("cannot open output bitset: " + path.string());
  }
  output.write(reinterpret_cast<const char*>(bitset.data()),
               static_cast<std::streamsize>(bitset.size()));
  if (!output) {
    throw std::runtime_error("failed to write output bitset: " + path.string());
  }
}

}  // namespace

int main(int argc, char** argv) {
  try {
    pf::CrcKind hash_kind = pf::CrcKind::crc32;
    int arg_index = 1;

    if (argc > arg_index && std::string(argv[arg_index]) == "--help") {
      print_usage(argv[0]);
      return EXIT_SUCCESS;
    }

    if (argc > arg_index && std::string(argv[arg_index]) == "--hash") {
      if (argc <= arg_index + 1) {
        throw std::invalid_argument("missing value after --hash");
      }
      hash_kind = pf::parse_crc_kind(argv[arg_index + 1]);
      arg_index += 2;
    }

    if (argc - arg_index != 2) {
      print_usage(argv[0]);
      return EXIT_FAILURE;
    }

    const std::filesystem::path input_path(argv[arg_index]);
    const std::filesystem::path output_path(argv[arg_index + 1]);

    const auto hpat = pf::read_hpat(input_path);
    pf::BloomBuildStats stats;
    const auto bitset = pf::build_bloom_bitset(hpat, hash_kind, &stats);
    write_bitset(output_path, bitset);

    std::cout << "[Heimdall Prefilter Builder]\n";
    std::cout << "  HPAT:        " << input_path << "\n";
    std::cout << "  Output:      " << output_path << "\n";
    std::cout << "  Hash:        " << pf::crc_kind_name(hash_kind) << "\n";
    std::cout << "  Records:     " << stats.records << "\n";
    std::cout << "  Skipped:     " << stats.skipped_short_records << "\n";
    std::cout << "  Windows:     " << stats.windows_hashed << "\n";
    std::cout << "  Bits set:    " << stats.new_bits_set << "\n";
    std::cout << "  Duplicates:  " << stats.duplicate_bit_sets << "\n";
    std::cout << "  Bitset size: " << bitset.size() << " bytes\n";
    return EXIT_SUCCESS;
  } catch (const std::exception& ex) {
    std::cerr << "ERROR: " << ex.what() << "\n";
    return EXIT_FAILURE;
  }
}