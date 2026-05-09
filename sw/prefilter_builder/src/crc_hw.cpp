#include "heimdall_prefilter/crc_hw.hpp"

#include <cstring>
#include <stdexcept>
#include <string>

namespace heimdall::prefilter {
namespace {

constexpr std::uint32_t kCrc32PolyReflected = 0xEDB88320u;
constexpr std::uint32_t kCrc32cPolyReflected = 0x82F63B78u;
constexpr std::uint32_t kCrcInit = 0xFFFFFFFFu;

std::uint32_t read_le32(const std::uint8_t* data) {
  return static_cast<std::uint32_t>(data[0]) |
         (static_cast<std::uint32_t>(data[1]) << 8) |
         (static_cast<std::uint32_t>(data[2]) << 16) |
         (static_cast<std::uint32_t>(data[3]) << 24);
}

std::uint32_t update_32_reflected(std::uint32_t crc, std::uint32_t data,
                                  std::uint32_t polynomial) {
  for (int bit = 0; bit < 32; ++bit) {
    const bool feedback = ((crc ^ (data >> bit)) & 1u) != 0;
    crc >>= 1;
    if (feedback) {
      crc ^= polynomial;
    }
  }
  return crc;
}

}  // namespace

std::uint32_t crc32_update_32_reflected(std::uint32_t crc,
                                        std::uint32_t data) {
  return update_32_reflected(crc, data, kCrc32PolyReflected);
}

std::uint32_t crc32c_update_32_reflected(std::uint32_t crc,
                                         std::uint32_t data) {
  return update_32_reflected(crc, data, kCrc32cPolyReflected);
}

std::uint32_t crc64_hw_compatible(const std::uint8_t* data, CrcKind kind) {
  // Keep this algorithm identical to bluelibrary/bsv/CRC32.bsv:
  // mkCRC32/mkCRC32C use reflected 32-bit updates, process lo32 then hi32
  // from the 64-bit anchor, initialize with 0xFFFFFFFF, and do not apply a
  // final XOR. The hardware URL of record is:
  // https://github.com/SeMinLim/bluelibrary/blob/main/bsv/CRC32.bsv
  const std::uint32_t lo32 = read_le32(data);
  const std::uint32_t hi32 = read_le32(data + 4);

  switch (kind) {
    case CrcKind::crc32:
      return crc32_update_32_reflected(
          crc32_update_32_reflected(kCrcInit, lo32), hi32);
    case CrcKind::crc32c:
      return crc32c_update_32_reflected(
          crc32c_update_32_reflected(kCrcInit, lo32), hi32);
  }
  throw std::logic_error("unreachable CRC kind");
}

std::uint32_t reduce_crc_to_prefilter_addr(std::uint32_t hash) {
  constexpr std::uint32_t mask19 = (std::uint32_t{1} << 19) - 1;
  return (hash & mask19) ^ ((hash >> 13) & mask19);
}

const char* crc_kind_name(CrcKind kind) {
  switch (kind) {
    case CrcKind::crc32:
      return "crc32";
    case CrcKind::crc32c:
      return "crc32c";
  }
  return "unknown";
}

CrcKind parse_crc_kind(const char* raw) {
  const std::string value(raw ? raw : "");
  if (value == "crc32") {
    return CrcKind::crc32;
  }
  if (value == "crc32c") {
    return CrcKind::crc32c;
  }
  throw std::invalid_argument("--hash must be either 'crc32' or 'crc32c'");
}

}  // namespace heimdall::prefilter