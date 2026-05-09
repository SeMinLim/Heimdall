#pragma once

#include <cstddef>
#include <cstdint>

namespace heimdall::prefilter {

enum class CrcKind {
  crc32,
  crc32c,
};

std::uint32_t crc32_update_32_reflected(std::uint32_t crc,
                                        std::uint32_t data);
std::uint32_t crc32c_update_32_reflected(std::uint32_t crc,
                                         std::uint32_t data);
std::uint32_t crc64_hw_compatible(const std::uint8_t* data, CrcKind kind);
std::uint32_t reduce_crc_to_prefilter_addr(std::uint32_t hash);
const char* crc_kind_name(CrcKind kind);
CrcKind parse_crc_kind(const char* raw);

}  // namespace heimdall::prefilter