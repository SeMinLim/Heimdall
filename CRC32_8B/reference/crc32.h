#pragma once

#include <cstddef>
#include <cstdint>

uint32_t crc32(const uint8_t* data, size_t len);

uint32_t crc32c(const uint8_t* data, size_t len);
