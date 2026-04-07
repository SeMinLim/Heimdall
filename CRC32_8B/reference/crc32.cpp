#include "crc32.h"

#define POLY32 0xEDB88320u   // Reflected polynomial for CRC32 (IEEE 802.3)
#define POLY32C 0x82F63B78u  // Reflected polynomial for CRC32C (Castagnoli)

static uint32_t crc32_table[256];
static uint32_t crc32c_table[256];
static bool tables_initialized = false;

static void build_table(uint32_t table[256], uint32_t poly) {
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t crc = i;
    for (int j = 0; j < 8; j++) crc = (crc >> 1) ^ ((crc & 1) ? poly : 0);
    table[i] = crc;
  }
}

static void ensure_tables() {
  if (!tables_initialized) {
    build_table(crc32_table, POLY32);
    build_table(crc32c_table, POLY32C);
    tables_initialized = true;
  }
}

uint32_t crc32(const uint8_t* data, size_t len) {
  ensure_tables();
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < len; i++)
    crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFF];
  return crc ^ 0xFFFFFFFFu;
}

uint32_t crc32c(const uint8_t* data, size_t len) {
  ensure_tables();
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < len; i++)
    crc = (crc >> 8) ^ crc32c_table[(crc ^ data[i]) & 0xFF];
  return crc ^ 0xFFFFFFFFu;
}
