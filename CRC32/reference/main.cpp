#include <cstdint>
#include <cstdio>

#include "crc32.h"

static bool verify(const char* label, uint32_t got, uint32_t expected) {
  if (got == expected) {
    printf("  PASS  %s: 0x%08X\n", label, got);
    return true;
  }
  printf("  FAIL  %s: 0x%08X (expected 0x%08X)\n", label, got, expected);
  return false;
}

int main() {
  // RFC 3720 / iSCSI test vector: CRC32C("123456789") = 0xE3069283
  // IEEE 802.3 test vector:       CRC32 ("123456789") = 0xCBF43926
  const uint8_t tv[] = "123456789";
  const size_t len = 9;

  printf("CRC32 reference test\n");
  bool ok = true;
  ok &= verify("CRC32  (\"123456789\")", crc32(tv, len),  0xCBF43926u);
  ok &= verify("CRC32C (\"123456789\")", crc32c(tv, len), 0xE3069283u);

  // 8-byte anchor golden values for HW verification
  const uint8_t anchor[8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
  printf("\n8-byte anchor hash\n");
  printf("  CRC32  = 0x%08X\n", crc32(anchor, 8));
  printf("  CRC32C = 0x%08X\n", crc32c(anchor, 8));

  return ok ? 0 : 1;
}
