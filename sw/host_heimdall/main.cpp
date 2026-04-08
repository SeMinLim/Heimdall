#include <xrt/experimental/xrt_xclbin.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "xrt/xrt_bo.h"
#include "xrt/xrt_device.h"
#include "xrt/xrt_kernel.h"

#define DEVICE_ID 0

static constexpr size_t PACKET_BYTES = 64;
static constexpr size_t WORD_BYTES = 64;  // 512-bit device memory word
static constexpr int NUM_LANES = 57;

using namespace std;

// SW reference CRC32 (matches bluelibrary mkCRC32)
static uint32_t crc32_reflected_32(uint32_t crc, uint32_t word) {
  for (int i = 0; i < 32; ++i) {
    uint32_t fb = (crc ^ (word >> i)) & 1u;
    crc >>= 1;
    if (fb) crc ^= 0xEDB88320u;
  }
  return crc;
}

// CRC32 of a 64-bit value: init=0xFFFFFFFF, process lo32 then hi32
static uint32_t crc32_64bit(uint64_t data) {
  uint32_t lo32 = static_cast<uint32_t>(data & 0xFFFFFFFF);
  uint32_t hi32 = static_cast<uint32_t>(data >> 32);
  uint32_t mid = crc32_reflected_32(0xFFFFFFFFu, lo32);
  return crc32_reflected_32(mid, hi32);
}

// Compute XOR checksum of 57-lane CRC32 hashes for a 64-byte packet
static uint32_t sw_xor_checksum(const uint8_t* pkt, size_t len) {
  int nValid = (len >= 8) ? static_cast<int>(len) - 7 : 0;
  if (nValid > NUM_LANES) nValid = NUM_LANES;

  uint32_t xorAcc = 0;
  for (int i = 0; i < nValid; i++) {
    uint64_t anchor;
    memcpy(&anchor, pkt + i, 8);  // little-endian
    xorAcc ^= crc32_64bit(anchor);
  }
  return xorAcc;
}

int main(int argc, char** argv) {
  if (argc < 3) {
    cout << "Usage: " << argv[0] << " <XCLBIN> <packet_file>" << endl;
    cout << "  packet_file : binary file with N x 64-byte packets" << endl;
    return EXIT_FAILURE;
  }

  string xclbin_file = argv[1];
  string packet_file = argv[2];

  // Read packet data
  ifstream pf(packet_file, ios::binary | ios::ate);
  if (!pf.is_open()) {
    cerr << "ERROR: cannot open packet file: " << packet_file << endl;
    return EXIT_FAILURE;
  }
  size_t pkt_size = pf.tellg();
  if (pkt_size == 0 || (pkt_size % PACKET_BYTES) != 0) {
    cerr << "ERROR: packet file size must be a multiple of " << PACKET_BYTES
         << " bytes" << endl;
    return EXIT_FAILURE;
  }
  uint32_t num_packets = static_cast<uint32_t>(pkt_size / PACKET_BYTES);
  pf.seekg(0);
  vector<uint8_t> pkt_data(pkt_size);
  pf.read(reinterpret_cast<char*>(pkt_data.data()), pkt_size);
  pf.close();

  cout << "[Heimdall CRC32 57-Lane Benchmark]" << endl;
  cout << "  Packets: " << packet_file << " (" << num_packets << " x 64B)"
       << endl;

  // Buffer layout:
  //   Input  = N x 64B packets
  //   Output = (N+1) x 64B words (header + N checksums)
  size_t in_bytes = num_packets * PACKET_BYTES;
  size_t out_bytes = (num_packets + 1) * WORD_BYTES;

  cout << "  Loading XCLBIN: " << xclbin_file << endl;
  xrt::device device = xrt::device(DEVICE_ID);
  xrt::uuid xclbin_uuid = device.load_xclbin(xclbin_file);
  auto krnl = xrt::kernel(device, xclbin_uuid, "kernel:{kernel_1}");

  // Allocate & fill buffers
  auto boIn = xrt::bo(device, in_bytes, krnl.group_id(1));
  auto boOut = xrt::bo(device, out_bytes, krnl.group_id(2));

  auto in_map = boIn.map<uint8_t*>();
  auto out_map = boOut.map<uint8_t*>();

  memset(in_map, 0, in_bytes);
  memset(out_map, 0, out_bytes);
  memcpy(in_map, pkt_data.data(), pkt_size);

  // Run kernel
  boIn.sync(XCL_BO_SYNC_BO_TO_DEVICE);

  cout << "  Running kernel with " << num_packets << " packets..." << endl;
  auto run = krnl(num_packets, boIn, boOut);
  run.wait();
  cout << "  Kernel done." << endl;

  // Read results
  boOut.sync(XCL_BO_SYNC_BO_FROM_DEVICE);

  // Word 0 = cycle counter header
  uint32_t cycleStart, cycleAllFed, cycleFirstOut, cycleAllDone, hwNumPkts;
  uint32_t leTsPut, leTsFeed, leTsDrain, leTsCollect;
  memcpy(&cycleStart, out_map + 0, 4);
  memcpy(&cycleAllFed, out_map + 4, 4);
  memcpy(&cycleFirstOut, out_map + 8, 4);
  memcpy(&cycleAllDone, out_map + 12, 4);
  memcpy(&hwNumPkts, out_map + 16, 4);
  memcpy(&leTsPut, out_map + 20, 4);
  memcpy(&leTsFeed, out_map + 24, 4);
  memcpy(&leTsDrain, out_map + 28, 4);
  memcpy(&leTsCollect, out_map + 32, 4);

  cout << endl;
  cout << "=== Cycle Counter Report ===" << endl;
  cout << "  cycleStart    = " << cycleStart << endl;
  cout << "  cycleAllFed   = " << cycleAllFed << endl;
  cout << "  cycleFirstOut = " << cycleFirstOut << endl;
  cout << "  cycleAllDone  = " << cycleAllDone << endl;
  cout << "  numPackets    = " << hwNumPkts << endl;
  cout << endl;

  cout << "=== LongEngine Per-Stage Breakdown (first packet, lane 0) ==="
       << endl;
  cout << "  tsPut         = " << leTsPut << endl;
  cout << "  tsFeed        = " << leTsFeed << endl;
  cout << "  tsDrain       = " << leTsDrain << endl;
  cout << "  tsCollect     = " << leTsCollect << endl;
  cout << endl;
  cout << "  AnchorExtractor latency (put -> feed) = " << (leTsFeed - leTsPut)
       << " cycles" << endl;
  cout << "  CRC32 pipeline latency  (feed -> drain) = "
       << (leTsDrain - leTsFeed) << " cycles" << endl;
  cout << "  Serial collect latency  (drain -> collect) = "
       << (leTsCollect - leTsDrain) << " cycles" << endl;
  cout << "  Total LongEngine latency (put -> collect) = "
       << (leTsCollect - leTsPut) << " cycles" << endl;
  cout << endl;

  cout << "=== KernelMain Overall ===" << endl;
  cout << "  Pipeline latency (first pkt in -> first result out) = "
       << (cycleFirstOut - cycleStart) << " cycles" << endl;
  cout << "  Feed time        (first pkt in -> last pkt in)      = "
       << (cycleAllFed - cycleStart) << " cycles" << endl;
  cout << "  Drain time       (first result -> last result)      = "
       << (cycleAllDone - cycleFirstOut) << " cycles" << endl;
  cout << "  Total compute    (first pkt in -> last result)      = "
       << (cycleAllDone - cycleStart) << " cycles" << endl;
  if (num_packets > 1) {
    double throughput =
        static_cast<double>(num_packets) / (cycleAllDone - cycleStart);
    cout << "  Throughput = " << fixed << setprecision(4) << throughput
         << " packets/cycle" << endl;
  }

  // Verify CRC checksums against SW reference
  cout << endl << "=== CRC32 Checksum Verification ===" << endl;
  int mismatches = 0;
  for (uint32_t i = 0; i < num_packets; i++) {
    uint32_t hw_checksum = 0;
    memcpy(&hw_checksum, out_map + (i + 1) * WORD_BYTES, 4);

    uint32_t sw_checksum =
        sw_xor_checksum(pkt_data.data() + i * PACKET_BYTES, PACKET_BYTES);

    if (hw_checksum != sw_checksum) {
      cout << "  MISMATCH pkt " << i << ": HW=0x" << hex << setw(8)
           << setfill('0') << hw_checksum << " SW=0x" << setw(8) << sw_checksum
           << dec << endl;
      mismatches++;
    }
  }

  if (mismatches == 0) {
    cout << "  All " << num_packets << " packets match. TEST PASSED" << endl;
  } else {
    cout << "  " << mismatches << " / " << num_packets
         << " mismatches. TEST FAILED" << endl;
  }

  return (mismatches == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
