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

using namespace std;

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

  cout << "[Heimdall Long Engine Prefilter Bring-up]" << endl;
  cout << "  Packets: " << packet_file << " (" << num_packets << " x 64B)"
       << endl;

  // Buffer layout:
  //   Input  = N x 64B packets
  //   Output = (N+1) x 64B words (header + N prefilter hit counts)
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

  cout << endl << "=== Prefilter Hit Count Report ===" << endl;
  cout << "  Note: Bloom table loading is not wired yet; counts reflect current"
       << " table contents." << endl;

  uint64_t total_hits = 0;
  uint32_t packets_with_hits = 0;
  uint32_t sample_count = min<uint32_t>(num_packets, 16);
  for (uint32_t i = 0; i < num_packets; i++) {
    uint32_t hit_count = 0;
    memcpy(&hit_count, out_map + (i + 1) * WORD_BYTES, 4);
    total_hits += hit_count;
    if (hit_count != 0) packets_with_hits++;

    if (i < sample_count) {
      cout << "  pkt " << setw(4) << i << ": prefilter hits = " << hit_count
           << endl;
    }
  }

  if (num_packets > sample_count) {
    cout << "  ... " << (num_packets - sample_count)
         << " more packets omitted" << endl;
  }
  cout << "  Packets with hits = " << packets_with_hits << " / " << num_packets
       << endl;
  cout << "  Total lane hits   = " << total_hits << endl;

  return EXIT_SUCCESS;
}
