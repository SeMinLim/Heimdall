/// Pattern Selector reference implementation — benchmark & correctness test.
///
/// Usage:
///   ./pattern_selector                           # synthetic 64K benchmark
///   ./pattern_selector --real-only [path.bin]    # real IPS data from HPAT
///   file

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <map>
#include <random>
#include <set>
#include <unordered_set>

#include "benchmark_data.hpp"
#include "pattern_selector.hpp"

using namespace pattern_selector;
using Record = benchmark_data::Record;

static Record make_random_record(std::mt19937& rng) {
  Record r;
  std::uniform_int_distribution<int> dist(0, 255);
  for (auto& b : r) b = static_cast<uint8_t>(dist(rng));
  return r;
}

static Record make_record_with_prefix(const uint8_t* prefix,
                                      std::size_t prefix_len,
                                      std::mt19937& rng) {
  Record r = make_random_record(rng);
  std::copy_n(prefix, std::min(prefix_len, kDefaultRecordSize), r.begin());
  return r;
}

static void mutate_record(Record& r, std::mt19937& rng, int n_mutations = 2) {
  std::uniform_int_distribution<int> pos_dist(0, kDefaultRecordSize - 1);
  std::uniform_int_distribution<int> val_dist(0, 255);
  for (int i = 0; i < n_mutations; ++i) {
    r[pos_dist(rng)] = static_cast<uint8_t>(val_dist(rng));
  }
}

// Simulated IPS patterns (representative HTTP attack signatures)
struct SimulatedRule {
  const char* name;
  const uint8_t* payload;
  std::size_t payload_len;
};

static const uint8_t p0[] = "/defect/defects/download?filename=<";
static const uint8_t p1[] =
    "/projectsend-r1605/templates.php?activate_template=<";
static const uint8_t p2[] = "/bloodbank/abs.php?error=\"><";
static const uint8_t p3[] = "/customer_support/manage_department.php?id=(";
static const uint8_t p4[] = "/login.do?jvar_page_title=<";
static const uint8_t p5[] =
    "/auth/AzureRedirect.php?error=&error_description=<";
static const uint8_t p6[] = "/exam/feedback.php?q=<";
static const uint8_t p7[] = "/auth/failure?provider=<";
static const uint8_t p8[] = "/resources/qmc/fonts/../../";
static const uint8_t p9[] = "GET /pdf-generator/";
static const uint8_t p10[] = "/wp-admin/admin-ajax.php?action=upload";
static const uint8_t p11[] = "POST /HNAP1/ HTTP/1.1";
static const uint8_t p12[] = "/cgi-bin/luci/;stok=";
static const uint8_t p13[] = "GET /setup.cgi?next_file=";
static const uint8_t p14[] = "/api/v1/users/../../../etc/passwd";
static const uint8_t p15[] = "SELECT+*+FROM+information_schema";
static const uint8_t p16[] = "UNION+SELECT+NULL,NULL,NULL--";
static const uint8_t p17[] = "/bin/sh -c wget http://";
static const uint8_t p18[] = "<script>alert(document.cookie)</script>";
static const uint8_t p19[] = "cmd=cat+/etc/shadow";

static const SimulatedRule kSimRules[] = {
    {"OrangeScrum XSS", p0, sizeof(p0) - 1},
    {"ProjectSend XSS", p1, sizeof(p1) - 1},
    {"BB error XSS", p2, sizeof(p2) - 1},
    {"CustomerSupport SQLi", p3, sizeof(p3) - 1},
    {"Login page_title XSS", p4, sizeof(p4) - 1},
    {"Azure redirect XSS", p5, sizeof(p5) - 1},
    {"Exam feedback XSS", p6, sizeof(p6) - 1},
    {"Auth failure XSS", p7, sizeof(p7) - 1},
    {"QMC path traversal", p8, sizeof(p8) - 1},
    {"PDF generator probe", p9, sizeof(p9) - 1},
    {"WP admin upload", p10, sizeof(p10) - 1},
    {"HNAP1 RCE", p11, sizeof(p11) - 1},
    {"Luci stok", p12, sizeof(p12) - 1},
    {"Setup.cgi probe", p13, sizeof(p13) - 1},
    {"Path traversal", p14, sizeof(p14) - 1},
    {"Info schema SQLi", p15, sizeof(p15) - 1},
    {"UNION SELECT SQLi", p16, sizeof(p16) - 1},
    {"wget RCE", p17, sizeof(p17) - 1},
    {"XSS cookie steal", p18, sizeof(p18) - 1},
    {"Shadow file read", p19, sizeof(p19) - 1},
};
static constexpr std::size_t kNumSimRules =
    sizeof(kSimRules) / sizeof(kSimRules[0]);

static std::vector<Record> build_dataset(std::size_t target_count,
                                         unsigned seed = 42) {
  std::mt19937 rng(seed);
  std::vector<Record> records;
  records.reserve(target_count);

  for (std::size_t i = 0; i < kNumSimRules && records.size() < target_count;
       ++i) {
    records.push_back(make_record_with_prefix(kSimRules[i].payload,
                                              kSimRules[i].payload_len, rng));
  }

  std::uniform_int_distribution<std::size_t> rule_dist(0, kNumSimRules - 1);
  while (records.size() < target_count) {
    const auto& rule = kSimRules[rule_dist(rng)];
    Record r = make_record_with_prefix(rule.payload, rule.payload_len, rng);
    mutate_record(r, rng, 1 + static_cast<int>(rng() % 3));
    records.push_back(r);
  }

  return records;
}

class Timer {
  using Clock = std::chrono::high_resolution_clock;
  Clock::time_point start_;

 public:
  Timer() : start_(Clock::now()) {}
  double elapsed_sec() const {
    return std::chrono::duration<double>(Clock::now() - start_).count();
  }
};

// Tests
static void test_basic_correctness() {
  std::printf("  [test] basic correctness ... ");

  const uint8_t shared[8] = {'C', 'O', 'M', 'M', 'O', 'N', '0', '0'};
  std::vector<Record> records(4);
  for (auto& r : records) std::fill(r.begin(), r.end(), 0);

  const char* tails[] = {"SIGA0001", "SIGB0002", "SIGC0003", "SIGD0004"};
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 7; ++j)
      std::copy_n(shared, 8, records[i].begin() + j * 8);
    std::copy_n(reinterpret_cast<const uint8_t*>(tails[i]), 8,
                records[i].begin() + 56);
  }

  auto results = select_representative_patterns(records);

  for (int i = 0; i < 4; ++i) {
    assert(results[i].offset >= 49);

    Pattern expected(
        records[i].begin() + results[i].offset,
        records[i].begin() + results[i].offset + kDefaultWindowSize);
    assert(results[i].pattern == expected);
  }

  std::unordered_set<Pattern, PatternHash> chosen_patterns;
  for (const auto& result : results) {
    chosen_patterns.insert(result.pattern);
  }
  assert(chosen_patterns.size() == results.size());
  std::puts("OK");
}

static void test_deduplication() {
  std::printf("  [test] deduplication ... ");

  std::mt19937 rng(123);
  Record base = make_random_record(rng);
  Record r2 = base;
  for (int i = 56; i < 64; ++i) r2[i] ^= 0xFF;

  std::vector<Record> records = {base, r2};
  auto results = select_representative_patterns(
      records, kDefaultRecordSize, kDefaultWindowSize, false, {}, true);

  assert(results[0].pattern != results[1].pattern);
  std::puts("OK");
}

static void test_identical_records_fallback() {
  std::printf("  [test] identical records fallback ... ");

  Record r;
  std::fill(r.begin(), r.end(), 0xAA);
  std::vector<Record> records = {r, r};

  auto results = select_representative_patterns(
      records, kDefaultRecordSize, kDefaultWindowSize, false, {}, true);
  assert(results.size() == 2);
  std::puts("OK");
}

// Synthetic benchmark
static int run_synthetic_benchmark() {
  std::puts("=== Pattern Selector C++17 Benchmark ===\n");

  std::puts("[Tests]");
  test_basic_correctness();
  test_deduplication();
  test_identical_records_fallback();
  std::puts("");

  constexpr std::size_t N = 65536;
  std::printf("[Dataset] Building %zu records (64B each, %zu base rules)...\n",
              N, kNumSimRules);
  Timer t_ds;
  auto records = build_dataset(N);
  std::printf("  Built in %.3f s\n", t_ds.elapsed_sec());

  std::set<Record> unique_records(records.begin(), records.end());
  std::printf("  Unique records: %zu / %zu\n\n", unique_records.size(),
              records.size());

  std::puts("[Benchmark] deduplicate=true");
  Timer t1;
  auto results_dedup = select_representative_patterns(records);
  double elapsed_dedup = t1.elapsed_sec();

  std::unordered_set<Pattern, PatternHash> dedup_set;
  for (const auto& r : results_dedup) dedup_set.insert(r.pattern);

  std::size_t collisions_dedup = results_dedup.size() - dedup_set.size();
  double sum_score = 0;
  double min_score = 1e9, max_score = -1e9;
  for (const auto& r : results_dedup) {
    sum_score += r.score;
    min_score = std::min(min_score, r.score);
    max_score = std::max(max_score, r.score);
  }

  std::printf("  Time:       %.3f s\n", elapsed_dedup);
  std::printf("  Unique:     %zu / %zu\n", dedup_set.size(),
              results_dedup.size());
  std::printf("  Collisions: %zu\n", collisions_dedup);
  std::printf("  Score min/avg/max: %.4f / %.4f / %.4f\n", min_score,
              sum_score / results_dedup.size(), max_score);

  std::puts("\n[Benchmark] deduplicate=false");
  Timer t2;
  auto results_nodup = select_representative_patterns(
      records, kDefaultRecordSize, kDefaultWindowSize, true, {}, false);
  double elapsed_nodup = t2.elapsed_sec();

  std::unordered_set<Pattern, PatternHash> nodup_set;
  for (const auto& r : results_nodup) nodup_set.insert(r.pattern);
  std::size_t collisions_nodup = results_nodup.size() - nodup_set.size();

  std::printf("  Time:       %.3f s\n", elapsed_nodup);
  std::printf("  Unique:     %zu / %zu\n", nodup_set.size(),
              results_nodup.size());
  std::printf("  Collisions: %zu\n", collisions_nodup);

  std::puts("\n[Offset Distribution] (deduplicated)");
  int offset_counts[8] = {};
  for (const auto& r : results_dedup) {
    int bucket = r.offset / static_cast<int>(kDefaultWindowSize);
    if (bucket >= 0 && bucket < 8) ++offset_counts[bucket];
  }
  for (int i = 0; i < 8; ++i) {
    std::printf("  offset %2d: %6d ", i * 8, offset_counts[i]);
    int bar = std::min(offset_counts[i] / 200, 60);
    for (int j = 0; j < bar; ++j) std::putchar('#');
    std::putchar('\n');
  }

  std::puts("\n[Sample Results] (first 20, deduplicated)");
  for (std::size_t i = 0; i < 20 && i < results_dedup.size(); ++i) {
    const auto& r = results_dedup[i];
    std::printf("  record[%5zu] offset=%2d score=%.4f pattern=", r.record_index,
                r.offset, r.score);
    for (auto b : r.pattern) std::printf("%02x", b);
    std::printf(" (");
    for (auto b : r.pattern) {
      char c = static_cast<char>(b);
      std::putchar((c >= 0x20 && c < 0x7f) ? c : '.');
    }
    std::puts(")");
  }

  std::puts("\n============================================================");
  std::puts("SUMMARY");
  std::printf("  Dataset:          %zu records x %zuB\n", N,
              kDefaultRecordSize);
  std::printf("  Window:           %zuB\n", kDefaultWindowSize);
  std::printf("  Base rules:       %zu (simulated IPS signatures)\n",
              kNumSimRules);
  std::printf("  Dedup time:       %.3f s  | collisions: %zu\n", elapsed_dedup,
              collisions_dedup);
  std::printf("  No-dedup time:    %.3f s  | collisions: %zu\n", elapsed_nodup,
              collisions_nodup);
  std::printf("  Dedup improvement: %zu fewer collisions\n",
              (collisions_nodup > collisions_dedup)
                  ? collisions_nodup - collisions_dedup
                  : 0);

  return 0;
}

// Real-data benchmark (reads HPAT binary exported by Python)
static std::string default_real_patterns_path() {
  const auto source_path = std::filesystem::path(__FILE__);
  return (source_path.parent_path().parent_path() / "data" /
          "real_patterns.bin")
      .string();
}

static int run_real_benchmark(const char* bin_path) {
  std::puts("=== Pattern Selector C++17 — Real IPS Data Benchmark ===\n");

  std::printf("[Loading] %s\n", bin_path);
  auto ds = benchmark_data::load_real_patterns(bin_path);
  std::printf("  Records: %zu\n", ds.records.size());

  std::size_t min_len =
      *std::min_element(ds.pattern_lens.begin(), ds.pattern_lens.end());
  std::size_t max_len =
      *std::max_element(ds.pattern_lens.begin(), ds.pattern_lens.end());
  double avg_len = 0;
  for (auto l : ds.pattern_lens) avg_len += l;
  avg_len /= ds.pattern_lens.size();
  std::printf("  Pattern length: min=%zu, avg=%.1f, max=%zu\n\n", min_len,
              avg_len, max_len);

  std::puts("[Benchmark] pattern_lens + deduplicate=true");
  Timer t1;
  auto results = select_representative_patterns(ds.records, kDefaultRecordSize,
                                                ds.window_size, true, {}, true,
                                                ds.pattern_lens);
  double elapsed = t1.elapsed_sec();

  std::unordered_set<Pattern, PatternHash> pset;
  for (const auto& r : results) pset.insert(r.pattern);
  std::size_t collisions = results.size() - pset.size();

  double sum_s = 0, min_s = 1e9, max_s = -1e9;
  for (const auto& r : results) {
    sum_s += r.score;
    min_s = std::min(min_s, r.score);
    max_s = std::max(max_s, r.score);
  }

  std::printf("  Time:       %.3f s\n", elapsed);
  std::printf("  Unique:     %zu / %zu\n", pset.size(), results.size());
  std::printf("  Collisions: %zu\n", collisions);
  std::printf("  Score min/avg/max: %.4f / %.4f / %.4f\n", min_s,
              sum_s / results.size(), max_s);

  std::puts("\n[Offset Distribution]");
  std::map<int, int> offset_dist;
  for (const auto& r : results) ++offset_dist[r.offset];
  for (auto& [off, cnt] : offset_dist) {
    std::printf("  offset %2d: %4d ", off, cnt);
    int bar = std::min(cnt, 60);
    for (int j = 0; j < bar; ++j) std::putchar('#');
    std::putchar('\n');
  }

  std::puts("\n[Sample Results] (first 30)");
  for (std::size_t i = 0; i < 30 && i < results.size(); ++i) {
    const auto& r = results[i];
    std::printf("  [%3zu] off=%2d score=%.4f len=%2zu pat=", r.record_index,
                r.offset, r.score, ds.pattern_lens[r.record_index]);
    for (auto b : r.pattern) std::printf("%02x", b);
    std::printf(" (");
    for (auto b : r.pattern) {
      char c = static_cast<char>(b);
      std::putchar((c >= 0x20 && c < 0x7f) ? c : '.');
    }
    std::puts(")");
  }

  std::puts("\n[Comparison] WITHOUT pattern_lens (scanning zero-pad too)");
  Timer t2;
  auto results_old = select_representative_patterns(
      ds.records, kDefaultRecordSize, ds.window_size, true, {}, true);
  double elapsed_old = t2.elapsed_sec();

  std::unordered_set<Pattern, PatternHash> pset_old;
  for (const auto& r : results_old) pset_old.insert(r.pattern);

  std::size_t zero_pad_picks = 0;
  for (std::size_t i = 0; i < results_old.size(); ++i) {
    if (results_old[i].offset + ds.window_size > ds.pattern_lens[i])
      ++zero_pad_picks;
  }
  std::printf("  Time:           %.3f s\n", elapsed_old);
  std::printf("  Unique:         %zu / %zu\n", pset_old.size(),
              results_old.size());
  std::printf("  Zero-pad picks: %zu\n", zero_pad_picks);

  std::puts("\n============================================================");
  std::puts("SUMMARY");
  std::printf("  Real rules:           %zu\n", ds.records.size());
  std::printf("  With pattern_lens:    %zu/%zu unique, %zu collisions\n",
              pset.size(), results.size(), collisions);
  std::printf("  Without pattern_lens: %zu/%zu unique, %zu zero-pad picks\n",
              pset_old.size(), results_old.size(), zero_pad_picks);

  return 0;
}

int main(int argc, char* argv[]) {
  if (argc >= 2 && std::strcmp(argv[1], "--real-only") == 0) {
    const auto default_bin_path = default_real_patterns_path();
    const char* bin_path = (argc >= 3) ? argv[2] : default_bin_path.c_str();
    return run_real_benchmark(bin_path);
  }

  return run_synthetic_benchmark();
}
