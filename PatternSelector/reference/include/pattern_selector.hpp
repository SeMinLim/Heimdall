#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace pattern_selector {

// Compile-time defaults
inline constexpr std::size_t kDefaultRecordSize =
    64;  // Fixed-size slot per pattern rule
inline constexpr std::size_t kDefaultWindowSize =
    8;  // Pre-filter fingerprint size

// Pattern: byte window whose length is determined by window_size
using Pattern = std::vector<uint8_t>;

struct PatternHash {
  std::size_t operator()(const Pattern& p) const noexcept {
    // FNV-1a (64-bit): offset_basis and prime from the FNV spec.
    // The accumulator uses a fixed 64-bit width so the hash definition is
    // independent of the host platform's size_t width.
    // Ref: https://www.rfc-editor.org/rfc/rfc9923#name-fnv-constants
    std::uint64_t h = 14695981039346656037ULL;  // FNV offset basis
    for (auto b : p) {
      h ^= static_cast<std::uint64_t>(b);
      h *= 1099511628211ULL;  // FNV prime
    }
    return static_cast<std::size_t>(h);
  }
};

// Key for positional document frequency: (offset, pattern)
struct PositionalKey {
  int offset;
  Pattern pattern;

  bool operator==(const PositionalKey& o) const noexcept {
    return offset == o.offset && pattern == o.pattern;
  }
};

struct PositionalKeyHash {
  std::size_t operator()(const PositionalKey& k) const noexcept {
    auto h = PatternHash{}(k.pattern);
    // Boost-style hash_combine: mixes offset hash into pattern hash.
    // 0x9e3779b9 ~= 2^32 / <golden ratio> — spreads bits to reduce
    // bucket collisions when composing independent hash values.
    h ^= std::hash<int>{}(k.offset) + 0x9e3779b9 + (h << 6) + (h >> 2);
    return h;
  }
};

struct ScoreWeights {
  double rarity = 0.45;
  double position_rarity = 0.25;
  double entropy = 0.20;
  double local_uniqueness = 0.10;
};

struct CandidateScore {
  int offset;
  Pattern pattern;
  double score;
  double rarity;
  double position_rarity;
  double entropy;
  double local_uniqueness;
};

struct RepresentativePattern {
  std::size_t record_index;
  int offset;
  Pattern pattern;
  double score;
  std::vector<CandidateScore> candidate_scores;
};

struct CorpusStats {
  std::size_t record_size;
  std::size_t window_size;
  std::size_t total_records;
  bool allow_overlap;

  std::unordered_map<Pattern, int, PatternHash> document_frequency;
  std::unordered_map<PositionalKey, int, PositionalKeyHash>
      positional_document_frequency;
};

/// Build frequency tables over the entire corpus.
/// @param window_size   Representative width in bytes. Must be a power of two
///                      and must not exceed record_size.
/// @param pattern_lens  Per-record valid byte count (3~64). Empty = use
/// record_size.
CorpusStats build_corpus_stats(
    const std::vector<std::array<uint8_t, kDefaultRecordSize>>& records,
    std::size_t record_size = kDefaultRecordSize,
    std::size_t window_size = kDefaultWindowSize, bool allow_overlap = true,
    const std::vector<std::size_t>& pattern_lens = {});

/// Score all candidate windows within a single record.
/// @param pattern_len  Valid byte count for this record. std::nullopt = use
/// full record.
std::vector<CandidateScore> score_record(
    const std::array<uint8_t, kDefaultRecordSize>& record,
    const CorpusStats& stats, const ScoreWeights& weights = {},
    std::optional<std::size_t> pattern_len = std::nullopt);

/// Select the best representative window for each record.
/// @param window_size   Representative width in bytes. Must be a power of two
///                      and must not exceed record_size.
/// @param pattern_lens  Per-record valid byte count (3~64). Empty = use
/// record_size.
std::vector<RepresentativePattern> select_representative_patterns(
    const std::vector<std::array<uint8_t, kDefaultRecordSize>>& records,
    std::size_t record_size = kDefaultRecordSize,
    std::size_t window_size = kDefaultWindowSize, bool allow_overlap = true,
    const ScoreWeights& weights = {}, bool deduplicate = true,
    const std::vector<std::size_t>& pattern_lens = {});

}  // namespace pattern_selector
