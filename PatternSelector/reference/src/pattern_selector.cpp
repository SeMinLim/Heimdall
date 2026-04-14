#include "pattern_selector.hpp"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <functional>
#include <queue>
#include <set>
#include <stdexcept>
#include <tuple>
#include <unordered_set>

namespace pattern_selector {

template <std::size_t WindowSize>
using StaticPattern = std::array<uint8_t, WindowSize>;

template <std::size_t WindowSize>
struct StaticPatternHash {
  std::size_t operator()(const StaticPattern<WindowSize>& p) const noexcept {
    std::uint64_t h = 14695981039346656037ULL;
    for (auto b : p) {
      h ^= static_cast<std::uint64_t>(b);
      h *= 1099511628211ULL;
    }
    return static_cast<std::size_t>(h);
  }
};

template <std::size_t WindowSize>
struct StaticPositionalKey {
  int offset;
  StaticPattern<WindowSize> pattern;

  bool operator==(const StaticPositionalKey& o) const noexcept {
    return offset == o.offset && pattern == o.pattern;
  }
};

template <std::size_t WindowSize>
struct StaticPositionalKeyHash {
  std::size_t operator()(
      const StaticPositionalKey<WindowSize>& k) const noexcept {
    auto h = StaticPatternHash<WindowSize>{}(k.pattern);
    h ^= std::hash<int>{}(k.offset) + 0x9e3779b9 + (h << 6) + (h >> 2);
    return h;
  }
};

template <std::size_t WindowSize>
struct StaticCandidateScore {
  int offset;
  StaticPattern<WindowSize> pattern;
  double score;
  double rarity;
  double position_rarity;
  double entropy;
  double local_uniqueness;
};

template <std::size_t WindowSize>
struct StaticCorpusStats {
  std::size_t total_records;
  std::size_t record_size;
  bool allow_overlap;
  std::unordered_map<StaticPattern<WindowSize>, int,
                     StaticPatternHash<WindowSize>>
      document_frequency;
  std::unordered_map<StaticPositionalKey<WindowSize>, int,
                     StaticPositionalKeyHash<WindowSize>>
      positional_document_frequency;
};

static void validate_selector_args(
    std::size_t record_size, std::size_t window_size,
    const std::vector<std::array<uint8_t, kDefaultRecordSize>>& records,
    const std::vector<std::size_t>& pattern_lens) {
  if (window_size == 0) {
    throw std::invalid_argument("window_size must be positive");
  }
  if (record_size > kDefaultRecordSize) {
    throw std::invalid_argument("record_size exceeds fixed record storage");
  }
  if (window_size > record_size) {
    throw std::invalid_argument("window_size must not exceed record_size");
  }
  if ((window_size & (window_size - 1)) != 0) {
    throw std::invalid_argument("window_size must be a power of two");
  }
  if (!pattern_lens.empty() && pattern_lens.size() != records.size()) {
    throw std::invalid_argument(
        "pattern_lens must match the number of records");
  }
  for (std::size_t i = 0; i < records.size(); ++i) {
    const auto valid_len = pattern_lens.empty() ? record_size : pattern_lens[i];
    if (valid_len > record_size) {
      throw std::invalid_argument("pattern_len must not exceed record_size");
    }
    if (valid_len > 0 && valid_len < window_size) {
      throw std::invalid_argument("pattern_len must be >= window_size or 0");
    }
  }
}

static std::vector<int> candidate_offsets(std::size_t record_size,
                                          std::size_t window_size,
                                          bool allow_overlap) {
  if (record_size < window_size) {
    return {};
  }

  const int stride = allow_overlap ? 1 : static_cast<int>(window_size);
  std::vector<int> offsets;
  for (int o = 0;
       o + static_cast<int>(window_size) <= static_cast<int>(record_size);
       o += stride) {
    offsets.push_back(o);
  }
  return offsets;
}

static Pattern extract_pattern(
    const std::array<uint8_t, kDefaultRecordSize>& record, int offset,
    std::size_t window_size) {
  Pattern pattern(window_size);
  std::copy_n(record.begin() + offset, window_size, pattern.begin());
  return pattern;
}

template <std::size_t WindowSize>
static StaticPattern<WindowSize> extract_pattern_static(
    const std::array<uint8_t, kDefaultRecordSize>& record, int offset) {
  StaticPattern<WindowSize> pattern{};
  std::copy_n(record.begin() + offset, WindowSize, pattern.begin());
  return pattern;
}

static double normalized_idf(int df, std::size_t total_records) {
  if (total_records <= 1) return 1.0;
  const double n = static_cast<double>(total_records);
  const double raw_idf = std::log2((n + 1.0) / (static_cast<double>(df) + 1.0));
  const double max_idf = std::log2(n + 1.0);
  return (max_idf > 0.0) ? raw_idf / max_idf : 0.0;
}

static double normalized_entropy(const Pattern& pattern) {
  const auto len = pattern.size();
  if (len <= 1) return 0.0;

  int counts[256] = {};
  for (auto b : pattern) ++counts[b];

  double entropy = 0.0;
  for (auto c : counts) {
    if (c == 0) continue;
    const double prob = static_cast<double>(c) / static_cast<double>(len);
    entropy -= prob * std::log2(prob);
  }
  return entropy / std::log2(static_cast<double>(len));
}

template <std::size_t WindowSize>
static double normalized_entropy_static(
    const StaticPattern<WindowSize>& pattern) {
  if constexpr (WindowSize <= 1) return 0.0;

  int counts[256] = {};
  for (auto b : pattern) ++counts[b];

  double entropy = 0.0;
  for (auto c : counts) {
    if (c == 0) continue;
    const double prob =
        static_cast<double>(c) / static_cast<double>(WindowSize);
    entropy -= prob * std::log2(prob);
  }
  return entropy / std::log2(static_cast<double>(WindowSize));
}

template <typename Candidate>
static auto candidate_sort_key_generic(const Candidate& c) {
  return std::tuple<double, double, double, double, int>{
      c.score, c.rarity, c.position_rarity, c.entropy, -c.offset};
}

static CandidateScore score_single_candidate(int offset, const Pattern& pattern,
                                             std::size_t total_records, int df,
                                             int pos_df, int local_count,
                                             const ScoreWeights& weights) {
  const double rarity = normalized_idf(df, total_records);
  const double position_rarity = normalized_idf(pos_df, total_records);
  const double entropy = normalized_entropy(pattern);
  const double local_uniqueness = 1.0 / static_cast<double>(local_count);

  const double score =
      weights.rarity * rarity + weights.position_rarity * position_rarity +
      weights.entropy * entropy + weights.local_uniqueness * local_uniqueness;

  return {offset,          pattern, score,           rarity,
          position_rarity, entropy, local_uniqueness};
}

template <std::size_t WindowSize>
static StaticCandidateScore<WindowSize> score_single_candidate_static(
    int offset, const StaticPattern<WindowSize>& pattern,
    std::size_t total_records, int df, int pos_df, int local_count,
    const ScoreWeights& weights) {
  const double rarity = normalized_idf(df, total_records);
  const double position_rarity = normalized_idf(pos_df, total_records);
  const double entropy = normalized_entropy_static(pattern);
  const double local_uniqueness = 1.0 / static_cast<double>(local_count);

  const double score =
      weights.rarity * rarity + weights.position_rarity * position_rarity +
      weights.entropy * entropy + weights.local_uniqueness * local_uniqueness;

  return {offset,          pattern, score,           rarity,
          position_rarity, entropy, local_uniqueness};
}

template <std::size_t WindowSize>
static Pattern to_dynamic_pattern(const StaticPattern<WindowSize>& pattern) {
  return Pattern(pattern.begin(), pattern.end());
}

template <std::size_t WindowSize>
static StaticCorpusStats<WindowSize> build_corpus_stats_static(
    const std::vector<std::array<uint8_t, kDefaultRecordSize>>& records,
    std::size_t record_size, bool allow_overlap,
    const std::vector<std::size_t>& pattern_lens) {
  StaticCorpusStats<WindowSize> stats{};
  stats.total_records = records.size();
  stats.record_size = record_size;
  stats.allow_overlap = allow_overlap;

  std::unordered_set<StaticPattern<WindowSize>, StaticPatternHash<WindowSize>>
      seen_patterns;
  std::unordered_set<StaticPositionalKey<WindowSize>,
                     StaticPositionalKeyHash<WindowSize>>
      seen_position_patterns;

  for (std::size_t i = 0; i < records.size(); ++i) {
    const auto valid_len = pattern_lens.empty() ? record_size : pattern_lens[i];
    const auto offsets =
        candidate_offsets(valid_len, WindowSize, allow_overlap);

    seen_patterns.clear();
    seen_position_patterns.clear();

    for (int offset : offsets) {
      auto pattern = extract_pattern_static<WindowSize>(records[i], offset);
      seen_patterns.insert(pattern);
      seen_position_patterns.insert(
          StaticPositionalKey<WindowSize>{offset, pattern});
    }

    for (const auto& pattern : seen_patterns) {
      ++stats.document_frequency[pattern];
    }
    for (const auto& key : seen_position_patterns) {
      ++stats.positional_document_frequency[key];
    }
  }

  return stats;
}

template <std::size_t WindowSize>
static std::vector<StaticCandidateScore<WindowSize>> score_record_static(
    const std::array<uint8_t, kDefaultRecordSize>& record,
    const StaticCorpusStats<WindowSize>& stats, const ScoreWeights& weights,
    std::optional<std::size_t> pattern_len) {
  const auto valid_len = pattern_len.value_or(stats.record_size);
  const auto offsets =
      candidate_offsets(valid_len, WindowSize, stats.allow_overlap);

  std::vector<std::pair<int, StaticPattern<WindowSize>>> patterns;
  patterns.reserve(offsets.size());
  std::unordered_map<StaticPattern<WindowSize>, int,
                     StaticPatternHash<WindowSize>>
      local_counts;

  for (int offset : offsets) {
    auto pattern = extract_pattern_static<WindowSize>(record, offset);
    patterns.emplace_back(offset, pattern);
    ++local_counts[pattern];
  }

  std::vector<StaticCandidateScore<WindowSize>> candidates;
  candidates.reserve(offsets.size());

  for (const auto& [offset, pattern] : patterns) {
    auto df_it = stats.document_frequency.find(pattern);
    auto pdf_it = stats.positional_document_frequency.find(
        StaticPositionalKey<WindowSize>{offset, pattern});

    const int df =
        (df_it != stats.document_frequency.end()) ? df_it->second : 0;
    const int pos_df = (pdf_it != stats.positional_document_frequency.end())
                           ? pdf_it->second
                           : 0;

    candidates.push_back(score_single_candidate_static<WindowSize>(
        offset, pattern, stats.total_records, df, pos_df, local_counts[pattern],
        weights));
  }

  return candidates;
}

template <std::size_t WindowSize>
static std::vector<RepresentativePattern> greedy_deduplicate_static(
    std::vector<std::vector<StaticCandidateScore<WindowSize>>>&
        all_candidates) {
  const std::size_t n = all_candidates.size();

  auto sorted_candidates = all_candidates;
  for (auto& candidates : sorted_candidates) {
    std::sort(
        candidates.begin(), candidates.end(), [](const auto& a, const auto& b) {
          return candidate_sort_key_generic(a) > candidate_sort_key_generic(b);
        });
  }

  struct HeapEntry {
    double score;
    std::size_t record_idx;
    std::size_t rank;
  };

  struct HeapEntryLess {
    bool operator()(const HeapEntry& a, const HeapEntry& b) const {
      if (a.score != b.score) {
        return a.score < b.score;
      }
      if (a.record_idx != b.record_idx) {
        return a.record_idx > b.record_idx;
      }
      return a.rank > b.rank;
    }
  };

  std::priority_queue<HeapEntry, std::vector<HeapEntry>, HeapEntryLess> heap;
  for (std::size_t i = 0; i < n; ++i) {
    if (!sorted_candidates[i].empty()) {
      heap.push({sorted_candidates[i][0].score, i, 0});
    }
  }

  std::vector<int> assigned(n, -1);
  std::unordered_set<StaticPattern<WindowSize>, StaticPatternHash<WindowSize>>
      taken_patterns;
  std::size_t assigned_count = 0;

  while (!heap.empty() && assigned_count < n) {
    auto [score, record_idx, rank] = heap.top();
    (void)score;
    heap.pop();

    if (assigned[record_idx] >= 0) {
      continue;
    }

    const auto& candidate = sorted_candidates[record_idx][rank];
    if (taken_patterns.find(candidate.pattern) == taken_patterns.end()) {
      assigned[record_idx] = static_cast<int>(rank);
      taken_patterns.insert(candidate.pattern);
      ++assigned_count;
    } else {
      const auto next_rank = rank + 1;
      if (next_rank < sorted_candidates[record_idx].size()) {
        heap.push({sorted_candidates[record_idx][next_rank].score, record_idx,
                   next_rank});
      } else {
        assigned[record_idx] = 0;
        ++assigned_count;
      }
    }
  }

  std::vector<RepresentativePattern> results;
  results.reserve(n);
  for (std::size_t i = 0; i < n; ++i) {
    const int best_idx = (assigned[i] >= 0) ? assigned[i] : 0;
    const auto& best = sorted_candidates[i][best_idx];

    std::vector<CandidateScore> candidate_scores;
    candidate_scores.reserve(all_candidates[i].size());
    for (const auto& candidate : all_candidates[i]) {
      candidate_scores.push_back({
          candidate.offset,
          to_dynamic_pattern(candidate.pattern),
          candidate.score,
          candidate.rarity,
          candidate.position_rarity,
          candidate.entropy,
          candidate.local_uniqueness,
      });
    }

    results.push_back({
        i,
        best.offset,
        to_dynamic_pattern(best.pattern),
        best.score,
        std::move(candidate_scores),
    });
  }

  return results;
}

template <std::size_t WindowSize>
static std::vector<RepresentativePattern> select_representative_patterns_static(
    const std::vector<std::array<uint8_t, kDefaultRecordSize>>& records,
    std::size_t record_size, bool allow_overlap, const ScoreWeights& weights,
    bool deduplicate, const std::vector<std::size_t>& pattern_lens) {
  auto stats = build_corpus_stats_static<WindowSize>(
      records, record_size, allow_overlap, pattern_lens);

  std::vector<std::vector<StaticCandidateScore<WindowSize>>> all_candidates;
  all_candidates.reserve(records.size());
  for (std::size_t i = 0; i < records.size(); ++i) {
    const auto plen = pattern_lens.empty()
                          ? std::nullopt
                          : std::optional<std::size_t>(pattern_lens[i]);
    all_candidates.push_back(
        score_record_static<WindowSize>(records[i], stats, weights, plen));
  }

  if (deduplicate) {
    return greedy_deduplicate_static<WindowSize>(all_candidates);
  }

  std::vector<RepresentativePattern> results;
  results.reserve(records.size());
  for (std::size_t i = 0; i < records.size(); ++i) {
    auto& candidates = all_candidates[i];
    auto best_it = std::max_element(
        candidates.begin(), candidates.end(), [](const auto& a, const auto& b) {
          return candidate_sort_key_generic(a) < candidate_sort_key_generic(b);
        });

    std::vector<CandidateScore> candidate_scores;
    candidate_scores.reserve(candidates.size());
    for (const auto& candidate : candidates) {
      candidate_scores.push_back({
          candidate.offset,
          to_dynamic_pattern(candidate.pattern),
          candidate.score,
          candidate.rarity,
          candidate.position_rarity,
          candidate.entropy,
          candidate.local_uniqueness,
      });
    }

    results.push_back({
        i,
        best_it->offset,
        to_dynamic_pattern(best_it->pattern),
        best_it->score,
        std::move(candidate_scores),
    });
  }

  return results;
}

#define HPAT_WINDOW_SWITCH(EXPR)                              \
  switch (window_size) {                                      \
    case 1:                                                   \
      return EXPR(1);                                         \
    case 2:                                                   \
      return EXPR(2);                                         \
    case 4:                                                   \
      return EXPR(4);                                         \
    case 8:                                                   \
      return EXPR(8);                                         \
    case 16:                                                  \
      return EXPR(16);                                        \
    case 32:                                                  \
      return EXPR(32);                                        \
    case 64:                                                  \
      return EXPR(64);                                        \
    default:                                                  \
      throw std::invalid_argument("unsupported window_size"); \
  }

#define HPAT_SELECT_CASE(N)                 \
  select_representative_patterns_static<N>( \
      records, record_size, allow_overlap, weights, deduplicate, pattern_lens)

CorpusStats build_corpus_stats(
    const std::vector<std::array<uint8_t, kDefaultRecordSize>>& records,
    std::size_t record_size, std::size_t window_size, bool allow_overlap,
    const std::vector<std::size_t>& pattern_lens) {
  validate_selector_args(record_size, window_size, records, pattern_lens);

  CorpusStats stats;
  stats.record_size = record_size;
  stats.window_size = window_size;
  stats.total_records = records.size();
  stats.allow_overlap = allow_overlap;

  std::unordered_set<Pattern, PatternHash> seen_patterns;
  std::unordered_set<PositionalKey, PositionalKeyHash> seen_position_patterns;

  for (std::size_t i = 0; i < records.size(); ++i) {
    const auto valid_len = pattern_lens.empty() ? record_size : pattern_lens[i];
    const auto offsets =
        candidate_offsets(valid_len, window_size, allow_overlap);

    seen_patterns.clear();
    seen_position_patterns.clear();

    for (int offset : offsets) {
      auto pattern = extract_pattern(records[i], offset, window_size);
      seen_patterns.insert(pattern);
      seen_position_patterns.insert(PositionalKey{offset, pattern});
    }

    for (const auto& pattern : seen_patterns) {
      ++stats.document_frequency[pattern];
    }
    for (const auto& key : seen_position_patterns) {
      ++stats.positional_document_frequency[key];
    }
  }

  return stats;
}

std::vector<CandidateScore> score_record(
    const std::array<uint8_t, kDefaultRecordSize>& record,
    const CorpusStats& stats, const ScoreWeights& weights,
    std::optional<std::size_t> pattern_len) {
  if (stats.window_size == 0 || stats.window_size > stats.record_size) {
    throw std::invalid_argument("invalid stats.window_size");
  }
  if ((stats.window_size & (stats.window_size - 1)) != 0) {
    throw std::invalid_argument("window_size must be a power of two");
  }

  const auto valid_len = pattern_len.value_or(stats.record_size);
  if (valid_len > stats.record_size) {
    throw std::invalid_argument("pattern_len must not exceed record_size");
  }
  if (valid_len > 0 && valid_len < stats.window_size) {
    throw std::invalid_argument("pattern_len must be >= window_size or 0");
  }

  const auto offsets =
      candidate_offsets(valid_len, stats.window_size, stats.allow_overlap);
  std::vector<std::pair<int, Pattern>> patterns;
  patterns.reserve(offsets.size());
  std::unordered_map<Pattern, int, PatternHash> local_counts;

  for (int offset : offsets) {
    auto pattern = extract_pattern(record, offset, stats.window_size);
    patterns.emplace_back(offset, pattern);
    ++local_counts[pattern];
  }

  std::vector<CandidateScore> candidates;
  candidates.reserve(offsets.size());
  for (const auto& [offset, pattern] : patterns) {
    auto df_it = stats.document_frequency.find(pattern);
    auto pdf_it = stats.positional_document_frequency.find(
        PositionalKey{offset, pattern});

    const int df =
        (df_it != stats.document_frequency.end()) ? df_it->second : 0;
    const int pos_df = (pdf_it != stats.positional_document_frequency.end())
                           ? pdf_it->second
                           : 0;

    candidates.push_back(
        score_single_candidate(offset, pattern, stats.total_records, df, pos_df,
                               local_counts[pattern], weights));
  }

  return candidates;
}

std::vector<RepresentativePattern> select_representative_patterns(
    const std::vector<std::array<uint8_t, kDefaultRecordSize>>& records,
    std::size_t record_size, std::size_t window_size, bool allow_overlap,
    const ScoreWeights& weights, bool deduplicate,
    const std::vector<std::size_t>& pattern_lens) {
  validate_selector_args(record_size, window_size, records, pattern_lens);
  HPAT_WINDOW_SWITCH(HPAT_SELECT_CASE);
}

#undef HPAT_SELECT_CASE
#undef HPAT_WINDOW_SWITCH

}  // namespace pattern_selector
