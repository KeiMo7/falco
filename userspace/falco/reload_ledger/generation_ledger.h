// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "drop_attribution.h"

namespace falco::reload_ledger {

enum class phase : uint8_t { idle = 0, validating, applied, rejected };

struct counts {
	sample delta;  // 该代次 17 字段累计增量
	uint64_t events = 0;  // 恒等于 delta.n_evts
	uint64_t drops = 0;  // 恒等于 delta.n_drops
	uint64_t detections = 0;
	uint64_t actions = 0;
	uint64_t bucket_denied = 0;
	uint64_t partial_windows = 0;
	uint64_t resets = 0;
	uint64_t out_of_order = 0;
};

struct record {
	uint64_t generation = 0;
	std::string instance_id;
	std::string source;
	phase stage = phase::idle;
	uint64_t requests = 0;
	uint64_t first_ts = 0;
	uint64_t last_ts = 0;
	uint64_t gap_ns = 0;
	bool baseline_unknown = false;
	bool engine_reset = false;
	counts tally;
	std::map<std::string, uint64_t> rule_matches;
	std::string reason;
	outcome last = outcome::ok;
};

class source_ledger final : public drop_observer {
public:
	source_ledger(std::string instance_id, std::string source, std::size_t retain = 32);
	source_ledger(const source_ledger&) = delete;
	source_ledger& operator=(const source_ledger&) = delete;

	outcome begin(uint64_t generation, uint64_t requests);
	outcome commit(uint64_t generation);
	outcome reject(uint64_t generation, const std::string& reason);
	outcome attribute(uint64_t generation, rule_totals_provider& provider);
	void observe_window(const window& w) noexcept override;

	record current() const;
	std::vector<record> history() const;
	uint64_t applied_generation() const;
	uint64_t unattributed_drops() const;
	uint64_t unattributed_resets() const;
	uint64_t evicted_generations() const;
	uint64_t evicted_drops() const;
	uint64_t lost_windows() const;
	bool degraded() const;
	nlohmann::json to_json() const;

private:
	struct generation_state {
		record rec;
		sample baseline;
		bool baseline_known = false;
		std::map<std::string, uint64_t> rule_baseline;
	};

	void mark_degraded() noexcept;
	void add_unattributed_locked(const sample& absolute) noexcept;
	void observe_generation_locked(generation_state& state, const window& w) noexcept;
	void evict_locked();
	record default_record_locked() const;

	mutable std::mutex m_mutex;
	const std::string m_instance_id;
	const std::string m_source;
	const std::size_t m_retain;
	bool m_degraded = false;
	uint64_t m_applied_generation = 0;
	uint64_t m_unattributed_drops = 0;
	uint64_t m_unattributed_resets = 0;
	uint64_t m_evicted_generations = 0;
	uint64_t m_evicted_drops = 0;
	uint64_t m_lost_windows = 0;
	bool m_unattributed_known = false;
	sample m_unattributed_baseline;
	std::map<uint64_t, generation_state> m_generations;
};

}  // namespace falco::reload_ledger
