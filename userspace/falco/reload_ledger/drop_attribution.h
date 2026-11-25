// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>

namespace falco::reload_ledger {

enum class outcome : uint8_t {
	ok = 0,
	stale,
	unknown,
	applied_already,
	rejected_already,
	counters_reset,
	bound_reached,
	degraded,
};

const char* to_string(outcome o);

// 17 个 uint64_t，字段名与 scap_stats 中的计数同名，宽度固定。
struct sample {
	uint64_t n_evts = 0;
	uint64_t n_drops = 0;
	uint64_t n_drops_buffer = 0;
	uint64_t n_drops_buffer_clone_fork_exit = 0;
	uint64_t n_drops_buffer_execve_exit = 0;
	uint64_t n_drops_buffer_connect_exit = 0;
	uint64_t n_drops_buffer_open_exit = 0;
	uint64_t n_drops_buffer_dir_file_exit = 0;
	uint64_t n_drops_buffer_other_interest_exit = 0;
	uint64_t n_drops_buffer_close_exit = 0;
	uint64_t n_drops_buffer_proc_exit = 0;
	uint64_t n_drops_scratch_map = 0;
	uint64_t n_drops_pf = 0;
	uint64_t n_drops_bug = 0;
	uint64_t n_preemptions = 0;
	uint64_t n_suppressed = 0;
	uint64_t n_tids_suppressed = 0;
};

// 逐字段相减；任一字段 newer < older 时返回 false，且不写 out。
bool subtract(const sample& older, const sample& newer, sample& out);

struct window {
	uint64_t generation = 0;
	uint64_t evt_ts = 0;
	sample absolute;
	bool threshold_exceeded = false;
	bool bucket_allowed = false;
};

class drop_observer {
public:
	virtual ~drop_observer() = default;
	virtual void observe_window(const window& w) noexcept = 0;
};

class rule_totals_provider {
public:
	virtual ~rule_totals_provider() = default;
	// 规则名到累计命中数；同一引擎实例内单调不减。
	virtual std::map<std::string, uint64_t> poll() = 0;
};

}  // namespace falco::reload_ledger
