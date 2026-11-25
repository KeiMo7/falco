// SPDX-License-Identifier: Apache-2.0

#include "generation_ledger.h"

#include <utility>

namespace falco::reload_ledger {

namespace {

const char* phase_to_string(phase p) {
	switch(p) {
	case phase::idle:
		return "idle";
	case phase::validating:
		return "validating";
	case phase::applied:
		return "applied";
	case phase::rejected:
		return "rejected";
	}
	return "idle";
}

nlohmann::json sample_to_json(const sample& s) {
	return nlohmann::json{
	        {"n_evts", s.n_evts},
	        {"n_drops", s.n_drops},
	        {"n_drops_buffer", s.n_drops_buffer},
	        {"n_drops_buffer_clone_fork_exit", s.n_drops_buffer_clone_fork_exit},
	        {"n_drops_buffer_execve_exit", s.n_drops_buffer_execve_exit},
	        {"n_drops_buffer_connect_exit", s.n_drops_buffer_connect_exit},
	        {"n_drops_buffer_open_exit", s.n_drops_buffer_open_exit},
	        {"n_drops_buffer_dir_file_exit", s.n_drops_buffer_dir_file_exit},
	        {"n_drops_buffer_other_interest_exit",
	         s.n_drops_buffer_other_interest_exit},
	        {"n_drops_buffer_close_exit", s.n_drops_buffer_close_exit},
	        {"n_drops_buffer_proc_exit", s.n_drops_buffer_proc_exit},
	        {"n_drops_scratch_map", s.n_drops_scratch_map},
	        {"n_drops_pf", s.n_drops_pf},
	        {"n_drops_bug", s.n_drops_bug},
	        {"n_preemptions", s.n_preemptions},
	        {"n_suppressed", s.n_suppressed},
	        {"n_tids_suppressed", s.n_tids_suppressed},
	};
}

nlohmann::json counts_to_json(const counts& c) {
	return nlohmann::json{
	        {"delta", sample_to_json(c.delta)},
	        {"events", c.events},
	        {"drops", c.drops},
	        {"detections", c.detections},
	        {"actions", c.actions},
	        {"bucket_denied", c.bucket_denied},
	        {"partial_windows", c.partial_windows},
	        {"resets", c.resets},
	        {"out_of_order", c.out_of_order},
	};
}

nlohmann::json record_to_json(const record& r) {
	return nlohmann::json{
	        {"generation", r.generation},
	        {"instance_id", r.instance_id},
	        {"source", r.source},
	        {"stage", phase_to_string(r.stage)},
	        {"requests", r.requests},
	        {"first_ts", r.first_ts},
	        {"last_ts", r.last_ts},
	        {"gap_ns", r.gap_ns},
	        {"baseline_unknown", r.baseline_unknown},
	        {"engine_reset", r.engine_reset},
	        {"tally", counts_to_json(r.tally)},
	        {"rule_matches", r.rule_matches},
	        {"reason", r.reason},
	        {"last", to_string(r.last)},
	};
}

void add_delta(sample& total, const sample& delta) {
	total.n_evts += delta.n_evts;
	total.n_drops += delta.n_drops;
	total.n_drops_buffer += delta.n_drops_buffer;
	total.n_drops_buffer_clone_fork_exit += delta.n_drops_buffer_clone_fork_exit;
	total.n_drops_buffer_execve_exit += delta.n_drops_buffer_execve_exit;
	total.n_drops_buffer_connect_exit += delta.n_drops_buffer_connect_exit;
	total.n_drops_buffer_open_exit += delta.n_drops_buffer_open_exit;
	total.n_drops_buffer_dir_file_exit += delta.n_drops_buffer_dir_file_exit;
	total.n_drops_buffer_other_interest_exit +=
	        delta.n_drops_buffer_other_interest_exit;
	total.n_drops_buffer_close_exit += delta.n_drops_buffer_close_exit;
	total.n_drops_buffer_proc_exit += delta.n_drops_buffer_proc_exit;
	total.n_drops_scratch_map += delta.n_drops_scratch_map;
	total.n_drops_pf += delta.n_drops_pf;
	total.n_drops_bug += delta.n_drops_bug;
	total.n_preemptions += delta.n_preemptions;
	total.n_suppressed += delta.n_suppressed;
	total.n_tids_suppressed += delta.n_tids_suppressed;
}

}  // namespace

source_ledger::source_ledger(std::string instance_id, std::string source, std::size_t retain):
		m_instance_id(std::move(instance_id)),
		m_source(std::move(source)),
		m_retain(retain),
		m_degraded(retain == 0) {}

record source_ledger::default_record_locked() const {
	record r;
	r.instance_id = m_instance_id;
	r.source = m_source;
	r.generation = m_applied_generation;
	return r;
}

void source_ledger::mark_degraded() noexcept {
	try {
		std::lock_guard<std::mutex> lock(m_mutex);
		m_degraded = true;
	} catch(...) {
		// There is no safe way to report a mutex failure from a status setter.
	}
}

void source_ledger::evict_locked() {
	while(m_generations.size() > m_retain) {
		auto it = m_generations.begin();
		++m_evicted_generations;
		m_evicted_drops += it->second.rec.tally.drops;
		m_generations.erase(it);
	}
}

outcome source_ledger::begin(uint64_t generation, uint64_t requests) {
	try {
		std::lock_guard<std::mutex> lock(m_mutex);
		if(generation < m_applied_generation) {
			return outcome::stale;
		}
		if(m_generations.find(generation) != m_generations.end()) {
			return outcome::stale;
		}
		if(m_retain == 0) {
			// Retention is explicitly disabled. Status is already degraded,
			// but lifecycle calls remain non-throwing and successful.
			return outcome::ok;
		}

		generation_state state;
		state.rec.generation = generation;
		state.rec.instance_id = m_instance_id;
		state.rec.source = m_source;
		state.rec.requests = requests;
		state.rec.stage = phase::validating;
		m_generations.emplace(generation, std::move(state));
		evict_locked();
		return outcome::ok;
	} catch(...) {
		mark_degraded();
		return outcome::degraded;
	}
}

outcome source_ledger::commit(uint64_t generation) {
	try {
		std::lock_guard<std::mutex> lock(m_mutex);
		auto it = m_generations.find(generation);
		if(it == m_generations.end()) {
			return outcome::unknown;
		}
		if(it->second.rec.stage == phase::applied) {
			return outcome::applied_already;
		}
		if(generation < m_applied_generation) {
			return outcome::stale;
		}
		if(it->second.rec.stage == phase::rejected) {
			return outcome::rejected_already;
		}

		const bool had_applied_generation = m_applied_generation != 0;
		for(auto& entry : m_generations) {
			if(entry.second.rec.stage == phase::applied) {
				entry.second.rec.stage = phase::idle;
			}
		}
		it->second.rec.stage = phase::applied;
		it->second.rec.last = outcome::ok;
		it->second.rec.baseline_unknown =
		        it->second.rec.baseline_unknown || had_applied_generation;
		m_applied_generation = generation;
		return outcome::ok;
	} catch(...) {
		mark_degraded();
		return outcome::degraded;
	}
}

outcome source_ledger::reject(uint64_t generation, const std::string& reason) {
	try {
		std::lock_guard<std::mutex> lock(m_mutex);
		auto it = m_generations.find(generation);
		if(it == m_generations.end()) {
			return outcome::unknown;
		}
		if(it->second.rec.stage == phase::applied) {
			return outcome::applied_already;
		}
		if(it->second.rec.stage == phase::rejected) {
			return outcome::rejected_already;
		}

		it->second.rec.stage = phase::rejected;
		it->second.rec.reason = reason;
		return outcome::ok;
	} catch(...) {
		mark_degraded();
		return outcome::degraded;
	}
}

outcome source_ledger::attribute(uint64_t generation, rule_totals_provider& provider) {
	// Poll outside the ledger mutex so a re-entrant provider can call history()
	// or current() without deadlocking.
	std::map<std::string, uint64_t> totals;
	try {
		totals = provider.poll();
	} catch(...) {
		try {
			std::lock_guard<std::mutex> lock(m_mutex);
			m_degraded = true;
			auto it = m_generations.find(generation);
			if(it != m_generations.end()) {
				it->second.rec.last = outcome::degraded;
			}
		} catch(...) {
			mark_degraded();
		}
		return outcome::degraded;
	}

	try {
		std::lock_guard<std::mutex> lock(m_mutex);
		auto it = m_generations.find(generation);
		if(it == m_generations.end()) {
			return outcome::unknown;
		}

		auto& state = it->second;
		bool engine_reset = false;
		for(const auto& rule_total : totals) {
			auto baseline_it = state.rule_baseline.find(rule_total.first);
			const auto baseline = baseline_it == state.rule_baseline.end()
			                              ? 0
			                              : baseline_it->second;
			if(rule_total.second < baseline) {
				engine_reset = true;
				break;
			}
		}

		if(engine_reset) {
			state.rec.engine_reset = true;
			for(const auto& rule_total : totals) {
				state.rec.rule_matches[rule_total.first] += rule_total.second;
			}
		} else {
			for(const auto& rule_total : totals) {
				auto baseline_it = state.rule_baseline.find(rule_total.first);
				const auto baseline = baseline_it == state.rule_baseline.end()
				                              ? 0
				                              : baseline_it->second;
				const auto delta = rule_total.second - baseline;
				state.rec.rule_matches[rule_total.first] += delta;
			}
		}
		state.rule_baseline = totals;
		state.rec.last = outcome::ok;
		return outcome::ok;
	} catch(...) {
		mark_degraded();
		return outcome::degraded;
	}
}

void source_ledger::add_unattributed_locked(const sample& absolute) noexcept {
	try {
		if(!m_unattributed_known) {
			m_unattributed_known = true;
			m_unattributed_baseline = absolute;
			return;
		}

		sample delta;
		if(subtract(m_unattributed_baseline, absolute, delta)) {
			m_unattributed_drops += delta.n_drops;
			m_unattributed_baseline = absolute;
		} else {
			++m_unattributed_resets;
			m_unattributed_baseline = absolute;
		}
	} catch(...) {
		m_degraded = true;
		++m_lost_windows;
	}
}

void source_ledger::observe_generation_locked(generation_state& state, const window& w) noexcept {
	try {
		auto& r = state.rec;
		if(!state.baseline_known) {
			state.baseline_known = true;
			state.baseline = w.absolute;
			++r.tally.partial_windows;
			r.first_ts = w.evt_ts;
			r.last_ts = w.evt_ts;
			r.last = outcome::ok;

			auto prev = m_generations.lower_bound(w.generation);
			if(prev != m_generations.begin()) {
				--prev;
				r.baseline_unknown = true;
				if(prev->second.rec.last_ts != 0 &&
				   w.evt_ts >= prev->second.rec.last_ts) {
					r.gap_ns = w.evt_ts - prev->second.rec.last_ts;
				}
			}
		} else {
			sample delta;
			if(!subtract(state.baseline, w.absolute, delta)) {
				++r.tally.resets;
				r.last = outcome::counters_reset;
				state.baseline = w.absolute;
			} else {
				add_delta(r.tally.delta, delta);
				r.tally.events = r.tally.delta.n_evts;
				r.tally.drops = r.tally.delta.n_drops;
				state.baseline = w.absolute;
				r.last = outcome::ok;
			}

			if(w.evt_ts < r.last_ts) {
				++r.tally.out_of_order;
			} else {
				r.last_ts = w.evt_ts;
			}
		}

		if(w.threshold_exceeded) {
			++r.tally.detections;
			if(w.bucket_allowed) {
				++r.tally.actions;
			} else {
				++r.tally.bucket_denied;
			}
		}
	} catch(...) {
		m_degraded = true;
		++m_lost_windows;
	}
}

void source_ledger::observe_window(const window& w) noexcept {
	try {
		std::lock_guard<std::mutex> lock(m_mutex);
		try {
			auto it = m_generations.find(w.generation);
			if(it == m_generations.end() ||
			   it->second.rec.stage != phase::applied ||
			   w.generation != m_applied_generation) {
				add_unattributed_locked(w.absolute);
				return;
			}
			observe_generation_locked(it->second, w);
		} catch(const std::bad_alloc&) {
			m_degraded = true;
			++m_lost_windows;
		} catch(...) {
			m_degraded = true;
			++m_lost_windows;
		}
	} catch(...) {
		// A noexcept observer must never let an exception reach the event loop.
	}
}

record source_ledger::current() const {
	try {
		std::lock_guard<std::mutex> lock(m_mutex);
		auto it = m_generations.find(m_applied_generation);
		if(it != m_generations.end()) {
			return it->second.rec;
		}
		if(!m_generations.empty()) {
			return m_generations.rbegin()->second.rec;
		}
		return default_record_locked();
	} catch(...) {
		return record{};
	}
}

std::vector<record> source_ledger::history() const {
	try {
		std::lock_guard<std::mutex> lock(m_mutex);
		std::vector<record> result;
		result.reserve(m_generations.size());
		for(const auto& entry : m_generations) {
			result.push_back(entry.second.rec);
		}
		return result;
	} catch(...) {
		return {};
	}
}

uint64_t source_ledger::applied_generation() const {
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_applied_generation;
}

uint64_t source_ledger::unattributed_drops() const {
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_unattributed_drops;
}

uint64_t source_ledger::unattributed_resets() const {
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_unattributed_resets;
}

uint64_t source_ledger::evicted_generations() const {
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_evicted_generations;
}

uint64_t source_ledger::evicted_drops() const {
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_evicted_drops;
}

uint64_t source_ledger::lost_windows() const {
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_lost_windows;
}

bool source_ledger::degraded() const {
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_degraded;
}

nlohmann::json source_ledger::to_json() const {
	uint64_t applied_generation = 0;
	uint64_t unattributed_drops = 0;
	uint64_t unattributed_resets = 0;
	uint64_t evicted_generations = 0;
	uint64_t evicted_drops = 0;
	uint64_t lost_windows = 0;
	bool degraded = false;
	std::vector<record> generations;

	{
		std::lock_guard<std::mutex> lock(m_mutex);
		applied_generation = m_applied_generation;
		unattributed_drops = m_unattributed_drops;
		unattributed_resets = m_unattributed_resets;
		evicted_generations = m_evicted_generations;
		evicted_drops = m_evicted_drops;
		lost_windows = m_lost_windows;
		degraded = m_degraded;
		generations.reserve(m_generations.size());
		for(const auto& entry : m_generations) {
			generations.push_back(entry.second.rec);
		}
	}

	auto generation_json = nlohmann::json::array();
	for(const auto& r : generations) {
		generation_json.push_back(record_to_json(r));
	}

	return nlohmann::json{
	        {"instance_id", m_instance_id},
	        {"source", m_source},
	        {"applied_generation", applied_generation},
	        {"degraded", degraded},
	        {"unattributed_drops", unattributed_drops},
	        {"unattributed_resets", unattributed_resets},
	        {"evicted_generations", evicted_generations},
	        {"evicted_drops", evicted_drops},
	        {"lost_windows", lost_windows},
	        {"generations", std::move(generation_json)},
	};
}

}  // namespace falco::reload_ledger
