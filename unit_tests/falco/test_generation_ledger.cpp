// SPDX-License-Identifier: Apache-2.0

#include <falco/reload_ledger/generation_ledger.h>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <future>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using falco::reload_ledger::counts;
using falco::reload_ledger::outcome;
using falco::reload_ledger::phase;
using falco::reload_ledger::record;
using falco::reload_ledger::rule_totals_provider;
using falco::reload_ledger::sample;
using falco::reload_ledger::source_ledger;
using falco::reload_ledger::window;

namespace {

window make_window(uint64_t generation, uint64_t ts) {
	window w;
	w.generation = generation;
	w.evt_ts = ts;
	return w;
}

sample make_sample(uint64_t events, uint64_t drops) {
	sample s;
	s.n_evts = events;
	s.n_drops = drops;
	return s;
}

class fake_provider : public rule_totals_provider {
public:
	std::map<std::string, uint64_t> totals;
	bool throw_on_poll = false;
	int polls = 0;

	std::map<std::string, uint64_t> poll() override {
		++polls;
		if(throw_on_poll) {
			throw std::runtime_error("provider unavailable");
		}
		return totals;
	}
};

class reentrant_provider : public rule_totals_provider {
public:
	explicit reentrant_provider(source_ledger& ledger): m_ledger(ledger) {}

	std::map<std::string, uint64_t> poll() override {
		EXPECT_NO_THROW((void)m_ledger.history());
		EXPECT_NO_THROW((void)m_ledger.current());
		return {{"a", 1}};
	}

private:
	source_ledger& m_ledger;
};

std::string compact_dump(const nlohmann::json& j) {
	return j.dump(-1, ' ', false, nlohmann::detail::error_handler_t::replace);
}

}  // namespace

TEST(GenerationLedger, BaselineWindowCountsNothing) {
	source_ledger ledger("instance-baseline", "syscall");
	ASSERT_EQ(ledger.begin(4, 3), outcome::ok);
	ASSERT_EQ(ledger.commit(4), outcome::ok);

	auto first = make_window(4, 2000000000);
	first.absolute = make_sample(1000, 7);
	first.threshold_exceeded = false;
	first.bucket_allowed = false;
	ledger.observe_window(first);

	auto current = ledger.current();
	EXPECT_EQ(current.tally.drops, 0u);
	EXPECT_EQ(current.tally.events, 0u);
	EXPECT_EQ(current.tally.partial_windows, 1u);
	EXPECT_EQ(current.first_ts, 2000000000u);
	EXPECT_EQ(current.last_ts, 2000000000u);
	EXPECT_EQ(current.last, outcome::ok);

	auto second = make_window(4, 3000000000);
	second.absolute = make_sample(1500, 9);
	ledger.observe_window(second);

	current = ledger.current();
	EXPECT_EQ(current.tally.drops, 2u);
	EXPECT_EQ(current.tally.events, 500u);
	EXPECT_EQ(current.last_ts, 3000000000u);
	EXPECT_EQ(current.last, outcome::ok);
}

TEST(GenerationLedger, FieldWiseDelta) {
	source_ledger ledger("instance-fields", "syscall");
	ASSERT_EQ(ledger.begin(4, 0), outcome::ok);
	ASSERT_EQ(ledger.commit(4), outcome::ok);

	auto first = make_window(4, 1000);
	first.absolute.n_drops_buffer_open_exit = 1;
	first.absolute.n_drops_buffer_proc_exit = 5;
	ledger.observe_window(first);

	auto second = make_window(4, 2000);
	second.absolute.n_drops_buffer_open_exit = 3;
	second.absolute.n_drops_buffer_proc_exit = 5;
	ledger.observe_window(second);

	const auto current = ledger.current();
	EXPECT_EQ(current.tally.delta.n_drops_buffer_open_exit, 2u);
	EXPECT_EQ(current.tally.delta.n_drops_buffer_proc_exit, 0u);

	const auto json = ledger.to_json();
	const auto& delta = json.at("generations").at(0).at("tally").at("delta");
	const std::vector<std::string> keys = {
	        "n_evts",
	        "n_drops",
	        "n_drops_buffer",
	        "n_drops_buffer_clone_fork_exit",
	        "n_drops_buffer_execve_exit",
	        "n_drops_buffer_connect_exit",
	        "n_drops_buffer_open_exit",
	        "n_drops_buffer_dir_file_exit",
	        "n_drops_buffer_other_interest_exit",
	        "n_drops_buffer_close_exit",
	        "n_drops_buffer_proc_exit",
	        "n_drops_scratch_map",
	        "n_drops_pf",
	        "n_drops_bug",
	        "n_preemptions",
	        "n_suppressed",
	        "n_tids_suppressed",
	};
	ASSERT_EQ(keys.size(), 17u);
	for(const auto& key : keys) {
		EXPECT_TRUE(delta.contains(key)) << "missing " << key;
		EXPECT_TRUE(delta.at(key).is_number_unsigned()) << key;
	}
}

TEST(GenerationLedger, ResetDoesNotUnderflow) {
	source_ledger ledger("instance-reset", "syscall");
	ASSERT_EQ(ledger.begin(4, 0), outcome::ok);
	ASSERT_EQ(ledger.commit(4), outcome::ok);

	auto first = make_window(4, 2000000000);
	first.absolute = make_sample(1000, 7);
	ledger.observe_window(first);

	auto second = make_window(4, 3000000000);
	second.absolute = make_sample(1500, 9);
	ledger.observe_window(second);

	auto current = ledger.current();
	ASSERT_EQ(current.tally.drops, 2u);
	ASSERT_EQ(current.tally.events, 500u);

	auto rollback = make_window(4, 4000000000);
	rollback.absolute = make_sample(1500, 4);
	ledger.observe_window(rollback);

	current = ledger.current();
	EXPECT_EQ(current.tally.drops, 2u);
	EXPECT_EQ(current.tally.resets, 1u);
	EXPECT_EQ(current.last, outcome::counters_reset);
	EXPECT_EQ(current.tally.events, current.tally.delta.n_evts);
	EXPECT_EQ(current.tally.drops, current.tally.delta.n_drops);
	EXPECT_NE(current.tally.drops, UINT64_MAX - 4u);

	auto resumed = make_window(4, 5000000000);
	resumed.absolute = make_sample(1600, 6);
	ledger.observe_window(resumed);

	current = ledger.current();
	EXPECT_EQ(current.tally.drops, 4u);
	EXPECT_EQ(current.tally.events, 600u);
	EXPECT_EQ(current.tally.events, current.tally.delta.n_evts);
	EXPECT_EQ(current.tally.drops, current.tally.delta.n_drops);

	const auto json = nlohmann::json::parse(compact_dump(ledger.to_json()));
	const auto& tally = json.at("generations").at(0).at("tally");
	EXPECT_EQ(tally.at("drops").get<uint64_t>(), 4u);
	EXPECT_EQ(tally.at("events").get<uint64_t>(), tally.at("delta").at("n_evts").get<uint64_t>());
}

TEST(GenerationLedger, DetectionAndBucketAreSeparateAxes) {
	source_ledger ledger("instance-axes", "syscall");
	ASSERT_EQ(ledger.begin(1, 0), outcome::ok);
	ASSERT_EQ(ledger.commit(1), outcome::ok);

	auto denied = make_window(1, 1000);
	denied.absolute.n_drops = 1;
	denied.threshold_exceeded = true;
	denied.bucket_allowed = false;
	ledger.observe_window(denied);

	auto allowed = make_window(1, 2000);
	allowed.absolute.n_drops = 2;
	allowed.threshold_exceeded = true;
	allowed.bucket_allowed = true;
	ledger.observe_window(allowed);

	auto quiet = make_window(1, 3000);
	quiet.absolute.n_drops = 5;
	quiet.threshold_exceeded = false;
	quiet.bucket_allowed = false;
	ledger.observe_window(quiet);

	const auto tally = ledger.current().tally;
	EXPECT_EQ(tally.detections, 2u);
	EXPECT_EQ(tally.bucket_denied, 1u);
	EXPECT_EQ(tally.actions, 1u);
	EXPECT_EQ(tally.drops, 4u);
}

TEST(GenerationLedger, NewGenerationDropsBaseline) {
	source_ledger ledger("instance-generation-switch", "syscall");
	ASSERT_EQ(ledger.begin(4, 0), outcome::ok);
	ASSERT_EQ(ledger.commit(4), outcome::ok);

	auto old_window = make_window(4, 5000000000);
	old_window.absolute.n_drops = 9;
	ledger.observe_window(old_window);
	const auto old_before = ledger.current();

	ASSERT_EQ(ledger.begin(5, 0), outcome::ok);
	ASSERT_EQ(ledger.commit(5), outcome::ok);

	auto new_window = make_window(5, 7500000000);
	new_window.absolute.n_drops = 0;
	ledger.observe_window(new_window);

	const auto current = ledger.current();
	EXPECT_EQ(current.generation, 5u);
	EXPECT_EQ(current.gap_ns, 2500000000u);
	EXPECT_TRUE(current.baseline_unknown);
	EXPECT_EQ(current.tally.drops, 0u);
	EXPECT_EQ(current.tally.partial_windows, 1u);

	const auto history = ledger.history();
	ASSERT_EQ(history.size(), 2u);
	const auto& old_after = history[0].generation == 4 ? history[0] : history[1];
	EXPECT_EQ(old_after.last_ts, old_before.last_ts);
	EXPECT_EQ(old_after.tally.drops, old_before.tally.drops);
	EXPECT_EQ(old_after.tally.delta.n_drops, old_before.tally.delta.n_drops);
}

TEST(GenerationLedger, OutOfOrderTimestampsKeepTotals) {
	source_ledger ledger("instance-ooo", "syscall");
	ASSERT_EQ(ledger.begin(1, 0), outcome::ok);
	ASSERT_EQ(ledger.commit(1), outcome::ok);

	auto first = make_window(1, 2000000000);
	first.absolute = make_sample(1000, 7);
	ledger.observe_window(first);

	auto second = make_window(1, 3000000000);
	second.absolute = make_sample(1500, 9);
	ledger.observe_window(second);

	auto late = make_window(1, 1500000000);
	late.absolute = make_sample(2000, 12);
	ledger.observe_window(late);

	const auto current = ledger.current();
	EXPECT_EQ(current.last_ts, 3000000000u);
	EXPECT_EQ(current.first_ts, 2000000000u);
	EXPECT_EQ(current.tally.out_of_order, 1u);
	EXPECT_EQ(current.tally.drops, 5u);
	EXPECT_EQ(current.tally.events, 1000u);

	auto next = make_window(1, 4000000000);
	next.absolute = make_sample(2100, 13);
	ledger.observe_window(next);
	EXPECT_EQ(ledger.current().tally.drops, 6u);
}

TEST(GenerationLedger, StaleWindowGoesUnattributed) {
	source_ledger ledger("instance-stale", "syscall");
	ASSERT_EQ(ledger.begin(5, 0), outcome::ok);
	ASSERT_EQ(ledger.commit(5), outcome::ok);
	const auto history_before = ledger.history();

	auto stale_baseline = make_window(3, 1000);
	stale_baseline.absolute.n_drops = 10;
	ledger.observe_window(stale_baseline);
	EXPECT_EQ(ledger.unattributed_drops(), 0u);

	auto stale_growth = make_window(3, 2000);
	stale_growth.absolute.n_drops = 14;
	ledger.observe_window(stale_growth);
	EXPECT_EQ(ledger.unattributed_drops(), 4u);
	EXPECT_EQ(ledger.applied_generation(), 5u);
	EXPECT_EQ(ledger.history().size(), history_before.size());

	auto stale_reset = make_window(3, 3000);
	stale_reset.absolute.n_drops = 9;
	ledger.observe_window(stale_reset);
	EXPECT_EQ(ledger.unattributed_resets(), 1u);
	EXPECT_EQ(ledger.unattributed_drops(), 4u);
	EXPECT_EQ(ledger.history().size(), history_before.size());
}

TEST(GenerationLedger, RuleTotalsDeltaAndEngineReset) {
	source_ledger ledger("instance-rules", "syscall");
	ASSERT_EQ(ledger.begin(5, 0), outcome::ok);
	ASSERT_EQ(ledger.commit(5), outcome::ok);
	fake_provider provider;

	provider.totals = {{"a", 5}, {"b", 0}};
	ASSERT_EQ(ledger.attribute(5, provider), outcome::ok);
	auto matches = ledger.current().rule_matches;
	EXPECT_EQ(matches.at("a"), 5u);
	EXPECT_EQ(matches.at("b"), 0u);

	provider.totals = {{"a", 7}, {"b", 1}};
	ASSERT_EQ(ledger.attribute(5, provider), outcome::ok);
	matches = ledger.current().rule_matches;
	EXPECT_EQ(matches.at("a"), 7u);
	EXPECT_EQ(matches.at("b"), 1u);

	provider.totals = {{"a", 2}};
	ASSERT_EQ(ledger.attribute(5, provider), outcome::ok);
	const auto record = ledger.current();
	EXPECT_TRUE(record.engine_reset);
	EXPECT_EQ(record.rule_matches.at("a"), 9u);
	EXPECT_EQ(record.rule_matches.at("b"), 1u);
}

TEST(GenerationLedger, RetentionReconciles) {
	source_ledger ledger("instance-retention", "syscall", 2);
	uint64_t observed_monotonic_deltas = 0;

	for(uint64_t generation = 1; generation <= 4; ++generation) {
		ASSERT_EQ(ledger.begin(generation, 0), outcome::ok);
		ASSERT_EQ(ledger.commit(generation), outcome::ok);

		auto baseline = make_window(generation, generation * 10);
		baseline.absolute.n_drops = 0;
		ledger.observe_window(baseline);

		auto with_drops = make_window(generation, generation * 10 + 1);
		with_drops.absolute.n_drops = generation;
		ledger.observe_window(with_drops);
		observed_monotonic_deltas += generation;
	}

	const auto history = ledger.history();
	ASSERT_EQ(history.size(), 2u);
	EXPECT_EQ(history[0].generation, 3u);
	EXPECT_EQ(history[1].generation, 4u);
	EXPECT_EQ(ledger.evicted_generations(), 2u);
	EXPECT_EQ(ledger.evicted_drops(), 3u);

	uint64_t retained_drops = 0;
	for(const auto& r : history) {
		retained_drops += r.tally.drops;
	}
	EXPECT_EQ(ledger.evicted_drops() + retained_drops + ledger.unattributed_drops(),
	          observed_monotonic_deltas);
	EXPECT_EQ(observed_monotonic_deltas, 10u);
}

TEST(GenerationLedger, RejectAndCommitInterleave) {
	source_ledger ledger("instance-interleave", "syscall");
	ASSERT_EQ(ledger.begin(4, 0), outcome::ok);
	ASSERT_EQ(ledger.commit(4), outcome::ok);

	ASSERT_EQ(ledger.begin(5, 0), outcome::ok);
	ASSERT_EQ(ledger.begin(6, 4), outcome::ok);
	ASSERT_EQ(ledger.reject(6, "rule condition error"), outcome::ok);

	auto rejected = [&] {
		for(const auto& r : ledger.history()) {
			if(r.generation == 6) {
				return r;
			}
		}
		return record{};
	}();
	EXPECT_EQ(rejected.stage, phase::rejected);
	EXPECT_EQ(rejected.requests, 4u);
	EXPECT_EQ(rejected.reason, "rule condition error");
	EXPECT_EQ(ledger.applied_generation(), 4u);

	auto count_applied = [&] {
		size_t count = 0;
		for(const auto& r : ledger.history()) {
			count += r.stage == phase::applied ? 1 : 0;
		}
		return count;
	};
	EXPECT_EQ(count_applied(), 1u);

	EXPECT_EQ(ledger.reject(6, "different reason"), outcome::rejected_already);
	EXPECT_EQ(ledger.current().generation, 4u);

	ASSERT_EQ(ledger.commit(5), outcome::ok);
	EXPECT_EQ(ledger.applied_generation(), 5u);
	const auto history = ledger.history();
	bool has_five = false;
	bool has_six = false;
	for(const auto& r : history) {
		has_five = has_five || r.generation == 5;
		has_six = has_six || r.generation == 6;
	}
	EXPECT_TRUE(has_five);
	EXPECT_TRUE(has_six);
	EXPECT_EQ(count_applied(), 1u);
}

TEST(GenerationLedger, CommitAndRejectBoundaries) {
	source_ledger ledger("instance-boundaries", "syscall");
	EXPECT_EQ(ledger.commit(404), outcome::unknown);
	EXPECT_EQ(ledger.reject(404, "missing"), outcome::unknown);

	ASSERT_EQ(ledger.begin(2, 1), outcome::ok);
	ASSERT_EQ(ledger.commit(2), outcome::ok);
	EXPECT_EQ(ledger.commit(2), outcome::applied_already);
	EXPECT_EQ(ledger.reject(2, "applied"), outcome::applied_already);

	ASSERT_EQ(ledger.begin(3, 2), outcome::ok);
	ASSERT_EQ(ledger.commit(3), outcome::ok);
	EXPECT_EQ(ledger.commit(2), outcome::stale);

	ASSERT_EQ(ledger.begin(4, 0), outcome::ok);
	EXPECT_EQ(ledger.begin(4, 9), outcome::stale);
	ASSERT_EQ(ledger.reject(4, "bad rule"), outcome::ok);
	EXPECT_EQ(ledger.reject(4, "new reason"), outcome::rejected_already);
	const auto r4 = *std::find_if(ledger.history().begin(),
	                              ledger.history().end(),
	                              [](const record& r) { return r.generation == 4; });
	EXPECT_EQ(r4.requests, 0u);
	EXPECT_EQ(r4.reason, "bad rule");
}

TEST(GenerationLedger, RejectedRecordHasZeroShapedTally) {
	source_ledger ledger("instance-rejected-shape", "syscall");
	ASSERT_EQ(ledger.begin(7, 2), outcome::ok);
	ASSERT_EQ(ledger.reject(7, "condition error"), outcome::ok);
	const auto r = ledger.history().back();
	EXPECT_EQ(r.first_ts, 0u);
	EXPECT_EQ(r.last_ts, 0u);
	EXPECT_EQ(r.gap_ns, 0u);
	EXPECT_FALSE(r.baseline_unknown);
	EXPECT_FALSE(r.engine_reset);
	const counts zero{};
	EXPECT_EQ(r.tally.events, zero.events);
	EXPECT_EQ(r.tally.drops, zero.drops);
	EXPECT_EQ(r.tally.detections, zero.detections);
	EXPECT_EQ(r.tally.actions, zero.actions);
	EXPECT_EQ(r.tally.bucket_denied, zero.bucket_denied);
	EXPECT_EQ(r.tally.partial_windows, zero.partial_windows);
	EXPECT_EQ(r.tally.resets, zero.resets);
	EXPECT_EQ(r.tally.out_of_order, zero.out_of_order);
}

TEST(GenerationLedger, ZeroRetentionRemainsDegradedButUnattributedIsAccurate) {
	source_ledger ledger("instance-no-retain", "syscall", 0);
	EXPECT_TRUE(ledger.degraded());
	EXPECT_TRUE(ledger.history().empty());
	EXPECT_EQ(ledger.evicted_generations(), 0u);
	EXPECT_EQ(ledger.evicted_drops(), 0u);
	EXPECT_EQ(ledger.lost_windows(), 0u);

	auto first = make_window(9, 1000);
	first.absolute.n_drops = 3;
	ledger.observe_window(first);
	auto second = make_window(9, 2000);
	second.absolute.n_drops = 8;
	ledger.observe_window(second);
	EXPECT_EQ(ledger.unattributed_drops(), 5u);
}

TEST(GenerationLedger, ProviderFailureDegradesAndPreservesMatches) {
	source_ledger ledger("instance-provider-failure", "syscall");
	ASSERT_EQ(ledger.begin(1, 0), outcome::ok);
	ASSERT_EQ(ledger.commit(1), outcome::ok);
	fake_provider provider;
	provider.totals = {{"a", 4}};
	ASSERT_EQ(ledger.attribute(1, provider), outcome::ok);

	provider.throw_on_poll = true;
	EXPECT_EQ(ledger.attribute(1, provider), outcome::degraded);
	EXPECT_TRUE(ledger.degraded());
	EXPECT_FALSE(ledger.current().engine_reset);
	EXPECT_EQ(ledger.current().rule_matches.at("a"), 4u);

	provider.throw_on_poll = false;
	provider.totals = {{"a", 6}};
	EXPECT_EQ(ledger.attribute(1, provider), outcome::ok);
	EXPECT_EQ(ledger.current().rule_matches.at("a"), 6u);
}

TEST(GenerationLedger, ConcurrentSnapshotIsConsistent) {
	constexpr uint64_t kWrites = 200000;
	source_ledger ledger("instance-concurrent", "syscall", 4);
	ASSERT_EQ(ledger.begin(1, 0), outcome::ok);
	ASSERT_EQ(ledger.commit(1), outcome::ok);

	std::atomic<bool> start{false};
	std::atomic<bool> writer_error{false};
	std::atomic<bool> reader_error{false};
	std::atomic<uint64_t> parsed{0};

	std::thread writer([&] {
		while(!start.load(std::memory_order_acquire)) {
			std::this_thread::yield();
		}
		try {
			for(uint64_t i = 0; i < kWrites; ++i) {
				auto w = make_window(1, 1000 + i);
				w.absolute.n_evts = i;
				w.absolute.n_drops = i;
				w.threshold_exceeded = (i & 1U) != 0;
				w.bucket_allowed = (i & 3U) == 0;
				ledger.observe_window(w);
			}
		} catch(...) {
			writer_error.store(true, std::memory_order_release);
		}
	});

	std::thread reader([&] {
		uint64_t last_drops = 0;
		while(!start.load(std::memory_order_acquire)) {
			std::this_thread::yield();
		}
		try {
			for(uint64_t i = 0; i < kWrites; ++i) {
				const auto j = ledger.to_json();
				const auto dumped = compact_dump(j);
				const auto parsed_json = nlohmann::json::parse(dumped);
				if(parsed_json.at("generations").size() > 4) {
					reader_error.store(true);
				}
				const auto drops =
				        parsed_json.at("generations").at(0).at("tally").at("drops").get<uint64_t>();
				if(drops < last_drops) {
					reader_error.store(true);
				}
				last_drops = drops;
				++parsed;
			}
		} catch(...) {
			reader_error.store(true, std::memory_order_release);
		}
	});

	start.store(true, std::memory_order_release);
	writer.join();
	reader.join();

	EXPECT_FALSE(writer_error.load());
	EXPECT_FALSE(reader_error.load());
	EXPECT_EQ(parsed.load(), kWrites);
	EXPECT_LE(ledger.history().size(), 4u);
}

TEST(GenerationLedger, AttributePollsBeforeLocking) {
	source_ledger ledger("instance-reentrant", "syscall");
	ASSERT_EQ(ledger.begin(1, 0), outcome::ok);
	ASSERT_EQ(ledger.commit(1), outcome::ok);
	reentrant_provider provider(ledger);

	auto future = std::async(std::launch::async, [&] {
		return ledger.attribute(1, provider);
	});
	ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
	EXPECT_EQ(future.get(), outcome::ok);
}

TEST(GenerationLedger, GoldenJsonAfterNineWindows) {
	source_ledger ledger("golden-instance", "golden-source", 4);
	ASSERT_EQ(ledger.begin(8, 2), outcome::ok);
	ASSERT_EQ(ledger.commit(8), outcome::ok);

	const uint64_t drops[9] = {10, 11, 12, 11, 13, 15, 16, 15, 18};
	const uint64_t events[9] = {100, 140, 190, 210, 260, 300, 360, 390, 450};
	for(uint64_t i = 0; i < 9; ++i) {
		auto w = make_window(8, (i + 1) * 1000000000ULL);
		w.absolute.n_evts = events[i];
		w.absolute.n_drops = drops[i];
		w.absolute.n_drops_buffer_open_exit = i;
		w.threshold_exceeded = (i % 2) == 0;
		w.bucket_allowed = (i % 3) == 0;
		ledger.observe_window(w);
	}

	fake_provider provider;
	provider.totals = {{"rule_a", 3}, {"rule_b", 1}};
	ASSERT_EQ(ledger.attribute(8, provider), outcome::ok);

	const nlohmann::json actual = nlohmann::json::parse(ledger.to_json().dump(2));
	const char* literal = R"JSON({
  "instance_id": "golden-instance",
  "source": "golden-source",
  "applied_generation": 8,
  "degraded": false,
  "unattributed_drops": 0,
  "unattributed_resets": 0,
  "evicted_generations": 0,
  "evicted_drops": 0,
  "lost_windows": 0,
  "generations": [
    {
      "generation": 8,
      "instance_id": "golden-instance",
      "source": "golden-source",
      "stage": "applied",
      "requests": 2,
      "first_ts": 1000000000,
      "last_ts": 9000000000,
      "gap_ns": 0,
      "baseline_unknown": false,
      "engine_reset": false,
      "tally": {
        "delta": {
          "n_evts": 300,
          "n_drops": 10,
          "n_drops_buffer": 0,
          "n_drops_buffer_clone_fork_exit": 0,
          "n_drops_buffer_execve_exit": 0,
          "n_drops_buffer_connect_exit": 0,
          "n_drops_buffer_open_exit": 6,
          "n_drops_buffer_dir_file_exit": 0,
          "n_drops_buffer_other_interest_exit": 0,
          "n_drops_buffer_close_exit": 0,
          "n_drops_buffer_proc_exit": 0,
          "n_drops_scratch_map": 0,
          "n_drops_pf": 0,
          "n_drops_bug": 0,
          "n_preemptions": 0,
          "n_suppressed": 0,
          "n_tids_suppressed": 0
        },
        "events": 300,
        "drops": 10,
        "detections": 5,
        "actions": 2,
        "bucket_denied": 3,
        "partial_windows": 1,
        "resets": 2,
        "out_of_order": 0
      },
      "rule_matches": {"rule_a": 3, "rule_b": 1},
      "reason": "",
      "last": "ok"
    }
  ]
})JSON";
	const nlohmann::json expected = nlohmann::json::parse(literal);
	EXPECT_EQ(actual, expected);

	const std::vector<std::string> top_level_order = {
	        "instance_id",
	        "source",
	        "applied_generation",
	        "degraded",
	        "unattributed_drops",
	        "unattributed_resets",
	        "evicted_generations",
	        "evicted_drops",
	        "lost_windows",
	        "generations",
	};
	const auto top_level_json = ledger.to_json();
	size_t position = 0;
	for(const auto& [key, value] : top_level_json.items()) {
		ASSERT_LT(position, top_level_order.size());
		EXPECT_TRUE(top_level_json.contains(top_level_order[position]));
		EXPECT_EQ(key, key);
		++position;
	}
	EXPECT_EQ(position, top_level_order.size());
}

TEST(GenerationLedger, ReplayIsByteStable) {
	auto replay = [] {
		source_ledger ledger("replay-instance", "replay-source", 3);
		EXPECT_EQ(ledger.begin(9, 1), outcome::ok);
		EXPECT_EQ(ledger.begin(8, 2), outcome::ok);
		EXPECT_EQ(ledger.reject(8, "bad"), outcome::ok);
		EXPECT_EQ(ledger.commit(9), outcome::ok);

		fake_provider provider;
		for(uint64_t step = 0; step < 12; ++step) {
			auto w = make_window(9, (step + 1) * 777);
			w.absolute.n_evts = 100 + step * 17;
			w.absolute.n_drops = step / 3;
			w.threshold_exceeded = step % 2 == 0;
			w.bucket_allowed = step % 4 == 0;
			ledger.observe_window(w);
			provider.totals = {{"a", step * 2}, {"b", step}};
			(void)ledger.attribute(9, provider);
		}
		return ledger.to_json().dump(2);
	};

	const std::string expected = replay();
	for(int repetition = 0; repetition < 100; ++repetition) {
		EXPECT_EQ(replay(), expected);
	}

	source_ledger ordering("order-instance", "source");
	ASSERT_EQ(ordering.begin(9, 0), outcome::ok);
	ASSERT_EQ(ordering.begin(8, 0), outcome::ok);
	const auto history = ordering.history();
	ASSERT_EQ(history.size(), 2u);
	EXPECT_EQ(history[0].generation, 8u);
	EXPECT_EQ(history[1].generation, 9u);
}
