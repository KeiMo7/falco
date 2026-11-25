// SPDX-License-Identifier: Apache-2.0

#include <falco/reload_ledger/drop_attribution.h>

#include <gtest/gtest.h>

using falco::reload_ledger::outcome;
using falco::reload_ledger::sample;
using falco::reload_ledger::subtract;
using falco::reload_ledger::to_string;

TEST(DropAttribution, SubtractsAllSeventeenFields) {
	sample older{};
	sample newer{};
	sample out{};

	int value = 1;
#define SET_FIELD(field)      \
		older.field = value;  \
		newer.field = value + \
		              10;     \
		out.field = 12345;    \
		++value;

	SET_FIELD(n_evts)
	SET_FIELD(n_drops)
	SET_FIELD(n_drops_buffer)
	SET_FIELD(n_drops_buffer_clone_fork_exit)
	SET_FIELD(n_drops_buffer_execve_exit)
	SET_FIELD(n_drops_buffer_connect_exit)
	SET_FIELD(n_drops_buffer_open_exit)
	SET_FIELD(n_drops_buffer_dir_file_exit)
	SET_FIELD(n_drops_buffer_other_interest_exit)
	SET_FIELD(n_drops_buffer_close_exit)
	SET_FIELD(n_drops_buffer_proc_exit)
	SET_FIELD(n_drops_scratch_map)
	SET_FIELD(n_drops_pf)
	SET_FIELD(n_drops_bug)
	SET_FIELD(n_preemptions)
	SET_FIELD(n_suppressed)
	SET_FIELD(n_tids_suppressed)
#undef SET_FIELD

	ASSERT_TRUE(subtract(older, newer, out));

	int expected = 1;
#define CHECK_FIELD(field)          \
		EXPECT_EQ(out.field, 10u)   \
		        << "field " #field; \
		++expected;

	CHECK_FIELD(n_evts)
	CHECK_FIELD(n_drops)
	CHECK_FIELD(n_drops_buffer)
	CHECK_FIELD(n_drops_buffer_clone_fork_exit)
	CHECK_FIELD(n_drops_buffer_execve_exit)
	CHECK_FIELD(n_drops_buffer_connect_exit)
	CHECK_FIELD(n_drops_buffer_open_exit)
	CHECK_FIELD(n_drops_buffer_dir_file_exit)
	CHECK_FIELD(n_drops_buffer_other_interest_exit)
	CHECK_FIELD(n_drops_buffer_close_exit)
	CHECK_FIELD(n_drops_buffer_proc_exit)
	CHECK_FIELD(n_drops_scratch_map)
	CHECK_FIELD(n_drops_pf)
	CHECK_FIELD(n_drops_bug)
	CHECK_FIELD(n_preemptions)
	CHECK_FIELD(n_suppressed)
	CHECK_FIELD(n_tids_suppressed)
#undef CHECK_FIELD
	(void)expected;
}

TEST(DropAttribution, RefusesUnderflowAndDoesNotWriteOutput) {
	sample older{};
	older.n_drops = 9;
	older.n_drops_buffer_open_exit = 4;
	sample newer{};
	newer.n_drops = 4;
	newer.n_drops_buffer_open_exit = 3;
	sample out{};
	out.n_drops = 0xdeadbeef;
	out.n_drops_buffer_open_exit = 0xdeadbeef;

	EXPECT_FALSE(subtract(older, newer, out));
	EXPECT_EQ(out.n_drops, 0xdeadbeef);
	EXPECT_EQ(out.n_drops_buffer_open_exit, 0xdeadbeef);
}

TEST(DropAttribution, OutcomeNamesAreStable) {
	EXPECT_STREQ(to_string(outcome::ok), "ok");
	EXPECT_STREQ(to_string(outcome::stale), "stale");
	EXPECT_STREQ(to_string(outcome::unknown), "unknown");
	EXPECT_STREQ(to_string(outcome::applied_already), "applied_already");
	EXPECT_STREQ(to_string(outcome::rejected_already), "rejected_already");
	EXPECT_STREQ(to_string(outcome::counters_reset), "counters_reset");
	EXPECT_STREQ(to_string(outcome::bound_reached), "bound_reached");
	EXPECT_STREQ(to_string(outcome::degraded), "degraded");
}
