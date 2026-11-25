// SPDX-License-Identifier: Apache-2.0

#include "drop_attribution.h"

namespace falco::reload_ledger {

const char* to_string(outcome o) {
	switch(o) {
	case outcome::ok:
		return "ok";
	case outcome::stale:
		return "stale";
	case outcome::unknown:
		return "unknown";
	case outcome::applied_already:
		return "applied_already";
	case outcome::rejected_already:
		return "rejected_already";
	case outcome::counters_reset:
		return "counters_reset";
	case outcome::bound_reached:
		return "bound_reached";
	case outcome::degraded:
		return "degraded";
	}
	return "unknown";
}

bool subtract(const sample& older, const sample& newer, sample& out) {
	if(newer.n_evts < older.n_evts || newer.n_drops < older.n_drops ||
	   newer.n_drops_buffer < older.n_drops_buffer ||
	   newer.n_drops_buffer_clone_fork_exit < older.n_drops_buffer_clone_fork_exit ||
	   newer.n_drops_buffer_execve_exit < older.n_drops_buffer_execve_exit ||
	   newer.n_drops_buffer_connect_exit < older.n_drops_buffer_connect_exit ||
	   newer.n_drops_buffer_open_exit < older.n_drops_buffer_open_exit ||
	   newer.n_drops_buffer_dir_file_exit < older.n_drops_buffer_dir_file_exit ||
	   newer.n_drops_buffer_other_interest_exit <
	           older.n_drops_buffer_other_interest_exit ||
	   newer.n_drops_buffer_close_exit < older.n_drops_buffer_close_exit ||
	   newer.n_drops_buffer_proc_exit < older.n_drops_buffer_proc_exit ||
	   newer.n_drops_scratch_map < older.n_drops_scratch_map ||
	   newer.n_drops_pf < older.n_drops_pf || newer.n_drops_bug < older.n_drops_bug ||
	   newer.n_preemptions < older.n_preemptions || newer.n_suppressed < older.n_suppressed ||
	   newer.n_tids_suppressed < older.n_tids_suppressed) {
		return false;
	}

	sample result{};
	result.n_evts = newer.n_evts - older.n_evts;
	result.n_drops = newer.n_drops - older.n_drops;
	result.n_drops_buffer = newer.n_drops_buffer - older.n_drops_buffer;
	result.n_drops_buffer_clone_fork_exit =
	        newer.n_drops_buffer_clone_fork_exit - older.n_drops_buffer_clone_fork_exit;
	result.n_drops_buffer_execve_exit =
	        newer.n_drops_buffer_execve_exit - older.n_drops_buffer_execve_exit;
	result.n_drops_buffer_connect_exit =
	        newer.n_drops_buffer_connect_exit - older.n_drops_buffer_connect_exit;
	result.n_drops_buffer_open_exit =
	        newer.n_drops_buffer_open_exit - older.n_drops_buffer_open_exit;
	result.n_drops_buffer_dir_file_exit =
	        newer.n_drops_buffer_dir_file_exit - older.n_drops_buffer_dir_file_exit;
	result.n_drops_buffer_other_interest_exit =
	        newer.n_drops_buffer_other_interest_exit -
	        older.n_drops_buffer_other_interest_exit;
	result.n_drops_buffer_close_exit =
	        newer.n_drops_buffer_close_exit - older.n_drops_buffer_close_exit;
	result.n_drops_buffer_proc_exit =
	        newer.n_drops_buffer_proc_exit - older.n_drops_buffer_proc_exit;
	result.n_drops_scratch_map = newer.n_drops_scratch_map - older.n_drops_scratch_map;
	result.n_drops_pf = newer.n_drops_pf - older.n_drops_pf;
	result.n_drops_bug = newer.n_drops_bug - older.n_drops_bug;
	result.n_preemptions = newer.n_preemptions - older.n_preemptions;
	result.n_suppressed = newer.n_suppressed - older.n_suppressed;
	result.n_tids_suppressed = newer.n_tids_suppressed - older.n_tids_suppressed;
	out = result;
	return true;
}

}  // namespace falco::reload_ledger
