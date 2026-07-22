#!/usr/bin/env bash
# Observe exact kernel futex-wait entries for matched sparse and diagnostic-rich
# workspace/diagnostic requests. The C helper traces only between acknowledged
# driver markers; it does not modify or instrument the LSP server source.

set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

work_dir=$(mktemp -d "$repo_root/.perfloop-futex.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT

probe="$work_dir/workspace_diagnostic_futex_probe"
cc -O2 -std=c11 -Wall -Wextra -Werror \
    -o "$probe" \
    scripts/workspace_diagnostic_futex_probe.c

cargo build --locked --profile profiling -p ty_server --example workspace_diagnostic_perf
target_dir=$(cargo metadata --format-version 1 --no-deps | jq -r '.target_directory')
driver="$target_dir/profiling/examples/workspace_diagnostic_perf"

if [[ ! -x "$driver" ]]; then
    printf 'workspace diagnostic driver is missing: %s\n' "$driver" >&2
    exit 1
fi

export TY_MAX_PARALLELISM=4

run_profile() {
    local name=$1
    local control_socket="$work_dir/$name.socket"
    local ack_socket="$work_dir/$name.ack"
    local output_file="$work_dir/$name.output"

    PERFLOOP_PROBE_CONTROL_SOCKET="$control_socket" \
        PERFLOOP_PROBE_ACK_SOCKET="$ack_socket" \
        "$probe" "$driver" "--probe-$name" > "$output_file"
}

read_metric() {
    local output_file=$1
    local metric_name=$2
    local value

    value=$(awk -F= -v name="$metric_name" '$1 == name { value = $2 } END { print value }' "$output_file")
    if [[ ! "$value" =~ ^[0-9]+$ ]]; then
        printf 'missing numeric %s in %s\n' "$metric_name" "$output_file" >&2
        exit 1
    fi
    printf '%s\n' "$value"
}

run_profile rich
run_profile sparse

rich_wait_attempts=$(read_metric "$work_dir/rich.output" futex_wait_attempts)
sparse_wait_attempts=$(read_metric "$work_dir/sparse.output" futex_wait_attempts)
rich_max_address_attempts=$(read_metric "$work_dir/rich.output" futex_wait_max_address_attempts)
sparse_max_address_attempts=$(read_metric "$work_dir/sparse.output" futex_wait_max_address_attempts)
wait_attempt_delta=$((rich_wait_attempts - sparse_wait_attempts))

# The request bodies and completed responses are validated by the driver. Require
# the tracer to observe actual wait entries and a corresponding address in both
# matched runs; a marker-only or pass-through trace is not a successful probe.
if ((rich_wait_attempts == 0 || sparse_wait_attempts == 0 || rich_max_address_attempts == 0 || sparse_max_address_attempts == 0)); then
    printf 'futex trace observed no in-interval wait entries for a completed workload\n' >&2
    exit 1
fi

printf 'futex_trace_completed=true futex_trace_observation=observed rich_futex_wait_attempts=%s sparse_futex_wait_attempts=%s rich_futex_wait_max_address_attempts=%s sparse_futex_wait_max_address_attempts=%s rich_minus_sparse_futex_wait_attempts=%s\n' \
    "$rich_wait_attempts" \
    "$sparse_wait_attempts" \
    "$rich_max_address_attempts" \
    "$sparse_max_address_attempts" \
    "$wait_attempt_delta"
