#!/usr/bin/env bash
# Compare externally sampled futex waits for matched sparse and diagnostic-rich
# workspace/diagnostic requests. The C helper traces the standalone workload;
# it does not modify or instrument the LSP server source.

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
    local status_file="$work_dir/$name.status"
    local output_file="$work_dir/$name.output"

    : > "$status_file"
    PERFLOOP_PROBE_STATUS_FILE="$status_file" \
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

rich_wait_samples=$(read_metric "$work_dir/rich.output" futex_wait_samples)
sparse_wait_samples=$(read_metric "$work_dir/sparse.output" futex_wait_samples)
rich_max_address_samples=$(read_metric "$work_dir/rich.output" futex_wait_max_address_samples)
sparse_max_address_samples=$(read_metric "$work_dir/sparse.output" futex_wait_max_address_samples)
rich_max_same_address=$(read_metric "$work_dir/rich.output" futex_wait_max_same_address)
sparse_max_same_address=$(read_metric "$work_dir/sparse.output" futex_wait_max_same_address)

delta_observed=false
if (( rich_wait_samples > sparse_wait_samples && rich_max_same_address >= 2 )); then
    delta_observed=true
fi

printf 'futex_probe_completed=true rich_futex_wait_samples=%s sparse_futex_wait_samples=%s rich_futex_wait_max_address_samples=%s sparse_futex_wait_max_address_samples=%s rich_futex_wait_max_same_address=%s sparse_futex_wait_max_same_address=%s\n' \
    "$rich_wait_samples" \
    "$sparse_wait_samples" \
    "$rich_max_address_samples" \
    "$sparse_max_address_samples" \
    "$rich_max_same_address" \
    "$sparse_max_same_address"
printf 'futex_wait_delta_observed=%s\n' "$delta_observed"
