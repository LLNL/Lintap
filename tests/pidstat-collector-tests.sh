#!/usr/bin/env bash

set -euo pipefail

readonly TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${TEST_DIR}/.." && pwd)"

source "${REPO_ROOT}/pidstat-collector.sh"

tests_run=0

fail_test() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

assert_eq() {
  local expected=$1
  local actual=$2
  local message=$3

  [[ "$expected" == "$actual" ]] || fail_test "$message (expected=$expected actual=$actual)"
}

assert_file_count() {
  local glob_pattern=$1
  local expected_count=$2
  local message=$3
  local -a matches=()

  shopt -s nullglob
  matches=( $glob_pattern )
  shopt -u nullglob
  assert_eq "$expected_count" "${#matches[@]}" "$message"
}

duckdb_scalar() {
  local sql=$1
  local -a rows

  mapfile -t rows < <(duckdb -csv -c "$sql")
  printf '%s\n' "${rows[1]}"
}

count_raw_pidstat_detail_lines() {
  local raw_file=$1
  local line
  local count=0
  local -a fields=()

  while IFS= read -r line; do
    [[ -n ${line//[[:space:]]/} ]] || continue
    [[ $line != Linux* ]] || continue
    [[ $line != \#* ]] || continue
    [[ $line != Average:* ]] || continue

    IFS=$' \t\n' read -r -a fields <<< "$line"
    if (( ${#fields[@]} >= 21 )) && [[ ${fields[0]} =~ ^[0-9]{2}:[0-9]{2}:[0-9]{2}$ ]]; then
      count=$((count + 1))
    fi
  done < "$raw_file"

  printf '%s\n' "$count"
}

normalize_raw_pidstat_file() {
  local raw_file=$1
  local normalized_file=$2
  local line
  local normalized_line

  : > "$normalized_file"
  while IFS= read -r line; do
    if normalized_line=$(normalize_pidstat_line "$line"); then
      printf '%s\n' "$normalized_line" >> "$normalized_file"
    fi
  done < "$raw_file"
}

setup_case() {
  local case_name=$1

  CASE_ROOT=$(mktemp -d "/tmp/${case_name}.XXXXXX")
  export WINTAP_DATA_ROOT="${CASE_ROOT}/data"
  export PIDSTAT_PARQUET_ROOT="${WINTAP_DATA_ROOT}/parquet"
  export PIDSTAT_SPOOL_DIR="${WINTAP_DATA_ROOT}/pidstat-spool"
  export PIDSTAT_HOSTNAME="testhost"
  export PIDSTAT_INTERVAL_SEC=1
  export PIDSTAT_ROTATE_INTERVAL_SEC=300
  export PIDSTAT_PARQUET_COMPRESSION=ZSTD
  export PIDSTAT_MAX_UNSHIPPED_BYTES=0
  export PIDSTAT_MAX_UNSHIPPED_AGE_SEC=0
  init_config
}

teardown_case() {
  rm -rf "$CASE_ROOT"
}

write_fixture_spool() {
  local spool_path=$1

  mkdir -p "$(dirname "$spool_path")"
  cat > "$spool_path" <<'EOF'
2026-08-12	07:50:00	0	128259	285.98	140.19	0.00	0.00	426.17	0	4317.76	0.00	814169220	1892724	0.48	-1.00	-1.00	-1.00	0	0.00	0.00	Lintap
2026-08-12	07:50:00	5081	1330372	55.14	11.21	0.00	0.00	66.36	23	708.41	0.00	75487136	749212	0.19	0.00	0.00	0.00	0	490.65	7.48	opencode
EOF
}

test_normalize_pidstat_line_with_loop_ifs() {
  local raw_line
  local normalized_line

  setup_case "pidstat-normalize"
  raw_line='09:05:05        0         1    0.00    0.00    0.00    0.00    0.00    12      0.00      0.00  242192   14800   0.00     -1.00     -1.00     -1.00       0      0.59      0.00  systemd'

  while IFS= read -r line; do
    normalized_line=$(normalize_pidstat_line "$line")
  done <<< "$raw_line"

  assert_eq $'2026-08-12\t09:05:05\t0\t1\t0.00\t0.00\t0.00\t0.00\t0.00\t12\t0.00\t0.00\t242192\t14800\t0.00\t-1.00\t-1.00\t-1.00\t0\t0.59\t0.00\tsystemd' "$normalized_line" "normalization should not inherit empty loop IFS"
  teardown_case
}

test_normalize_pidstat_line_with_joined_raw_records() {
  local raw_chunk
  local normalized_chunk

  setup_case "pidstat-joined"
  raw_chunk='09:14:33 0 1391556 0.00 0.00 0.00 0.00 0.00 22 0.00 0.00 0 0 0.00 -1.00 -1.00 -1.00 0 0.00 0.0009:14:33 0 1391647 0.00 0.00 0.00 0.00 0.00 12 0.00 0.00 0 0 0.00 -1.00 -1.00 -1.00 0 0.00 0.00 kworker/12:1-cgroup_destroy'

  normalized_chunk=$(normalize_pidstat_line "$raw_chunk")

  assert_eq $'2026-08-12\t09:14:33\t0\t1391556\t0.00\t0.00\t0.00\t0.00\t0.00\t22\t0.00\t0.00\t0\t0\t0.00\t-1.00\t-1.00\t-1.00\t0\t0.00\t0.00\t\n2026-08-12\t09:14:33\t0\t1391647\t0.00\t0.00\t0.00\t0.00\t0.00\t12\t0.00\t0.00\t0\t0\t0.00\t-1.00\t-1.00\t-1.00\t0\t0.00\t0.00\tkworker/12:1-cgroup_destroy' "$normalized_chunk" "joined raw pidstat records should be split into separate normalized rows"
  teardown_case
}

test_convert_spool_to_partitioned_parquet() {
  local pending_spool
  local pending_meta
  local window_start_epoch
  local parquet_file
  local row_count
  local hostname_value
  local command_value

  setup_case "pidstat-convert"
  pending_spool="${PIDSTAT_SPOOL_DIR}/pending-1754985000-1-$$.tsv"
  pending_meta="${PIDSTAT_SPOOL_DIR}/pending-1754985000-1-$$.meta"
  window_start_epoch=$(date -d '2026-08-12 07:50:00' +%s)

  write_fixture_spool "$pending_spool"
  write_meta_file "$pending_meta" "$window_start_epoch"

  process_pending_spools

  assert_file_count "${PIDSTAT_RAW_SENSOR_DIR}/dayPK=20260812/hourPK=07/*.parquet" 1 "converted parquet should land in the expected partition"
  parquet_file=$(compgen -G "${PIDSTAT_RAW_SENSOR_DIR}/dayPK=20260812/hourPK=07/*.parquet")
  row_count=$(duckdb_scalar "select count(*) from read_parquet('${parquet_file}');")
  hostname_value=$(duckdb_scalar "select min(hostname) from read_parquet('${parquet_file}');")
  command_value=$(duckdb_scalar "select max(command) from read_parquet('${parquet_file}');")

  assert_eq "2" "$row_count" "parquet row count"
  assert_eq "testhost" "$hostname_value" "hostname column"
  assert_eq "opencode" "$command_value" "command column"
  teardown_case
}

test_salvages_leftover_current_spool() {
  local current_spool
  local current_meta

  setup_case "pidstat-salvage"
  current_spool=$(current_spool_path)
  current_meta=$(current_meta_path)

  write_fixture_spool "$current_spool"
  write_meta_file "$current_meta" "$(date -d '2026-08-12 07:50:00' +%s)"

  salvage_spool_files

  assert_file_count "${PIDSTAT_RAW_SENSOR_DIR}/dayPK=20260812/hourPK=07/*.parquet" 1 "salvage should convert leftover current spool"
  [[ ! -e "$current_spool" ]] || fail_test "current spool should be removed after salvage"
  [[ ! -e "$current_meta" ]] || fail_test "current meta should be removed after salvage"
  teardown_case
}

test_byte_cap_drops_oldest_files() {
  local first_file
  local second_file
  local third_file

  setup_case "pidstat-guard-bytes"
  mkdir -p "${PIDSTAT_RAW_SENSOR_DIR}/dayPK=20260812/hourPK=07"

  first_file="${PIDSTAT_RAW_SENSOR_DIR}/dayPK=20260812/hourPK=07/testhost+pidstat+1.parquet"
  second_file="${PIDSTAT_RAW_SENSOR_DIR}/dayPK=20260812/hourPK=07/testhost+pidstat+2.parquet"
  third_file="${PIDSTAT_RAW_SENSOR_DIR}/dayPK=20260812/hourPK=07/testhost+pidstat+3.parquet"

  dd if=/dev/zero of="$first_file" bs=60 count=1 status=none
  dd if=/dev/zero of="$second_file" bs=60 count=1 status=none
  dd if=/dev/zero of="$third_file" bs=60 count=1 status=none
  touch -d '2026-08-12 07:50:00' "$first_file"
  touch -d '2026-08-12 07:51:00' "$second_file"
  touch -d '2026-08-12 07:52:00' "$third_file"

  export PIDSTAT_MAX_UNSHIPPED_BYTES=100
  enforce_accumulation_guard

  [[ ! -e "$first_file" ]] || fail_test "oldest file should be deleted first"
  [[ ! -e "$second_file" ]] || fail_test "second-oldest file should be deleted when still over cap"
  [[ -e "$third_file" ]] || fail_test "newest file should be retained"
  teardown_case
}

test_age_cap_drops_stale_files() {
  local stale_file
  local fresh_file

  setup_case "pidstat-guard-age"
  mkdir -p "${PIDSTAT_RAW_SENSOR_DIR}/dayPK=20260812/hourPK=07"

  stale_file="${PIDSTAT_RAW_SENSOR_DIR}/dayPK=20260812/hourPK=07/testhost+pidstat+10.parquet"
  fresh_file="${PIDSTAT_RAW_SENSOR_DIR}/dayPK=20260812/hourPK=07/testhost+pidstat+11.parquet"

  dd if=/dev/zero of="$stale_file" bs=32 count=1 status=none
  dd if=/dev/zero of="$fresh_file" bs=32 count=1 status=none
  touch -d '2026-08-12 07:40:00' "$stale_file"
  touch "$fresh_file"

  export PIDSTAT_MAX_UNSHIPPED_AGE_SEC=60
  enforce_accumulation_guard

  [[ ! -e "$stale_file" ]] || fail_test "stale file should be deleted by age cap"
  [[ -e "$fresh_file" ]] || fail_test "fresh file should remain after age pruning"
  teardown_case
}

test_live_pidstat_row_preservation() {
  local raw_file
  local normalized_file
  local pending_spool
  local pending_meta
  local parquet_glob
  local raw_count
  local normalized_count
  local parquet_count
  local distinct_commands
  local window_start_epoch
  local rc

  setup_case "pidstat-live-validate"
  raw_file="${CASE_ROOT}/raw-pidstat.txt"
  normalized_file="${CASE_ROOT}/normalized-pidstat.tsv"
  pending_spool="${PIDSTAT_SPOOL_DIR}/pending-live-$$.tsv"
  pending_meta="${PIDSTAT_SPOOL_DIR}/pending-live-$$.meta"

  set +e
  timeout --signal=TERM 12 env S_TIME_FORMAT=ISO pidstat -u -d -r -w -h -p ALL 5 > "$raw_file"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 && "$rc" -ne 124 ]]; then
    fail_test "live pidstat validation capture failed with exit code $rc"
  fi

  raw_count=$(count_raw_pidstat_detail_lines "$raw_file")
  [[ "$raw_count" -gt 0 ]] || fail_test "live pidstat validation captured zero raw detail rows"

  normalize_raw_pidstat_file "$raw_file" "$normalized_file"
  normalized_count=$(wc -l < "$normalized_file")
  assert_eq "$raw_count" "$normalized_count" "normalized row count should match raw pidstat detail row count"

  mv "$normalized_file" "$pending_spool"
  window_start_epoch=$(window_start_for_epoch "$(date +%s)")
  write_meta_file "$pending_meta" "$window_start_epoch"
  convert_spool_to_parquet "$pending_spool" "$pending_meta"

  parquet_glob="${PIDSTAT_RAW_SENSOR_DIR}/**/*.parquet"
  parquet_count=$(duckdb_scalar "select count(*) from read_parquet('${PIDSTAT_RAW_SENSOR_DIR}/**/*.parquet');")
  distinct_commands=$(duckdb_scalar "select count(distinct command) from read_parquet('${PIDSTAT_RAW_SENSOR_DIR}/**/*.parquet');")

  assert_eq "$normalized_count" "$parquet_count" "parquet row count should match normalized row count"
  [[ "$distinct_commands" -gt 1 ]] || fail_test "expected multiple commands in live pidstat parquet output"
  teardown_case
}

run_test() {
  local test_name=$1

  tests_run=$((tests_run + 1))
  printf 'RUN %s\n' "$test_name"
  "$test_name"
  printf 'PASS %s\n' "$test_name"
}

run_test test_convert_spool_to_partitioned_parquet
run_test test_normalize_pidstat_line_with_loop_ifs
run_test test_normalize_pidstat_line_with_joined_raw_records
run_test test_salvages_leftover_current_spool
run_test test_byte_cap_drops_oldest_files
run_test test_age_cap_drops_stale_files
run_test test_live_pidstat_row_preservation

printf 'PASS all %s tests\n' "$tests_run"
