#!/usr/bin/env bash

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"

log() {
  printf '%s - %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}

fail() {
  log "ERROR: $*"
  exit 1
}

require_command() {
  local command_name=$1

  command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: $command_name"
}

is_nonnegative_integer() {
  [[ ${1:-} =~ ^[0-9]+$ ]]
}

is_positive_integer() {
  [[ ${1:-} =~ ^[0-9]+$ ]] && (( $1 > 0 ))
}

duckdb_escape_literal() {
  local value=${1//\'/\'\'}
  printf '%s' "$value"
}

window_start_for_epoch() {
  local epoch=$1
  printf '%s\n' $(( epoch - (epoch % PIDSTAT_ROTATE_INTERVAL_SEC) ))
}

current_spool_path() {
  printf '%s/current.tsv\n' "$PIDSTAT_SPOOL_DIR"
}

current_meta_path() {
  printf '%s/current.meta\n' "$PIDSTAT_SPOOL_DIR"
}

meta_path_for_spool() {
  local spool_path=$1
  printf '%s.meta\n' "${spool_path%.tsv}"
}

write_meta_file() {
  local meta_path=$1
  local window_start_epoch=$2

  printf 'window_start_epoch=%s\n' "$window_start_epoch" > "$meta_path"
}

read_window_start_from_meta() {
  local meta_path=$1
  local key
  local value

  [[ -f "$meta_path" ]] || return 1

  while IFS='=' read -r key value; do
    if [[ $key == "window_start_epoch" ]]; then
      printf '%s\n' "$value"
      return 0
    fi
  done < "$meta_path"

  return 1
}

infer_window_start_from_spool() {
  local spool_path=$1
  local first_line
  local sample_date
  local sample_time
  local inferred_epoch

  [[ -s "$spool_path" ]] || return 1

  IFS= read -r first_line < "$spool_path" || return 1
  IFS=$'\t' read -r sample_date sample_time _ <<< "$first_line"
  [[ -n ${sample_date:-} && -n ${sample_time:-} ]] || return 1

  inferred_epoch=$(date -d "$sample_date $sample_time" +%s 2>/dev/null) || return 1
  window_start_for_epoch "$inferred_epoch"
}

ensure_meta_for_spool() {
  local spool_path=$1
  local meta_path=$2
  local inferred_window_start

  if read_window_start_from_meta "$meta_path" >/dev/null 2>&1; then
    return 0
  fi

  if inferred_window_start=$(infer_window_start_from_spool "$spool_path"); then
    write_meta_file "$meta_path" "$inferred_window_start"
    return 0
  fi

  return 1
}

initialize_current_window() {
  local window_start_epoch=$1

  mkdir -p "$PIDSTAT_SPOOL_DIR"
  : > "$(current_spool_path)"
  write_meta_file "$(current_meta_path)" "$window_start_epoch"
}

normalize_pidstat_line() {
  local line=$1
  local -a raw_fields
  local -a fields
  local sample_date
  local command_name
  local output=""
  local record
  local start_index=0
  local next_start_index
  local index

  [[ -n ${line//[[:space:]]/} ]] || return 1
  [[ $line != Linux* ]] || return 1
  [[ $line != \#* ]] || return 1
  [[ $line != Average:* ]] || return 1

  IFS=$' \t\n' read -r -a raw_fields <<< "$line"
  fields=()
  for token in "${raw_fields[@]}"; do
    if [[ ! $token =~ ^[0-9]{2}:[0-9]{2}:[0-9]{2}$ && $token =~ ^(.+)([0-9]{2}:[0-9]{2}:[0-9]{2})$ ]]; then
      fields+=("${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}")
    else
      fields+=("$token")
    fi
  done

  (( ${#fields[@]} >= 21 )) || return 1

  sample_date=$(date '+%Y-%m-%d')

  while (( ${#fields[@]} - start_index >= 21 )); do
    [[ ${fields[start_index]} =~ ^[0-9]{2}:[0-9]{2}:[0-9]{2}$ ]] || return 1

    next_start_index=${#fields[@]}
    for (( index = start_index + 20; index < ${#fields[@]}; index++ )); do
      if [[ ${fields[index]} =~ ^[0-9]{2}:[0-9]{2}:[0-9]{2}$ ]] && (( ${#fields[@]} - index >= 21 )); then
        next_start_index=$index
        break
      fi
    done

    command_name=""
    for (( index = start_index + 20; index < next_start_index; index++ )); do
      if [[ -z $command_name ]]; then
        command_name=${fields[index]}
      else
        command_name+=" ${fields[index]}"
      fi
    done

    printf -v record '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$sample_date" \
      "${fields[start_index]}" \
      "${fields[start_index + 1]}" \
      "${fields[start_index + 2]}" \
      "${fields[start_index + 3]}" \
      "${fields[start_index + 4]}" \
      "${fields[start_index + 5]}" \
      "${fields[start_index + 6]}" \
      "${fields[start_index + 7]}" \
      "${fields[start_index + 8]}" \
      "${fields[start_index + 9]}" \
      "${fields[start_index + 10]}" \
      "${fields[start_index + 11]}" \
      "${fields[start_index + 12]}" \
      "${fields[start_index + 13]}" \
      "${fields[start_index + 14]}" \
      "${fields[start_index + 15]}" \
      "${fields[start_index + 16]}" \
      "${fields[start_index + 17]}" \
      "${fields[start_index + 18]}" \
      "${fields[start_index + 19]}" \
      "$command_name"
    output+="$record"

    start_index=$next_start_index
  done

  [[ -n $output ]] || return 1
  printf '%s' "$output"
}

seal_current_spool() {
  local current_spool
  local current_meta
  local window_start_epoch
  local pending_base
  local pending_spool
  local pending_meta

  current_spool=$(current_spool_path)
  current_meta=$(current_meta_path)

  [[ -f "$current_spool" ]] || return 0

  if [[ ! -s "$current_spool" ]]; then
    rm -f "$current_spool" "$current_meta"
    return 0
  fi

  if ! window_start_epoch=$(read_window_start_from_meta "$current_meta"); then
    window_start_epoch=$(infer_window_start_from_spool "$current_spool") || fail "could not determine window start for $current_spool"
    write_meta_file "$current_meta" "$window_start_epoch"
  fi

  pending_base="$PIDSTAT_SPOOL_DIR/pending-${window_start_epoch}-$(date +%s)-$$"
  pending_spool="${pending_base}.tsv"
  pending_meta="${pending_base}.meta"

  mv "$current_spool" "$pending_spool"
  mv "$current_meta" "$pending_meta"
}

rotate_current_window_if_needed() {
  local sample_epoch=$1
  local desired_window_start
  local active_window_start

  desired_window_start=$(window_start_for_epoch "$sample_epoch")

  if [[ ! -f "$(current_meta_path)" ]]; then
    initialize_current_window "$desired_window_start"
    return 0
  fi

  active_window_start=$(read_window_start_from_meta "$(current_meta_path)") || active_window_start=""
  if [[ $active_window_start != "$desired_window_start" ]]; then
    seal_current_spool
    initialize_current_window "$desired_window_start"
    process_pending_spools
  fi
}

build_destination_file() {
  local window_start_epoch=$1
  local partition_day
  local partition_hour
  local output_dir
  local output_file

  partition_day=$(date -d "@$window_start_epoch" +%Y%m%d)
  partition_hour=$(date -d "@$window_start_epoch" +%H)
  output_dir="$PIDSTAT_RAW_SENSOR_DIR/dayPK=${partition_day}/hourPK=${partition_hour}"
  mkdir -p "$output_dir"

  output_file="$output_dir/${PIDSTAT_HOSTNAME}+pidstat+${window_start_epoch}.parquet"
  if [[ -e "$output_file" ]]; then
    output_file="$output_dir/${PIDSTAT_HOSTNAME}+pidstat+${window_start_epoch}-$(date +%s)-$$.parquet"
  fi

  printf '%s\n' "$output_file"
}

convert_spool_to_parquet() {
  local spool_path=$1
  local meta_path=$2
  local window_start_epoch
  local destination_file
  local temp_destination_file
  local sql
  local escaped_spool
  local escaped_temp
  local escaped_hostname

  [[ -s "$spool_path" ]] || return 0

  ensure_meta_for_spool "$spool_path" "$meta_path" || fail "missing meta for $spool_path"
  window_start_epoch=$(read_window_start_from_meta "$meta_path")
  destination_file=$(build_destination_file "$window_start_epoch")
  temp_destination_file="${destination_file}.active"

  rm -f "$temp_destination_file"

  escaped_spool=$(duckdb_escape_literal "$spool_path")
  escaped_temp=$(duckdb_escape_literal "$temp_destination_file")
  escaped_hostname=$(duckdb_escape_literal "$PIDSTAT_HOSTNAME")

  sql=$(cat <<SQL
COPY (
    SELECT
        CAST(date_col || ' ' || sample_time AS TIMESTAMP) AS time,
        CAST(uid AS INTEGER) AS uid,
        CAST(pid AS INTEGER) AS pid,
        CAST(usr_percent AS REAL) AS usr_percent,
        CAST(system_percent AS REAL) AS system_percent,
        CAST(guest_percent AS REAL) AS guest_percent,
        CAST(wait_percent AS REAL) AS wait_percent,
        CAST(cpu_percent AS REAL) AS cpu_percent,
        CAST(cpu_core AS INTEGER) AS cpu_core,
        CAST(minflt_per_sec AS REAL) AS minflt_per_sec,
        CAST(majflt_per_sec AS REAL) AS majflt_per_sec,
        CAST(vsz_kb AS BIGINT) AS vsz_kb,
        CAST(rss_kb AS BIGINT) AS rss_kb,
        CAST(mem_percent AS REAL) AS mem_percent,
        CAST(kb_read_per_sec AS REAL) AS kb_read_per_sec,
        CAST(kb_write_per_sec AS REAL) AS kb_write_per_sec,
        CAST(kb_cancelled_write_per_sec AS REAL) AS kb_cancelled_write_per_sec,
        CAST(iodelay_ticks AS INTEGER) AS iodelay_ticks,
        CAST(context_switch_per_sec AS REAL) AS context_switch_per_sec,
        CAST(nonvoluntary_context_switch_per_sec AS REAL) AS nonvoluntary_context_switch_per_sec,
        CAST(command AS VARCHAR) AS command,
        '${escaped_hostname}' AS hostname
    FROM read_csv(
        '${escaped_spool}',
        delim='\t',
        header=false,
        auto_detect=false,
        columns={
            'date_col': 'VARCHAR',
            'sample_time': 'VARCHAR',
            'uid': 'VARCHAR',
            'pid': 'VARCHAR',
            'usr_percent': 'VARCHAR',
            'system_percent': 'VARCHAR',
            'guest_percent': 'VARCHAR',
            'wait_percent': 'VARCHAR',
            'cpu_percent': 'VARCHAR',
            'cpu_core': 'VARCHAR',
            'minflt_per_sec': 'VARCHAR',
            'majflt_per_sec': 'VARCHAR',
            'vsz_kb': 'VARCHAR',
            'rss_kb': 'VARCHAR',
            'mem_percent': 'VARCHAR',
            'kb_read_per_sec': 'VARCHAR',
            'kb_write_per_sec': 'VARCHAR',
            'kb_cancelled_write_per_sec': 'VARCHAR',
            'iodelay_ticks': 'VARCHAR',
            'context_switch_per_sec': 'VARCHAR',
            'nonvoluntary_context_switch_per_sec': 'VARCHAR',
            'command': 'VARCHAR'
        }
    )
) TO '${escaped_temp}' (FORMAT PARQUET, COMPRESSION '${PIDSTAT_PARQUET_COMPRESSION}');
SQL
)

  if duckdb -c "$sql" >/dev/null 2>&1; then
    mv "$temp_destination_file" "$destination_file"
    log "wrote ${destination_file}"
    rm -f "$spool_path" "$meta_path"
    enforce_accumulation_guard
    return 0
  fi

  rm -f "$temp_destination_file"
  return 1
}

process_pending_spools() {
  local pending_spool
  local pending_meta

  shopt -s nullglob
  for pending_spool in "$PIDSTAT_SPOOL_DIR"/pending-*.tsv; do
    pending_meta=$(meta_path_for_spool "$pending_spool")
    if convert_spool_to_parquet "$pending_spool" "$pending_meta"; then
      :
    else
      log "WARN: parquet conversion failed for ${pending_spool}; leaving spool in place for retry"
    fi
  done
  shopt -u nullglob
}

enforce_accumulation_guard() {
  local current_time
  local file_info
  local file_mtime
  local file_path
  local total_bytes

  [[ -d "$PIDSTAT_RAW_SENSOR_DIR" ]] || return 0

  if (( PIDSTAT_MAX_UNSHIPPED_AGE_SEC > 0 )); then
    current_time=$(date +%s)
    while IFS= read -r file_info; do
      file_mtime=${file_info%% *}
      file_mtime=${file_mtime%%.*}
      file_path=${file_info#* }
      if (( current_time - file_mtime > PIDSTAT_MAX_UNSHIPPED_AGE_SEC )); then
        log "dropping stale unshipped pidstat parquet ${file_path}"
        rm -f "$file_path"
      fi
    done < <(find "$PIDSTAT_RAW_SENSOR_DIR" -type f -name '*.parquet' -printf '%T@ %p\n' | LC_ALL=C sort -n)
  fi

  if (( PIDSTAT_MAX_UNSHIPPED_BYTES <= 0 )); then
    return 0
  fi

  total_bytes=0
  while IFS= read -r file_info; do
    file_path=${file_info#* * }
    total_bytes=$(( total_bytes + ${file_info%% *} ))
  done < <(find "$PIDSTAT_RAW_SENSOR_DIR" -type f -name '*.parquet' -printf '%s %T@ %p\n' | LC_ALL=C sort -k2,2n)

  while (( total_bytes > PIDSTAT_MAX_UNSHIPPED_BYTES )); do
    file_info=$(find "$PIDSTAT_RAW_SENSOR_DIR" -type f -name '*.parquet' -printf '%s %T@ %p\n' | LC_ALL=C sort -k2,2n | head -n 1)
    [[ -n $file_info ]] || break
    file_path=${file_info#* * }
    log "dropping unshipped pidstat parquet to respect byte cap ${file_path}"
    rm -f "$file_path"
    total_bytes=$(( total_bytes - ${file_info%% *} ))
  done
}

salvage_spool_files() {
  local current_spool
  local current_meta

  current_spool=$(current_spool_path)
  current_meta=$(current_meta_path)

  if [[ -f "$current_spool" ]]; then
    if [[ -s "$current_spool" ]]; then
      log "salvaging leftover active spool ${current_spool}"
      if [[ ! -f "$current_meta" ]]; then
        ensure_meta_for_spool "$current_spool" "$current_meta" || fail "could not infer meta for ${current_spool}"
      fi
      seal_current_spool
    else
      rm -f "$current_spool" "$current_meta"
    fi
  fi

  process_pending_spools
}

handle_shutdown() {
  log "received shutdown signal; sealing current pidstat spool"
  seal_current_spool || true
  process_pending_spools || true
  exit 0
}

init_config() {
  require_command pidstat
  require_command duckdb
  require_command find

  : "${WINTAP_DATA_ROOT:=${HOME}/data/lintap/lintap-dev}"
  : "${PIDSTAT_INTERVAL_SEC:=5}"
  : "${PIDSTAT_ROTATE_INTERVAL_SEC:=${WINTAP_ETL_UPLOAD_INTERVAL_SEC:-300}}"
  : "${PIDSTAT_PARQUET_ROOT:=${WINTAP_DATA_ROOT}/parquet}"
  : "${PIDSTAT_SPOOL_DIR:=${WINTAP_DATA_ROOT}/pidstat-spool}"
  : "${PIDSTAT_PARQUET_COMPRESSION:=ZSTD}"
  : "${PIDSTAT_MAX_UNSHIPPED_BYTES:=1073741824}"
  : "${PIDSTAT_MAX_UNSHIPPED_AGE_SEC:=0}"
  : "${PIDSTAT_HOSTNAME:=$(hostname -s 2>/dev/null || hostname)}"

  is_positive_integer "$PIDSTAT_INTERVAL_SEC" || fail "PIDSTAT_INTERVAL_SEC must be a positive integer"
  is_positive_integer "$PIDSTAT_ROTATE_INTERVAL_SEC" || fail "PIDSTAT_ROTATE_INTERVAL_SEC must be a positive integer"
  is_nonnegative_integer "$PIDSTAT_MAX_UNSHIPPED_BYTES" || fail "PIDSTAT_MAX_UNSHIPPED_BYTES must be a non-negative integer"
  is_nonnegative_integer "$PIDSTAT_MAX_UNSHIPPED_AGE_SEC" || fail "PIDSTAT_MAX_UNSHIPPED_AGE_SEC must be a non-negative integer"

  PIDSTAT_RAW_SENSOR_DIR="${PIDSTAT_PARQUET_ROOT}/raw_sensor/pidstat"
  export PIDSTAT_RAW_SENSOR_DIR

  mkdir -p "$PIDSTAT_SPOOL_DIR" "$PIDSTAT_RAW_SENSOR_DIR"
}

run_collector() {
  local line
  local normalized_line
  local sample_epoch

  log "starting ${SCRIPT_NAME}: interval=${PIDSTAT_INTERVAL_SEC}s rotate=${PIDSTAT_ROTATE_INTERVAL_SEC}s parquet_root=${PIDSTAT_PARQUET_ROOT}"
  salvage_spool_files

  trap handle_shutdown INT TERM

  while IFS= read -r line; do
    if normalized_line=$(normalize_pidstat_line "$line"); then
      sample_epoch=$(date +%s)
      rotate_current_window_if_needed "$sample_epoch"
      printf '%s\n' "$normalized_line" >> "$(current_spool_path)"
    fi
  done < <(S_TIME_FORMAT=ISO pidstat -u -d -r -w -h -p ALL "$PIDSTAT_INTERVAL_SEC")
}

main() {
  init_config
  run_collector
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
