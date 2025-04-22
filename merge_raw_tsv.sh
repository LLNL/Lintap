#!/bin/bash
#
# Merge all the raw_[event] tsv files into single parquet files per dayPK
#
# Usage:
#   merge_raw_tsv [target path]
#
# target path is the dir containing "raw_process, raw_thread, etc"

function event_time_sql {
    echo """
copy (
  select 
    event_time: event_time::timestamp_ns,
    * exclude (event_time)
  from read_csv('$1_tsv/$2/**/*.tsv',filename=true)
  ) to '$1/$2' (format parquet, partition_by (daypk));
"""
}

function first_last_sql {
    echo """
copy (
  select 
    first_seen: first_seen::timestamp_ns,
    last_seen: last_seen::timestamp_ns,
    * exclude (first_seen, last_seen)
  from read_csv('$1_tsv/$2/**/*.tsv',filename=true)
  ) to '$1/$2' (format parquet, partition_by (daypk));
"""
}

# For SELinux data from auditd
function timestamp_sql {
    echo """
copy (
  select 
    event_time: timestamp,
    * exclude (timestamp)
  from read_csv('$1_tsv/$2/**/*.tsv',filename=src_filename,union_by_name=true,types={'timestamp': 'VARCHAR'})
  ) to '$1/$2' (format parquet, partition_by (daypk));
"""
}

for EVENT in raw_selinux_contexts raw_selinux_paths
do
    echo `date` $EVENT
    # Subdirs MUST exist
    mkdir -p $1/$EVENT
    merge_sql=$(timestamp_sql $1 $EVENT)
    ~/apps/duckdb -s "$merge_sql"
done

exit

# Process by event type
for EVENT in raw_process raw_thread
do
    echo `date` $EVENT
    # Subdirs MUST exist
    mkdir -p $1/$EVENT
    merge_sql=$(event_time_sql $1 $EVENT)
    ~/apps/duckdb -s "$merge_sql"
done

for EVENT in raw_process_conn_incr raw_process_file
do
    echo `date` $EVENT
    # Subdirs MUST exist
    mkdir -p $1/$EVENT
    merge_sql=$(first_last_sql $1 $EVENT)
    ~/apps/duckdb -s "$merge_sql"
done
