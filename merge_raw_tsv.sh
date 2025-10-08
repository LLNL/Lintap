#!/bin/bash
#
# Merge all the raw_[event] tsv files into single parquet files per dayPK
#
# Usage:
#   merge_raw_tsv [base_path]
#
# base_path is the dir containing "raw_process, raw_thread, etc"
# The script assumes raw tsv files are in [target]_tsv

# Default data base path
base_path=data/lintap

# Validate dirs
# Override default base_path
if [ "$1" ]; then
    base_path=$1
fi
tsv_source=${base_path}/raw_sensor_tsv
target=${base_path}/raw_sensor

echo -e "Dirs\n    TSV: $tsv_source\n    Merged Parquet: $target"

# Check if the target directory exists (should not exist)
if [ -d "$target" ]; then
    echo "Error: Target directory $target already exists"
    exit 1
fi

# Check if the _tsv directory exists (should exist)
if [ ! -d "$tsv_source" ]; then
    echo "Error: Source directory $tsv_source does not exist"
    exit 1
fi

# For tables with a single event_time field
function event_time_sql {
    echo """
copy (
  select 
    event_time: (event_time AT TIME ZONE 'UTC')::timestamp_ns,
    * exclude (event_time)
  from read_csv('$1/$2/**/*.tsv',filename=true)
  ) to '$5/$2' (format parquet, partition_by (daypk), filename_pattern '$3+$2+$4');
"""
}

# For tables with first_seen/last_seen fields
function first_last_sql {
    echo """
copy (
  select 
    first_seen: (first_seen AT TIME ZONE 'UTC')::timestamp_ns,
    last_seen: (last_seen AT TIME ZONE 'UTC')::timestamp_ns,
    * exclude (first_seen, last_seen)
  from read_csv('$1/$2/**/*.tsv',filename=true)
  ) to '$5/$2' (format parquet, partition_by (daypk), filename_pattern '$3+$2+$4');
"""
}

# For SELinux data from auditd
function timestamp_sql {
    echo """
copy (
  select 
    event_time: timestamp,
    * exclude (timestamp)
  from read_csv('$1/$2/**/*.tsv',filename=src_filename,union_by_name=true,types={'timestamp': 'VARCHAR'})
  ) to '$5/$2' (format parquet, partition_by (daypk), filename_pattern '$3+$2+$4');
"""
}

# Process by event type
for EVENT in raw_process raw_thread
do
    echo `date` $EVENT
    if [ -d "$tsv_source/$EVENT" ]; then
      # Subdirs MUST exist
      mkdir -p $target/$EVENT
      merge_sql=$(event_time_sql $tsv_source $EVENT `hostname` `date +%s` $target)
      duckdb -s "$merge_sql"
    else
	    echo Source event dir missing: $tsv_source/$EVENT
    fi
done

for EVENT in raw_process_conn_incr raw_process_file
do
    if [ -d "$tsv_source/$EVENT" ]; then
      echo `date` $EVENT
      # Subdirs MUST exist
      mkdir -p $target/$EVENT
      merge_sql=$(first_last_sql $tsv_source $EVENT `hostname` `date +%s` $target)
      duckdb -s "$merge_sql"
    else
	    echo Source event dir missing: $tsv_source/$EVENT
    fi
done

for EVENT in raw_selinux_contexts raw_selinux_paths
do
    if [ -d "$tsv_source/$EVENT" ]; then
      echo `date` $EVENT
      # Subdirs MUST exist
      mkdir -p $target/$EVENT
      merge_sql=$(timestamp_sql $tsv_source $EVENT `hostname` `date +%s` $target)
      duckdb -s "$merge_sql"
    else
    	echo Source dir missing: $tsv_source/$EVENT
    fi
done

echo `date` Merge TSV complete