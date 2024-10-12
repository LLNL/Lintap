#!/bin/bash
#
# Merge all the raw_[event] tsv files into single parquet files per dayPK
#
# Usage:
#   merge_raw_tsv [source path]

function merge_sql {
    echo """
copy (from read_csv('$1/$2/**/*.tsv',timestampformat='%m/%d/%Y %H:%M:%S')) to '$1_pk/$2_pk' (format parquet, partition_by (daypk));
"""
}


# Process by event type
for EVENT in raw_process raw_process_conn_incr raw_process_file raw_thread
do
    echo `date` $EVENT 
    merge_sql=$(merge_sql $1 $EVENT)
    echo ~/apps/duckdb -s "$merge_sql"
done
