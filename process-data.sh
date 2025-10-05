#!/bin/bash
#
# Process from TSV to gold
# Usage:
#   process-data.sh [database.db]

# Merge all existing TSV by type into a single parquet file per type
./merge_raw_tsv.sh

# Convert from raw lintap to base tables, leave at duckdb prompt
 duckdb --cmd ".read sql/rawtostdview.sql" --cmd ".read sql/lintap-pci.sql" -cmd "show tables;" $1
