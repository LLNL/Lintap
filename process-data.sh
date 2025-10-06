#!/bin/bash
#
# Process from TSV to gold
# Usage:
#   process-data.sh [database.db] [--overwrite]

OVERWRITE=false
DATABASE=""

# Parse arguments
for arg in "$@"; do
  if [ "$arg" == "--overwrite" ]; then
    OVERWRITE=true
  elif [ "${arg:0:1}" != "-" ]; then
    # Assume this is the database file
    DATABASE="$arg"
  fi
done

# Handle overwrite if flag is set
if [ "$OVERWRITE" = true ]; then
  echo "Overwrite flag detected. Removing raw_sensor directory..."
  rm -rf data/lintap/raw_sensor  # Replace with your actual directory
fi

# Merge all existing TSV by type into a single parquet file per type
./merge_raw_tsv.sh

# Build the duckdb command
DUCKDB_CMD='duckdb --cmd ".read sql/rawtostdview.sql" --cmd ".read sql/lintap-pci.sql" -cmd ".read sql/summary.sql"'

# Add database parameter if provided
if [ -n "$DATABASE" ]; then
  DUCKDB_CMD="$DUCKDB_CMD $DATABASE"
fi

# Execute the command
eval "$DUCKDB_CMD"