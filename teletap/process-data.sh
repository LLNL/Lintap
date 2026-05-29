#!/bin/bash
#
# Process from Raw Parquet to gold
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
  echo "Overwrite flag detected. Removing database only; raw_sensor is read-only."
  if [ -n "$DATABASE" ]; then
    rm -f "$DATABASE"
  fi
fi

# Build the duckdb command
DUCKDB_CMD='duckdb --cmd ".read initdb.sql" --cmd ".read load-data.sql" --cmd ".read load-pidstat.sql" --cmd ".read summary_ddl.sql" --cmd ".read summary.sql"'

# Add database parameter if provided
if [ -n "$DATABASE" ]; then
  DUCKDB_CMD="$DUCKDB_CMD $DATABASE"
fi

# Execute the command
eval "$DUCKDB_CMD"