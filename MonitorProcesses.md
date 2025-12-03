# Simple process metrics

The goal is to have resource metrics (cpu, memory, io) for a short time surrounding some process/operation of interest.

Keeping it very simple, we'll use `pidstat` to collect data and then load it into duckdb.

# Quickstart

1. Collect data
    `pidstat-collect.sh > mysample.out`

    Just `ctlr-c` when you're done collecting.

2. Load into duckdb
    `duckdb --cmd .read load-pidstat.sql`

3. Chart it - For now, look at `teletap/grokdata.py` which charts the pidstat data along with data collected with LinTap.