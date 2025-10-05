# Typical WOrkflows

## Dead Simple
These steps are done in series with the result being a database with Foraker base tables for all data.

1. Run full-capture.sh
  1. While its running, use another terminal session to perform some interesting activity
  2. Quit capturing (ctrl-c)
2. Process data - `./process-data.sh` converts raw TSV to base tables
    1. With no args, uses a memory database
    2. Pass filename (`[filename].db`) to create a duckdb database
    3. Note: Currently only writes parquet for `raw_*` tables
3. Inspect/analyze data - from the duckdb prompt you have a few options:
    1. Run SQL directly
    2. Start the DuckDB UI and use its notebook interface
        1. For multipass/remote systems, you'll need to create a tunnel using SSH
           `ssh -L4213:localhost:4213 [user@lintap host]`
        2. Note that there isn't an easy way to import/export notebooks right now
    3. Run saved SQL queries
        1. (Create some examples and list here)
4. Save DB to new, persistent DB

## Use DuckDB embedded UI for simple SQL notebooks

# References

## Add your ssh key to multipass instance
`multipass exec lintap-dev -- sh -c "echo '$(cat ~/.ssh/id_ed25519.pub)' >> .ssh/authorized_keys"`