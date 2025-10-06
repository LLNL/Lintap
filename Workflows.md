# Typical Workflows

This page assumes you're using the (Multipass)[https://canonical.com/multipass] Ubuntu VM Manager. Following the instructions there to get Multipass installed.

Once installed, from your host, in this repo, run:

1. `launch-multipass.sh`
2. (optional) `config-ssh.sh`

## Dead Simple
These steps are done in series with the result being a database with Foraker base tables for all data.

1. Run full-capture.sh
  `sudo ./full-capture`
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

_Prerequisite: Follow the instructions for configuring ssh tunnelling_

From a duckdb prompt, launch the UI server: `call start_ui_server()`

From a browser, connect to `http://localhost:4213`

* Run SQL in a cell
* Click on a table in the schema browser to see its structure and some simple stats in the lower left
* Click on a result set in the notebook to see simple stats on the upper right

Caveats

* It may be a little slow to start the first time as it needs to download the extension
* There doesn't seem to be a way to export/import or save notebooks
* Notebooks are stored in the table `_duckdb_ui.main.notebook_versions`, so there should be a way to export/import...

# Configure for ssh and tunneling to use duckdb notebooks, coretap server, vs-code, etc.
The `multipass shell` command uses an ssh key that it generates and manages. To get your regular ssh and ssh config working, we can just add your ssh key to the `lintap` instance.

For port forwarding, the problem is that Multipass itself doesn't support it. The solution here is to use your regular ssh and .ssh/config. 

The final issue that multipass assigns a new IP for each launch, so we need to get that and update your ./ssh/config.

Putting it all together, there is a small script `config-ssh.sh` that will do these steps:

1. Add your ssh key to multipass instance
`multipass exec lintap-dev -- sh -c "echo '$(cat ~/.ssh/id_ed25519.pub)' >> .ssh/authorized_keys"`

2. Create/update an entry in `.ssh/config`
_Note: only the IP will be updated on subsequent runs, so other config options can be added_
```
Hostname lintap-dev
  Host <current_ip>
  User ubuntu
  LocalForward 4213 localhost:4213
```

With these changes, you can:

* `ssh lintap-dev` which connects and sets up any tunnels defined
* Use VS Code to open a remote folder on `lintap-dev`

