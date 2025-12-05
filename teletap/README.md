# Running Lintap (dotnet version)

## Prerequisites

- Linux system with root access
- Sufficient disk space for data collection
- eBPF Tools
- DotNet 8.0 Core
- Python
- DuckDB for data processing
- Git repos for: Wintap and Lintap

## Ubuntu with Multipass

The fastest and easiest way to get up and running is using [Multipass](https://canonical.com/multipass). This method leverages Multipass to install and manage a local Ubuntu VM. We provide a script that will buildout the environment and be ready to use.

* Get multipass itself running: [Multipass](https://canonical.com/multipass)
* Build the Lintap-ready-instance: [Detailed Instructions](../Multipass.md)

### Build Commands
```sh
cd ~ubuntu/git/Wintap/wintap/platform/linux/sensor/ebpf/tracers/
make clean
make all
make test
cd ~ubuntu/git/Wintap/wintap/
dotnet build Lintap.csproj 
dotnet run --project Lintap.csproj 
```

### Load Data
_Note: major changes are coming for how TeleTap writes files which will simplify this step._

#### Gather up data
* `scp -rp @lintap-dev:/var/log/lintap/parquet/\* ~/data/lintap/lintap-dev/`
* `mkdir ~/data/lintap/lintap-dev/pidstat`
* `cp ~/git/Lintap/mydata.tsv ~/data/lintap/lintap-dev/pidstat/`

#### Convert to normalized name and tree structure
```sh
python mergedtoraw -s ~/data/lintap/lintap-dev
```

This should create a new dir `~/data/lintap/lintap-dev/raw_sensor` with subdirs for each event type.

#### Load into DuckDB
* `cd teletap`
* `./process-data [sample.db]`
  * Copies parquet files from `merged` into `raw_sensor` and partitions by event type and time.
  * Runs a set of SQL files to load data, including `pidstat`, into database
  * Displays a simple summary of data to confirm it worked

#### Visualize 
Run a simple streamlit app to visualize the host resource data and simple telemetry info. The intent is 
to use this to start to understand what was collected and how much resource was used to get it.

* `streamlit run grokdata.py`

Be amazed by the app created using Grok. Basically, it should show time-series of some very basic telemetry such as: CPU/Mem use and Process/File/Network event counts.

#### Dev Tools

VS Code should be able to just connect using the remote-ssh connection. Just open a workspace on the Wintap or Lintap repo.
To get all of the appropriate plugins installed:

~Note: run the shell as a terminal window from VS Code. I had trouble with `code` not being in the path when just ssh'd in.
```sh
cd ~ubuntu/git/Lintap/teletap
cat vscode-remote-extensions.txt | xargs -n 1 code --install-extension
```

#### Now the real work...
This scaffolding is all to support ongoing development and debugging of the sensor itself. 

