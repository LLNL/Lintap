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

#### Now the real work...
This scaffolding is all to support ongoing development and debugging of the sensor itself. 
