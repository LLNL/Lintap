<p align="center"><img src="lintap-logo.png" alt="Lintap Logo" width="200" height="200"></p>

# Lintap

Lintap is a proof-of-concept host-based event sensor for Linux that implements Wintap-like functionality for Linux environments. It collects system telemetry data and transforms it into the semantic Wintap data model for analysis.

## Project Overview

The first phase of this project focuses on proving that we can collect the necessary telemetry data and transform it into the Wintap data model. To achieve this quickly and simply, we're following this approach:

### 1. Collect Event-Based Telemetry from eBPF

We're using `sysdig` as our primary data collection tool because it's robust, simple, and extensible with LUA. Sysdig runs continuously, writing TSV files of events for processes, files, and network activity.

We've also added experimental support for collecting and processing SELinux activity using auditd. SELinux features are optional.

> **Note:** Core sysdig is completely open source and works well for almost any Linux system. While internet searches may lead to their commercial offerings, we're using the open-source version.

### 2. Convert Raw Sysdig Data to Raw Wintap Format

After collection, we convert the raw TSV files to the raw Wintap format. This allows us to leverage the existing, mature Wintap post-processing pipeline for the final ETL stages.

### 3. Run the Wintap ETL Pipeline

The existing pipeline ingests the raw Wintap format data and produces silver and gold final datasets for analysis.

## Prerequisites

- Linux system with root access
- Sufficient disk space for data collection
- Python 3.6+ for processing scripts
- DuckDB for data processing

## Quick Start

### Installing

#### Sysdig

Source: https://github.com/draios/sysdig
Cheat Sheet: https://www.scribd.com/document/414390974/Linux-Cheatsheet-FINAL-eBOOK-1-pdf

As `sysdig` requires installing and configuring a kernel module, you'll need root privileges.

**Debian/Ubuntu:**
```bash
sudo apt-get update
sudo apt-get install -y sysdig
```

**RHEL/CentOS/Fedora:**
```bash
sudo yum install -y sysdig
```

**Amazon Linux 2023:**
```bash
# Amazon Linux 2023 may require building from source:
git clone https://github.com/draios/sysdig.git
cd sysdig
mkdir build && cd build
cmake ..
make
sudo make install
```

#### Lintap Collection

1. Clone the repository:
   ```bash
   git clone https://github.com/LLNL/Lintap.git
   cd Lintap
   ```

2. Run the full collection script:
   ```bash
   ./full-capture.sh
   ```
   
   By default, files will be written to `./data/lintap`. Some parsing errors may occur, which can be ignored for now.

3. After collecting enough data (a few minutes is usually sufficient), stop the collection with Ctrl+C.

4. Verify that data files are being generated in the output directory.

## Post-processing

### On Each Host

1. Run the merge script to create combined parquet files:
   ```bash
   ./merge_raw_tsv.sh
   ```
   
   This script combines thousands of tiny TSV files into a single parquet file per day. It must be run on the host to capture the hostname correctly.

2. Transfer the parquet files to a central location for processing. The directory layout is designed to allow easy merging in the central location.

### On the Central Host

The current process requires manual execution of DuckDB SQL scripts in the following order:

1. `rawtostdview.sql` - Defines the datapath for all incoming data using a macro (dp)
2. `selinux.sql` - Processes SELinux data
3. `~/git/foraker-support/foraker-everest/ontology/duckdb/everest-lintap-ddl.sql` - Creates Files and All_Files tables for Lintap data
4. `selinux-everest.sql` - Adds SELinux data to Files and All_Files tables
5. `Everest-network.sql` - Processes network data

## Data File Layout

The data is organized in the following structure:

```
Data Path/                      # Top level of all data sets
└── Data Set/                   # Data from a specific environment, time frame and configuration
    ├── raw_sensor_tsv/         # Raw sensor data in TSV format
    │   └── daypk=YYYYMMDD/     # Partitioned by day
    │       └── [hostname]+[event type]+[epoch].tsv  # Files written by chisel, rolling based on time
    └── scap/                   # Sysdig capture format
        └── [hostname]-[epoch].scap[n]  # Files written by sysdig, rolling based on size
```

## Troubleshooting

- **Sysdig Installation Issues**: If you encounter problems installing sysdig, check that you have the appropriate kernel headers installed for your distribution.
- **Data Collection Errors**: Some parsing errors are expected and can be ignored. If no data files are being generated, check that sysdig is running correctly with `sysdig -l`.
- **Processing Errors**: Ensure all paths in the SQL scripts are correctly set to point to your data location.

## Contributing

Contributions to Lintap are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

LLNL-CODE-837816