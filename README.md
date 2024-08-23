# Lintap
Proof of concept host-based event sensor for Linux. An attempt to implement Wintap for Linux.

# Quick Start
## Installing
### Sysdig
### Lintap
## Validation

# Data File Layout

* Data Path - top level of all data sets
    * Data Set - data from a specific environment, time frame and configuration.
        * Raw_sensor - raw sensor data in TSV format
            * Paritioned by Day
            * Chisel writes files, rolling based on time. Example name:
            ```data/acme/raw_sensor/daypk=YYYYMMDD/[hostname]+[event type]+[epoch].tsv```
            
        * scap - Sysdig capture format
            * Sysdig writes files, rolling based on size. Example name:
            ```data/acme/scap/[hostname]-[epoch].scap[n]```



# Release
LLNL-CODE-837816
