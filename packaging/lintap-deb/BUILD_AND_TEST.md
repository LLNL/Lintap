# Lintap Debian Package Build and Smoke-Test Guide

This guide explains how to build and install the current dev/smoke-test Ubuntu package for the Lintap Linux sensor.

## What this package is

This package installs the Lintap sensor app, its eBPF tracer object files, a default config file, and a systemd service.

Installed layout:

```text
/usr/lib/lintap/                 Lintap application files
/usr/lib/lintap/tracers/*.bpf.o  eBPF tracer objects
/usr/bin/lintap                  launcher for /usr/lib/lintap/Lintap
/etc/lintap/lintap.env           service environment/config override
/var/log/lintap/                 default data/log root
/usr/lib/systemd/system/lintap.service
```

The systemd service is enabled on install, but it is **not started automatically**. You start it manually after reviewing the config.

## Current dev-build assumption

The Ubuntu VM currently cannot reach NuGet reliably, so a clean `dotnet publish` is not practical right now.

For the initial smoke test, build the package from the existing Lintap build output:

```text
wintap/wintap/bin/Debug/net8.0
```

This is acceptable for the current dev package. Later, when NuGet access/cache is fixed, use the normal release path described near the end of this guide.

## 1. Connect to the Ubuntu VM

From your host:

```sh
ssh lintap-dev
```

If you see warnings like this, they are currently non-fatal as long as the shell opens and commands run:

```text
bind [::1]:4213: Address already in use
channel_setup_fwd_listener_tcpip: cannot listen to port: 4213
Could not request local forwarding.
```

Go to the mounted repo root:

```sh
cd /home/ubuntu/git
```

## 2. Build the dev/smoke-test package

Run:

```sh
Lintap/packaging/lintap-deb/build-deb.sh \
  --version 0.1.0 \
  --revision 1 \
  --framework-dependent \
  --publish-dir wintap/wintap/bin/Debug/net8.0
```

Expected output ends with something like:

```text
==> Package built: /home/ubuntu/git/artifacts/lintap-deb/lintap_0.1.0-1_arm64.deb
```

The architecture may differ if the VM changes. On the current VM it has been `arm64`.

## 3. Inspect the package before installing

```sh
dpkg-deb --info artifacts/lintap-deb/lintap_0.1.0-1_arm64.deb
```

Confirm key contents:

```sh
dpkg-deb --contents artifacts/lintap-deb/lintap_0.1.0-1_arm64.deb | \
  grep -E '(/usr/lib/lintap/Lintap$|/usr/lib/lintap/tracers/.*\.bpf\.o$|lintap.service|lintap.env|/usr/bin/lintap$)'
```

You should see:

```text
/etc/lintap/lintap.env
/usr/lib/systemd/system/lintap.service
/usr/lib/lintap/Lintap
/usr/lib/lintap/tracers/clone_tracer.bpf.o
/usr/lib/lintap/tracers/execve_tracer.bpf.o
/usr/lib/lintap/tracers/exit_tracer.bpf.o
/usr/lib/lintap/tracers/file_ops_tracer.bpf.o
/usr/lib/lintap/tracers/network_ops_tracer.bpf.o
/usr/lib/lintap/tracers/openat_tracer.bpf.o
```

## 4. Install the package

```sh
sudo apt install ./artifacts/lintap-deb/lintap_0.1.0-1_arm64.deb
```

If your package filename differs, list it first:

```sh
ls -lh artifacts/lintap-deb/*.deb
```

Then install that file.

### If apt reports a missing .NET runtime

The current dev package is framework-dependent and declares:

```text
aspnetcore-runtime-8.0
```

Check installed runtimes:

```sh
dotnet --list-runtimes
```

If needed and package sources are available:

```sh
sudo apt-get update
sudo apt-get install -y aspnetcore-runtime-8.0
sudo apt install ./artifacts/lintap-deb/lintap_0.1.0-1_arm64.deb
```

## 5. Review installed config and service

```sh
cat /etc/lintap/lintap.env
systemctl cat lintap
```

Default config:

```text
WINTAP_DATA_ROOT=/var/log/lintap
```

Data and logs should go under:

```text
/var/log/lintap
/var/log/lintap/Logs
/var/log/lintap/parquet
```

## 6. Start the service

```sh
sudo systemctl start lintap
```

Check status:

```sh
systemctl status lintap --no-pager
```

Check systemd logs:

```sh
sudo journalctl -u lintap -n 100 --no-pager
```

Follow logs live if needed:

```sh
sudo journalctl -u lintap -f
```

## 7. Check Lintap file logs and output directories

```sh
sudo ls -la /var/log/lintap
sudo ls -la /var/log/lintap/Logs || true
sudo tail -n 200 /var/log/lintap/Logs/Lintap.log || true
```

Look for parquet/raw sensor output:

```sh
sudo find /var/log/lintap -maxdepth 5 -type f | head -100
```

The desired raw sensor shape is eventually:

```text
/var/log/lintap/parquet/raw_sensor/<event>/dayPK=YYYYMMDD/hourPK=HH/<file>.parquet
/var/log/lintap/parquet/raw_sensor/raw_process_conn_incr/dayPK=YYYYMMDD/hourPK=HH/protoPK=tcp|udp/<file>.parquet
```

## 8. Stop the service

```sh
sudo systemctl stop lintap
systemctl status lintap --no-pager
```

## 9. Uninstall if needed

Remove package but keep config/data:

```sh
sudo apt remove lintap
```

Purge package config:

```sh
sudo apt purge lintap
```

The package intentionally preserves sensor data under `/var/log/lintap`. Remove it manually only if you are sure:

```sh
sudo rm -rf /var/log/lintap
```

## Troubleshooting

### Service fails immediately

Run:

```sh
systemctl status lintap --no-pager
sudo journalctl -u lintap -n 200 --no-pager
sudo tail -n 200 /var/log/lintap/Logs/Lintap.log || true
```

### Test Lintap manually

This bypasses systemd and runs from the installed directory:

```sh
cd /usr/lib/lintap
sudo env WINTAP_DATA_ROOT=/var/log/lintap ./Lintap
```

Use `Ctrl-C` to stop.

### Check eBPF tracer files

```sh
ls -l /usr/lib/lintap/tracers
```

Expected files:

```text
clone_tracer.bpf.o
execve_tracer.bpf.o
exit_tracer.bpf.o
file_ops_tracer.bpf.o
network_ops_tracer.bpf.o
/usr/lib/lintap/tracers/openat_tracer.bpf.o
```

### Check native dependency availability

```sh
ldd /usr/lib/lintap/Lintap || true
ldconfig -p | grep libbpf || true
```

The package depends on:

```text
libbpf1, libc6, zlib1g, libelf1, systemd
```

The dev/framework-dependent package also depends on:

```text
aspnetcore-runtime-8.0
```

## Normal release build path for later

Once NuGet access/cache is fixed, the preferred build is:

```sh
cd /home/ubuntu/git
Lintap/packaging/lintap-deb/build-deb.sh --version 0.1.0 --revision 1
```

That path runs `dotnet publish` and defaults to a self-contained package. It should not need `aspnetcore-runtime-8.0` as a runtime dependency.

For a smaller framework-dependent release package:

```sh
Lintap/packaging/lintap-deb/build-deb.sh \
  --version 0.1.0 \
  --revision 1 \
  --framework-dependent
```

## Quick command summary

```sh
ssh lintap-dev
cd /home/ubuntu/git

Lintap/packaging/lintap-deb/build-deb.sh \
  --version 0.1.0 \
  --revision 1 \
  --framework-dependent \
  --publish-dir wintap/wintap/bin/Debug/net8.0

dpkg-deb --info artifacts/lintap-deb/lintap_0.1.0-1_arm64.deb
sudo apt install ./artifacts/lintap-deb/lintap_0.1.0-1_arm64.deb
cat /etc/lintap/lintap.env
systemctl cat lintap
sudo systemctl start lintap
systemctl status lintap --no-pager
sudo journalctl -u lintap -n 100 --no-pager
sudo find /var/log/lintap -maxdepth 5 -type f | head -100
```
