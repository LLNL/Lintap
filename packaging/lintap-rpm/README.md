# Lintap RPM Package

This directory contains RPM packaging for the Lintap Linux sensor. The initial target is RHEL 8 on `x86_64`.

The RPM layout intentionally matches the Ubuntu package layout where possible.

## Quickstart

Build on a RHEL 8 compatible `x86_64` host with the .NET 8 SDK and eBPF tooling installed:

```sh
Lintap/packaging/lintap-rpm/build-rpm.sh --version 0.1.0 --release 1.el8
```

The default build is self-contained .NET for `linux-x64`. Output is written under:

```text
artifacts/lintap-rpm/x86_64/lintap-<version>-<release>.x86_64.rpm
```

Build intermediates, MCP publish output, and `dotnet publish` output are written to native storage by default:

```text
/var/tmp/lintap-rpm-build
```

This avoids .NET apphost mmap failures and runtime-codegen issues when the source repo is on a VM shared mount. Override with `--work-root` or `LINTAP_RPM_WORK_ROOT` if needed.

## Cross-Build From A Non-x86 Host

The script can also produce the `x86_64` RPM from a non-x86 host, such as a Fedora `aarch64` VM, because `rpmbuild` only packages the staged payload and the script builds the eBPF objects with `TARGET_ARCH=x86_64`.

```sh
Lintap/packaging/lintap-rpm/build-rpm.sh \
  --version 0.1.0 \
  --release 1.el8 \
  --arch x86_64 \
  --runtime linux-x64
```

Cross-build requirements:

- The .NET SDK on the build host must be able to restore/publish the `linux-x64` runtime pack.
- If using `--publish-dir`, that directory must already contain `linux-x64` output, not host-architecture output.
- The eBPF tracer Makefile must support `TARGET_ARCH=x86_64` on the host.
- The RPM build disables ReadyToRun publishing because crossgen is expensive and unreliable during cross-architecture packaging.

## Development Build From Existing Output

If NuGet access is unavailable, package an existing build output as a framework-dependent smoke-test package:

```sh
Lintap/packaging/lintap-rpm/build-rpm.sh \
  --version 0.1.0 \
  --release 1.el8 \
  --framework-dependent \
  --publish-dir wintap/wintap/bin/Debug/net8.0
```

`--publish-dir` skips `dotnet publish` and packages an existing publish/build output directory. Prefer a fresh `dotnet publish` for release packages. The script defensively filters stale `obj/`, VCS metadata, `.venv/`, `.fuse_hidden*`, and non-Linux runtime assets.

## Build Prerequisites

Install the .NET 8 SDK, RPM build tools, and eBPF build tooling. Package names vary by repo setup, but a typical RHEL 8 build host needs:

```sh
sudo dnf install -y rpm-build dotnet-sdk-8.0 clang llvm make bpftool libbpf-devel elfutils-libelf-devel kernel-devel
```

If using Microsoft packages for .NET, configure the Microsoft RHEL package repository before installing `dotnet-sdk-8.0`.

## Runtime Layout

The package installs:

```text
/usr/lib/lintap/                 published Lintap app
/usr/lib/lintap/tracers/*.bpf.o  eBPF tracer objects
/usr/bin/lintap                  launcher for /usr/lib/lintap/Lintap
/etc/lintap/lintap.env           systemd environment overrides
/var/log/lintap/                 default data root
/usr/lib/systemd/system/lintap.service
```

External config parity with the Ubuntu package:

```text
/etc/lintap/lintap.env
```

The RPM marks this file as `%config(noreplace)`, so local edits are preserved across upgrades when possible. By default it sets:

```text
WINTAP_DATA_ROOT=/var/log/lintap
WINTAP_DISABLE_MCP=true
WINTAP_DISABLE_DUCKDB_UI=true
WINTAP_DISABLE_ETL=false
WINTAP_DISABLE_SENSORS=false
WINTAP_ENABLE_EXECVE_SENSOR=true
WINTAP_ENABLE_EXIT_SENSOR=true
WINTAP_ENABLE_NETWORK_SENSOR=true
WINTAP_ENABLE_FILEOPS_SENSOR=true
WINTAP_ENABLE_PROCESS_RUNDOWN_SENSOR=true
WINTAP_ENABLE_CLONE_SENSOR=false
WINTAP_PARQUET_COMPRESSION=Uncompressed
```

Lintap logs are expected under `/var/log/lintap/Logs`, and parquet/raw sensor output under `/var/log/lintap/parquet`.

## Install And Run

```sh
sudo dnf install ./artifacts/lintap-rpm/x86_64/lintap-*.x86_64.rpm
cat /etc/lintap/lintap.env
sudo systemctl start lintap
sudo systemctl status lintap
sudo journalctl -u lintap -f
```

The package enables the service on install but does not start it automatically.

## Quickstart: Install On RHEL 8

Copy the RPM to the RHEL 8 `x86_64` target host, then install it:

```sh
sudo dnf install ./lintap-0.1.0-1.el8.x86_64.rpm
```

Before starting the service, review the external config file:

```sh
sudoedit /etc/lintap/lintap.env
```

Default config:

```text
WINTAP_DATA_ROOT=/var/log/lintap
WINTAP_DISABLE_MCP=true
WINTAP_DISABLE_DUCKDB_UI=true
WINTAP_DISABLE_ETL=false
WINTAP_DISABLE_SENSORS=false
WINTAP_ENABLE_EXECVE_SENSOR=true
WINTAP_ENABLE_EXIT_SENSOR=true
WINTAP_ENABLE_NETWORK_SENSOR=true
WINTAP_ENABLE_FILEOPS_SENSOR=true
WINTAP_ENABLE_PROCESS_RUNDOWN_SENSOR=true
WINTAP_ENABLE_CLONE_SENSOR=false
WINTAP_PARQUET_COMPRESSION=Uncompressed
```

Config notes:

- `/etc/lintap/lintap.env` is read by systemd via `EnvironmentFile=-/etc/lintap/lintap.env`.
- The RPM marks `/etc/lintap/lintap.env` as `%config(noreplace)`, so local edits are preserved across upgrades when possible.
- Runtime logs, Parquet output, raw sensor output, and state default under `/var/log/lintap`.
- The stable Linux sensors are enabled by default; `CloneSensor` remains disabled because `sched_process_fork` attach failed during Fedora bring-up.
- The RPM defaults `WINTAP_PARQUET_COMPRESSION=Uncompressed` for RHEL 8 glibc compatibility. Snappy remains the application default outside this package.
- The service is enabled during install, but not started automatically.

Start and inspect the service:

```sh
sudo systemctl start lintap
systemctl status lintap --no-pager
sudo journalctl -u lintap -n 100 --no-pager
```

Verify expected paths:

```sh
systemctl cat lintap
sudo find /var/log/lintap -maxdepth 4 -type f | sort
curl -fsS http://localhost:8099/ || true
```

If you need to change runtime settings later, edit `/etc/lintap/lintap.env` and restart:

```sh
sudoedit /etc/lintap/lintap.env
sudo systemctl restart lintap
```

## Inspect Package

```sh
rpm -qpi artifacts/lintap-rpm/x86_64/lintap-*.x86_64.rpm
rpm -qpl artifacts/lintap-rpm/x86_64/lintap-*.x86_64.rpm
rpm -qp --scripts artifacts/lintap-rpm/x86_64/lintap-*.x86_64.rpm
```

Check RHEL 8 glibc compatibility before installing on a RHEL 8 host:

```sh
rpm -qp --requires artifacts/lintap-rpm/x86_64/lintap-*.x86_64.rpm | grep 'GLIBC_'
```

RHEL 8 provides glibc 2.28. If the RPM requires `GLIBC_2.29` or newer, a bundled native dependency must be replaced or rebuilt for RHEL 8 before the package can be considered RHEL 8 runtime-compatible.

Current validation note: a Fedora 44 `aarch64` VM successfully cross-built `lintap-0.1.0-1.el8.x86_64.rpm` on 2026-06-09. The package payload and `%config(noreplace)` external config were verified. The RPM excludes bundled `libnironcompress.so` and sets `WINTAP_PARQUET_COMPRESSION=Uncompressed` because that native library required `GLIBC_2.29` on this cross-build host while RHEL 8 provides glibc 2.28.
