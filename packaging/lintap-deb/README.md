# Lintap Debian package

This directory contains simple Debian packaging for the Lintap Linux sensor.

## Quickstart: build packages

Build on Ubuntu, not macOS:

```sh
cd /path/to/git-lintap
```

The default build is self-contained .NET for the host Debian architecture. Output is written to:

```text
artifacts/lintap-deb/lintap_<version>-<revision>_<arch>.deb
```

### Build for the current host architecture

```sh
Lintap/packaging/lintap-deb/build-deb.sh --version 0.1.0 --revision 1
```

### Build an arm64 package

Use this on an arm64 Ubuntu host, or on a cross-build host with the required .NET runtime packs and eBPF tooling available:

```sh
Lintap/packaging/lintap-deb/build-deb.sh \
  --version 0.1.0 \
  --revision 3 \
  --arch arm64 \
  --runtime linux-arm64
```

This produces:

```text
artifacts/lintap-deb/lintap_0.1.0-1_arm64.deb
```

### Build an amd64 package

Use this on an amd64 Ubuntu host, or on a cross-build host with the required .NET runtime packs and eBPF tooling available:

```sh
Lintap/packaging/lintap-deb/build-deb.sh \
  --version 0.1.0 \
  --revision 3 \
  --arch amd64 \
  --runtime linux-x64
```

This produces:

```text
artifacts/lintap-deb/lintap_0.1.0-1_amd64.deb
```

### Development/smoke-test build from existing output

If NuGet access is unavailable, package an existing build output as a framework-dependent smoke-test package:

```sh
Lintap/packaging/lintap-deb/build-deb.sh \
  --version 0.1.0 \
  --revision 1 \
  --framework-dependent \
  --publish-dir wintap/wintap/bin/Debug/net8.0
```

Useful options:

```sh
Lintap/packaging/lintap-deb/build-deb.sh --framework-dependent
Lintap/packaging/lintap-deb/build-deb.sh --no-restore
Lintap/packaging/lintap-deb/build-deb.sh --project-dir /path/to/wintap/wintap
```

`--project-dir` or `LINTAP_PROJECT_DIR` can be used when the Lintap .NET project is outside the auto-detected checkout layouts.

`--publish-dir` is a development escape hatch: it skips `dotnet publish` and packages an existing publish/build output directory. Prefer a fresh `dotnet publish` for release packages. The script applies defensive filtering to this path and fails if forbidden build artifacts such as `obj/`, VCS metadata, `.venv/`, or `.fuse_hidden*` files would be staged.

## Build prerequisites

The build host needs the .NET 8 SDK and eBPF build tooling, for example:

```sh
sudo apt-get update
sudo apt-get install -y dotnet-sdk-8.0 clang llvm make bpftool libbpf-dev linux-headers-$(uname -r) dpkg-dev fakeroot
```

Package names may vary by Ubuntu release and by how Microsoft .NET packages are configured.

## Runtime layout

The package installs:

```text
/usr/lib/lintap/                 published Lintap app
/usr/lib/lintap/tracers/*.bpf.o  eBPF tracer objects
/usr/bin/lintap                  launcher for /usr/lib/lintap/Lintap
/etc/lintap/lintap.env           systemd environment overrides
/var/log/lintap/                 default data root
/usr/lib/systemd/system/lintap.service
```

By default, `/etc/lintap/lintap.env` sets:

```text
WINTAP_DATA_ROOT=/var/log/lintap
```

Lintap logs are expected under `/var/log/lintap/Logs`, and parquet/raw sensor output under `/var/log/lintap/parquet`.

## Install and run

```sh
sudo apt install ./artifacts/lintap-deb/lintap_*_amd64.deb
sudo systemctl start lintap
sudo systemctl status lintap
sudo journalctl -u lintap -f
```

The package enables the service on install but does not start it automatically.
