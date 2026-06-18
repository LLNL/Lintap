## Lintap RHEL 8 RPM Migration Handoff

Last updated: 2026-06-18

This document is the handoff for moving from the current cross-build/development workflow to building and validating the Lintap RPM on a real RHEL 8 `x86_64` system.

### Current State Summary

1. RPM installs via `dnf` successfully.
1. `libbpf` is present on the target and the service starts.
1. Esper logs warnings about duplicate EPL context name ("Every10Seconds"), currently treated as non-blocking.
1. Network telemetry is spotty: only `TcpIpDisconnect`, `UdpIpSend`, `UdpIpRecv` seen; most `IpAddr` values missing.
1. Process telemetry not deeply reviewed.
1. File events are plentiful and look reasonable.

### What Changed In Packaging Since Yesterday

These changes were made to accommodate drift in `wintap/wintap` and to make cross-building from non-x86 hosts possible.

1. eBPF build arch mapping: for `x86_64/linux-x64` the eBPF Makefile expects `TARGET_ARCH=x86` (which produces `__TARGET_ARCH_x86`). Packaging was updated to match.
1. Cross-build eBPF mode: cross-build packaging forces tracepoint-only objects (disables BTF/vmlinux.h generation) to avoid using host-kernel BTF headers.
1. `--skip-mcp`: added to the RPM builder to allow building when NuGet/network access is blocked. When used, the packaged payload contains no `/usr/lib/lintap/mcp/*`.
1. Tracer assertions: RPM staging validation expects the tracepoint fallback objects in cross-build mode.

### Target Environment

1. RHEL 8 `x86_64` (real hardware or VM running a RHEL8-compatible kernel).
1. Build host requirements (for building the RPM on RHEL8):
   - `dotnet-sdk-8.0`
   - `rpm-build`, `rpmbuild`
   - `clang`, `llvm`, `make`, `bpftool`
   - eBPF deps: `libbpf`, `libbpf-devel`, `elfutils-libelf`, `elfutils-libelf-devel`, `kernel-devel`

Example install (package names may vary by repo configuration):

```sh
sudo dnf install -y rpm-build dotnet-sdk-8.0 clang llvm make bpftool \
  libbpf libbpf-devel elfutils-libelf elfutils-libelf-devel kernel-devel
```

### Artifacts

RPM output from the build script is written to:

```text
artifacts/lintap-rpm/x86_64/lintap-<version>-<release>.x86_64.rpm
```

If building with `--skip-mcp`, validate the RPM does not contain `/usr/lib/lintap/mcp/`.

### Build Procedure On RHEL 8 (Preferred)

From the repo root on the RHEL8 `x86_64` build host:

```sh
Lintap/packaging/lintap-rpm/build-rpm.sh \
  --version 0.1.0 \
  --release 1.el8 \
  --arch x86_64 \
  --runtime linux-x64
```

If NuGet access is not available on the build host:

```sh
Lintap/packaging/lintap-rpm/build-rpm.sh \
  --version 0.1.0 \
  --release 1.el8 \
  --arch x86_64 \
  --runtime linux-x64 \
  --skip-mcp
```

Notes:

1. The script builds eBPF tracers first, then runs `dotnet publish`.
1. Intermediates are written under `/var/tmp/lintap-rpm-build` by default to avoid shared-mount issues.
1. If you need to reuse a prior restore, add `--no-restore`.

### Install/Upgrade On The Target RHEL 8 Host

1. Copy the RPM to the target host.
1. Install/upgrade:

```sh
sudo dnf install -y ./lintap-0.1.0-1.el8.x86_64.rpm
```

3. Inspect config:

```sh
sudo cat /etc/lintap/lintap.env
```

4. Start and tail logs:

```sh
sudo systemctl daemon-reload
sudo systemctl restart lintap
sudo systemctl status lintap --no-pager
sudo journalctl -u lintap -n 200 --no-pager
```

### Runtime Verification Checklist

#### A. Packaging/layout sanity

```sh
rpm -qpl ./lintap-*.rpm | egrep '(/usr/lib/lintap/|/usr/lib/lintap/tracers/|/etc/lintap/lintap.env|/usr/lib/systemd/system/lintap.service|/usr/bin/lintap)'
```

Confirm `libbpf` availability:

```sh
rpm -q libbpf
ldconfig -p | grep -E 'libbpf\.so\.(0|1)' || true
```

#### B. eBPF sensor startup

In the log you should see each sensor searching candidates and then loading one.

Expected on RHEL8 (depending on BTF availability):

1. CO-RE path: loads `*_tracer.bpf.o`.
1. Fallback path: if CO-RE objects are not present or do not load, it should load `*_tracepoint.bpf.o`.

If you still see `Unable to load shared library 'libbpf.so.1'` on RHEL8, that indicates either:

1. `libbpf` is missing on the target, or
1. the deployed build predates the runtime resolver fallback fix.

#### C. EPL duplicate context warnings

Current known warning:

```text
Context by name 'Every10Seconds' already exists
```

Status: not treated as a blocker; track if it correlates with missing event types.

#### D. Data outputs

Default data paths are controlled by `/etc/lintap/lintap.env` and the runtime. Verify parquet output is created:

```sh
sudo find /var/log/lintap -maxdepth 4 -type f | sort | tail -n 100
sudo find /tmp/lintap-data -maxdepth 4 -type f | sort | tail -n 100 || true
```

### Known Issues / Investigation Threads

#### 1) Network data is spotty (missing most IpAddr values)

Symptoms observed:

1. Only `TcpIpDisconnect`, `UdpIpSend`, `UdpIpRecv` show up.
1. Many records missing `IpAddr` values.

Likely causes to check on the real RHEL8 target:

1. eBPF attachment type mismatch: CO-RE vs tracepoint fallback differences (some fields may not be populated in fallback paths).
1. Kernel support/permissions: verify required tracepoints/kprobes are present and attach succeeds (libbpf errors in logs).
1. Network tracer object used: ensure the runtime is loading the intended object file.
   - If `network_ops_tracer.bpf.o` fails and only `network_tracepoint.bpf.o` is used, expect less context.

Suggested next checks:

```sh
sudo journalctl -u lintap -n 400 --no-pager | egrep -i 'Network|bpf|libbpf|attach|tracepoint|kprobe|failed'
sudo bpftool prog list | grep -i wintap || true
sudo bpftool link list | grep -i wintap || true
```

If the target has BTF (`/sys/kernel/btf/vmlinux` exists), prefer packaging CO-RE objects for that target and validate that `network_ops_tracer.bpf.o` loads successfully.

#### 2) Process telemetry review

Not yet deeply validated in the last deploy. Recommended minimum checks:

1. Verify process parquet files are being written and contain expected columns.
1. Confirm parent/child relationships look plausible.

#### 3) File events

Currently: plentiful and appear reasonable.

### Recommended Next Steps (Sequenced)

1. Build the RPM directly on the real RHEL8 `x86_64` build host (avoid cross-build artifacts).
1. Deploy to the real RHEL8 target and validate eBPF sensors start without fallback-only limitations (if BTF available).
1. Re-evaluate network telemetry with CO-RE objects present:
   - confirm which `.bpf.o` is loaded for Network.
   - confirm whether `IpAddr` fields populate.
1. If network remains spotty:
   - capture `bpftool prog/link` output,
   - capture the service logs around sensor startup,
   - inspect the network tracer code paths for field extraction differences between CO-RE and tracepoint modes.
