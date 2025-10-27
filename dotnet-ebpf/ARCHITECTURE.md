# Architecture Diagram

```mermaid
graph TB
    subgraph "User Space"
        App[".NET Control Plane<br/>(Program.cs)"]
        LibBpf["libbpf Library<br/>(P/Invoke wrapper)"]
    end
    
    subgraph "Kernel Space"
        Tracepoint["openat Tracepoint<br/>(sys_enter_openat)"]
        BPF["eBPF Program<br/>(openat_tracer.bpf.c)"]
        RingBuf["Ring Buffer<br/>(BPF Map)"]
    end
    
    subgraph "System Calls"
        Process1["Process: bash"]
        Process2["Process: ls"]
        Process3["Process: cat"]
    end
    
    Process1 -->|"openat('/etc/bashrc')"| Tracepoint
    Process2 -->|"openat('/tmp')"| Tracepoint
    Process3 -->|"openat('/etc/hostname')"| Tracepoint
    
    Tracepoint -->|"Trigger"| BPF
    BPF -->|"1. Read PID"| BPF
    BPF -->|"2. Read comm"| BPF
    BPF -->|"3. Read filename"| BPF
    BPF -->|"4. Write event"| RingBuf
    
    RingBuf -->|"Poll events"| LibBpf
    LibBpf -->|"Marshal data"| App
    App -->|"Display:<br/>PID | COMMAND | FILENAME"| Output["Console Output"]
    
    style BPF fill:#e1f5ff
    style App fill:#ffe1e1
    style RingBuf fill:#fff5e1
    style Tracepoint fill:#e1ffe1
```

## Data Flow

1. **System Call**: A process calls `openat()` to open a file
2. **Tracepoint Trigger**: Kernel tracepoint `sys_enter_openat` fires
3. **eBPF Execution**: 
   - eBPF program reads PID from kernel
   - Reads process command name
   - Reads filename argument
   - Creates event structure
4. **Ring Buffer**: Event is written to BPF ring buffer (shared memory)
5. **.NET Poll**: Control plane polls ring buffer for new events
6. **Marshal**: Binary data is marshaled into C# struct
7. **Display**: Event is formatted and printed to console

## Event Structure

```
┌─────────────────────────────────────┐
│     OpenatEvent Structure           │
├─────────────────────────────────────┤
│ pid       (4 bytes)   → 1234        │
│ comm      (16 bytes)  → "bash\0"    │
│ filename  (256 bytes) → "/etc/..."  │
└─────────────────────────────────────┘
```

## Key Technologies

- **eBPF**: Extended Berkeley Packet Filter - runs code in kernel space
- **Tracepoints**: Static kernel instrumentation points
- **Ring Buffer**: Lock-free, per-CPU circular buffer for passing data
- **libbpf**: User-space library for loading and managing eBPF programs
- **P/Invoke**: .NET mechanism for calling native C libraries
