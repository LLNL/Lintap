# Architecture: Abstraction Layer & Unified Tracer

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                   eBPF Programs (Kernel)                │
│  ┌──────────────────┐      ┌──────────────────┐        │
│  │ execve_tracer    │      │ openat_tracer    │        │
│  │   .bpf.c         │      │   .bpf.c         │        │
│  └────────┬─────────┘      └────────┬─────────┘        │
│           │                         │                   │
│           └─────────┬───────────────┘                   │
│                     │ Ring Buffers                      │
└─────────────────────┼───────────────────────────────────┘
                      │
┌─────────────────────┼───────────────────────────────────┐
│                     │  .NET Application                 │
│                     ↓                                    │
│  ┌──────────────────────────────────────────────────┐  │
│  │         UnifiedTracer.cs (Orchestrator)          │  │
│  │  - Loads multiple eBPF programs                  │  │
│  │  - Polls multiple ring buffers                   │  │
│  │  - Routes events to handlers                     │  │
│  └────────┬──────────────────────────┬──────────────┘  │
│           │                          │                  │
│           ↓                          ↓                  │
│  ┌─────────────────┐      ┌─────────────────┐         │
│  │ ExecveEvent.cs  │      │ OpenatEvent.cs  │         │
│  │ (Raw eBPF data) │      │ (Raw eBPF data) │         │
│  └────────┬────────┘      └────────┬────────┘         │
│           │                        │                   │
│           └───────────┬────────────┘                   │
│                       ↓                                 │
│  ┌────────────────────────────────────────────────┐   │
│  │      EventAbstraction.cs (OUR LAYER)           │   │
│  │                                                 │   │
│  │  ┌───────────────────────────────────────────┐ │   │
│  │  │  ISystemEvent (Interface)                 │ │   │
│  │  │  - EventId, EventTime, EventType          │ │   │
│  │  └───────────────────────────────────────────┘ │   │
│  │           ↑                    ↑                │   │
│  │           │                    │                │   │
│  │  ┌────────────────┐   ┌───────────────┐       │   │
│  │  │ ProcessEvent   │   │  FileEvent    │       │   │
│  │  │ (Our Model)    │   │  (Our Model)  │       │   │
│  │  └────────────────┘   └───────────────┘       │   │
│  │           │                    │                │   │
│  │           └────────┬───────────┘                │   │
│  │                    ↓                            │   │
│  │  ┌─────────────────────────────────────────┐   │   │
│  │  │  IEventAdapter<T> (Adapter Pattern)     │   │   │
│  │  │  - ToExternal(ISystemEvent) → T         │   │   │
│  │  └─────────────────────────────────────────┘   │   │
│  │                    ↓                            │   │
│  │  ┌─────────────────────────────────────────┐   │   │
│  │  │  WintapMessageAdapter                   │   │   │
│  │  │  (ONLY place that knows WintapMessage)  │   │   │
│  │  └─────────────────────────────────────────┘   │   │
│  └────────────────────────┬───────────────────────┘   │
│                           ↓                            │
│  ┌────────────────────────────────────────────────┐   │
│  │  WintapMessage.cs (External Format)            │   │
│  │  (Eventually: NuGet package from LLNL/Wintap)  │   │
│  └────────────────────────┬───────────────────────┘   │
│                           ↓                            │
│  ┌────────────────────────────────────────────────┐   │
│  │      IEventHandler (Output Strategy)           │   │
│  │  ┌──────────────┐  ┌──────────────────────┐   │   │
│  │  │ Console      │  │ File                 │   │   │
│  │  │ Handler      │  │ Handler              │   │   │
│  │  └──────────────┘  └──────────────────────┘   │   │
│  │  ┌──────────────────────────────────────────┐ │   │
│  │  │ CompositeHandler (Multiple outputs)     │ │   │
│  │  └──────────────────────────────────────────┘ │   │
│  └────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────┘
```

## Key Components

### 1. ISystemEvent (Our Internal Model)

**Purpose**: Define OUR representation of system events, independent of external formats.

```csharp
public interface ISystemEvent
{
    Guid EventId { get; }
    DateTime EventTime { get; }
    string EventType { get; }
}
```

**Why**: 
- We own this interface
- Changes to external formats don't affect this
- Can add new event types without touching external code

### 2. ProcessEvent & FileEvent (Concrete Internal Events)

**Purpose**: Strongly-typed internal representations.

```csharp
public class ProcessEvent : ISystemEvent
{
    // Rich, Linux-specific data
    public int ProcessId { get; set; }
    public uint UserId { get; set; }
    public string CommandLine { get; set; }
    // ... all the fields WE need
}
```

**Why**:
- Type-safe
- Easy to test
- Easy to extend
- No external dependencies

### 3. IEventAdapter<T> (Adapter Pattern)

**Purpose**: Convert between internal and external formats.

```csharp
public interface IEventAdapter<TExternal>
{
    TExternal ToExternal(ISystemEvent systemEvent);
}
```

**Why**:
- Single responsibility: conversion only
- Easy to swap adapters (Wintap, Splunk, custom format)
- Testable in isolation

### 4. WintapMessageAdapter (Concrete Adapter)

**Purpose**: THE ONLY CLASS that knows about WintapMessage.

```csharp
public class WintapMessageAdapter : IEventAdapter<WintapMessage>
{
    public WintapMessage ToExternal(ISystemEvent systemEvent)
    {
        // Convert ProcessEvent → WintapMessage
        // Convert FileEvent → WintapMessage
    }
}
```

**Why**:
- When WintapMessage changes, only THIS file needs updating
- Could have SplunkAdapter, ElasticAdapter, etc.
- Can swap adapters at runtime

### 5. IEventHandler (Output Strategy)

**Purpose**: Define how/where to output events.

```csharp
public interface IEventHandler
{
    void HandleEvent(ISystemEvent systemEvent);
}
```

**Implementations**:
- `ConsoleEventHandler` - Print to console
- `FileEventHandler` - Write to JSON file
- `CompositeEventHandler` - Multiple outputs
- Future: `KafkaEventHandler`, `SplunkEventHandler`, etc.

### 6. UnifiedTracer (Orchestrator)

**Purpose**: Load multiple eBPF programs, poll events, route to handlers.

**Features**:
- Loads multiple eBPF programs simultaneously
- Command-line configuration
- Flexible output options
- Clean error handling and cleanup

## Benefits of This Architecture

### 1. Loose Coupling

```
Before (Tight Coupling):
ExecveEvent → [Direct conversion] → WintapMessage → Console

After (Loose Coupling):
ExecveEvent → ProcessEvent → IEventAdapter → WintapMessage → IEventHandler
                    ↑              ↑                              ↑
                 We own       Swappable                     Swappable
```

### 2. Single Responsibility Principle

Each component has ONE job:
- `ExecveEvent.cs`: Marshal eBPF data
- `ProcessEvent.cs`: Internal representation
- `WintapMessageAdapter.cs`: Convert formats
- `ConsoleEventHandler.cs`: Output to console
- `UnifiedTracer.cs`: Orchestrate everything

### 3. Future-Proof

#### When WintapMessage changes:
```csharp
// ONLY update this one method:
private WintapMessage ConvertProcessEvent(ProcessEvent evt)
{
    // New WintapMessage API here
}
```

#### To add a new output format:
```csharp
// Create new adapter
public class SplunkAdapter : IEventAdapter<SplunkEvent>
{
    public SplunkEvent ToExternal(ISystemEvent evt) { ... }
}

// Use it
var handler = new SplunkEventHandler(new SplunkAdapter());
```

#### To add a new syscall:
```csharp
// 1. Create NetworkEvent.cs
public class NetworkEvent : ISystemEvent { ... }

// 2. Update adapter
public WintapMessage ToExternal(ISystemEvent evt)
{
    return evt switch 
    {
        ProcessEvent pe => ...,
        FileEvent fe => ...,
        NetworkEvent ne => ConvertNetworkEvent(ne), // Add this
        ...
    };
}

// 3. Add to UnifiedTracer
if (config.TraceConnect)
{
    var tracer = LoadTracer("connect", "connect_tracer.bpf.o", ...);
}
```

### 4. Testability

Each layer can be tested independently:

```csharp
// Test adapter without eBPF
var evt = new ProcessEvent { ProcessId = 1234, ... };
var adapter = new WintapMessageAdapter();
var msg = adapter.ToExternal(evt);
Assert.Equal(1234, msg.ProcessId);

// Test handler without real events
var mockEvent = new ProcessEvent { ... };
var handler = new ConsoleEventHandler(adapter);
handler.HandleEvent(mockEvent);

// Mock adapter for testing handlers
var mockAdapter = new Mock<IEventAdapter<WintapMessage>>();
```

### 5. Flexibility

```bash
# Trace only processes
sudo dotnet run --execve

# Trace only files
sudo dotnet run --openat

# Trace both
sudo dotnet run --all

# Output to file
sudo dotnet run --all -o events.json

# Output to both console and file
sudo dotnet run --all -o events.json --console
```

## Migration Path to External WintapMessage

### Current State
```csharp
// WintapMessage.cs (in our repo)
public class WintapMessage { ... }
```

### Future State (when LLNL publishes NuGet package)

```csharp
// 1. Add package reference
<PackageReference Include="Wintap.Messages" Version="1.0.0" />

// 2. Remove our WintapMessage.cs

// 3. Update using statement
using Wintap.Messages; // Instead of: using EbpfOpenatPoc;

// 4. Update adapter if API changed
public class WintapMessageAdapter : IEventAdapter<WintapMessage>
{
    public WintapMessage ToExternal(ISystemEvent evt)
    {
        // Use official WintapMessage API
        return new WintapMessage
        {
            // Updated property names/types if needed
        };
    }
}
```

**That's it!** Only the adapter needs updating, not our entire codebase.

## Usage Examples

### Basic Usage

```bash
# Build everything
make all
dotnet build UnifiedTracer.csproj

# Run (traces everything)
sudo dotnet run --project UnifiedTracer.csproj

# Or use convenience script
sudo ./run-unified.sh
```

### Advanced Usage

```bash
# Only process creation
sudo ./run-unified.sh --execve

# Only file access
sudo ./run-unified.sh --openat

# Write to JSON file
sudo ./run-unified.sh -o /var/log/events.json

# Console + file
sudo ./run-unified.sh -o events.json --console
```

### Adding Custom Handler

```csharp
// Create custom handler
public class SyslogEventHandler : IEventHandler
{
    public void HandleEvent(ISystemEvent evt)
    {
        var adapter = new WintapMessageAdapter();
        var msg = adapter.ToExternal(evt);
        
        // Send to syslog
        Syslog.Write(msg.ToString());
    }
}

// Use in UnifiedTracer.cs
_eventHandler = new SyslogEventHandler();
```

## File Summary

| File | Purpose | Dependencies |
|------|---------|-------------|
| `EventAbstraction.cs` | Internal event models & adapters | None (we own) |
| `WintapMessage.cs` | External format (temporary) | None (will be NuGet) |
| `UnifiedTracer.cs` | Main application | EventAbstraction |
| `ExecveEvent.cs` | eBPF marshaling | None |
| `OpenatEvent.cs` | eBPF marshaling | None |
| `LibBpf.cs` | P/Invoke | None |

## Key Principles

1. **Depend on abstractions, not concretions**
   - Code depends on `ISystemEvent`, not specific event types
   - Code depends on `IEventAdapter`, not specific adapters

2. **Open/Closed Principle**
   - Open for extension (new events, adapters, handlers)
   - Closed for modification (core interfaces don't change)

3. **Dependency Inversion**
   - High-level (UnifiedTracer) doesn't depend on low-level (WintapMessage)
   - Both depend on abstractions (IEventAdapter)

4. **Single Source of Truth**
   - ProcessEvent is our truth
   - WintapMessage is just one view of that truth
   - Can have SplunkEvent, ElasticEvent, etc. as other views

## Summary

**Before**: Tightly coupled, single syscall, hard to maintain
**After**: Loosely coupled, multiple syscalls, easy to extend

When WintapMessage becomes a NuGet package:
1. Add package reference
2. Remove our WintapMessage.cs
3. Update WintapMessageAdapter
4. Done!

Our internal models and adapters remain unchanged. 🎉