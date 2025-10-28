using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace EbpfTracer;

/// <summary>
/// Internal representation of system events from eBPF.
/// This is OUR model - we own and control it.
/// </summary>
public interface ISystemEvent
{
    Guid EventId { get; }
    DateTime EventTime { get; }
    string EventType { get; }
}

/// <summary>
/// Internal process event representation with enriched data from /proc.
/// </summary>
public class ProcessEvent : ISystemEvent
{
    public Guid EventId { get; set; } = Guid.NewGuid();
    public DateTime EventTime { get; set; }
    public string EventType { get; set; } = "PROCESS_CREATE";
    
    // Process data
    public int ProcessId { get; set; }
    public int ParentProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string CommandLine { get; set; } = string.Empty;
    public string ExecutablePath { get; set; } = string.Empty;
    
    // User context
    public uint UserId { get; set; }
    public uint GroupId { get; set; }
    public uint SessionId { get; set; }
    public string Username { get; set; } = string.Empty;
    
    // Environment
    public string HomeDirectory { get; set; } = string.Empty;
    public string Shell { get; set; } = string.Empty;
    public string WorkingDirectory { get; set; } = string.Empty;
    
    // Security
    public ulong Capabilities { get; set; }
    public uint SeccompMode { get; set; }
    public uint Flags { get; set; }
    
    // Timing
    public ulong TimestampNanoseconds { get; set; }
    public ulong StartTime { get; set; }
    
    /// <summary>
    /// Create ProcessEvent from eBPF execve event, enriched with /proc data.
    /// </summary>
    public static ProcessEvent FromExecveEvent(ExecveEvent evt)
    {
        var pid = evt.Pid;
        var procData = ProcReader.ReadProcessData(pid);
        
        return new ProcessEvent
        {
            EventTime = DateTime.UtcNow,
            ProcessId = (int)pid,
            ParentProcessId = procData.ParentProcessId,
            ProcessName = evt.GetComm(),
            CommandLine = procData.CommandLine,
            ExecutablePath = evt.GetFilename(),
            UserId = evt.Uid,
            GroupId = evt.Gid,
            SessionId = procData.SessionId,
            Username = procData.Username,
            HomeDirectory = procData.HomeDirectory,
            Shell = procData.Shell,
            WorkingDirectory = procData.WorkingDirectory,
            Capabilities = evt.Capabilities,
            SeccompMode = evt.SeccompMode,
            Flags = evt.Flags,
            TimestampNanoseconds = evt.TimestampNs,
            StartTime = evt.StartTime
        };
    }
}

/// <summary>
/// Internal file event representation with enriched process context.
/// </summary>
public class FileEvent : ISystemEvent
{
    public Guid EventId { get; set; } = Guid.NewGuid();
    public DateTime EventTime { get; set; }
    public string EventType { get; set; } = "FILE_OPEN";
    
    // Process context
    public int ProcessId { get; set; }
    public int ParentProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string ProcessCommandLine { get; set; } = string.Empty;
    
    // User context
    public uint UserId { get; set; }
    public uint GroupId { get; set; }
    public string Username { get; set; } = string.Empty;
    
    // File data
    public string FilePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string FileDirectory { get; set; } = string.Empty;
    
    /// <summary>
    /// Create FileEvent from eBPF openat event, enriched with /proc data.
    /// </summary>
    public static FileEvent FromOpenatEvent(OpenatEvent evt)
    {
        var filename = evt.GetFilename();
        var pid = evt.Pid;
        var procData = ProcReader.ReadProcessData(pid);
        
        return new FileEvent
        {
            EventTime = DateTime.UtcNow,
            ProcessId = (int)pid,
            ParentProcessId = procData.ParentProcessId,
            ProcessName = evt.GetComm(),
            ProcessCommandLine = procData.CommandLine,
            UserId = procData.UserId,        // Get from /proc, not event
            GroupId = procData.GroupId,      // Get from /proc, not event
            Username = procData.Username,
            FilePath = filename,
            FileName = Path.GetFileName(filename),
            FileDirectory = Path.GetDirectoryName(filename) ?? string.Empty
        };
    }
}

/// <summary>
/// Adapter interface to convert our internal events to external formats.
/// This is the ONLY place that knows about WintapMessage.
/// </summary>
public interface IEventAdapter<TExternal>
{
    TExternal ToExternal(ISystemEvent systemEvent);
}

/// <summary>
/// Adapter for WintapMessage format.
/// When WintapMessage changes, only this class needs updating.
/// </summary>
public class WintapMessageAdapter : IEventAdapter<WintapMessage>
{
    public WintapMessage ToExternal(ISystemEvent systemEvent)
    {
        return systemEvent switch
        {
            ProcessEvent pe => ConvertProcessEvent(pe),
            FileEvent fe => ConvertFileEvent(fe),
            _ => throw new NotSupportedException($"Unknown event type: {systemEvent.GetType()}")
        };
    }
    
    private WintapMessage ConvertProcessEvent(ProcessEvent evt)
    {
        var msg = new WintapMessage
        {
            EventId = evt.EventId,
            EventType = evt.EventType,
            EventTime = evt.EventTime,
            
            ProcessId = evt.ProcessId,
            ProcessName = evt.ProcessName,
            ProcessCommandLine = evt.CommandLine,
            ParentProcessId = evt.ParentProcessId,
            
            User = evt.Username,
            Domain = "localhost",
            Session = (int)evt.SessionId,
            LogonId = evt.UserId.ToString(),
            
            FileName = Path.GetFileName(evt.ExecutablePath),
            FileDirectory = Path.GetDirectoryName(evt.ExecutablePath) ?? string.Empty,
            
            Details = $"User: {evt.Username}, Shell: {evt.Shell}"
        };
        
        // Extended properties for additional context
        msg.ExtendedProperties["uid"] = evt.UserId.ToString();
        msg.ExtendedProperties["gid"] = evt.GroupId.ToString();
        msg.ExtendedProperties["sid"] = evt.SessionId.ToString();
        msg.ExtendedProperties["ppid"] = evt.ParentProcessId.ToString();
        msg.ExtendedProperties["flags"] = $"0x{evt.Flags:X}";
        msg.ExtendedProperties["capabilities"] = $"0x{evt.Capabilities:X}";
        msg.ExtendedProperties["seccomp_mode"] = evt.SeccompMode.ToString();
        msg.ExtendedProperties["timestamp_ns"] = evt.TimestampNanoseconds.ToString();
        
        if (!string.IsNullOrEmpty(evt.HomeDirectory))
            msg.ExtendedProperties["home"] = evt.HomeDirectory;
        if (!string.IsNullOrEmpty(evt.Shell))
            msg.ExtendedProperties["shell"] = evt.Shell;
        if (!string.IsNullOrEmpty(evt.WorkingDirectory))
            msg.ExtendedProperties["cwd"] = evt.WorkingDirectory;
        
        return msg;
    }
    
    private WintapMessage ConvertFileEvent(FileEvent evt)
    {
        var msg = new WintapMessage
        {
            EventId = evt.EventId,
            EventType = evt.EventType,
            EventTime = evt.EventTime,
            
            ProcessId = evt.ProcessId,
            ProcessName = evt.ProcessName,
            ProcessCommandLine = evt.ProcessCommandLine,
            ParentProcessId = evt.ParentProcessId,
            
            User = evt.Username,
            Domain = "localhost",
            LogonId = evt.UserId.ToString(),
            
            FileName = evt.FileName,
            FileDirectory = evt.FileDirectory,
            
            Details = $"File opened: {evt.FilePath}"
        };
        
        // Extended properties
        msg.ExtendedProperties["file_path"] = evt.FilePath;
        msg.ExtendedProperties["uid"] = evt.UserId.ToString();
        msg.ExtendedProperties["gid"] = evt.GroupId.ToString();
        msg.ExtendedProperties["ppid"] = evt.ParentProcessId.ToString();
        
        return msg;
    }
}

/// <summary>
/// Event handler interface - implement this for different outputs.
/// </summary>
public interface IEventHandler
{
    void HandleEvent(ISystemEvent systemEvent);
}

/// <summary>
/// Console output handler with compact and full message display.
/// </summary>
public class ConsoleEventHandler : IEventHandler
{
    private readonly IEventAdapter<WintapMessage> _adapter;
    private int _eventCount = 0;
    
    public ConsoleEventHandler(IEventAdapter<WintapMessage> adapter)
    {
        _adapter = adapter;
    }
    
    public void HandleEvent(ISystemEvent systemEvent)
    {
        _eventCount++;
        var wintapMsg = _adapter.ToExternal(systemEvent);
        
        Console.WriteLine($"[{_eventCount,5}] {wintapMsg.ToCompactString()}");
        
        // Show full JSON every 10 events
        if (_eventCount % 10 == 0)
        {
            Console.WriteLine();
            Console.WriteLine("Sample full WintapMessage:");
            Console.WriteLine(wintapMsg.ToString());
            Console.WriteLine(new string('-', 120));
        }
    }
}

/// <summary>
/// File output handler - writes JSON to file.
/// </summary>
public class FileEventHandler : IEventHandler
{
    private readonly IEventAdapter<WintapMessage> _adapter;
    private readonly string _outputPath;
    
    public FileEventHandler(IEventAdapter<WintapMessage> adapter, string outputPath)
    {
        _adapter = adapter;
        _outputPath = outputPath;
    }
    
    public void HandleEvent(ISystemEvent systemEvent)
    {
        var wintapMsg = _adapter.ToExternal(systemEvent);
        var json = JsonSerializer.Serialize(wintapMsg, new JsonSerializerOptions 
        { 
            WriteIndented = true 
        });
        File.AppendAllText(_outputPath, json + "\n");
    }
}

/// <summary>
/// Composite handler - send events to multiple destinations.
/// </summary>
public class CompositeEventHandler : IEventHandler
{
    private readonly List<IEventHandler> _handlers = new();
    
    public void AddHandler(IEventHandler handler)
    {
        _handlers.Add(handler);
    }
    
    public void HandleEvent(ISystemEvent systemEvent)
    {
        foreach (var handler in _handlers)
        {
            try
            {
                handler.HandleEvent(systemEvent);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Handler error: {ex.Message}");
            }
        }
    }
}