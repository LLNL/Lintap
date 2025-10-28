using System;
using System.Collections.Generic;

namespace EbpfOpenatPoc;

/// <summary>
/// Internal representation of system events from eBPF
/// This is OUR model - we own and control it
/// </summary>
public interface ISystemEvent
{
    Guid EventId { get; }
    DateTime EventTime { get; }
    string EventType { get; }
}

/// <summary>
/// Internal process event representation
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
    /// Create from eBPF execve event
    /// Enhanced with /proc filesystem data
    /// </summary>
    public static ProcessEvent FromExecveEvent(ExecveEvent evt)
    {
        var pid = evt.Pid;
        
        // Read additional data from /proc
        var procData = ReadProcData(pid);
        
        return new ProcessEvent
        {
            EventTime = DateTime.UtcNow,
            ProcessId = (int)pid,
            ParentProcessId = procData.PPid,
            ProcessName = evt.GetComm(),
            CommandLine = procData.CommandLine,
            ExecutablePath = evt.GetFilename(),
            UserId = evt.Uid,
            GroupId = evt.Gid,
            SessionId = procData.SessionId,
            Username = procData.Username,
            HomeDirectory = procData.Home,
            Shell = procData.Shell,
            WorkingDirectory = procData.Cwd,
            Capabilities = evt.Capabilities,
            SeccompMode = evt.SeccompMode,
            Flags = evt.Flags,
            TimestampNanoseconds = evt.TimestampNs,
            StartTime = evt.StartTime
        };
    }
    
    /// <summary>
    /// Read comprehensive process data from /proc filesystem
    /// </summary>
    private static ProcData ReadProcData(uint pid)
    {
        var data = new ProcData();
        
        try
        {
            var procDir = $"/proc/{pid}";
            
            // Read /proc/<pid>/status for PPID, session, etc.
            var statusPath = $"{procDir}/status";
            if (System.IO.File.Exists(statusPath))
            {
                foreach (var line in System.IO.File.ReadLines(statusPath))
                {
                    if (line.StartsWith("PPid:", StringComparison.Ordinal))
                    {
                        var parts = line.Split(new[] { ':', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 2 && int.TryParse(parts[1], out int ppid))
                            data.PPid = ppid;
                    }
                    else if (line.StartsWith("NSpid:", StringComparison.Ordinal))
                    {
                        // Session ID approximation
                        var parts = line.Split(new[] { ':', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 2 && uint.TryParse(parts[1], out uint sid))
                            data.SessionId = sid;
                    }
                }
            }
            
            // Read /proc/<pid>/cmdline for full command line with arguments
            var cmdlinePath = $"{procDir}/cmdline";
            if (System.IO.File.Exists(cmdlinePath))
            {
                var cmdlineBytes = System.IO.File.ReadAllBytes(cmdlinePath);
                // cmdline uses null bytes as separators
                var args = new System.Collections.Generic.List<string>();
                int start = 0;
                for (int i = 0; i < cmdlineBytes.Length; i++)
                {
                    if (cmdlineBytes[i] == 0)
                    {
                        if (i > start)
                        {
                            args.Add(System.Text.Encoding.UTF8.GetString(cmdlineBytes, start, i - start));
                        }
                        start = i + 1;
                    }
                }
                data.CommandLine = string.Join(" ", args);
            }
            
            // Read /proc/<pid>/environ for environment variables
            var environPath = $"{procDir}/environ";
            if (System.IO.File.Exists(environPath))
            {
                var environBytes = System.IO.File.ReadAllBytes(environPath);
                int start = 0;
                for (int i = 0; i < environBytes.Length; i++)
                {
                    if (environBytes[i] == 0)
                    {
                        if (i > start)
                        {
                            var envVar = System.Text.Encoding.UTF8.GetString(environBytes, start, i - start);
                            if (envVar.StartsWith("USER="))
                                data.Username = envVar.Substring(5);
                            else if (envVar.StartsWith("HOME="))
                                data.Home = envVar.Substring(5);
                            else if (envVar.StartsWith("SHELL="))
                                data.Shell = envVar.Substring(6);
                        }
                        start = i + 1;
                    }
                }
            }
            
            // Read /proc/<pid>/cwd symlink for current working directory
            var cwdPath = $"{procDir}/cwd";
            if (System.IO.Directory.Exists(cwdPath))
            {
                try
                {
                    // ReadLink equivalent in C#
                    var fileInfo = new System.IO.FileInfo(cwdPath);
                    if (fileInfo.Exists)
                    {
                        data.Cwd = fileInfo.LinkTarget ?? fileInfo.FullName;
                    }
                }
                catch
                {
                    // Permission denied or not a symlink
                }
            }
        }
        catch (Exception)
        {
            // Process may have exited, or permission denied
        }
        
        return data;
    }
    
    private struct ProcData
    {
        public int PPid;
        public uint SessionId;
        public string CommandLine;
        public string Username;
        public string Home;
        public string Shell;
        public string Cwd;
    }
}

/// <summary>
/// Internal file event representation
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
    /// Create from eBPF openat event
    /// Enhanced with /proc filesystem data
    /// </summary>
    public static FileEvent FromOpenatEvent(OpenatEvent evt)
    {
        var filename = evt.GetFilename();
        var pid = evt.Pid;
        
        // Read process context from /proc
        var procData = ReadProcContextForFile(pid);
        
        return new FileEvent
        {
            EventTime = DateTime.UtcNow,
            ProcessId = (int)pid,
            ParentProcessId = procData.PPid,
            ProcessName = evt.GetComm(),
            ProcessCommandLine = procData.CommandLine,
            UserId = procData.Uid,
            GroupId = procData.Gid,
            Username = procData.Username,
            FilePath = filename,
            FileName = System.IO.Path.GetFileName(filename),
            FileDirectory = System.IO.Path.GetDirectoryName(filename) ?? string.Empty
        };
    }
    
    /// <summary>
    /// Read process context from /proc for file events
    /// </summary>
    private static FileProcData ReadProcContextForFile(uint pid)
    {
        var data = new FileProcData();
        
        try
        {
            var procDir = $"/proc/{pid}";
            
            // Read /proc/<pid>/status for PPID and IDs
            var statusPath = $"{procDir}/status";
            if (System.IO.File.Exists(statusPath))
            {
                foreach (var line in System.IO.File.ReadLines(statusPath))
                {
                    if (line.StartsWith("PPid:", StringComparison.Ordinal))
                    {
                        var parts = line.Split(new[] { ':', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 2 && int.TryParse(parts[1], out int ppid))
                            data.PPid = ppid;
                    }
                    else if (line.StartsWith("Uid:", StringComparison.Ordinal))
                    {
                        var parts = line.Split(new[] { ':', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 2 && uint.TryParse(parts[1], out uint uid))
                            data.Uid = uid;
                    }
                    else if (line.StartsWith("Gid:", StringComparison.Ordinal))
                    {
                        var parts = line.Split(new[] { ':', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 2 && uint.TryParse(parts[1], out uint gid))
                            data.Gid = gid;
                    }
                }
            }
            
            // Read /proc/<pid>/cmdline for command line
            var cmdlinePath = $"{procDir}/cmdline";
            if (System.IO.File.Exists(cmdlinePath))
            {
                var cmdlineBytes = System.IO.File.ReadAllBytes(cmdlinePath);
                var args = new System.Collections.Generic.List<string>();
                int start = 0;
                for (int i = 0; i < cmdlineBytes.Length; i++)
                {
                    if (cmdlineBytes[i] == 0)
                    {
                        if (i > start)
                        {
                            args.Add(System.Text.Encoding.UTF8.GetString(cmdlineBytes, start, i - start));
                        }
                        start = i + 1;
                    }
                }
                data.CommandLine = string.Join(" ", args);
            }
            
            // Read /proc/<pid>/environ for username
            var environPath = $"{procDir}/environ";
            if (System.IO.File.Exists(environPath))
            {
                var environBytes = System.IO.File.ReadAllBytes(environPath);
                int start = 0;
                for (int i = 0; i < environBytes.Length; i++)
                {
                    if (environBytes[i] == 0)
                    {
                        if (i > start)
                        {
                            var envVar = System.Text.Encoding.UTF8.GetString(environBytes, start, i - start);
                            if (envVar.StartsWith("USER="))
                                data.Username = envVar.Substring(5);
                        }
                        start = i + 1;
                    }
                }
            }
        }
        catch (Exception)
        {
            // Process may have exited or permission denied
        }
        
        return data;
    }
    
    private struct FileProcData
    {
        public int PPid;
        public uint Uid;
        public uint Gid;
        public string CommandLine;
        public string Username;
    }
}

/// <summary>
/// Adapter interface to convert our events to external format
/// This is the ONLY place that knows about WintapMessage
/// </summary>
public interface IEventAdapter<TExternal>
{
    TExternal ToExternal(ISystemEvent systemEvent);
}

/// <summary>
/// Adapter for WintapMessage format
/// When WintapMessage changes, only this class needs updating
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
            
            FileName = System.IO.Path.GetFileName(evt.ExecutablePath),
            FileDirectory = System.IO.Path.GetDirectoryName(evt.ExecutablePath) ?? string.Empty,
            
            Details = $"User: {evt.Username}, Shell: {evt.Shell}"
        };
        
        // Extended properties
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
/// Event handler interface - implement this for different outputs
/// </summary>
public interface IEventHandler
{
    void HandleEvent(ISystemEvent systemEvent);
}

/// <summary>
/// Console output handler
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
        
        // Full JSON every 10 events
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
/// File output handler - writes JSON to file
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
        var json = System.Text.Json.JsonSerializer.Serialize(wintapMsg, new System.Text.Json.JsonSerializerOptions 
        { 
            WriteIndented = true 
        });
        System.IO.File.AppendAllText(_outputPath, json + "\n");
    }
}

/// <summary>
/// Multi-output handler - send to multiple destinations
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