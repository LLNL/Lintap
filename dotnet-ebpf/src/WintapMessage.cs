using System;
using System.Collections.Generic;

namespace EbpfTracer;

/// <summary>
/// Maps Linux eBPF execve events to Wintap message format
/// Based on: https://github.com/LLNL/Wintap/blob/main/WintapAPI/WintapMessage.cs
/// </summary>
public class WintapMessage
{
    // Event identification
    public Guid EventId { get; set; }
    public string EventType { get; set; } = string.Empty;
    public DateTime EventTime { get; set; }
    
    // Process information
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string ProcessCommandLine { get; set; } = string.Empty;
    public int ParentProcessId { get; set; }
    public string ParentProcessName { get; set; } = string.Empty;
    
    // User/Session information
    public string User { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;  // N/A on Linux
    public int Session { get; set; }
    public string LogonId { get; set; } = string.Empty; // Map to UID
    
    // File information (for execve, this is the executable)
    public string FileName { get; set; } = string.Empty;
    public string FileDirectory { get; set; } = string.Empty;
    
    // Network information (N/A for execve)
    public string IpAddress { get; set; } = string.Empty;
    public int Port { get; set; }
    public string Protocol { get; set; } = string.Empty;
    
    // Additional context
    public string Details { get; set; } = string.Empty;
    public Dictionary<string, string> ExtendedProperties { get; set; } = new();
    
    /// <summary>
    /// Format as JSON-like string for display
    /// </summary>
    public override string ToString()
    {
        return $@"{{
  ""EventId"": ""{EventId}"",
  ""EventType"": ""{EventType}"",
  ""EventTime"": ""{EventTime:O}"",
  ""ProcessId"": {ProcessId},
  ""ProcessName"": ""{ProcessName}"",
  ""ProcessCommandLine"": ""{ProcessCommandLine}"",
  ""ParentProcessId"": {ParentProcessId},
  ""User"": ""{User}"",
  ""Session"": {Session},
  ""FileName"": ""{FileName}"",
  ""FileDirectory"": ""{FileDirectory}""
}}";
    }
    
    /// <summary>
    /// Format as compact single-line for logging
    /// </summary>
    public string ToCompactString()
    {
        return $"[{EventTime:HH:mm:ss}] PID:{ProcessId} PPID:{ParentProcessId} User:{User} | {ProcessCommandLine}";
    }
}