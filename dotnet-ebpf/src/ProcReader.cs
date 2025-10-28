using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

namespace EbpfTracer;

/// <summary>
/// Utility class for reading process information from the /proc filesystem
/// </summary>
public static class ProcReader
{
    /// <summary>
    /// Comprehensive process data from /proc
    /// </summary>
    public class ProcessData
    {
        public int ParentProcessId { get; set; }
        public uint SessionId { get; set; }
        public uint UserId { get; set; }
        public uint GroupId { get; set; }
        public string CommandLine { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string HomeDirectory { get; set; } = string.Empty;
        public string Shell { get; set; } = string.Empty;
        public string WorkingDirectory { get; set; } = string.Empty;
    }

    /// <summary>
    /// Read comprehensive process information from /proc/<pid>
    /// </summary>
    public static ProcessData ReadProcessData(uint pid)
    {
        var data = new ProcessData();
        var procDir = $"/proc/{pid}";

        try
        {
            // Read /proc/<pid>/status for PPID, UIDs, session info
            ReadStatus(procDir, ref data);
            
            // Read /proc/<pid>/cmdline for full command line
            ReadCommandLine(procDir, ref data);
            
            // Read /proc/<pid>/environ for environment variables
            ReadEnvironment(procDir, ref data);
            
            // Read /proc/<pid>/cwd for working directory
            ReadWorkingDirectory(procDir, ref data);
        }
        catch (Exception)
        {
            // Process may have exited or permission denied
            // Return partial data
        }

        return data;
    }

    /// <summary>
    /// Read /proc/<pid>/status file for process metadata
    /// </summary>
    private static void ReadStatus(string procDir, ref ProcessData data)
    {
        var statusPath = $"{procDir}/status";
        if (!File.Exists(statusPath))
            return;

        foreach (var line in File.ReadLines(statusPath))
        {
            if (line.StartsWith("PPid:", StringComparison.Ordinal))
            {
                var parts = line.Split(new[] { ':', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && int.TryParse(parts[1], out int ppid))
                    data.ParentProcessId = ppid;
            }
            else if (line.StartsWith("NSpid:", StringComparison.Ordinal))
            {
                // Approximate session ID
                var parts = line.Split(new[] { ':', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && uint.TryParse(parts[1], out uint sid))
                    data.SessionId = sid;
            }
            else if (line.StartsWith("Uid:", StringComparison.Ordinal))
            {
                var parts = line.Split(new[] { ':', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && uint.TryParse(parts[1], out uint uid))
                    data.UserId = uid;
            }
            else if (line.StartsWith("Gid:", StringComparison.Ordinal))
            {
                var parts = line.Split(new[] { ':', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && uint.TryParse(parts[1], out uint gid))
                    data.GroupId = gid;
            }
        }
    }

    /// <summary>
    /// Read /proc/<pid>/cmdline for full command line with arguments
    /// </summary>
    private static void ReadCommandLine(string procDir, ref ProcessData data)
    {
        var cmdlinePath = $"{procDir}/cmdline";
        if (!File.Exists(cmdlinePath))
            return;

        var cmdlineBytes = File.ReadAllBytes(cmdlinePath);
        var args = ParseNullSeparatedBytes(cmdlineBytes);
        data.CommandLine = string.Join(" ", args);
    }

    /// <summary>
    /// Read /proc/<pid>/environ for environment variables
    /// </summary>
    private static void ReadEnvironment(string procDir, ref ProcessData data)
    {
        var environPath = $"{procDir}/environ";
        if (!File.Exists(environPath))
            return;

        var environBytes = File.ReadAllBytes(environPath);
        var envVars = ParseNullSeparatedBytes(environBytes);

        foreach (var envVar in envVars)
        {
            if (envVar.StartsWith("USER="))
                data.Username = envVar.Substring(5);
            else if (envVar.StartsWith("HOME="))
                data.HomeDirectory = envVar.Substring(5);
            else if (envVar.StartsWith("SHELL="))
                data.Shell = envVar.Substring(6);
        }
    }

    /// <summary>
    /// Read /proc/<pid>/cwd symlink for current working directory
    /// </summary>
    private static void ReadWorkingDirectory(string procDir, ref ProcessData data)
    {
        var cwdPath = $"{procDir}/cwd";
        
        try
        {
            // In .NET, read the symlink target
            var fileInfo = new FileInfo(cwdPath);
            if (fileInfo.Exists && fileInfo.LinkTarget != null)
            {
                data.WorkingDirectory = fileInfo.LinkTarget;
            }
        }
        catch (Exception)
        {
            // Permission denied or not a symlink
        }
    }

    /// <summary>
    /// Parse null-separated byte array into strings
    /// Used for /proc/*/cmdline and /proc/*/environ
    /// </summary>
    private static List<string> ParseNullSeparatedBytes(byte[] bytes)
    {
        var results = new List<string>();
        int start = 0;

        for (int i = 0; i < bytes.Length; i++)
        {
            if (bytes[i] == 0)
            {
                if (i > start)
                {
                    var str = Encoding.UTF8.GetString(bytes, start, i - start);
                    results.Add(str);
                }
                start = i + 1;
            }
        }

        // Handle last item if no trailing null
        if (start < bytes.Length)
        {
            var str = Encoding.UTF8.GetString(bytes, start, bytes.Length - start);
            if (!string.IsNullOrEmpty(str))
                results.Add(str);
        }

        return results;
    }
}
