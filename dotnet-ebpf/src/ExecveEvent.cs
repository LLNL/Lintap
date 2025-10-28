using System;
using System.Runtime.InteropServices;
using System.Text;

namespace EbpfTracer;

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public unsafe struct ExecveEvent
{
    // Process identification
    public uint Pid;
    public uint PPid;     // Will be 0 from eBPF, filled in C#
    public uint Uid;
    public uint Gid;
    public uint Sid;      // Will be 0 from eBPF, filled in C#
    
    // Process details
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] Comm;
    
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
    public byte[] Filename;
    
    // Timing
    public ulong TimestampNs;
    
    // Placeholder fields (for compatibility)
    public uint ExitCode;
    public uint Flags;
    public ulong StartTime;
    public ulong Capabilities;
    public uint SeccompMode;
    
    // Helper methods
    public string GetComm() => GetString(Comm);
    public string GetFilename() => GetString(Filename);
    
    private static string GetString(byte[] bytes)
    {
        if (bytes == null) return string.Empty;
        int nullIndex = Array.IndexOf(bytes, (byte)0);
        if (nullIndex == -1) nullIndex = bytes.Length;
        return Encoding.UTF8.GetString(bytes, 0, nullIndex);
    }
    
    public DateTime GetTimestamp()
    {
        return DateTime.UtcNow;
    }
}