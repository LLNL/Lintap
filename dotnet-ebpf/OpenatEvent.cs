using System;
using System.Runtime.InteropServices;

namespace EbpfOpenatPoc;

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public unsafe struct OpenatEvent
{
    public uint Pid;
    
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] Comm;
    
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
    public byte[] Filename;

    public string GetComm()
    {
        int nullIndex = Array.IndexOf(Comm, (byte)0);
        if (nullIndex == -1)
            nullIndex = Comm.Length;
        return System.Text.Encoding.UTF8.GetString(Comm, 0, nullIndex);
    }

    public string GetFilename()
    {
        int nullIndex = Array.IndexOf(Filename, (byte)0);
        if (nullIndex == -1)
            nullIndex = Filename.Length;
        return System.Text.Encoding.UTF8.GetString(Filename, 0, nullIndex);
    }
}
