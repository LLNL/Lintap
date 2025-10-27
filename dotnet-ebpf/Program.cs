using System;
using System.IO;
using System.Runtime.InteropServices;
using EbpfOpenatPoc;

class Program
{
    private static bool _running = true;

    static int Main(string[] args)
    {
        Console.WriteLine("eBPF OpenAt Tracer - .NET Control Plane");
        Console.WriteLine("========================================");
        Console.WriteLine();

        // Check for root privileges
        if (Environment.UserName != "root" && GetEuid() != 0)
        {
            Console.WriteLine("ERROR: This program requires root privileges.");
            Console.WriteLine("Please run with sudo.");
            return 1;
        }

        string bpfObjectPath = "openat_tracer.bpf.o";
        if (!File.Exists(bpfObjectPath))
        {
            Console.WriteLine($"ERROR: BPF object file not found: {bpfObjectPath}");
            Console.WriteLine("Please run 'make' first to compile the eBPF program.");
            return 1;
        }

        IntPtr bpfObject = IntPtr.Zero;
        IntPtr bpfLink = IntPtr.Zero;
        IntPtr ringBuffer = IntPtr.Zero;

        try
        {
            // Open BPF object
            Console.WriteLine($"Loading BPF object: {bpfObjectPath}");
            bpfObject = LibBpf.bpf_object__open(bpfObjectPath);
            if (bpfObject == IntPtr.Zero)
            {
                Console.WriteLine("ERROR: Failed to open BPF object");
                return 1;
            }

            // Load BPF object into kernel
            Console.WriteLine("Loading BPF program into kernel...");
            int ret = LibBpf.bpf_object__load(bpfObject);
            if (ret != 0)
            {
                Console.WriteLine($"ERROR: Failed to load BPF object: {ret}");
                return 1;
            }

            // Find the program
            Console.WriteLine("Finding BPF program...");
            IntPtr prog = LibBpf.bpf_object__find_program_by_name(bpfObject, "trace_openat_entry");
            if (prog == IntPtr.Zero)
            {
                Console.WriteLine("ERROR: Failed to find BPF program 'trace_openat_entry'");
                return 1;
            }

            // Attach the program
            Console.WriteLine("Attaching BPF program to tracepoint...");
            bpfLink = LibBpf.bpf_program__attach(prog);
            if (bpfLink == IntPtr.Zero)
            {
                Console.WriteLine("ERROR: Failed to attach BPF program");
                return 1;
            }

            // Find the ring buffer map
            Console.WriteLine("Finding ring buffer map...");
            IntPtr eventsMap = LibBpf.bpf_object__find_map_by_name(bpfObject, "events");
            if (eventsMap == IntPtr.Zero)
            {
                Console.WriteLine("ERROR: Failed to find 'events' map");
                return 1;
            }

            int mapFd = LibBpf.bpf_map__fd(eventsMap);
            if (mapFd < 0)
            {
                Console.WriteLine("ERROR: Failed to get map FD");
                return 1;
            }

            // Setup ring buffer
            Console.WriteLine("Setting up ring buffer...");
            var callback = new LibBpf.RingBufferCallback(HandleEvent);
            ringBuffer = LibBpf.ring_buffer__new(mapFd, callback, IntPtr.Zero, IntPtr.Zero);
            if (ringBuffer == IntPtr.Zero)
            {
                Console.WriteLine("ERROR: Failed to create ring buffer");
                return 1;
            }

            Console.WriteLine();
            Console.WriteLine("Successfully attached! Tracing openat() calls...");
            Console.WriteLine("Press Ctrl+C to exit");
            Console.WriteLine();
            Console.WriteLine($"{"PID",-10} {"COMMAND",-16} {"FILENAME"}");
            Console.WriteLine(new string('-', 80));

            // Setup signal handler
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                _running = false;
                Console.WriteLine("\nShutting down...");
            };

            // Poll for events
            while (_running)
            {
                int pollRet = LibBpf.ring_buffer__poll(ringBuffer, 100);
                if (pollRet < 0 && pollRet != -4) // -4 is EINTR (interrupted)
                {
                    Console.WriteLine($"ERROR: ring_buffer__poll failed: {pollRet}");
                    break;
                }
            }

            Console.WriteLine("Cleanup complete.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ERROR: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
            return 1;
        }
        finally
        {
            // Cleanup
            if (ringBuffer != IntPtr.Zero)
                LibBpf.ring_buffer__free(ringBuffer);
            
            if (bpfLink != IntPtr.Zero)
                LibBpf.bpf_link__destroy(bpfLink);
            
            if (bpfObject != IntPtr.Zero)
                LibBpf.bpf_object__close(bpfObject);
        }
    }

    private static int HandleEvent(IntPtr ctx, IntPtr data, UIntPtr size)
    {
        try
        {
            // Marshal the data into our struct
            var evt = Marshal.PtrToStructure<OpenatEvent>(data);
            
            // Print the event
            Console.WriteLine($"{evt.Pid,-10} {evt.GetComm(),-16} {evt.GetFilename()}");
            
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ERROR in callback: {ex.Message}");
            return -1;
        }
    }

    [DllImport("libc", SetLastError = true)]
    private static extern uint GetEuid();
}
