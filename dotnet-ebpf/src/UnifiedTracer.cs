using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace EbpfTracer;

/// <summary>
/// Main unified tracer application that orchestrates multiple eBPF tracers.
/// </summary>
class UnifiedTracer
{
    private static bool _running = true;
    private static IEventHandler? _eventHandler;

    static int Main(string[] args)
    {
        Console.WriteLine("eBPF Unified System Tracer");
        Console.WriteLine("===========================");
        Console.WriteLine();

        // Parse command line arguments
        var config = ParseArguments(args);
        if (config == null)
        {
            PrintUsage();
            return 1;
        }

        // Check for root privileges
        if (Environment.UserName != "root" && GetEuid() != 0)
        {
            Console.WriteLine("ERROR: This program requires root privileges.");
            Console.WriteLine("Please run with sudo.");
            return 1;
        }

        // Setup event handler based on configuration
        var adapter = new WintapMessageAdapter();
        _eventHandler = CreateEventHandler(config, adapter);

        var tracers = new List<TracerInstance>();

        try
        {
            // Load requested tracers
            if (config.TraceExecve)
            {
                var execveTracer = LoadTracer("execve", "execve_tracer.bpf.o", "trace_execve_entry");
                if (execveTracer != null)
                    tracers.Add(execveTracer);
            }

            if (config.TraceOpenat)
            {
                var openatTracer = LoadTracer("openat", "openat_tracer.bpf.o", "trace_openat_entry");
                if (openatTracer != null)
                    tracers.Add(openatTracer);
            }

            if (tracers.Count == 0)
            {
                Console.WriteLine("ERROR: No tracers successfully loaded.");
                return 1;
            }

            Console.WriteLine();
            Console.WriteLine($"Successfully attached {tracers.Count} tracer(s)!");
            Console.WriteLine("Press Ctrl+C to exit");
            Console.WriteLine();
            Console.WriteLine(new string('=', 120));

            // Setup signal handler for graceful shutdown
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                _running = false;
                Console.WriteLine("\nShutting down...");
            };

            // Poll all tracers
            while (_running)
            {
                foreach (var tracer in tracers)
                {
                    int pollRet = LibBpf.ring_buffer__poll(tracer.RingBuffer, 10);
                    if (pollRet < 0 && pollRet != -4) // -4 is EINTR (interrupted system call)
                    {
                        Console.WriteLine($"ERROR: {tracer.Name} ring_buffer__poll failed: {pollRet}");
                    }
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
            // Cleanup all tracers
            foreach (var tracer in tracers)
            {
                tracer.Dispose();
            }
        }
    }

    private static IEventHandler CreateEventHandler(TracerConfig config, WintapMessageAdapter adapter)
    {
        if (config.EnableConsole && config.OutputFile != null)
        {
            // Both console and file output
            var composite = new CompositeEventHandler();
            composite.AddHandler(new ConsoleEventHandler(adapter));
            composite.AddHandler(new FileEventHandler(adapter, config.OutputFile));
            return composite;
        }
        else if (config.OutputFile != null)
        {
            // File output only
            return new FileEventHandler(adapter, config.OutputFile);
        }
        else
        {
            // Console output (default)
            return new ConsoleEventHandler(adapter);
        }
    }

    private static TracerInstance? LoadTracer(string name, string objectPath, string programName)
    {
        Console.WriteLine($"Loading {name} tracer...");

        if (!File.Exists(objectPath))
        {
            Console.WriteLine($"  WARNING: {objectPath} not found, skipping {name} tracer");
            return null;
        }

        try
        {
            // Open BPF object
            IntPtr bpfObject = LibBpf.bpf_object__open(objectPath);
            if (bpfObject == IntPtr.Zero)
            {
                Console.WriteLine($"  ERROR: Failed to open {objectPath}");
                return null;
            }

            // Load into kernel
            int ret = LibBpf.bpf_object__load(bpfObject);
            if (ret != 0)
            {
                Console.WriteLine($"  ERROR: Failed to load {name}: {ret}");
                LibBpf.bpf_object__close(bpfObject);
                return null;
            }

            // Find program
            IntPtr prog = LibBpf.bpf_object__find_program_by_name(bpfObject, programName);
            if (prog == IntPtr.Zero)
            {
                Console.WriteLine($"  ERROR: Failed to find program '{programName}'");
                LibBpf.bpf_object__close(bpfObject);
                return null;
            }

            // Attach
            IntPtr link = LibBpf.bpf_program__attach(prog);
            if (link == IntPtr.Zero)
            {
                Console.WriteLine($"  ERROR: Failed to attach {name}");
                LibBpf.bpf_object__close(bpfObject);
                return null;
            }

            // Find ring buffer
            IntPtr eventsMap = LibBpf.bpf_object__find_map_by_name(bpfObject, "events");
            if (eventsMap == IntPtr.Zero)
            {
                Console.WriteLine($"  ERROR: Failed to find events map");
                LibBpf.bpf_link__destroy(link);
                LibBpf.bpf_object__close(bpfObject);
                return null;
            }

            int mapFd = LibBpf.bpf_map__fd(eventsMap);
            if (mapFd < 0)
            {
                Console.WriteLine($"  ERROR: Failed to get map FD");
                LibBpf.bpf_link__destroy(link);
                LibBpf.bpf_object__close(bpfObject);
                return null;
            }

            // Setup ring buffer with appropriate callback
            LibBpf.RingBufferCallback callback = name switch
            {
                "execve" => HandleExecveEvent,
                "openat" => HandleOpenatEvent,
                _ => throw new NotSupportedException($"Unknown tracer: {name}")
            };

            IntPtr ringBuffer = LibBpf.ring_buffer__new(mapFd, callback, IntPtr.Zero, IntPtr.Zero);
            if (ringBuffer == IntPtr.Zero)
            {
                Console.WriteLine($"  ERROR: Failed to create ring buffer");
                LibBpf.bpf_link__destroy(link);
                LibBpf.bpf_object__close(bpfObject);
                return null;
            }

            Console.WriteLine($"  ✓ {name} tracer attached successfully");

            return new TracerInstance
            {
                Name = name,
                BpfObject = bpfObject,
                Link = link,
                RingBuffer = ringBuffer
            };
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  ERROR: Exception loading {name}: {ex.Message}");
            return null;
        }
    }

    private static int HandleExecveEvent(IntPtr ctx, IntPtr data, UIntPtr size)
    {
        try
        {
            var evt = Marshal.PtrToStructure<ExecveEvent>(data);
            var processEvent = ProcessEvent.FromExecveEvent(evt);
            _eventHandler?.HandleEvent(processEvent);
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ERROR in execve callback: {ex.Message}");
            return -1;
        }
    }

    private static int HandleOpenatEvent(IntPtr ctx, IntPtr data, UIntPtr size)
    {
        try
        {
            var evt = Marshal.PtrToStructure<OpenatEvent>(data);
            var fileEvent = FileEvent.FromOpenatEvent(evt);
            _eventHandler?.HandleEvent(fileEvent);
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ERROR in openat callback: {ex.Message}");
            return -1;
        }
    }

    private static TracerConfig? ParseArguments(string[] args)
    {
        var config = new TracerConfig();

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--execve":
                    config.TraceExecve = true;
                    break;
                case "--openat":
                    config.TraceOpenat = true;
                    break;
                case "--all":
                    config.TraceExecve = true;
                    config.TraceOpenat = true;
                    break;
                case "--output":
                case "-o":
                    if (i + 1 < args.Length)
                    {
                        config.OutputFile = args[++i];
                    }
                    else
                    {
                        Console.WriteLine("ERROR: --output requires a filename");
                        return null;
                    }
                    break;
                case "--console":
                    config.EnableConsole = true;
                    break;
                case "--help":
                case "-h":
                    return null;
                default:
                    Console.WriteLine($"Unknown option: {args[i]}");
                    return null;
            }
        }

        // Default to all tracers if none specified
        if (!config.TraceExecve && !config.TraceOpenat)
        {
            config.TraceExecve = true;
            config.TraceOpenat = true;
        }

        return config;
    }

    private static void PrintUsage()
    {
        Console.WriteLine(@"
Usage: sudo dotnet run [OPTIONS]

Options:
  --execve              Trace execve() system calls (process creation)
  --openat              Trace openat() system calls (file access)
  --all                 Trace all available system calls (default)
  
  -o, --output FILE     Write events to JSON file
  --console             Also show events on console (with --output)
  
  -h, --help            Show this help message

Examples:
  sudo dotnet run                          # Trace everything
  sudo dotnet run --execve                 # Only process creation
  sudo dotnet run --openat                 # Only file access
  sudo dotnet run -o events.json           # Write to file
  sudo dotnet run -o events.json --console # File + console output
");
    }

    [DllImport("libc", SetLastError = true)]
    private static extern uint GetEuid();
}

/// <summary>
/// Configuration for the tracer application.
/// </summary>
class TracerConfig
{
    public bool TraceExecve { get; set; }
    public bool TraceOpenat { get; set; }
    public string? OutputFile { get; set; }
    public bool EnableConsole { get; set; }
}

/// <summary>
/// Represents a loaded eBPF tracer instance.
/// </summary>
class TracerInstance : IDisposable
{
    public string Name { get; set; } = string.Empty;
    public IntPtr BpfObject { get; set; }
    public IntPtr Link { get; set; }
    public IntPtr RingBuffer { get; set; }

    public void Dispose()
    {
        if (RingBuffer != IntPtr.Zero)
        {
            LibBpf.ring_buffer__free(RingBuffer);
            RingBuffer = IntPtr.Zero;
        }

        if (Link != IntPtr.Zero)
        {
            LibBpf.bpf_link__destroy(Link);
            Link = IntPtr.Zero;
        }

        if (BpfObject != IntPtr.Zero)
        {
            LibBpf.bpf_object__close(BpfObject);
            BpfObject = IntPtr.Zero;
        }
    }
}
