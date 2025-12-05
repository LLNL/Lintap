#!/usr/bin/env python3
"""
eBPF Playground - Test /proc paths and process events
Usage: sudo python3 ebpf_playground.py [mode]
Modes: execve, clone, all (default: all)
"""

from bcc import BPF
import sys
import argparse
from datetime import datetime

# Color output for terminal
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

# BPF program with both execve and clone tracing
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

// Event types
enum event_type {
    EVENT_EXECVE = 1,
    EVENT_CLONE = 2,
};

struct event_t {
    u32 event_type;
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    u64 timestamp_ns;
};

BPF_PERF_OUTPUT(events);

// Execve tracepoint
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t event = {};
    
    event.event_type = EVENT_EXECVE;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    
    u64 uid_gid = bpf_get_current_uid_gid();
    event.uid = uid_gid & 0xFFFFFFFF;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Read filename from syscall args
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);
    
    event.timestamp_ns = bpf_ktime_get_ns();
    
    // Get parent PID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &parent->tgid);
    
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// Clone/fork tracepoint
TRACEPOINT_PROBE(sched, sched_process_fork) {
    struct event_t event = {};
    
    event.event_type = EVENT_CLONE;
    
    // Parent info
    event.pid = args->parent_pid;
    bpf_probe_read_kernel_str(&event.comm, sizeof(event.comm), args->parent_comm);
    
    // Child PID (in filename field for simplicity)
    u32 child_pid = args->child_pid;
    bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &child_pid);
    
    u64 uid_gid = bpf_get_current_uid_gid();
    event.uid = uid_gid & 0xFFFFFFFF;
    
    event.timestamp_ns = bpf_ktime_get_ns();
    
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

class EbpfPlayground:
    def __init__(self, mode='all'):
        self.mode = mode
        self.proc_count = 0
        self.total_count = 0
        self.start_time = datetime.now()
        
        print(f"{Colors.HEADER}{Colors.BOLD}=== eBPF Playground ==={Colors.END}")
        print(f"Mode: {Colors.CYAN}{mode}{Colors.END}")
        print(f"Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Colors.YELLOW}Watching for /proc paths...{Colors.END}\n")
        
        # Load BPF program
        self.b = BPF(text=bpf_text)
        
        # Open perf buffer
        self.b["events"].open_perf_buffer(self.handle_event)
    
    def is_proc_path(self, path):
        """Check if path starts with /proc/"""
        return path.startswith("/proc/")
    
    def resolve_symlink(self, path):
        """Attempt to resolve symlink (like our .NET code will do)"""
        import os
        try:
            if os.path.exists(path):
                return os.path.realpath(path)
        except:
            pass
        return None
    
    def handle_event(self, cpu, data, size):
        """Handle events from BPF"""
        event = self.b["events"].event(data)
        self.total_count += 1
        
        # Decode strings
        comm = event.comm.decode('utf-8', 'replace').rstrip('\x00')
        filename = event.filename.decode('utf-8', 'replace').rstrip('\x00')
        
        # Filter by mode
        if self.mode == 'execve' and event.event_type != 1:
            return
        if self.mode == 'clone' and event.event_type != 2:
            return
        
        # Determine event type
        event_name = "EXECVE" if event.event_type == 1 else "CLONE "
        
        # Check for /proc path
        is_proc = self.is_proc_path(filename) if filename else False
        
        # Color code based on /proc detection
        if is_proc:
            self.proc_count += 1
            color = Colors.RED
            indicator = "🔴 /PROC"
        else:
            color = Colors.GREEN
            indicator = "✓"
        
        # Print event
        timestamp = datetime.fromtimestamp(event.timestamp_ns / 1e9).strftime('%H:%M:%S.%f')[:-3]
        
        print(f"{color}{indicator} [{event_name}]{Colors.END} "
              f"{Colors.BOLD}PID:{event.pid}{Colors.END} "
              f"PPID:{event.ppid} "
              f"UID:{event.uid} "
              f"{Colors.CYAN}{comm:16s}{Colors.END}")
        
        if filename:
            print(f"  └─ Filename: {color}{filename}{Colors.END}")
            
            # Try to resolve if it's a /proc path
            if is_proc:
                resolved = self.resolve_symlink(filename)
                if resolved and resolved != filename:
                    print(f"  └─ Resolved: {Colors.GREEN}{resolved}{Colors.END}")
                else:
                    print(f"  └─ {Colors.YELLOW}Could not resolve (process may have exited){Colors.END}")
        
        print()  # Blank line between events
    
    def print_stats(self):
        """Print statistics"""
        duration = (datetime.now() - self.start_time).total_seconds()
        proc_pct = (self.proc_count / self.total_count * 100) if self.total_count > 0 else 0
        
        print(f"\n{Colors.HEADER}{Colors.BOLD}=== Statistics ==={Colors.END}")
        print(f"Duration: {duration:.1f}s")
        print(f"Total events: {self.total_count}")
        print(f"/proc paths: {Colors.RED}{self.proc_count}{Colors.END} ({proc_pct:.1f}%)")
        print(f"Normal paths: {Colors.GREEN}{self.total_count - self.proc_count}{Colors.END}")
    
    def run(self):
        """Main event loop"""
        print(f"{Colors.BOLD}Listening for events... Press Ctrl-C to stop{Colors.END}\n")
        
        try:
            while True:
                self.b.perf_buffer_poll()
        except KeyboardInterrupt:
            self.print_stats()
            print(f"\n{Colors.CYAN}Exiting...{Colors.END}")

def main():
    parser = argparse.ArgumentParser(
        description='eBPF Playground - Test /proc paths and process events',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 ebpf_playground.py              # Watch all events
  sudo python3 ebpf_playground.py execve       # Only execve events
  sudo python3 ebpf_playground.py clone        # Only clone/fork events
  
Tips:
  - Look for RED 🔴 markers for /proc paths
  - Test by running: exec /proc/self/exe
  - Try: systemctl restart some-service
        """
    )
    parser.add_argument('mode', nargs='?', default='all',
                       choices=['execve', 'clone', 'all'],
                       help='Event type to monitor (default: all)')
    
    args = parser.parse_args()
    
    # Check if running as root
    import os
    if os.geteuid() != 0:
        print(f"{Colors.RED}Error: This script requires root privileges{Colors.END}")
        print(f"Run with: sudo python3 {sys.argv[0]}")
        sys.exit(1)
    
    playground = EbpfPlayground(mode=args.mode)
    playground.run()

if __name__ == '__main__':
    main()
